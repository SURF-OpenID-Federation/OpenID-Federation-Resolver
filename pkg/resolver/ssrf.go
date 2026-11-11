package resolver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrBlockedDestination is returned when an outbound fetch targets a
// disallowed scheme, literal IP, or non-public resolved address (SSRF guard).
var ErrBlockedDestination = errors.New("blocked destination: SSRF protection")

// isBlockedIP reports whether ip must not be dialed for federation fetches.
// Covers loopback, RFC1918/ULA, link-local (incl. cloud metadata), multicast,
// and unspecified addresses.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func hostIsLiteralIP(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	// Strip brackets from IPv6 literals ("[::1]").
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return net.ParseIP(h) != nil
}

// validateFetchURL checks scheme and rejects literal IP hosts unless private
// networks are explicitly allowed (tests / controlled docker mappings).
func validateFetchURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid URL: %v", ErrBlockedDestination, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: scheme %q not allowed", ErrBlockedDestination, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrBlockedDestination)
	}
	if !allowPrivate && hostIsLiteralIP(host) {
		ip := net.ParseIP(host)
		if ip == nil {
			// Bracketed form already handled by Hostname().
			ip = net.ParseIP(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["))
		}
		if ip != nil && isBlockedIP(ip) {
			return fmt.Errorf("%w: address %s is not publicly routable", ErrBlockedDestination, host)
		}
		// Public literal IPs (e.g. firewalled DC ranges) are still blocked:
		// entity identifiers are expected to be hostnames, not raw addresses.
		return fmt.Errorf("%w: literal IP hosts are not allowed", ErrBlockedDestination)
	}
	return nil
}

type ssrfDialer struct {
	base         *net.Dialer
	allowPrivate bool
	// allowedHosts are hostname allowlist entries (lowercased) that may resolve
	// to private addresses — used for configured URL mapping targets.
	allowedHosts map[string]struct{}
}

func (d *ssrfDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBlockedDestination, err)
	}

	if d.allowPrivate {
		return d.base.DialContext(ctx, network, addr)
	}

	if _, ok := d.allowedHosts[strings.ToLower(host)]; ok {
		return d.base.DialContext(ctx, network, addr)
	}

	if hostIsLiteralIP(host) {
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("%w: invalid IP host %q", ErrBlockedDestination, host)
		}
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("%w: address %s is not publicly routable", ErrBlockedDestination, host)
		}
		// Still refuse literal public IPs at dial time for defense in depth.
		return nil, fmt.Errorf("%w: literal IP hosts are not allowed", ErrBlockedDestination)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ipa := range ips {
		if isBlockedIP(ipa.IP) {
			lastErr = fmt.Errorf("%w: %s resolved to non-public address %s", ErrBlockedDestination, host, ipa.IP)
			continue
		}
		target := net.JoinHostPort(ipa.IP.String(), port)
		conn, err := d.base.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%w: no usable addresses for %s", ErrBlockedDestination, host)
	}
	return nil, lastErr
}

func mappingAllowedHosts(mappings map[string]string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, v := range mappings {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			out[strings.ToLower(u.Hostname())] = struct{}{}
			continue
		}
		// Host-only mapping values (e.g. "trust-anchor").
		if !strings.Contains(v, "/") {
			host := v
			if h, _, err := net.SplitHostPort(v); err == nil {
				host = h
			}
			out[strings.ToLower(host)] = struct{}{}
		}
	}
	return out
}

func newSafeHTTPClient(cfg *Config) *http.Client {
	allowPrivate := cfg != nil && cfg.AllowPrivateNetworks
	var mappings map[string]string
	if cfg != nil {
		mappings = cfg.URLMappings
	}

	dialer := &ssrfDialer{
		base: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		allowPrivate: allowPrivate,
		allowedHosts: mappingAllowedHosts(mappings),
	}

	tlsCfg := &tls.Config{}
	if cfg != nil && cfg.SkipTLSVerify {
		tlsCfg.InsecureSkipVerify = true
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsCfg,
	}

	timeout := 30 * time.Second
	if cfg != nil && cfg.RequestTimeout > 0 {
		timeout = cfg.RequestTimeout
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if err := validateFetchURL(req.URL.String(), allowPrivate); err != nil {
				return err
			}
			return nil
		},
	}
}

// safeResponseSnippet returns a short, non-sensitive summary of an upstream
// body for error messages — never the raw body (prevents SSRF data leak via errors).
func safeResponseSnippet(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "empty body"
	}
	if strings.Count(trimmed, ".") == 2 {
		parts := strings.Split(trimmed, ".")
		if len(parts[0]) > 0 && len(parts[1]) > 0 {
			return fmt.Sprintf("JWT-like body (%d bytes)", len(trimmed))
		}
	}
	// Surface only well-known OAuth/OIDF error codes — never arbitrary JSON fields.
	var probe struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &probe) == nil && probe.Error != "" {
		desc := truncateForLog(probe.ErrorDescription, 80)
		if desc != "" {
			return fmt.Sprintf("error=%q desc=%q", probe.Error, desc)
		}
		return fmt.Sprintf("error=%q", probe.Error)
	}
	ctHint := "non-JWT body"
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html"):
		ctHint = "HTML body"
	case strings.HasPrefix(lower, "{") || strings.HasPrefix(lower, "["):
		ctHint = "JSON body"
	}
	return fmt.Sprintf("%s (%d bytes)", ctHint, len(trimmed))
}

// looksLikeCompactJWT reports whether s has the three-part shape of a JWS.
func looksLikeCompactJWT(s string) bool {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

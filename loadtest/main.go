// Load test for a running Federation Resolver.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type target struct {
	name   string
	url    string
	weight int
}

type phaseSpec struct {
	title    string
	duration time.Duration
	workers  int
}

type bucket struct {
	n, ok, fail atomic.Int64
	bytes       atomic.Int64
	lat         []time.Duration
	mu          sync.Mutex
	codes       sync.Map
}

type phaseResult struct {
	title   string
	workers int
	elapsed time.Duration
	bucket  *bucket
	sorted  []time.Duration
	rps     float64
	status  string
}

func (b *bucket) add(code int, d time.Duration, n int64, err error) {
	b.n.Add(1)
	b.bytes.Add(n)
	if err == nil && code >= 200 && code < 400 {
		b.ok.Add(1)
	} else {
		b.fail.Add(1)
	}
	key := "err"
	if err == nil {
		key = fmt.Sprintf("%d", code)
	}
	if v, ok := b.codes.Load(key); ok {
		v.(*atomic.Int64).Add(1)
	} else {
		c := &atomic.Int64{}
		c.Add(1)
		actual, loaded := b.codes.LoadOrStore(key, c)
		if loaded {
			actual.(*atomic.Int64).Add(1)
		}
	}
	b.mu.Lock()
	b.lat = append(b.lat, d)
	b.mu.Unlock()
}

func (b *bucket) snapshot() []time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]time.Duration, len(b.lat))
	copy(out, b.lat)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (b *bucket) statusSummary() string {
	type kv struct {
		k string
		n int64
	}
	var items []kv
	b.codes.Range(func(k, v any) bool {
		items = append(items, kv{k.(string), v.(*atomic.Int64).Load()})
		return true
	})
	sort.Slice(items, func(i, j int) bool { return items[i].k < items[j].k })
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", it.k, it.n))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, " ")
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(float64(len(sorted)-1)*p)]
}

func fmtLat(d time.Duration) string {
	if d == 0 {
		return "—"
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		ms := float64(d) / float64(time.Millisecond)
		if ms >= 10 {
			return fmt.Sprintf("%.0fms", ms)
		}
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func fmtCount(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func pick(targets []target) target {
	total := 0
	for _, t := range targets {
		total += t.weight
	}
	x := rand.Intn(total)
	for _, t := range targets {
		x -= t.weight
		if x < 0 {
			return t
		}
	}
	return targets[0]
}

func mergeInto(all, b *bucket) {
	all.n.Add(b.n.Load())
	all.ok.Add(b.ok.Load())
	all.fail.Add(b.fail.Load())
	all.bytes.Add(b.bytes.Load())
	b.mu.Lock()
	all.mu.Lock()
	all.lat = append(all.lat, b.lat...)
	all.mu.Unlock()
	b.mu.Unlock()
	b.codes.Range(func(k, v any) bool {
		n := v.(*atomic.Int64).Load()
		if existing, ok := all.codes.Load(k); ok {
			existing.(*atomic.Int64).Add(n)
		} else {
			c := &atomic.Int64{}
			c.Add(n)
			all.codes.Store(k, c)
		}
		return true
	})
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

func main() {
	base := flag.String("base", envOr("RESOLVER_URL", "https://resolver.poc2.dev.oidf.lab.surfconext.nl"), "Resolver base URL")
	ta := flag.String("ta", envOr("TRUST_ANCHOR", "https://ta.poc2.dev.oidf.lab.surfconext.nl"), "Registered trust anchor entity ID")
	quick := flag.Bool("quick", false, "Shorter phases (about 20s total)")
	timeout := flag.Duration("timeout", 20*time.Second, "Per-request timeout")
	var subs stringList
	flag.Var(&subs, "sub", "Entity to resolve (repeatable or comma-separated). Defaults to intermediary and rp under the same domain as -ta")
	flag.Parse()

	*base = strings.TrimRight(*base, "/")
	if len(subs) == 0 {
		host := hostOf(*ta)
		subs = []string{
			"https://intermediary." + host,
			"https://rp." + host,
		}
	}

	targets := buildTargets(*base, *ta, subs)
	client := newClient(*timeout)

	fmt.Printf("Resolver:     %s\n", *base)
	fmt.Printf("Trust anchor: %s\n", *ta)
	fmt.Printf("Subjects:     %s\n", strings.Join(subs, ", "))
	fmt.Println()

	if err := preflight(client, *base, *ta, subs[0]); err != nil {
		fmt.Fprintf(os.Stderr, "preflight failed: %v\n", err)
		os.Exit(1)
	}

	phases := defaultPhases(*quick)
	results := make([]phaseResult, 0, len(phases))
	var all bucket

	for _, p := range phases {
		fmt.Printf(">> %s  (%s, %d workers)\n", p.title, p.duration, p.workers)
		b, elapsed := runPhase(client, targets, p)
		sorted := b.snapshot()
		rps := 0.0
		if elapsed > 0 {
			rps = float64(b.n.Load()) / elapsed.Seconds()
		}
		res := phaseResult{
			title:   p.title,
			workers: p.workers,
			elapsed: elapsed,
			bucket:  b,
			sorted:  sorted,
			rps:     rps,
			status:  b.statusSummary(),
		}
		results = append(results, res)
		printPhaseLine(res)
		mergeInto(&all, b)
	}

	allSorted := all.snapshot()
	printMatrix(results, &all, allSorted)

	fmt.Println("\nPost-test health:")
	if err := checkURL(client, *base+"/health"); err != nil {
		fmt.Fprintf(os.Stderr, "  health: %v\n", err)
		os.Exit(1)
	}

	if all.fail.Load() > 0 {
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func hostOf(entityID string) string {
	u, err := url.Parse(entityID)
	if err != nil {
		return strings.TrimPrefix(entityID, "https://")
	}
	h := u.Hostname()
	h = strings.TrimPrefix(h, "ta.")
	return h
}

func buildTargets(base, ta string, subs []string) []target {
	taQ := url.QueryEscape(ta)
	out := []target{
		{name: "federation_list", url: base + "/api/v1/federation_list?trust_anchor=" + taQ, weight: 20},
		{name: "well-known", url: base + "/.well-known/openid-federation", weight: 7},
		{name: "health", url: base + "/health", weight: 3},
	}
	weights := []int{55, 15, 10, 10}
	for i, sub := range subs {
		w := 10
		if i < len(weights) {
			w = weights[i]
		}
		out = append(out, target{
			name:   "resolve:" + sub,
			url:    base + "/api/v1/resolve?sub=" + url.QueryEscape(sub) + "&trust_anchor=" + taQ,
			weight: w,
		})
	}
	return out
}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          2000,
			MaxIdleConnsPerHost:   2000,
			MaxConnsPerHost:       2000,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

func defaultPhases(quick bool) []phaseSpec {
	if quick {
		return []phaseSpec{
			{"Warm-up", 5 * time.Second, 20},
			{"Steady", 8 * time.Second, 100},
			{"High", 5 * time.Second, 400},
		}
	}
	return []phaseSpec{
		{"Warm-up", 10 * time.Second, 20},
		{"Steady", 20 * time.Second, 100},
		{"High", 20 * time.Second, 400},
		{"Spike", 15 * time.Second, 800},
	}
}

func runPhase(client *http.Client, targets []target, p phaseSpec) (*bucket, time.Duration) {
	b := &bucket{}
	start := time.Now()
	stop := start.Add(p.duration)
	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				t := pick(targets)
				req, err := http.NewRequest(http.MethodGet, t.url, nil)
				if err != nil {
					b.add(0, 0, 0, err)
					continue
				}
				req.Header.Set("User-Agent", "resolver-loadtest/1.0")
				t0 := time.Now()
				resp, err := client.Do(req)
				d := time.Since(t0)
				var n int64
				code := 0
				if err == nil {
					code = resp.StatusCode
					n, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				b.add(code, d, n, err)
			}
		}()
	}
	wg.Wait()
	return b, time.Since(start)
}

func printPhaseLine(r phaseResult) {
	fmt.Printf("   %s req  %s ok  %s fail  %.0f rps  p50=%s p99=%s  %s\n",
		fmtCount(r.bucket.n.Load()),
		fmtCount(r.bucket.ok.Load()),
		fmtCount(r.bucket.fail.Load()),
		r.rps,
		fmtLat(percentile(r.sorted, 0.50)),
		fmtLat(percentile(r.sorted, 0.99)),
		r.status,
	)
}

func printMatrix(results []phaseResult, all *bucket, allSorted []time.Duration) {
	fmt.Println()
	fmt.Println("| Phase   | Workers | Throughput | p50    | p99    | Errors |")
	fmt.Println("| ------- | ------- | ---------- | ------ | ------ | ------ |")
	for _, r := range results {
		fmt.Printf("| %-7s | %7d | %7.0f rps | %6s | %6s | %6s |\n",
			r.title,
			r.workers,
			r.rps,
			fmtLat(percentile(r.sorted, 0.50)),
			fmtLat(percentile(r.sorted, 0.99)),
			fmtCount(r.bucket.fail.Load()),
		)
	}
	fmt.Printf("| %-7s | %7s | %7s req | %6s | %6s | %6s |\n",
		"TOTAL",
		"—",
		fmtCount(all.n.Load()),
		fmtLat(percentile(allSorted, 0.50)),
		fmtLat(percentile(allSorted, 0.99)),
		fmtCount(all.fail.Load()),
	)
	fmt.Println()
	fmt.Printf("%s requests, %s ok, %s fail  (%s)\n",
		fmtCount(all.n.Load()),
		fmtCount(all.ok.Load()),
		fmtCount(all.fail.Load()),
		all.statusSummary(),
	)
}

func preflight(client *http.Client, base, ta, sub string) error {
	if err := expectStatus(client, base+"/health", 200); err != nil {
		return fmt.Errorf("health: %w", err)
	}
	listURL := base + "/api/v1/federation_list?trust_anchor=" + url.QueryEscape(ta)
	if err := expectStatus(client, listURL, 200); err != nil {
		return fmt.Errorf("federation_list: %w", err)
	}
	resolveURL := base + "/api/v1/resolve?sub=" + url.QueryEscape(sub) + "&trust_anchor=" + url.QueryEscape(ta)
	if err := expectStatus(client, resolveURL, 200); err != nil {
		return fmt.Errorf("resolve (is the TA registered for signing?): %w", err)
	}
	fmt.Println("Preflight OK (health, federation_list, resolve).")
	fmt.Println()
	return nil
}

func checkURL(client *http.Client, raw string) error {
	if err := expectStatus(client, raw, 200); err != nil {
		return err
	}
	fmt.Printf("  OK %s\n", raw)
	return nil
}

func expectStatus(client *http.Client, raw string, want int) error {
	resp, err := client.Get(raw)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("%s -> HTTP %d (want %d)", raw, resp.StatusCode, want)
	}
	return nil
}

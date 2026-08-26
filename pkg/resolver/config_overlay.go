package resolver

import "strings"

// ApplyMutableOverlay updates day-2 config fields (organization metadata, authority
// hints, trust anchors). Identity and infrastructure stay ENV-locked and are not
// changed here. Overlay slices replace the previous values when non-nil; use an
// empty non-nil slice to clear. Returns a shallow copy of the effective config.
func (r *FederationResolver) ApplyMutableOverlay(o MutableOverlay) *Config {
	r.configMu.Lock()
	defer r.configMu.Unlock()

	cfg := *r.config
	cfg.OrganizationName = strings.TrimSpace(o.OrganizationName)
	cfg.OrganizationURI = strings.TrimSpace(o.OrganizationURI)
	cfg.LogoURI = strings.TrimSpace(o.LogoURI)
	if o.Contacts != nil {
		cfg.Contacts = append([]string(nil), o.Contacts...)
	} else {
		cfg.Contacts = nil
	}
	if o.AuthorityHints != nil {
		cfg.AuthorityHints = append([]string(nil), o.AuthorityHints...)
	} else {
		cfg.AuthorityHints = nil
	}
	if o.TrustAnchors != nil {
		cfg.TrustAnchors = append([]string(nil), o.TrustAnchors...)
	} else {
		cfg.TrustAnchors = nil
	}
	r.config = &cfg
	return r.snapshotConfigLocked()
}

// SnapshotConfig returns a shallow copy of the current resolver config.
func (r *FederationResolver) SnapshotConfig() *Config {
	r.configMu.RLock()
	defer r.configMu.RUnlock()
	return r.snapshotConfigLocked()
}

func (r *FederationResolver) snapshotConfigLocked() *Config {
	if r.config == nil {
		return &Config{}
	}
	out := *r.config
	out.TrustAnchors = append([]string(nil), r.config.TrustAnchors...)
	out.AuthorityHints = append([]string(nil), r.config.AuthorityHints...)
	out.Contacts = append([]string(nil), r.config.Contacts...)
	if r.config.URLMappings != nil {
		out.URLMappings = make(map[string]string, len(r.config.URLMappings))
		for k, v := range r.config.URLMappings {
			out.URLMappings[k] = v
		}
	}
	return &out
}

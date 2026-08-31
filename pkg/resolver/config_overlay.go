package resolver

import "strings"

// ApplyMutableOverlay updates day-2 config fields (organization metadata, authority
// hints, trust anchors, Entity Configuration overlay). Identity and infrastructure
// stay ENV-locked and are not changed here. Overlay slices replace the previous
// values when non-nil; use an empty non-nil slice to clear. Returns a shallow copy
// of the effective config.
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
	cfg.EntityStatementLifetime = o.EntityStatementLifetime
	if o.Crit != nil {
		cfg.Crit = append([]string(nil), o.Crit...)
	} else {
		cfg.Crit = nil
	}
	if o.TrustMarks != nil {
		cfg.TrustMarks = cloneTrustMarks(o.TrustMarks)
	} else {
		cfg.TrustMarks = nil
	}
	if o.MetadataOverlay != nil {
		cfg.MetadataOverlay = cloneMetadataOverlay(o.MetadataOverlay)
	} else {
		cfg.MetadataOverlay = nil
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
	out.Crit = append([]string(nil), r.config.Crit...)
	out.TrustMarks = cloneTrustMarks(r.config.TrustMarks)
	out.MetadataOverlay = cloneMetadataOverlay(r.config.MetadataOverlay)
	if r.config.URLMappings != nil {
		out.URLMappings = make(map[string]string, len(r.config.URLMappings))
		for k, v := range r.config.URLMappings {
			out.URLMappings[k] = v
		}
	}
	return &out
}

func cloneTrustMarks(in []map[string]any) []map[string]any {
	if in == nil {
		return nil
	}
	out := make([]map[string]any, 0, len(in))
	for _, m := range in {
		if m == nil {
			continue
		}
		cp := make(map[string]any, len(m))
		for k, v := range m {
			cp[k] = v
		}
		out = append(out, cp)
	}
	return out
}

func cloneMetadataOverlay(in map[string]map[string]any) map[string]map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]map[string]any, len(in))
	for typ, obj := range in {
		if obj == nil {
			out[typ] = nil
			continue
		}
		cp := make(map[string]any, len(obj))
		for k, v := range obj {
			cp[k] = v
		}
		out[typ] = cp
	}
	return out
}

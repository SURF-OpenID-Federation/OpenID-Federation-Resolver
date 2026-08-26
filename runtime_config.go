package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"resolver/pkg/resolver"
)

const runtimeConfigFileName = "runtime-config.json"

var errConfigConflict = errors.New("config conflict with environment")

const serviceTypeFederationResolver = "federation_resolver"

// RuntimeConfig is the JSON shape of GET/POST /api/v1/config (OIDF Admin compatible).
type RuntimeConfig struct {
	EntityID         string   `json:"entity_id"`
	ServiceType      string   `json:"service_type"`
	OrganizationName string   `json:"organization_name,omitempty"`
	OrganizationURI  string   `json:"organization_uri,omitempty"`
	LogoURI          string   `json:"logo_uri,omitempty"`
	Contacts         []string `json:"contacts,omitempty"`
	AuthorityHints   []string `json:"authority_hints,omitempty"`
	TrustAnchors     []string `json:"trust_anchors,omitempty"`
	Port             int      `json:"port,omitempty"`
	KeysPath         string   `json:"keys_path,omitempty"`
	DataPath         string   `json:"data_path,omitempty"`
}

func runtimeConfigPath(dataPath string) string {
	if dataPath == "" {
		dataPath = "./data"
	}
	return filepath.Join(dataPath, runtimeConfigFileName)
}

func envRuntimeConfig() *RuntimeConfig {
	port, _ := strconv.Atoi(getEnvWithDefault("PORT", "8080"))
	return &RuntimeConfig{
		EntityID:         getEnvWithDefault("RESOLVER_ENTITY_ID", "https://resolver.example.org"),
		ServiceType:      serviceTypeFederationResolver,
		OrganizationName: getEnvWithDefault("SERVICE_NAME", "Federation Resolver"),
		OrganizationURI:  strings.TrimSpace(os.Getenv("ORGANIZATION_URI")),
		LogoURI:          strings.TrimSpace(os.Getenv("LOGO_URI")),
		Contacts:         parseCommaSeparatedEnv("CONTACTS"),
		AuthorityHints:   parseCommaSeparatedEnv("AUTHORITY_HINTS"),
		TrustAnchors:     append([]string(nil), config.TrustAnchors...),
		Port:             port,
		KeysPath:         resolveKeyPath(),
		DataPath:         config.DataPath,
	}
}

func applyLockedFields(dst, env *RuntimeConfig) {
	dst.EntityID = env.EntityID
	dst.ServiceType = serviceTypeFederationResolver
	dst.Port = env.Port
	dst.KeysPath = env.KeysPath
	dst.DataPath = env.DataPath
}

func checkIdentityConflict(env *RuntimeConfig, entityID, serviceType string) error {
	if entityID != "" && entityID != env.EntityID {
		return fmt.Errorf("%w: entity_id in runtime config %q does not match RESOLVER_ENTITY_ID %q",
			errConfigConflict, entityID, env.EntityID)
	}
	if serviceType != "" && serviceType != serviceTypeFederationResolver {
		return fmt.Errorf("%w: service_type in runtime config %q must be %q",
			errConfigConflict, serviceType, serviceTypeFederationResolver)
	}
	return nil
}

// mergeRuntimeOverlay merges a JSON body onto ENV base (same semantics as OpenID-Federation).
func mergeRuntimeOverlay(base *RuntimeConfig, body []byte) (*RuntimeConfig, error) {
	if base == nil {
		return nil, fmt.Errorf("base config is nil")
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		out := *base
		applyLockedFields(&out, base)
		return &out, nil
	}

	var probe struct {
		EntityID    string  `json:"entity_id"`
		ServiceType string  `json:"service_type"`
		Port        *int    `json:"port"`
		KeysPath    *string `json:"keys_path"`
		DataPath    *string `json:"data_path"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := checkIdentityConflict(base, probe.EntityID, probe.ServiceType); err != nil {
		return nil, err
	}
	if probe.Port != nil && *probe.Port != 0 && *probe.Port != base.Port {
		return nil, fmt.Errorf("port cannot be changed via runtime config (ENV PORT=%d)", base.Port)
	}
	if probe.KeysPath != nil && *probe.KeysPath != "" && *probe.KeysPath != base.KeysPath {
		return nil, fmt.Errorf("keys_path cannot be changed via runtime config")
	}
	if probe.DataPath != nil && *probe.DataPath != "" && *probe.DataPath != base.DataPath {
		return nil, fmt.Errorf("data_path cannot be changed via runtime config")
	}

	baseBytes, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	var merged map[string]interface{}
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	var overlay map[string]interface{}
	if err := json.Unmarshal(body, &overlay); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	for k, v := range overlay {
		merged[k] = v
	}
	outBytes, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	var out RuntimeConfig
	if err := json.Unmarshal(outBytes, &out); err != nil {
		return nil, err
	}
	applyLockedFields(&out, base)
	return &out, nil
}

func loadRuntimeConfigFile(path string) (*RuntimeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg RuntimeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

func saveRuntimeConfigFile(path string, cfg *RuntimeConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func validateRuntimeConfig(cfg *RuntimeConfig) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if strings.TrimSpace(cfg.EntityID) == "" {
		return fmt.Errorf("entity_id is required")
	}
	if !strings.HasPrefix(strings.ToLower(cfg.EntityID), "https://") {
		return fmt.Errorf("entity_id must be a valid HTTPS URL")
	}
	if cfg.ServiceType != "" && cfg.ServiceType != serviceTypeFederationResolver {
		return fmt.Errorf("service_type must be %q", serviceTypeFederationResolver)
	}
	if strings.TrimSpace(cfg.OrganizationName) == "" {
		return fmt.Errorf("organization_name is required")
	}
	return nil
}

func runtimeToMutable(cfg *RuntimeConfig) resolver.MutableOverlay {
	contacts := cfg.Contacts
	if contacts == nil {
		contacts = []string{}
	}
	hints := cfg.AuthorityHints
	if hints == nil {
		hints = []string{}
	}
	tas := cfg.TrustAnchors
	if tas == nil {
		tas = []string{}
	}
	return resolver.MutableOverlay{
		OrganizationName: cfg.OrganizationName,
		OrganizationURI:  cfg.OrganizationURI,
		LogoURI:          cfg.LogoURI,
		Contacts:         contacts,
		AuthorityHints:   hints,
		TrustAnchors:     tas,
	}
}

func effectiveFromResolver(env *RuntimeConfig, live *resolver.Config) *RuntimeConfig {
	out := *env
	if live == nil {
		return &out
	}
	out.OrganizationName = live.OrganizationName
	out.OrganizationURI = live.OrganizationURI
	out.LogoURI = live.LogoURI
	out.Contacts = append([]string(nil), live.Contacts...)
	out.AuthorityHints = append([]string(nil), live.AuthorityHints...)
	out.TrustAnchors = append([]string(nil), live.TrustAnchors...)
	applyLockedFields(&out, env)
	return &out
}

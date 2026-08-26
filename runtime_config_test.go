package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"resolver/pkg/resolver"
)

func TestMergeRuntimeOverlayLocksIdentity(t *testing.T) {
	config = &Config{DataPath: t.TempDir(), TrustAnchors: []string{"https://ta.example.org"}}
	base := &RuntimeConfig{
		EntityID:         "https://resolver.example.org",
		ServiceType:      serviceTypeFederationResolver,
		OrganizationName: "Env Name",
		TrustAnchors:     []string{"https://ta.example.org"},
		Port:             8080,
		KeysPath:         "./keys",
		DataPath:         config.DataPath,
	}
	merged, err := mergeRuntimeOverlay(base, []byte(`{
		"organization_name": "Overlay Org",
		"organization_uri": "https://surf.nl",
		"contacts": ["ops@example.org"],
		"authority_hints": ["https://ta.example.org"],
		"trust_anchors": ["https://ta.example.org", "https://other.example.org"],
		"entity_id": "https://resolver.example.org"
	}`))
	require.NoError(t, err)
	require.Equal(t, "Overlay Org", merged.OrganizationName)
	require.Equal(t, "https://surf.nl", merged.OrganizationURI)
	require.Equal(t, []string{"ops@example.org"}, merged.Contacts)
	require.Equal(t, "https://resolver.example.org", merged.EntityID)
	require.Equal(t, serviceTypeFederationResolver, merged.ServiceType)
	require.Equal(t, 8080, merged.Port)
}

func TestMergeRuntimeOverlayRejectsEntityIDChange(t *testing.T) {
	base := &RuntimeConfig{
		EntityID:         "https://resolver.example.org",
		ServiceType:      serviceTypeFederationResolver,
		OrganizationName: "Env Name",
		Port:             8080,
	}
	_, err := mergeRuntimeOverlay(base, []byte(`{"entity_id":"https://evil.example.org"}`))
	require.Error(t, err)
	require.True(t, errors.Is(err, errConfigConflict))
}

func TestApplyMutableOverlayUpdatesEntityMetadata(t *testing.T) {
	r, err := resolver.NewFederationResolver(&resolver.Config{
		RequestTimeout:   time.Second,
		ResolverEntityID: "https://resolver.example.org",
		OrganizationName: "Before",
		EnableSigning:    true,
	})
	require.NoError(t, err)
	require.NoError(t, r.InitializeResolverKeys())

	r.ApplyMutableOverlay(resolver.MutableOverlay{
		OrganizationName: "After",
		OrganizationURI:  "https://surf.nl",
		LogoURI:          "https://surf.nl/logo.svg",
		Contacts:         []string{"ops@surf.nl"},
		AuthorityHints:   []string{"https://ta.example.org"},
		TrustAnchors:     []string{"https://ta.example.org"},
	})
	snap := r.SnapshotConfig()
	require.Equal(t, "After", snap.OrganizationName)
	require.Equal(t, "https://surf.nl", snap.OrganizationURI)

	compact, err := r.GetResolverEntityStatement()
	require.NoError(t, err)
	claims := decodeJWTPayload(t, compact)
	md := claims["metadata"].(map[string]interface{})
	fed := md["federation_entity"].(map[string]interface{})
	require.Equal(t, "After", fed["organization_name"])
	require.Equal(t, "https://surf.nl", fed["organization_uri"])
	require.Equal(t, "https://surf.nl/logo.svg", fed["logo_uri"])
	require.Equal(t, []interface{}{"ops@surf.nl"}, fed["contacts"])
	require.Equal(t, []interface{}{"https://ta.example.org"}, claims["authority_hints"])
}

func TestRuntimeConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, runtimeConfigFileName)
	cfg := &RuntimeConfig{
		EntityID:         "https://resolver.example.org",
		ServiceType:      serviceTypeFederationResolver,
		OrganizationName: "Persisted",
		TrustAnchors:     []string{"https://ta.example.org"},
		Port:             8080,
		DataPath:         dir,
		KeysPath:         "./keys",
	}
	require.NoError(t, saveRuntimeConfigFile(path, cfg))
	loaded, err := loadRuntimeConfigFile(path)
	require.NoError(t, err)
	require.Equal(t, "Persisted", loaded.OrganizationName)
	_, err = os.Stat(path)
	require.NoError(t, err)
}

func decodeJWTPayload(t *testing.T, compact string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(compact, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &obj))
	return obj
}

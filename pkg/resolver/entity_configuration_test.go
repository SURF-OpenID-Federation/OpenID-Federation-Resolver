package resolver

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolverEntityConfigurationMatchesFederationSpec(t *testing.T) {
	r, err := NewFederationResolver(&Config{
		RequestTimeout:   time.Second,
		ResolverEntityID: "https://resolver.example.org/",
		OrganizationName: "SURF Resolver",
		AuthorityHints:   []string{"https://ta.example.org"},
		EnableSigning:    true,
	})
	require.NoError(t, err)
	require.NoError(t, r.InitializeResolverKeys())

	compact, err := r.GetResolverEntityStatement()
	require.NoError(t, err)

	header := decodeJWTJSON(t, compact, 0)
	require.Equal(t, "entity-statement+jwt", header["typ"])
	require.NotEmpty(t, header["kid"])
	require.NotEqual(t, "none", header["alg"])

	claims := decodeJWTJSON(t, compact, 1)
	require.Equal(t, "https://resolver.example.org", claims["iss"])
	require.Equal(t, "https://resolver.example.org", claims["sub"])
	require.NotZero(t, claims["iat"])
	require.NotZero(t, claims["exp"])

	jwks, ok := claims["jwks"].(map[string]interface{})
	require.True(t, ok, "jwks must be a top-level JWKS object")
	keys, ok := jwks["keys"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, keys)
	seen := map[string]struct{}{}
	for _, ki := range keys {
		k, ok := ki.(map[string]interface{})
		require.True(t, ok)
		kid, _ := k["kid"].(string)
		require.NotEmpty(t, kid, "every JWK must have a kid")
		_, dup := seen[kid]
		require.False(t, dup, "JWK kids must be unique")
		seen[kid] = struct{}{}
	}

	metadata, ok := claims["metadata"].(map[string]interface{})
	require.True(t, ok)
	resolverType, hasResolverType := metadata["federation_resolver"].(map[string]interface{})
	require.True(t, hasResolverType, "resolver must publish federation_resolver Entity Type Identifier")
	require.Equal(t, "https://resolver.example.org/api/v1/resolve", resolverType["federation_resolve_endpoint"])
	require.Equal(t, "https://resolver.example.org/api/v1/collection", resolverType["federation_collection_endpoint"])

	fed, ok := metadata["federation_entity"].(map[string]interface{})
	require.True(t, ok, "resolver that publishes federation_entity must include that type")
	require.Equal(t, "https://resolver.example.org/api/v1/resolve", fed["federation_resolve_endpoint"])
	require.Equal(t, "https://resolver.example.org/api/v1/collection", fed["federation_collection_endpoint"])
	require.Equal(t, "SURF Resolver", fed["organization_name"])
	_, hasList := fed["federation_list_endpoint"]
	require.False(t, hasList, "list endpoint would claim this entity lists its own subordinates")
	_, hasContacts := fed["contacts"]
	require.False(t, hasContacts, "empty contacts array is not allowed (one or more strings)")

	hints, ok := claims["authority_hints"].([]interface{})
	require.True(t, ok)
	require.Equal(t, []interface{}{"https://ta.example.org"}, hints)
}

func TestResolverEntityConfigurationOmitsAuthorityHintsWhenUnset(t *testing.T) {
	r, err := NewFederationResolver(&Config{
		RequestTimeout:   time.Second,
		ResolverEntityID: "https://resolver.example.org",
		EnableSigning:    true,
	})
	require.NoError(t, err)
	require.NoError(t, r.InitializeResolverKeys())

	compact, err := r.GetResolverEntityStatement()
	require.NoError(t, err)
	claims := decodeJWTJSON(t, compact, 1)
	_, present := claims["authority_hints"]
	require.False(t, present)
}

func decodeJWTJSON(t *testing.T, compact string, part int) map[string]interface{} {
	t.Helper()
	parts := strings.Split(compact, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[part])
	require.NoError(t, err)
	var obj map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &obj))
	return obj
}

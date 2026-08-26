package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRotateSigningKeyKeepsPreviousInJWKS(t *testing.T) {
	r, err := NewFederationResolver(&Config{RequestTimeout: time.Second})
	require.NoError(t, err)
	require.NoError(t, r.InitializeResolverKeys())

	before := r.SigningKeyPublicInfo(context.Background())
	require.NotEmpty(t, before.ActiveKid)
	require.NotEmpty(t, before.JWKS)

	// KeyManager kids are second-resolution timestamps; avoid a collision.
	time.Sleep(1100 * time.Millisecond)

	previous, next, err := r.RotateSigningKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, before.ActiveKid, previous)
	require.NotEmpty(t, next)
	require.NotEqual(t, previous, next)
	require.Equal(t, next, r.getResolverSigningKeyID())

	after := r.SigningKeyPublicInfo(context.Background())
	require.Equal(t, next, after.ActiveKid)
	require.GreaterOrEqual(t, len(after.JWKS), 2)

	var sawOld, sawNew bool
	for _, k := range after.JWKS {
		kid, _ := k["kid"].(string)
		if kid == previous {
			sawOld = true
		}
		if kid == next {
			sawNew = true
		}
	}
	require.True(t, sawOld, "previous kid should remain in JWKS")
	require.True(t, sawNew, "new kid should be in JWKS")
}

func TestRotateSigningKeyRequiresKeyManager(t *testing.T) {
	r := &FederationResolver{}
	_, _, err := r.RotateSigningKey(context.Background())
	require.Error(t, err)
}

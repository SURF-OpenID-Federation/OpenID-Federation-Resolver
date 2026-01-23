package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// testEntity is a tiny test helper that provides the minimal behaviour the
// resolver tests expect from shared.NewEntity: a jwks, and the ability to
// sign entity-statement and resolve-response JWTs with the correct `typ`
// header.
type testEntity struct {
	EntityID string
	priv     *ecdsa.PrivateKey
	kid      string
	jwk      map[string]interface{}
}

func newTestEntity(entityID string) (*testEntity, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey

	x := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	kid := fmt.Sprintf("test-%d", time.Now().UnixNano())
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   x,
		"y":   y,
		"kid": kid,
	}
	return &testEntity{EntityID: entityID, priv: priv, kid: kid, jwk: jwk}, nil
}

func (e *testEntity) GetJWKS() map[string]interface{} {
	return map[string]interface{}{"keys": []interface{}{e.jwk}}
}

// signJWT creates a compact JWT signed with ES256 and sets the provided typ.
func (e *testEntity) signJWT(claims map[string]interface{}, typ string) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	// ensure required headers
	tok.Header["typ"] = typ
	tok.Header["kid"] = e.kid
	// jwt library handles ES256 signing with *ecdsa.PrivateKey
	return tok.SignedString(e.priv)
}

func (e *testEntity) SignEntityStatement(claims map[string]interface{}) (string, error) {
	return e.signJWT(claims, "entity-statement+jwt")
}

func (e *testEntity) SignResolveResponse(claims map[string]interface{}) (string, error) {
	return e.signJWT(claims, "resolve-response+jwt")
}

// helper to pretty-print JWKS for debugging (unused by tests but handy while
// iterating locally)
func jwkToJSON(j map[string]interface{}) string {
	b, _ := json.MarshalIndent(j, "", "  ")
	return string(b)
}

package resolver

import (
	"net/http"
	"time"

	"github.com/patrickmn/go-cache"
)

type Config struct {
	MaxRetries         int
	RequestTimeout     time.Duration
	TrustAnchors       []string
	ValidateSignatures bool
	AllowSelfSigned    bool
	ConcurrentFetches  int
	ResolverEntityID   string // New: Resolver's own entity identifier
	EnableSigning      bool   // New: Whether resolver can sign responses
}

type FederationResolver struct {
	config            *Config
	httpClient        *http.Client
	entityCache       *cache.Cache
	chainCache        *cache.Cache
	cachedEntities    map[string]*CachedEntityStatement   // Index of cached entities by cache key
	registeredAnchors map[string]*TrustAnchorRegistration // Trust anchors registered with this resolver
	signingKey        interface{}                         // New: Signing key for the resolver
	signingkid        string                              // New: Key ID for the signing key
	resolverKeys      *JWKSet                             // Resolver's own signing keys for responses
}

type CachedEntityStatement struct {
	EntityID     string                 `json:"entity_id"`
	Statement    string                 `json:"statement"`
	ParsedClaims map[string]interface{} `json:"parsed_claims"`
	Issuer       string                 `json:"issuer"`
	Subject      string                 `json:"subject"`
	TrustAnchor  string                 `json:"trust_anchor"`
	IssuedAt     time.Time              `json:"issued_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	CachedAt     time.Time              `json:"cached_at"`
	FetchedFrom  string                 `json:"fetched_from"`
	Validated    bool                   `json:"validated"`
}

type CachedTrustChain struct {
	EntityID    string                  `json:"entity_id"`
	TrustAnchor string                  `json:"trust_anchor"`
	Chain       []CachedEntityStatement `json:"chain"`
	Status      string                  `json:"status"`
	CachedAt    time.Time               `json:"cached_at"`
	ExpiresAt   time.Time               `json:"expires_at"`
	Signature   string                  `json:"signature,omitempty"` // Signed by resolver
	SignedBy    string                  `json:"signed_by,omitempty"` // Resolver entity ID
}

// New types for trust anchor registration
type TrustAnchorRegistration struct {
	EntityID        string                 `json:"entity_id"`
	SigningKeys     *JWKSet                `json:"signing_keys"`
	Metadata        map[string]interface{} `json:"metadata"`
	ExpiresAt       time.Time              `json:"expires_at"`
	RegistrationJWT string                 `json:"registration_jwt"` // Self-signed by TA
	RegisteredAt    time.Time              `json:"registered_at"`
}

type ResolverSignedResponse struct {
	EntityID    string                  `json:"entity_id"`
	TrustAnchor string                  `json:"trust_anchor"`
	TrustChain  []CachedEntityStatement `json:"trust_chain"`
	Metadata    map[string]interface{}  `json:"metadata"`
	IssuedAt    time.Time               `json:"issued_at"`
	ExpiresAt   time.Time               `json:"expires_at"`
	Issuer      string                  `json:"issuer"` // Resolver entity ID
}

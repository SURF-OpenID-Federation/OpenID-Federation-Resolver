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
}

type FederationResolver struct {
	config       *Config
	httpClient   *http.Client
	entityCache  *cache.Cache
	chainCache   *cache.Cache
	cachedEntities map[string]*CachedEntityStatement // Index of cached entities by cache key
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
}

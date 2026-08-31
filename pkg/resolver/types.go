package resolver

import (
	"net/http"
	"sync"
	"time"

	"github.com/harrykodden/keymanager"
	cache "resolver/pkg/cache"
)

type Config struct {
	MaxRetries         int
	RequestTimeout     time.Duration
	TrustAnchors       []string
	ValidateSignatures bool
	AllowSelfSigned    bool
	ConcurrentFetches  int
	ResolverEntityID   string            // Resolver's own entity identifier
	EnableSigning      bool              // Whether resolver can sign responses
	OrganizationName   string            // federation_entity.organization_name
	OrganizationURI    string            // federation_entity.organization_uri
	LogoURI            string            // federation_entity.logo_uri
	Contacts           []string          // federation_entity.contacts
	AuthorityHints     []string          // Immediate superiors (omit if none)
	SkipTLSVerify      bool              // Skip TLS certificate verification
	URLMappings        map[string]string // New: Map external URLs to internal service URLs
	// NegativeCacheTTL controls how long permanently-failed entity IDs
	// (missing well-known / not resolvable via any TA) are skipped. Zero uses
	// the default (10 minutes).
	NegativeCacheTTL time.Duration
	// RegistryPath, if set, persists TA signing registrations as JSON.
	RegistryPath string
	// CacheMaxEntries caps each in-memory cache. Zero means unlimited.
	CacheMaxEntries int
	// CacheSweepInterval for the expired-entry janitor. Zero disables it.
	CacheSweepInterval time.Duration
	// EntityStatementLifetime is used for iss Entity Configuration exp.
	// Zero means 24 hours.
	EntityStatementLifetime time.Duration
	// Crit is copied into the published Entity Configuration when non-empty.
	Crit []string
	// TrustMarks are Trust Marks this node holds about itself (copied unchanged).
	TrustMarks []map[string]any
	// MetadataOverlay is merged into published metadata (protocol endpoints stay locked).
	MetadataOverlay map[string]map[string]any
}

// MutableOverlay is the day-2 config surface (PUT/PATCH /admin/v1/configuration).
// Identity and infra fields are applied separately from ENV and cannot be changed here.
type MutableOverlay struct {
	OrganizationName        string
	OrganizationURI         string
	LogoURI                 string
	Contacts                []string
	AuthorityHints          []string
	TrustAnchors            []string
	EntityStatementLifetime time.Duration
	Crit                    []string
	TrustMarks              []map[string]any
	MetadataOverlay         map[string]map[string]any
}

type FederationResolver struct {
	configMu          sync.RWMutex
	config            *Config
	httpClient        *http.Client
	entityCache       *cache.Cache
	chainCache        *cache.Cache
	negativeCache     *cache.Cache // entityID → unresolvableEntry
	entitiesMu        sync.RWMutex
	cachedEntities    map[string]*CachedEntityStatement // Index of cached entities by cache key
	entityInflight    inflightGroup
	registeredMu      sync.RWMutex
	registeredAnchors map[string]*TrustAnchorRegistration
	registryPath      string
	keysMu            sync.RWMutex
	signingKey        interface{}
	signingkid        string
	resolverKeys      *JWKSet
	// KeyManager provides key storage and signing operations for the resolver
	KeyManager keymanager.AdvancedKeyManager
	// KeyProvider allows customizing how public keys are retrieved for JWT validation
	KeyProvider KeyProvider
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

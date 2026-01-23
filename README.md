# Smart OpenID Federation Resolver

[![CI](https://github.com/SURF-OpenID-Federation/OpenID-Federation-Resolver/workflows/CI/badge.svg)](https://github.com/SURF-OpenID-Federation/OpenID-Federation-Resolver/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/SURF-OpenID-Federation/OpenID-Federation-Resolver)](https://goreportcard.com/report/github.com/SURF-OpenID-Federation/OpenID-Federation-Resolver)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A powerful, intelligent OpenID Federation resolver that can act as an authorized resolver for multiple trust anchors, providing signed JWT responses and comprehensive federation services.

## 🚀 Key Features

- 🧠 **Smart Multi-Trust Anchor Support**: Register and manage multiple trust anchors dynamically
- 🔐 **Signed JWT Responses**: Automatically signs trust chain responses when authorized (OpenID Federation spec compliant)
- 🏗️ **Zero Config Files**: All configuration via environment variables
- � **Official Federation Resolve Endpoint**: Full OpenID Federation 1.0 specification compliance
- 🔑 **Trust Anchor Management**: REST API for registering/managing trust anchor authorizations
- 📊 **Prometheus Metrics**: Built-in monitoring and health checks
- 🐳 **Docker Ready**: Optimized for containerized deployments
- ⚡ **Lean Architecture**: Minimal dependencies, fast startup
- 💾 **Intelligent Caching**: TTL-based caching for performance optimization
- 🔍 **Cache Management**: Inspect and manage cached entities and trust chains
- 🌐 **Web Interface**: Browser-based cache management and monitoring
- 📋 **Federation Lists**: Generate signed JWT federation member lists

## Quick Start

### Environment Variables

Set the required environment variables:

```bash
export TRUST_ANCHORS="https://trust-anchor1.example.com,https://trust-anchor2.example.com"
```

### Run

```bash
go run .                    # Development
docker-compose up resolver  # Docker
```

### Access Web Interface

Once running, access the cache management interface at:

- **Web UI**: http://localhost:8080/
- **Health Check**: http://localhost:8080/health
- **Metrics**: http://localhost:8080/metrics

## Configuration

All configuration is done via environment variables. No config files are needed.

### Environment Variables

| Variable                     | Description                                  | Default                        | Type   | Required |
| ---------------------------- | -------------------------------------------- | ------------------------------ | ------ | -------- |
| `TRUST_ANCHORS`              | Comma-separated list of trust anchor URLs    | (empty)                        | string | Yes      |
| `RESOLVER_ENTITY_ID`         | Resolver's own entity identifier for signing | "https://resolver.example.org" | string | No       |
| `ENABLE_SIGNING`             | Enable JWT signing capabilities              | true                           | bool   | No       |
| `SERVICE_NAME`               | Service name for health endpoint             | "Federation Resolver"          | string | No       |
| `HOST`                       | Host to bind to                              | "0.0.0.0"                      | string | No       |
| `LOG_LEVEL`                  | Log level (debug, info, warn, error)         | "info"                         | string | No       |
| `MAX_RETRIES`                | Maximum number of retries for requests       | 3                              | int    | No       |
| `REQUEST_TIMEOUT`            | Timeout for HTTP requests (duration)         | "30s"                          | string | No       |
| `VALIDATE_SIGNATURES`        | Whether to validate JWT signatures           | true                           | bool   | No       |
| `ALLOW_SELF_SIGNED`          | Whether to allow self-signed certificates    | true                           | bool   | No       |
| `CONCURRENT_FETCHES`         | Maximum concurrent fetch operations          | 10                             | int    | No       |
| `METRICS_ENABLED`            | Whether to enable Prometheus metrics         | true                           | bool   | No       |
| `HEALTH_CHECK_TRUST_ANCHORS` | Whether health checks include trust anchors  | true                           | bool   | No       |

### Trust Anchors Configuration

Trust anchors are the foundation of OpenID Federation. Configure them as a comma-separated list:

```bash
# Single trust anchor
TRUST_ANCHORS="https://federation.example.com"

# Multiple trust anchors
TRUST_ANCHORS="https://federation1.example.com,https://federation2.example.com"
```

## Caching

The resolver includes intelligent TTL-based caching to improve performance and reduce external API calls.

### Cache Configuration

Caching is automatically configured with sensible defaults:

- **Entity Cache**: 24-hour TTL with 30-minute cleanup interval
- **Trust Chain Cache**: 24-hour TTL with 30-minute cleanup interval
- **Cache Size**: Unlimited (grows as needed, cleans up expired entries)

### Cache Management

The resolver provides comprehensive cache management capabilities:

- **Web Interface**: Browser-based cache monitoring at `http://localhost:8080/`
- **API Endpoints**: Programmatic cache inspection and management
- **Granular Control**: Inspect and remove individual cached items
- **Bulk Operations**: Clear entire caches when needed

### Cache Statistics

Monitor cache performance through the web interface or API:

```bash
curl http://localhost:8080/api/v1/cache/stats
# Returns: {"entity_cache_size": 42, "chain_cache_size": 15}
```

## API Endpoints

### Core Endpoints

- `GET /health` - Health check with trust anchor validation
- `GET /metrics` - Prometheus metrics (if enabled)

### Smart Federation API (v1)

#### Entity Resolution

- `GET /api/v1/entity/{entity_id}?trust_anchor={ta}` - Resolve entity via specific trust anchor or any configured trust anchor
- `GET /api/v1/trust-chain/{entity_id}` - Resolve complete trust chain for entity (returns signed JWT when authorized)
- `GET /api/v1/test/resolve/{entity_id}` - Test resolution against all trust anchors

#### OpenID Federation Spec Compliance

- `GET /api/v1/resolve?sub={entity_id}&trust_anchor={ta}&entity_type={type}` - **Official federation resolve endpoint** (OpenID Federation 1.0 Section 8.3)

**Compatibility note:** Resolver implementations MUST publish JWKS in the standard JSON shape (i.e. `{"keys": [ { ... } ]}`) and produce `entity-statement+jwt` tokens for entity statements. Clients may run strict local revalidation of resolver-supplied chains (signature + embedded `jwks` or `jwks_uri`) — ensure resolver-produced entity statements include either an embedded `jwks` or a reachable `jwks_uri`, and set the required `typ` header on entity statements so strict clients accept the chain.

#### Trust Anchor Management 🆕

- `POST /api/v1/register-trust-anchor` - Register resolver to act for a trust anchor
- `GET /api/v1/registered-trust-anchors` - List all registered trust anchor authorizations
- `DELETE /api/v1/registered-trust-anchors/{entity_id}` - Unregister trust anchor authorization

#### Federation Services

- `GET /api/v1/federation_list?trust_anchor={ta}` - Get federation member list as signed JWT
- `GET /api/v1/trust-anchors` - List all configured trust anchors

### Cache Management API (v1)

- `GET /` - Web interface for cache management and monitoring
- `GET /api/v1/cache/stats` - Get cache statistics and sizes
- `GET /api/v1/cache/entities` - List all cached entity statements
- `GET /api/v1/cache/chains` - List all cached trust chains
- `GET /api/v1/cache/entity/{entity_id}?trust_anchor={ta}` - Inspect specific cached entity metadata
- `GET /api/v1/cache/chain/{entity_id}` - Inspect specific cached trust chain
- `POST /api/v1/cache/clear-entities` - Clear all cached entity statements
- `POST /api/v1/cache/clear-chains` - Clear all cached trust chains
- `POST /api/v1/cache/clear-all` - Clear all caches
- `DELETE /api/v1/cache/entity/{entity_id}?trust_anchor={ta}` - Remove specific entity from cache
- `DELETE /api/v1/cache/chain/{entity_id}` - Remove specific trust chain from cache

### Example Usage

#### Basic Operations

```bash
# Health check
curl http://localhost:8080/health

# Resolve an entity via any trust anchor
curl "http://localhost:8080/api/v1/entity/https://example.com/op"

# Resolve an entity via specific trust anchor
curl "http://localhost:8080/api/v1/entity/https://example.com/op?trust_anchor=https://trust-anchor.com"

# Get trust chain (returns signed JWT if resolver is authorized for the trust anchor)
curl "http://localhost:8080/api/v1/trust-chain/https://example.com/op"

# Test resolution against all trust anchors
curl "http://localhost:8080/api/v1/test/resolve/https://example.com/op"
```

#### 🆕 Smart Resolver Features

##### Official Federation Resolve Endpoint (OpenID Federation 1.0 compliant)

```bash
# Resolve with signed JWT response (when authorized)
curl "http://localhost:8080/api/v1/resolve?sub=https://rp.example.com&trust_anchor=https://federation.example.org"

# With optional entity type
curl "http://localhost:8080/api/v1/resolve?sub=https://op.example.com&trust_anchor=https://federation.example.org&entity_type=openid_relying_party"
```

##### Trust Anchor Registration & Management

```bash
# Register resolver to act for a trust anchor
# IMPORTANT: entity_statement should be a SIGNED JWT containing PUBLIC keys only!
curl -X POST "http://localhost:8080/api/v1/register-trust-anchor" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "https://federation.example.org",
    "entity_statement": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0In0.eyJpc3MiOiJodHRwczovL2ZlZGVyYXRpb24uZXhhbXBsZS5vcmciLCJzdWIiOiJodHRwczovL2ZlZGVyYXRpb24uZXhhbXBsZS5vcmciLCJpYXQiOjE3NjA0MjYyMjQsImV4cCI6MTczNTY4MDAwMCwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJ1c2UiOiJzaWciLCJraWQiOiJ0YS1rZXktMSIsImFsZyI6IlJTMjU2IiwibiI6InB1YmxpY19rZXlfbW9kdWx1cyIsImUiOiJBUUFCIn1dfX0.trust_anchor_signature_here",
    "expires_at": "2025-12-31T23:59:59Z"
  }'

# List registered trust anchor authorizations
curl "http://localhost:8080/api/v1/registered-trust-anchors"

# Unregister trust anchor authorization
curl -X DELETE "http://localhost:8080/api/v1/registered-trust-anchors/https://federation.example.org"
```

##### Federation Services

```bash
# Get federation member list (signed JWT)
curl "http://localhost:8080/api/v1/federation_list?trust_anchor=https://trust-anchor.com"

# Get configured trust anchors
curl "http://localhost:8080/api/v1/trust-anchors"
```

#### Cache Management

```bash
# Cache statistics
curl "http://localhost:8080/api/v1/cache/stats"

# List cached entities and chains
curl "http://localhost:8080/api/v1/cache/entities"
curl "http://localhost:8080/api/v1/cache/chains"

# Inspect specific cached items
curl "http://localhost:8080/api/v1/cache/entity/https://example.com/op"
curl "http://localhost:8080/api/v1/cache/chain/https://example.com/op"

# Clear caches
curl -X POST "http://localhost:8080/api/v1/cache/clear-all"
curl -X POST "http://localhost:8080/api/v1/cache/clear-entities"
curl -X POST "http://localhost:8080/api/v1/cache/clear-chains"

# Remove specific cached items
curl -X DELETE "http://localhost:8080/api/v1/cache/entity/https://example.com/op"
curl -X DELETE "http://localhost:8080/api/v1/cache/chain/https://example.com/op"
```

### Web Interface

Access the web-based cache management interface at `http://localhost:8080/` which provides:

- **Cache Statistics**: Real-time view of cache sizes and contents
- **Entity Inspection**: Inspect metadata for specific cached entities
- **Trust Chain Inspection**: View complete cached trust chains
- **Cache Management**: Clear entire caches or remove specific entries
- **API Documentation**: Complete endpoint reference

### Federation Lists

The resolver can generate signed JWT federation member lists for trust anchors. This feature allows trust anchors to publish authoritative lists of federation participants.

**Key Features:**

- Signed JWT responses for security
- Automatic member discovery from cached entities
- Configurable JWT expiration
- Trust anchor authorization checks

**Usage:**

```bash
curl "http://localhost:8080/api/v1/federation_list?trust_anchor=https://your-trust-anchor.com"
```

**Response:** A signed JWT containing the federation member list with metadata.

### 🚀 Sample API Responses

#### Trust Chain Resolution (Signed JWT Response)

```bash
curl "http://localhost:8080/api/v1/trust-chain/https://rp.example.com"
```

**Response (when authorized):**

```
Content-Type: application/resolve-response+jwt

eyJhbGciOiJSUzI1NiIsInR5cCI6InJlc29sdmUtcmVzcG9uc2Urand0Iiwia2lkIjoicmVzb2x2ZXIta2V5LTEifQ.eyJhdWQiOiJodHRwczovL2ZlZGVyYXRpb24uZXhhbXBsZS5vcmciLCJleHAiOjE3NjA1MTI2MjQsImlhdCI6MTc2MDQyNjIyNCwiaXNzIjoiaHR0cHM6Ly9yZXNvbHZlci5leGFtcGxlLm9yZyIsIm1ldGFkYXRhIjp7Im9wZW5pZF9yZWx5aW5nX3BhcnR5Ijp7ImNsaWVudF9pZCI6Imh0dHBzOi8vcnAuZXhhbXBsZS5jb20ifX0sInN1YiI6Imh0dHBzOi8vcnAuZXhhbXBsZS5jb20iLCJ0cnVzdF9hbmNob3IiOiJodHRwczovL2ZlZGVyYXRpb24uZXhhbXBsZS5vcmciLCJ0cnVzdF9jaGFpbiI6WyJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SW1WdWRHbDBlUzF6ZEdGMFpXMWxiblFyYW5kMEluMC4uLiJdfQ.signature
```

#### Federation Resolve Endpoint (OpenID Federation Spec)

```bash
curl "http://localhost:8080/api/v1/resolve?sub=https://op.example.com&trust_anchor=https://federation.example.org"
```

**Response (when authorized):**

```json
HTTP/1.1 200 OK
Content-Type: application/resolve-response+jwt

eyJhbGciOiJSUzI1NiIsInR5cCI6InJlc29sdmUtcmVzcG9uc2Urand0In0...
```

**Response (when not authorized):**

```json
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Resolver not authorized to resolve for this trust anchor"
}
```

#### Trust Anchor Registration

```bash
# SECURITY NOTE: entity_statement must be a signed JWT with PUBLIC keys only!
curl -X POST "http://localhost:8080/api/v1/register-trust-anchor" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "https://federation.example.org",
    "entity_statement": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImVudGl0eS1zdGF0ZW1lbnQrand0In0.eyJpc3MiOiJodHRwczovL2ZlZGVyYXRpb24uZXhhbXBsZS5vcmciLCJzdWIiOiJodHRwczovL2ZlZGVyYXRpb24uZXhhbXBsZS5vcmciLCJpYXQiOjE3NjA0MjYyMjQsImV4cCI6MTczNTY4MDAwMCwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJ1c2UiOiJzaWciLCJraWQiOiJ0YS1rZXktMSIsImFsZyI6IlJTMjU2IiwibiI6InB1YmxpY19rZXlfbW9kdWx1cyIsImUiOiJBUUFCIn1dfX0.trust_anchor_signature",
    "expires_at": "2025-12-31T23:59:59Z"
  }'
```

**⚠️ CRITICAL SECURITY NOTE**: The `entity_statement` should contain:

- ✅ **Signed JWT** with trust anchor's signature
- ✅ **Public keys only** in the JWKS section
- ✅ **Entity metadata** (issuer, subject, expiration)
- ❌ **NEVER include private keys** - major security risk!

**Success Response:**

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "message": "Trust anchor registered successfully",
  "entity_id": "https://federation.example.org",
  "registered_at": "2025-10-14T07:30:00Z",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**Error Response:**

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "Invalid registration JWT",
  "details": "Invalid registration JWT"
}
```

#### Registered Trust Anchors

```bash
curl "http://localhost:8080/api/v1/registered-trust-anchors"
```

**Response:**

```json
{
  "count": 2,
  "registered_trust_anchors": {
    "https://federation.example.org": {
      "entity_id": "https://federation.example.org",
      "registered_at": "2025-10-14T07:30:00Z",
      "expires_at": "2025-12-31T23:59:59Z"
    },
    "https://another-federation.org": {
      "entity_id": "https://another-federation.org",
      "registered_at": "2025-10-14T08:15:00Z",
      "expires_at": "2025-11-30T23:59:59Z"
    }
  }
}
```

## Docker Deployment

### Standalone Container

```bash
docker run -p 8080:8080 \
  -e TRUST_ANCHORS="https://federation.example.com" \
  -e PORT=8080 \
  your-resolver-image
```

## Development

### Local Development

```bash
# Set environment variables
export TRUST_ANCHORS="https://test-trust-anchor.com"
export LOG_LEVEL=debug

# Run the service
go run .
```

### Building

```bash
# Build for local platform
go build -o federation-resolver .

# Build for Docker
docker build -t federation-resolver .
```

### Testing

```bash
# Run with test trust anchors
TRUST_ANCHORS="https://test.example.com" go run .

# Test health endpoint
curl http://localhost:8080/health

# Test entity resolution
curl "http://localhost:8080/api/v1/test/resolve/https://test-entity.com"

# Test cache functionality
curl "http://localhost:8080/api/v1/cache/stats"
curl "http://localhost:8080/"  # Web interface
```

## 🔐 Smart Resolver Architecture

### Trust Anchor Authorization Model

The smart resolver is designed to implement a sophisticated authorization model that allows it to act on behalf of multiple trust anchors:

1. **Dynamic Registration**: Trust anchors can register the resolver as an authorized entity
2. **JWT Signing**: Resolver signs responses using appropriate keys for each trust anchor
3. **Spec Compliance**: Full OpenID Federation 1.0 Section 8.3 compliance
4. **Security**: Proper validation and key management for each trust anchor relationship

### Registration Process

1. **Trust Anchor Creates Entity Statement**: Trust anchor generates a signed JWT containing:

   - **Public keys only** (JWKS with RSA/EC public key parameters)
   - **Entity metadata** (issuer, subject, capabilities)
   - **Expiration time** and **issued at** timestamps
   - **Signed with trust anchor's private key**

2. **Register with Resolver**: POST the signed entity statement JWT to the resolver
3. **Resolver Validation**: Resolver validates the JWT signature using trust anchor's public key
4. **Authorization Storage**: Resolver stores the authorization (public keys + metadata only)
5. **Signed Responses**: Resolver uses its **own private keys** to sign responses on behalf of the trust anchor

### Security Model

- **JWT Validation**: Entity statements are validated (signature, expiration, issuer)
- **Public Key Only**: Only public keys are stored, never private keys
- **Separate Signing Keys**: Resolver maintains its own private keys for signing responses
- **Expiration Management**: Registrations automatically expire based on entity statement validity
- **Authorization Checks**: All signing operations verify current authorization status

### Key Management Architecture

```
Trust Anchor                           Smart Resolver
┌─────────────────┐                   ┌─────────────────┐
│ Private Key A   │ ────signs────→    │ Public Key A    │
│ Public Key A    │                   │ Private Key R   │ ────signs────→ Signed Response
└─────────────────┘                   └─────────────────┘
     (stays with TA)                      (resolver's own keys)
```

**Critical Point**: The resolver acts as an **authorized intermediary** that can sign responses for the trust anchor, but never has access to the trust anchor's private keys.

## Architecture

### Design Principles

- **Smart Multi-Trust Anchor Support**: Dynamic authorization for multiple federations
- **OpenID Federation Compliance**: Full specification implementation
- **Zero Configuration Files**: All settings via environment variables
- **Container First**: Optimized for containerized deployments
- **Lean Dependencies**: Minimal external dependencies
- **Observable**: Built-in metrics and health checks
- **Federation Focused**: Specialized for OpenID Federation operations

### Components

- **HTTP Server**: Gin-based REST API with web interface
- **Smart Resolver Core**: Multi-trust anchor federation resolution with JWT signing capabilities
- **Trust Anchor Manager**: Dynamic registration and authorization management
- **Cache Manager**: TTL-based caching system for entities and trust chains
- **JWT Service**: Signing and validation for federation responses
- **Metrics**: Prometheus-compatible monitoring with cache statistics
- **Health Checks**: Trust anchor and service health validation

### Data Flow

```
Client Request → HTTP Server → Authorization Check → Cache Check → Resolver → Trust Anchor API → JWT Signing → Response
                      ↓                    ↑                              ↑
                Metrics Collection        Cache Hit                    Signed JWT
```

## Security Considerations

- **HTTPS Recommended**: Use HTTPS in production environments
- **Trust Anchor Validation**: Only configure trusted federation authorities
- **Network Security**: Restrict access to resolver endpoints
- **Environment Variables**: Secure storage of sensitive configuration

## Troubleshooting

### Common Issues

1. **No Trust Anchors Configured**

   ```
   Error: No TRUST_ANCHORS environment variable set
   Solution: export TRUST_ANCHORS="https://your-trust-anchor.com"
   ```

2. **Trust Anchor Unreachable**

   ```
   Health check fails with trust anchor errors
   Solution: Verify trust anchor URLs are accessible
   ```

3. **Stale Cache Data**

   ```
   Cached entity data appears outdated
   Solution: Use cache management API to clear specific entries or entire cache
   ```

4. **High Memory Usage**
   ```
   Cache growing too large
   Solution: Monitor cache stats and clear caches periodically
   ```

### Debug Mode

Enable detailed logging:

```bash
LOG_LEVEL=debug TRUST_ANCHORS="https://example.com" go run .
```

### Logs

The service logs all operations with configurable log levels:

```
[RESOLVER] Loaded 2 trust anchors from environment
[RESOLVER] Federation resolver initialized
[RESOLVER] Registered route: GET /health
[RESOLVER] Starting server on 0.0.0.0:8080
```

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Federation Resolver

A lightweight, container-optimized OpenID Federation entity resolver service with zero configuration files.

## Features

- 🏗️ **Zero Config Files**: All configuration via environment variables
- 🔐 **OpenID Federation**: Entity resolution and trust chain discovery
- 🌐 **Multi-Trust Anchor**: Support for multiple federation trust anchors
- 📊 **Prometheus Metrics**: Built-in monitoring and health checks
- 🐳 **Docker Ready**: Optimized for containerized deployments
- ⚡ **Lean Architecture**: Minimal dependencies, fast startup
- 💾 **Intelligent Caching**: TTL-based caching for performance optimization
- 🔍 **Cache Management**: Inspect and manage cached entities and trust chains
- 🌐 **Web Interface**: Browser-based cache management and monitoring

## Quick Start

### Environment Variables

Set the required environment variables:

```bash
export TRUST_ANCHORS="https://trust-anchor1.example.com,https://trust-anchor2.example.com"
export PORT=8080
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

| Variable | Description | Default | Type | Required |
|----------|-------------|---------|------|----------|
| `TRUST_ANCHORS` | Comma-separated list of trust anchor URLs | (empty) | string | Yes |
| `SERVICE_NAME` | Service name for health endpoint | "Federation Resolver" | string | No |
| `PORT` | Port to listen on | 8080 | int | No |
| `HOST` | Host to bind to | "0.0.0.0" | string | No |
| `LOG_LEVEL` | Log level (debug, info, warn, error) | "info" | string | No |
| `MAX_RETRIES` | Maximum number of retries for requests | 3 | int | No |
| `REQUEST_TIMEOUT` | Timeout for HTTP requests (duration) | "30s" | string | No |
| `VALIDATE_SIGNATURES` | Whether to validate JWT signatures | true | bool | No |
| `ALLOW_SELF_SIGNED` | Whether to allow self-signed certificates | true | bool | No |
| `CONCURRENT_FETCHES` | Maximum concurrent fetch operations | 10 | int | No |
| `METRICS_ENABLED` | Whether to enable Prometheus metrics | true | bool | No |
| `HEALTH_CHECK_TRUST_ANCHORS` | Whether health checks include trust anchors | true | bool | No |

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

### Federation API (v1)

- `GET /api/v1/entity/{entityId}` - Resolve entity via any configured trust anchor
- `GET /api/v1/entity/{entityId}/trust-anchor/{trustAnchor}` - Resolve entity via specific trust anchor
- `GET /api/v1/trust-chain/{entityId}` - Resolve complete trust chain for entity
- `GET /api/v1/test/resolve/{entityId}` - Test resolution against all trust anchors
- `GET /api/v1/trust-anchors` - List all configured trust anchors

### Cache Management API (v1)

- `GET /` - Web interface for cache management and monitoring
- `GET /api/v1/cache/stats` - Get cache statistics and sizes
- `GET /api/v1/cache/entity/{entityId}` - Inspect specific cached entity metadata
- `GET /api/v1/cache/chain/{entityId}` - Inspect specific cached trust chain
- `POST /api/v1/cache/clear-entities` - Clear all cached entity statements
- `POST /api/v1/cache/clear-chains` - Clear all cached trust chains
- `POST /api/v1/cache/clear-all` - Clear all caches
- `DELETE /api/v1/cache/entity/{entityId}` - Remove specific entity from cache
- `DELETE /api/v1/cache/chain/{entityId}` - Remove specific trust chain from cache

### Example Usage

```bash
# Health check
curl http://localhost:8080/health

# Resolve an entity
curl "http://localhost:8080/api/v1/entity/https://example.com/op"

# Test resolution against all trust anchors
curl "http://localhost:8080/api/v1/test/resolve/https://example.com/op"

# Get configured trust anchors
curl "http://localhost:8080/api/v1/trust-anchors"

# Cache management
curl "http://localhost:8080/api/v1/cache/stats"
curl "http://localhost:8080/api/v1/cache/entity/https://example.com/op"
curl -X POST "http://localhost:8080/api/v1/cache/clear-all"
curl -X DELETE "http://localhost:8080/api/v1/cache/entity/https://example.com/op"
```

### Web Interface

Access the web-based cache management interface at `http://localhost:8080/` which provides:

- **Cache Statistics**: Real-time view of cache sizes and contents
- **Entity Inspection**: Inspect metadata for specific cached entities
- **Trust Chain Inspection**: View complete cached trust chains
- **Cache Management**: Clear entire caches or remove specific entries
- **API Documentation**: Complete endpoint reference

## Docker Deployment

### Standalone Container

```bash
docker run -p 8080:8080 \
  -e TRUST_ANCHORS="https://federation.example.com" \
  -e PORT=8080 \
  your-resolver-image
```

### Docker Compose

The resolver is included in the main `docker-compose.yaml`:

```yaml
resolver:
  environment:
    - TRUST_ANCHORS=https://test-op:8083
    - PORT=8080
    - LOG_LEVEL=info
    # ... other variables
```

### Health Checks

The container includes built-in health checks:

```yaml
healthcheck:
  test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
```

## Development

### Local Development

```bash
# Set environment variables
export TRUST_ANCHORS="https://test-trust-anchor.com"
export PORT=8080
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

## Architecture

### Design Principles

- **Zero Configuration Files**: All settings via environment variables
- **Container First**: Optimized for containerized deployments
- **Lean Dependencies**: Minimal external dependencies
- **Observable**: Built-in metrics and health checks
- **Federation Focused**: Specialized for OpenID Federation operations

### Components

- **HTTP Server**: Gin-based REST API with web interface
- **Resolver Core**: Federation entity resolution logic with intelligent caching
- **Cache Manager**: TTL-based caching system for entities and trust chains
- **Metrics**: Prometheus-compatible monitoring with cache statistics
- **Health Checks**: Trust anchor and service health validation

### Data Flow

```
Client Request → HTTP Server → Cache Check → Resolver → Trust Anchor API → Cache Store → Response
                      ↓                    ↑
                Metrics Collection        Cache Hit
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

2. **Port Already in Use**
   ```
   Error: bind: address already in use
   Solution: Change PORT environment variable
   ```

3. **Trust Anchor Unreachable**
   ```
   Health check fails with trust anchor errors
   Solution: Verify trust anchor URLs are accessible
   ```

4. **Stale Cache Data**
   ```
   Cached entity data appears outdated
   Solution: Use cache management API to clear specific entries or entire cache
   ```

5. **High Memory Usage**
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

[Add your license information here]
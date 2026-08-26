# Resolver load test

Phased HTTP load against a running Federation Resolver. Mixes signed `/api/v1/resolve` (needs a **registered** trust anchor), `/api/v1/federation_list`, `/.well-known/openid-federation`, and `/health`. `/api/v1/collection` is not included — a single collection walk can take several seconds.

Default target is the poc2 lab resolver.

## Prerequisites

- Go 1.22+
- The trust anchor must already be registered for signing (`POST /api/v1/register-trust-anchor`, or the TA dashboard **Re-register with Resolver** button). Configured `TRUST_ANCHORS` alone is not enough for `/api/v1/resolve`.
- Confirm:

```bash
curl -sS https://resolver.poc2.dev.oidf.lab.surfconext.nl/api/v1/registered-trust-anchors
```

## Start

From the repository root:

```bash
go run ./loadtest
```

That uses:

| Flag / env | Default |
| --- | --- |
| `-base` / `RESOLVER_URL` | `https://resolver.poc2.dev.oidf.lab.surfconext.nl` |
| `-ta` / `TRUST_ANCHOR` | `https://ta.poc2.dev.oidf.lab.surfconext.nl` |
| `-sub` | `https://intermediary.<domain>` and `https://rp.<domain>` derived from `-ta` |

Full run is about **65 seconds** (warm-up 10s / 20 workers, steady 20s / 100, high 20s / 400, spike 15s / 800).

### Other examples

```bash
# Shorter local check (~20s)
go run ./loadtest -quick

# Local resolver
go run ./loadtest -base http://localhost:8080 -ta https://ta.example.org \
  -sub https://leaf.example.org

# Extra subjects (repeat -sub or comma-separate)
go run ./loadtest -sub https://intermediary.poc2.dev.oidf.lab.surfconext.nl \
  -sub https://rp.poc2.dev.oidf.lab.surfconext.nl
```

Preflight fails fast if health, federation list, or resolve is not HTTP 200 (typical cause: TA not registered). The process exits `1` if any request during the run is not 2xx/3xx.

## Result matrix

The run prints per-phase progress, then a summary table:

```
| Phase   | Workers | Throughput  | p50    | p99    | Errors |
| ------- | ------- | ----------- | ------ | ------ | ------ |
| Warm-up |      20 |    1031 rps |   15ms |   79ms |      0 |
| Steady  |     100 |     832 rps |   94ms |  483ms |      0 |
| High    |     400 |     398 rps |  849ms |   2.4s |      0 |
| Spike   |     800 |     415 rps |   1.8s |   5.5s |      0 |
| TOTAL   |       — |  41,805 req |  119ms |   3.7s |      0 |
```

Throughput dropping while p99 climbs means the resolver is saturated: extra workers queue rather than increase rps. Peak useful rate on poc2 was around **1k rps** at 20 workers for this cached resolve mix.

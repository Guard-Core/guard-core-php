# guard-core-php advanced example

A production-style deployment of the guard-core-php engine: multi-stage Docker
build, non-root runtime, nginx reverse proxy, Redis for shared bans and rate
limits, a route gate, and admin routes that drive the ban manager.

For the minimal single-file version, see [`../simple_app`](../simple_app).

## Architecture

```text
Client -> nginx (port 80) -> guard adapter -> built-in-server front controller
                                    |
                             GuardEngine
                                    |
                            Redis (bans, rate limits)
```

- `public/index.php` - assembly: engine lifecycle and dispatch
- `src/config.php` - environment-driven `SecurityConfig` tuning
- `src/guard_mw.php` - the SAPI adapter (request translation, route gate,
  verdict writing)
- `src/routes.php` - handlers, including `/admin/*` operational routes

## Quick start

```bash
cd examples/advanced_app
docker compose up --build
```

## Endpoints

| Endpoint | Notes |
|---|---|
| `GET /` | API info |
| `GET /health`, `GET /ready` | Probes, excluded from the pipeline |
| `POST /echo` | Body-bearing request through detection |
| `GET /rate/burst` | `endpointRateLimits`: 5 requests per 60 seconds |
| `GET /admin/banned?ip=...` | Ban check for one IP (requires `X-Admin-Token`) |
| `POST /admin/ban` | Body `{"ip": "...", "seconds": 300, "reason": "..."}` (requires `X-Admin-Token`) |
| `POST /admin/unban` | Body `{"ip": "..."}` (requires `X-Admin-Token`) |
| `GET /test/xss`, `GET /test/sqli`, `GET /test/traversal` | Hostile query-param payloads; the guard blocks them before the handler runs |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost/

# Penetration detection blocks the payload as suspicious activity (400)
curl -i "http://localhost/test/xss?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

# Rate limiting: the sixth request in 60 seconds returns 429
for i in $(seq 1 6); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost/rate/burst; done

# Route gate: missing admin token -> 400
curl -i http://localhost/admin/banned

# With the token
curl -i -H 'X-Admin-Token: admin-token-change-me' 'http://localhost/admin/banned?ip=203.0.113.9'

# Manual ban, then observe the banned IP verdict, then unban
curl -s -X POST http://localhost/admin/ban -H 'X-Admin-Token: admin-token-change-me' \
  -H 'Content-Type: application/json' -d '{"ip": "203.0.113.9", "seconds": 120}'
curl -s -H 'X-Admin-Token: admin-token-change-me' 'http://localhost/admin/banned?ip=203.0.113.9'
curl -s -X POST http://localhost/admin/unban -H 'X-Admin-Token: admin-token-change-me' \
  -H 'Content-Type: application/json' -d '{"ip": "203.0.113.9"}'
```

## Intentional simplifications

- The admin gate lives in `src/guard_mw.php` and reproduces the engine's
  `RequiredHeadersCheck` semantics (400, `Missing required header:
  X-Admin-Token`) because the `GuardEngine` facade does not expose a route
  registry yet: its internal `RouteResolver` is built with no route configs.
  The route ID is still attached to the request state, so the example is
  correct once a registry seam lands.
- This port returns the fixed `Too many requests` body for 429 verdicts;
  `customErrorResponses` only tunes 403 here.
- The ban manager exposes ban / unban / is-banned (no count surface yet), so
  `/admin/banned` checks one IP instead of reporting counters.
- The `/test/*` payloads ride in query parameters so the smoke keeps the
  request surface identical to simple_app; body scanning is exercised by the
  engine's test runners.

## Configuration knobs demonstrated

- Proxy trust: `trustedProxies` + `trustedProxyDepth` (one hop: nginx)
- Global rate limiting plus a per-endpoint override (`endpointRateLimits`)
- Auto-banning (`autoBanThreshold`, `autoBanDuration`) and per-threat bans
  (`threatBanConfig` for `sqli` and `xss`)
- Penetration detection with all categories
- `customErrorResponses` for a consistent block body (403)
- `excludePaths` so probes never touch the pipeline
- `logRequestLevel` / `logSuspiciousLevel`
- `onBlock` hook: the telemetry seam for
  [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) wiring
  (comment-level guidance in `src/config.php`; `enableAgent` is fail-closed
  in this port, so the hook is the integration point)

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTED_PROXIES` | empty | CIDRs whose forwarded headers are trusted |
| `TRUSTED_PROXY_DEPTH` | `1` | Forwarding hops to trust |
| `ENABLE_REDIS` | `1` | Set `0` to run without Redis (in-process state) |
| `REDIS_HOST` | `127.0.0.1` | Shared ban/rate-limit state host (compose sets `redis`) |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PREFIX` | `guard_core:` | Redis key prefix |
| `RATE_LIMIT` / `RATE_LIMIT_WINDOW` | `30` / `60` | Global rate limit |
| `AUTO_BAN_THRESHOLD` / `AUTO_BAN_DURATION` | `5` / `300` | Auto-ban policy |
| `BLOCK_CLOUD_PROVIDERS` | empty | Comma-separated providers (e.g. `AWS,GCP`) |
| `LOG_REQUEST_LEVEL` / `LOG_SUSPICIOUS_LEVEL` | `INFO` / `WARNING` | Log levels |

## Key differences from simple_app

| Feature | simple_app | advanced_app |
|---|---|---|
| Reverse proxy | none | nginx with edge rate limiting |
| Layout | single `index.php` | `public/` + `src/` split |
| Docker build | single stage | multi-stage build, non-root user |
| Route gate | not used | `admin` gate with `X-Admin-Token` |
| Admin/ops routes | none | ban, unban, ban check |
| Health checks | compose probe only | compose probes + nginx |
| Resource limits | none | CPU and memory limits per service |

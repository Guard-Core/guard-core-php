# guard-core-php simple app

A minimal guarded HTTP server built directly on the guard-core-php engine, in
a single `index.php`. It shows the canonical engine wiring and the complete
SAPI request shim, so it doubles as a reference for writing your own adapter.

For a production-style layout (multi-stage Docker, nginx, admin routes, route
gate), see [`../advanced_app`](../advanced_app).

## Run it

With Docker Compose (recommended, includes Redis):

```bash
cd examples/simple_app
docker compose up --build
```

Or with a local PHP 8.3+ toolchain (in-process state unless `ENABLE_REDIS=1`
with a reachable Redis):

```bash
composer install
php -S 0.0.0.0:8080 examples/simple_app/index.php
```

## Endpoints

| Endpoint | What it demonstrates |
|---|---|
| `GET /` | API info; passes the guard |
| `GET /health` | Liveness probe; excluded from the pipeline via `excludePaths` |
| `POST /echo` | Body-bearing request through detection |
| `GET /rate/strict` | Per-endpoint rate limit: 1 request per 10 seconds (`endpointRateLimits`) |
| `GET /search?q=...` | Query parameter scanning; XSS payloads are blocked as suspicious activity |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost:8080/

# Blocked by penetration detection (400, suspicious activity)
curl -i -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'

# Rate limited: the second request within 10 seconds returns 429
curl -i http://localhost:8080/rate/strict
curl -i http://localhost:8080/rate/strict

# Blocked user agent: the verdict carries the custom 403 body
curl -i -A 'badbot/1.0' http://localhost:8080/

# Auto-banned: after autoBanThreshold (5) violations the IP is banned and
# every verdict carries the custom 403 body. Note that the violation
# counters are in-process; the PHP built-in server starts a fresh process
# per request, so this demo accumulates them only under a persistent worker
# (worker-mode runtimes). Redis-backed state (rate limits, bans) is
# unaffected, and the advanced example drives the ban manager directly
# through its admin routes.
curl -i http://localhost:8080/
```

## A note on address headers

The engine skips the `ssrf` category for the proxy identity headers (`host`, `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip`, `forwarded`, ...) by default, so a plain `Host: localhost` request is not flagged and `index.php` needs no workaround. Every other category still scans those headers. Pass `excludedDetectionHeaders` to extend the set with your own address-carrying headers, and `excludedSemanticDetectionHeaders` to keep a header out of the semantic analyzer only.

## Configuration knobs demonstrated

Inline comments in `index.php` walk through every knob used:

- Global rate limiting (`rateLimit`, `rateLimitWindow`) and per-endpoint
  overrides (`endpointRateLimits`)
- Auto-banning (`autoBanThreshold`, `autoBanDuration`)
- Penetration detection with all categories enabled
- Blocked user agents (regex patterns), exercising `customErrorResponses`
  (this port returns the fixed `Too many requests` body for 429; the
  override tunes 403)
- `excludePaths` for health and docs routes
- Redis via `REDIS_HOST` / `REDIS_PORT` / `REDIS_PREFIX` (compose wires Redis
  in; without it the managers fall back to in-process state)
- The `onBlock` hook: the in-process hook for block events; for telemetry
  attach [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) with
  `setAgentHandler()` and set `enableAgent: true` (guidance in `index.php`)

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ENABLE_REDIS` | `1` | Set `0` to run without Redis (in-process state) |
| `REDIS_HOST` | `127.0.0.1` | Redis host (compose sets `redis`) |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PREFIX` | `guard_core:` | Redis key prefix |

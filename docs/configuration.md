# Configuration

`SecurityConfig` is built through a single constructor of named arguments
(every field nullable with an engine default). Arguments belonging to features
this port does not implement, when set to an enabling value, throw
`UnsupportedFeatureError` (fail closed): guard agent telemetry, and dynamic
rules.

## CORS

| Argument | Default | Notes |
|---|---|---|
| `enableCors` | `false` | Enables the CORS handler over the engine |
| `corsAllowOrigins` | `['*']` | Exact origins; `*` allows every origin |
| `corsAllowMethods` | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | Uppercased at config time; an empty list falls back to `GET` |
| `corsAllowHeaders` | `['*']` | Lowercased at config time; `*` echoes the requested headers verbatim |
| `corsAllowCredentials` | `false` | Incompatible with the `*` origin: that combination fails config construction |
| `corsExposeHeaders` | `[]` | Joined into `Access-Control-Expose-Headers` on responses |
| `corsMaxAge` | `600` | A configured `0` falls back to `600` |

Behavior mirrors the reference `CorsHandler` (guard-core
`handlers/cors_handler.py`) and the adapter dispatch: a preflight (OPTIONS
carrying `Access-Control-Request-Method`) executes the security pipeline and
is then short-circuited with `200 OK` (or `400 Disallowed CORS: origin,
method, headers`), blocked responses compose the CORS headers on top of the
engine's blocked-response set, and disallowed origins simply get no CORS
headers (the browser enforces). For pass-through responses the adapter merges
`GuardEngine::corsResponseHeaders($request)` with its own outgoing headers.

## Security headers

| Argument | Default | Notes |
|---|---|---|
| `securityHeaders` | reference default block | Reference-shaped dict: `enabled`, `hsts` (`max_age`/`include_subdomains`/`preload`), `csp` (ordered directive => sources), `frame_options`, `content_type_options`, `xss_protection`, `referrer_policy`, `permissions_policy`, `custom` |

Behavior mirrors the reference `SecurityHeadersManager`
(guard-core `handlers/security_headers_handler.py`): disabled configuration
emits no headers, the class defaults apply, an absent or `null` override key
keeps the class default, an empty `permissions_policy` removes that header
(the reference falsy check), an ordered `csp` block joins directives into
`Content-Security-Policy`, the `hsts` block builds
`max-age`/`includeSubDomains`/`preload` with the preload corrections
(preload requires at least one year and subdomains), and `custom` headers
land last and may override anything. Validation is fail-closed at config
construction (the reference `configure()` raising): RFC 7230 token names for
custom headers, CRLF rejected, values capped at 8192 bytes, control
characters sanitized away. Blocked responses carry the headers engine-side;
pass-through responses take `GuardEngine::responseHeaders()`.

## Geo country rules

| Argument | Default | Notes |
|---|---|---|
| `whitelistCountries` | `[]` | ISO country codes, uppercased and deduplicated at construction. Non-empty is restrictive: only listed countries pass, and an unresolved country is denied |
| `blockedCountries` | `[]` | ISO country codes that are always denied. Ignored while `whitelistCountries` is non-empty (construction warns via `error_log`) |
| `geoIpDbPath` | `''` | Path to a local MMDB database with top-level `country` records (the ipinfo `country_asn.mmdb` layout). Required when country rules are set and no handler is injected |
| `geoIpHandler` | `null` | Injected `CountryResolver` (`getCountry(ip): ?string`); replaces the built-in MMDB reader |

Country rules run inside the `ip_security` check: after the global IP lists
and before the exempt-ips resolution, mirroring the reference
`check_ip_access`. A global `whitelist` match skips the country stage.
Loopback IPs are exempt from the country stage. An unresolvable country
fails closed in allowlist mode and open in blocklist mode. The engine does
not download databases: provision the MMDB file yourself or inject a
resolver. Exempt IPs are not exempt from country rules. Route-level country
rules are deferred (the PHP `RouteConfig` surface has no route-level IP
rule lists to combine with).

## Client identity and proxy trust

| Argument | Default | Notes |
|---|---|---|
| `trustedProxies` | `[]` | IPs or CIDRs whose forwarding headers are trusted |
| `trustedProxyDepth` | `1` | Must be >= 1 |
| `trustXForwardedProto` | `false` | Honor `X-Forwarded-Proto` for HTTPS detection |

## Access lists

| Argument | Notes |
|---|---|
| `whitelist` | IPs or CIDRs, validated at config time |
| `blacklist` | IPs or CIDRs, validated at config time |
| `excludePaths` | Paths skipped by the pipeline (defaults: `/docs`, `/redoc`, `/openapi.json`, `/openapi.yaml`, `/favicon.ico`, `/static`) |
| `emergencyMode` / `emergencyWhitelist` | Blocks everything except the whitelist |

## Redis

| Argument | Default | Notes |
|---|---|---|
| `enableRedis` | `true` | Required for distributed bans and rate limits |
| `redisUrl` | `redis://localhost:6379` | Kept for parity; the connection uses `REDIS_HOST` / `REDIS_PORT` |
| `redisPrefix` | `guard_core:` | Key prefix |
| `redisFailOpen` | `false` | On Redis failure, allow traffic instead of blocking |

## IP banning

| Argument | Default | Notes |
|---|---|---|
| `enableIpBanning` | `true` | |
| `autoBanThreshold` | `10` | Violations before an auto-ban; must be >= 1 |
| `autoBanDuration` | `3600` | Auto-ban length in seconds |
| `threatBanConfig` | `[]` | Per-category `['threshold' => .., 'duration' => ..]` overrides |
| `enableRateLimitAutoBan` | `false` | Count rate-limit violations toward auto-ban |

## Rate limiting

| Argument | Default | Notes |
|---|---|---|
| `enableRateLimiting` | `true` | |
| `rateLimit` | `10` | Requests per window |
| `rateLimitWindow` | `60` | Window length in seconds |
| `endpointRateLimits` | `[]` | Exact-path overrides, e.g. `['/api' => ['limit' => 5, 'window' => 60]]` |

## Penetration detection

| Argument | Default | Notes |
|---|---|---|
| `enablePenetrationDetection` | `true` | |
| `enabledDetectionCategories` | all 19 categories | `xss`, `sqli`, `cmd_injection`, `path_traversal`, and more |
| `detectionSemanticThreshold` | `0.7` | Semantic model threshold, in `[0.0, 1.0]` |
| `logSensitiveHeaders` | `[]` | Headers skipped by detection scanning and redacted from logs; use for the address headers (`host`, `x-forwarded-for`, ...) until a dedicated detection-exclusion knob lands |

## Cloud provider blocking, user agents, auth

| Argument | Notes |
|---|---|
| `blockCloudProviders` | Selectors `AWS` or `AWS:!us-east-1` for a region carve-out; unknown names rejected |
| `cloudIpRefreshInterval` | Seconds, clamped to `[60, 86400]` |
| `blockedUserAgents` | Regex patterns, validated at config time |
| `authVerifier` | `Closure(object $request, string $credential): mixed` used by auth-required routes |

## Logging

| Argument | Default | Notes |
|---|---|---|
| `logRequestLevel` | `null` (off) | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `logSuspiciousLevel` | `WARNING` | |
| `mutedCheckLogs` | `[]` | Check names whose logs are suppressed |
| `logSensitiveHeaders` / `logSensitiveParams` / `logSensitiveBodyFields` | `[]` | Values redacted from logs and skipped by detection scanning (headers) |

## Custom behavior

| Argument | Notes |
|---|---|
| `customErrorResponses` | Map of int status code to body message, used for every block verdict except 429 in this port |
| `onBlock` | Telemetry hook, see [Usage](usage.md) |
| `customRequestCheck` | Final user-defined gate; a non-null response blocks |
| `passiveMode` | Log violations without blocking |
| `failSecure` | Default `true`; fail-closed on unresolvable client identity and internal errors |
| `routeResolutionStrict` | Reject requests whose route cannot be resolved |

Config values are immutable; `with(['rate_limit' => 20])` returns a copy with
a bumped revision so the pipeline rebuilds its checks.

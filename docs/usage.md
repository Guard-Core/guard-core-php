# Usage

## Engine lifecycle

The `GuardEngine` facade composes config, route resolution, Redis, the IP ban
manager, the rate limit handler, and the check pipeline.

```php
$config = new SecurityConfig(
    enableRedis: true,
    redisPrefix: 'guard_core:',
    enableRateLimiting: true,
    rateLimit: 30,
    rateLimitWindow: 60,
);

$engine = new GuardEngine($config);
// Connects Redis when enabled and initializes ban/rate-limit state.
// Call once before the first execute().
$engine->initialize();
```

Exposed accessors: `config()`, `redis()`, `banManager()`, `rateLimitHandler()`,
`cloudManager()`, `responseFactory()`, `pipeline()`.

## The request contract

Adapters (or your own middleware) translate native requests into a
`GuardRequest` implementation. `SimpleGuardRequest` covers the common shape:

```php
$request = new SimpleGuardRequest(
    urlPath: '/api',
    urlScheme: 'http',
    host: 'example.com',
    method: 'POST',
    clientHost: '203.0.113.9',   // null lets the engine resolve from headers
    headers: ['content-type' => 'application/json'],
    queryParams: ['q' => 'value'],
    body: '{"key": "value"}',
);
```

Pass `clientHost: null` to have the engine resolve the client IP through
`ClientIpResolver` using `trustedProxies` and the forwarded header chain. A
`RequestState` carries per-request resolution results (`clientIp`,
`guardRouteId`, bypass flags); seed your own instance to attach route IDs.

## Checking requests

```php
$verdict = $engine->execute($request);
if ($verdict !== null) {
    // Blocked. Write $verdict->statusCode(), $verdict->headers(), $verdict->body().
}
```

Well-known block verdicts:

| Situation | Status | Body |
|---|---|---|
| Banned IP | 403 | `IP address banned` |
| Auto-ban during detection | 403 | `IP has been banned` |
| Suspicious content | 400 | `Suspicious activity detected` |
| Rate limit exceeded | 429 | `Too many requests` (fixed body in this port; `customErrorResponses` does not tune 429) |

All other default bodies can be overridden through `customErrorResponses`.

## Managers

The managers are usable on their own for admin tooling:

```php
// IP bans
$engine->banManager()->ban('192.0.2.10', 3600, 'manual');
$engine->banManager()->isIpBanned('192.0.2.10');
$engine->banManager()->unban('192.0.2.10');

// Redis state (built-in RESP2 client; REDIS_HOST / REDIS_PORT env respected)
$engine->redis()->ping();
```

Bans that overlap loopback or a configured trusted proxy are refused (the
manager warns and returns `false`) so a deployment cannot ban itself.

## The block hook

`SecurityConfig(onBlock: Closure(object $request, array $payload): void)` is
the telemetry seam. The pipeline fires it for every block or passive
detection verdict with a flat payload: `check_name`, `reason`, `trigger_info`,
`passive_mode`, `client_ip`, `path`, `method`, and `status_code`. The hook is
panic-guarded (throwing hooks are swallowed) and never alters the verdict.

## ReDoS safety gates (section 04)

`preg_*` is PCRE: a backtracking engine with real ReDoS exposure, so every
detection scan runs behind the spec 04 gates ported from the reference
(`src/Detection/Redos/`):

- `Prefilters` - the section 04 pattern-safety gate order: dangerous
  constructs, the compile check, the structural checks, then the probe
  (`CostArbiter::probeWithTestStrings`, 0.05 s per string, 2.0 s overall,
  fail closed) or the cost arbiter (`CostArbiter::costVerdict`, timed probe
  ladder, load-factor normalization, 0.05 s budget, one retry).
- `ScanGuard` - per-scan execution: `pcre.backtrack_limit` set for the scan
  with the previous limit restored, `PREG_BACKTRACK_LIMIT_ERROR` /
  `PREG_RECURSION_LIMIT_ERROR` / `PREG_JIT_STACKLIMIT_ERROR` trips classified
  as scan timeouts (never 500s), an hrtime deadline, and a canary probe
  before a plain-pattern scan of a large subject.
- `SusPatterns` - the per-pattern classification and the reference's timeout
  semantics: a scan timeout emits a `pattern_timeout` threat
  ("threats-logged-and-miss") so an engine that could not finish a scan
  fails closed; scan-window bounded patterns carry no timeout arm, windowed
  finders run under the full compiler timeout.

`validatePatternSafety` is the custom-rule entry point; `bin/test_redos_gates.php`
pins the gates, including catastrophic fixtures.

## Geo database lifecycle (section 10)

`IpInfoManager` ports the reference IPInfoManager lifecycle: the free
`country_asn.mmdb` download with an IPInfo token (3 attempts, exponential
backoff from 1 s), atomic writes, mtime freshness against `maxAge`, the
Redis-cached database copy (`ipinfo:database`, TTL `maxAge`), the
never-raising `getCountry`, and the `check_country_access` verdicts with
their `country_blocked` / `geo_lookup_failed` events. Events go to the
injectable `eventSink` (the reference sends them to the agent handler).

## Cross-request refresh single-flight

The cloud refresh's in-flight guard is per-request in FPM (specs/impl/php.md).
Workers that share the `RedisCloudIpStore` additionally coordinate through
`RedisLock` (`cloud_refresh_lock:{provider}`, SET NX PX 15 s + token-checked
release): one cache-miss thundering herd produces one network fetch per
provider, and a worker that loses the race re-reads the cache once and skips
the fetch. The lock is fail-open: with Redis disabled or erroring, behavior
degrades to the per-request guard.

## Event bus, metrics, and dynamic rules (section 12)

`GuardEngine::eventBus()` exposes the spec 12 security event bus: blocked
checks emit their mapped event (`rate_limit` -> `rate_limited`,
`ip_security` -> `ip_blocked`, `user_agent` -> `user_agent_blocked`,
`cloud_provider` -> `cloud_blocked`, `suspicious_activity` ->
`suspicious_request`, `authentication` -> `authentication_failed`,
`emergency_mode` -> `emergency_mode_block`, anything else ->
`penetration_attempt`) through the bus while the `on_block` hook stays as
the compatibility layer. The bus queues until an agent handler (anything
duck-typed `sendEvent(SecurityEvent)`) attaches via `setAgentHandler()`;
adapters can also `drain()` the queue. Gating: `agent_enable_events`,
`EventFilter` muted types. Send failures log and never raise.
`MetricsCollector` mirrors this for `response_time` / `request_count` /
`error_rate` under `agent_enable_metrics`.

`DynamicRuleManager` ports the agent-synced dynamic rules: the update flow
(expiry, staleness gate, updated/applied events), transactional
application over the immutable config (`SecurityConfig::with()` builds the
full validated candidate; on any failure the previous config stays
installed - partial application never survives), last-known persistence
(Redis `dynamic_rules:last_known` plus an optional atomic file copy), one
shot hydration at startup, and the `match_event` correlation. With no
readable store the manager keeps the base config (fail closed). Enable it
with `enable_dynamic_rules` and hand the manager
`$engine->applyDynamicConfig(...)` as its `applyConfig` seam.

## Conformance

`php bin/conformance.php` replays the shared JSON fixture corpus
(`tests/Conformance/guard-core-spec-4.0.2/`) generated from the Python engine
and compares verdicts field by field, so any detector change that would drift
from the reference fails CI. Never hand-edit expected values or the generated
tables under `src/Support/Generated/`.

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

## Conformance

`php bin/conformance.php` replays the shared JSON fixture corpus
(`conformance/guard-core-spec-4.1.0/`) generated from the Python engine
and compares verdicts field by field, so any detector change that would drift
from the reference fails CI. Never hand-edit expected values or the generated
tables under `src/Support/Generated/`.

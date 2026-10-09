<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Guard Core PHP: the API security core engine for PHP. A framework-agnostic port of the <a href="https://github.com/Guard-Core/guard-core">guard-core</a> detection engine with Redis-backed rate limiting, IP policy, and payload inspection.</strong>
</p>

<p align="center">
    <a href="https://packagist.org/packages/rennf93/guard-core-php">
        <img src="https://img.shields.io/packagist/v/rennf93/guard-core-php?color=0080ff" alt="Packagist version">
    </a>
    <a href="https://guard-core.github.io/guard-core-php/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-php/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/guard-core-php/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-php/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-core-php/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-core-php/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/guard-core-php/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-php/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-core-php/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/guard-core-php?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/PHP-777BB4.svg?style=flat&logo=php&logoColor=white" alt="PHP"> <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&logo=redis&logoColor=white" alt="Redis">
    <a href="https://packagist.org/packages/rennf93/guard-core-php">
        <img src="https://img.shields.io/packagist/dm/rennf93/guard-core-php" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/guard-core-php/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---


## Ecosystem

Guard Core is the Python engine. Framework adapters are thin wrappers that translate native request/response types into Guard Core's protocols. The telemetry agents ship security events and metrics to the monitoring backend. Parallel engine implementations exist for Go, PHP, TypeScript (on npm), and Rust (on crates.io) - all ports of the same reference semantics, conformance-tested against the shared adversarial corpus.

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/Guard-Core/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/Guard-Core/guard-agent) | Telemetry agent | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/Guard-Core/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/Guard-Core/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### Go

Go modules published via GitHub releases. **Production-ready.**

| Package | Role | Release |
|---|---|---|
| [guard-core-go](https://github.com/Guard-Core/guard-core-go) | Go engine | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-core-go?label=tag)](https://github.com/Guard-Core/guard-core-go/releases) |
| [nethttp-guard](https://github.com/Guard-Core/nethttp-guard) | net/http adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/nethttp-guard?label=tag)](https://github.com/Guard-Core/nethttp-guard/releases) |
| [gin-guard](https://github.com/Guard-Core/gin-guard) | Gin adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/gin-guard?label=tag)](https://github.com/Guard-Core/gin-guard/releases) |
| [echo-guard](https://github.com/Guard-Core/echo-guard) | Echo (v4) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/echo-guard?label=tag)](https://github.com/Guard-Core/echo-guard/releases) |
| [fiber-guard](https://github.com/Guard-Core/fiber-guard) | Fiber (v3) adapter | [![release](https://img.shields.io/github/v/tag/Guard-Core/fiber-guard?label=tag)](https://github.com/Guard-Core/fiber-guard/releases) |
| [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) | Telemetry agent | [![release](https://img.shields.io/github/v/tag/Guard-Core/guard-agent-go?label=tag)](https://github.com/Guard-Core/guard-agent-go/releases) |

### PHP

Published on [Packagist](https://packagist.org/) under the `rennf93` vendor. **Production-ready.**

| Package | Role | Packagist |
|---|---|---|
| [guard-core-php](https://github.com/Guard-Core/guard-core-php) | PHP engine | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-core-php)](https://packagist.org/packages/rennf93/guard-core-php) |
| [laravel-guard](https://github.com/Guard-Core/laravel-guard) | Laravel adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/laravel-guard)](https://packagist.org/packages/rennf93/laravel-guard) |
| [symfony-guard](https://github.com/Guard-Core/symfony-guard) | Symfony adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/symfony-guard)](https://packagist.org/packages/rennf93/symfony-guard) |
| [psr15-guard](https://github.com/Guard-Core/psr15-guard) | PSR-15 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/psr15-guard)](https://packagist.org/packages/rennf93/psr15-guard) |
| [slim-guard](https://github.com/Guard-Core/slim-guard) | Slim 4 adapter | [![Packagist](https://img.shields.io/packagist/v/rennf93/slim-guard)](https://packagist.org/packages/rennf93/slim-guard) |
| [guard-agent-php](https://github.com/Guard-Core/guard-agent-php) | Telemetry agent | [![Packagist](https://img.shields.io/packagist/v/rennf93/guard-agent-php)](https://packagist.org/packages/rennf93/guard-agent-php) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope; source in the [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| | [@guardcore/core](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/@guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/Guard-Core/guard-core-ts/tree/master/packages/hono) | Hono (edge) adapter | [![npm](https://img.shields.io/npm/v/@guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |
| [guardagent](https://github.com/Guard-Core/guard-agent-ts) | Telemetry agent | [![npm](https://img.shields.io/npm/v/guardagent)](https://www.npmjs.com/package/guardagent) |

### Rust

Published on crates.io. **Production-ready.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core-engine](https://github.com/Guard-Core/guard-core-rs) | Core engine crate | [![crates.io](https://img.shields.io/crates/v/guard-core-engine)](https://crates.io/crates/guard-core-engine) |
| [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) | Facade crate (consumer entry point) | [![crates.io](https://img.shields.io/crates/v/guard-core-rs)](https://crates.io/crates/guard-core-rs) |
| [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs) | Actix Web adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |
| [rocket-guard-rs](https://github.com/Guard-Core/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs) | Telemetry agent | [![crates.io](https://img.shields.io/crates/v/guard-agent-rs)](https://crates.io/crates/guard-agent-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/Guard-Core/guard-core-mcp) | MCP server: config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

___

## Features

- **IP lists**: whitelist, blacklist, and exemptions with CIDR support
- **Geo rate limits and country blocking**: per-country rules via GeoIP
- **CORS handling and security headers**: OWASP-aligned defaults
- **Behavior rules**: per-route usage counting and bans
- **Per-route detection exclusions** and detection limits (ReDoS-safe custom patterns)
- **Redis-backed distributed state** with fail-open / fail-secure modes

___

## Documentation

📚 **[Documentation](https://guard-core.github.io/guard-core-php/latest/)** - full technical documentation for this package.

🛡️ **[Guard Core](https://guard-core.github.io/guard-core/latest/)** - the engine's reference documentation.

🤖 **[Monitoring Agent Integration](https://github.com/Guard-Core/guard-agent)** - monitor your Guard instance with a monitoring agent.
___

## Install

```bash
composer require rennf93/guard-core-php:^4.0.4
```

Requires PHP `^8.2` with `ext-pcre`, `ext-mbstring`, and `ext-json`. The engine is consumed through the adapter packages or driven directly:

```php
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;

$config = new SecurityConfig(
    enableRedis: false,
    blacklist: ['192.0.2.0/24'],
    rateLimit: 100,
    rateLimitWindow: 60,
    enableRateLimiting: true,
);

$engine = new GuardEngine($config);
```

## IP lists: whitelist vs exempt_ips

`whitelist` and `exempt_ips` answer different questions. A non-empty `whitelist` is restrictive: every IP not on it is denied by the global IP check. `exempt_ips` is noise reduction for known-friendly automation (monitoring probes, VPN egress, a partner's server): a listed IP or CIDR skips the rate-limit, user-agent and per-route cloud-provider checks, but it is not immunity. The blacklist, dynamic IP bans, the global `block_cloud_providers` list and penetration detection still apply to exempt IPs, the whitelist deny path is unchanged (an exempt IP does not pass a restrictive whitelist it is not on), and an invalid entry fails closed at config construction. Entries accept IPv4, IPv6 and IPv4-mapped forms with the same matching semantics as the whitelist.

```php
$config = new SecurityConfig(
    enableRedis: false,
    exemptIps: ['198.51.100.7', '198.51.100.0/28'],
);

$engine = new GuardEngine($config);
```

## Geo rate limits

Routes can carry per-country rate-limit tiers: `RouteConfig::$geoRateLimits` maps a country code (`'DE'`) or the `'*'` fallback to a `{limit, window}` tier, mirroring the reference engines' `@geo_rate_limit` decorator. Country resolution is pluggable and the tiers only activate when a country resolver is configured on the rate limit handler: **without a resolver the geo tier is inert and the default limit applies** (a route can carry the map, but nothing fires until one is wired). The resolver is a `Closure(string): string` from client ip to country code (empty string when unknown, which takes the `'*'` fallback); adapters wire it after engine construction:

```php
$engine = new GuardEngine($config);
$engine->rateLimitHandler()->setGeoResolver(
    static fn (string $ip): string => $ipinfo->countryOf($ip) // your geo lookup
);

$request->state()->routeConfig = new RouteConfig(
    geoRateLimits: ['DE' => ['limit' => 5, 'window' => 60], '*' => ['limit' => 20, 'window' => 60]],
);
```

A request from a resolved country enforces that country's tier first (`'*'` when the country is missing from the map, nothing when neither matches), the tier shares the route's hashed bucket, and exempt and whitelisted clients still skip the check entirely.

## Geo country blocking

Set `blockedCountries` and/or `whitelistCountries` and the `ip_security` check enforces them after the global IP lists: a non-empty `whitelistCountries` is restrictive (only listed countries pass, an unresolved country is denied), `blockedCountries` denies its matches, loopback IPs are exempt, and a global `whitelist` match skips the country stage entirely. Country rules with no resolver fail config construction: point `geoIpDbPath` at a locally provisioned MMDB file with top-level `country` records (the ipinfo `country_asn.mmdb` layout) or inject a `CountryResolver`. The engine never downloads databases.

```php
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;

final class MyGeoIp implements CountryResolver
{
    public function getCountry(string $ip): ?string
    {
        return $this->mmdb->countryOf($ip); // your lookup, null when unresolved
    }
}

$config = new SecurityConfig(
    enableRedis: false,
    blockedCountries: ['CN', 'RU'],
    geoIpDbPath: __DIR__ . '/country_asn.mmdb', // or geoIpHandler: new MyGeoIp(),
);
```

## CORS

Set `enableCors: true` and the engine runs the reference `CorsHandler` behavior: a preflight (OPTIONS carrying `Access-Control-Request-Method`) executes the security pipeline and is short-circuited with `200 OK` or `400 Disallowed CORS: origin, method, headers`, every blocked response carries the CORS verdict headers, and a disallowed origin on a normal request simply gets no CORS headers (the browser enforces). The wildcard-origin plus `corsAllowCredentials` combination fails config construction.

```php
$config = new SecurityConfig(
    enableRedis: false,
    enableCors: true,
    corsAllowOrigins: ['https://app.example.com'],
    corsAllowMethods: ['GET', 'POST'],
);
$engine = new GuardEngine($config);
```

For pass-through (non-blocked) responses, adapters merge the per-request CORS map into their outgoing headers:

```php
foreach ($engine->corsResponseHeaders($request) as $name => $value) {
    $response = $response->withHeader($name, $value);
}
```

## Security headers

By default the engine computes the reference security header set (port of
guard-core `handlers/security_headers_handler.py`): the ten class defaults
(`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`,
`X-XSS-Protection: 1; mode=block`,
`Referrer-Policy: strict-origin-when-cross-origin`,
`Permissions-Policy: geolocation=(), microphone=(), camera=()`,
`X-Permitted-Cross-Domain-Policies: none`, `X-Download-Options: noopen`, COEP/COOP/CORP
`require-corp`/`same-origin`/`same-origin`) plus
`Strict-Transport-Security: max-age=31536000; includeSubDomains`. Blocked
responses carry the headers engine-side (the fail-secure 500s included), and
blocked responses compose them with the CORS verdict headers when CORS is
enabled. For pass-through responses the adapter merges
`GuardEngine::responseHeaders()` with its outgoing headers. Setting
`securityHeaders: ['enabled' => false]` removes every security header.

```php
$config = new SecurityConfig(
    enableRedis: false,
    securityHeaders: [
        'enabled' => true,
        'hsts' => ['max_age' => 31536000, 'include_subdomains' => true, 'preload' => false],
        'csp' => ['default-src' => ["'self'"]],
        'frame_options' => 'DENY',          // null keeps the class default
        'permissions_policy' => 'geolocation=(self)', // '' removes the header
        'custom' => ['X-Request-Id' => 'trace'],      // lands last, may override anything
    ],
);
$engine = new GuardEngine($config);
foreach ($engine->responseHeaders() as $name => $value) {
    $response = $response->withHeader($name, $value);
}
```

## Behavior rules

Attach behavior rules to a route (or globally with `globalBehaviorRules`):
`usage`/`frequency` rules count requests the pipeline allowed per (endpoint,
client) over a sliding window and dispatch `ban`/`log`/`throttle`/`alert`
when the count exceeds the threshold; `return_pattern` rules match outgoing
responses (`status:<code>`, `json:<path>==<expected>`, `regex:<pattern>`, or
a bare substring) and dispatch the same actions. Body-reading patterns
require `behaviorScanResponseBody: true` (they fail config construction
otherwise, mirroring the reference's fail-closed check) and read at most
`behaviorMaxResponseBodyInspectBytes` of the leading body.

```php
$config = new SecurityConfig(
    enableRedis: false,
    behaviorScanResponseBody: true,
    globalBehaviorRules: [
        ['rule_type' => 'return_pattern', 'threshold' => 5, 'window' => 60,
         'pattern' => 'status:404', 'action' => 'ban', 'ban_duration' => 600],
    ],
);
$engine = new GuardEngine($config);

// Route-level rules (usage rules run automatically on allowed requests):
$engine->execute($request); // tracks routeConfig->behaviorRules usage/frequency

// Response side: adapters call this on every pass-through response:
$engine->processResponse($request, $response);
```

### Per-route detection exclusions

`RouteConfig` carries the reference detection-exclusion surface: `enableSuspiciousDetection` (route-level kill switch or opt-in, winning over the global flag), `excludedDetectionParams`, `excludedDetectionBodyFields` and `enabledDetectionCategories` (a non-null route set replaces the global one, an empty category list disables every category), `excludedDetectionHeaders` (always merged on top of the defaults and the global set, suppressing ssrf address-chain false positives only) and `detectionScanBody` (a false skips the request-body surface only).

```php
$route = new RouteConfig(
    enableSuspiciousDetection: true,          // route-level kill switch / opt-in
    excludedDetectionParams: ['search_hint'], // replaces the global param set
    enabledDetectionCategories: ['sqli'],     // narrows the category set
    detectionScanBody: false,                 // skips the body surface only
);
$request->state()->routeConfig = $route;
```

## Detection limits


### Size-gated pattern family (large single-line subjects)

A family of detection patterns anchored at `\A` walks the subject one character
(or one path segment) at a time: the `etc/passwd`, `boot.ini`, `proc/self/environ`
and `var/log` line walks, the keyword-lookahead double walks, and the anchored
path-walk segment loops for `.htaccess`, `wp-admin`, `.env`, `.git`, recon path
targets and siblings (`PatternData::SIZE_GATED_PATTERN_INDICES`). PCRE2 consumes
stack proportional to the walked line, so on stock php:8.3 ini a benign
single-line subject can exhaust PCRE2 and abort detection entirely:

- `pcre.jit=1` (default): failures from ~24.5KB subjects
  (`PREG_JIT_STACKLIMIT_ERROR`) for the line-walk shapes, and from ~16.4KB for
  the segment-loop shapes once a trailing target follows ~16KB of path
  segments (`a/` repeated is the stack-densest input, floor cliff ~16392
  bytes).
- `pcre.jit=0`: failures from ~100KB subjects (`PREG_RECURSION_LIMIT_ERROR`).

Mitigation: when a view subject's first line reaches
`SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES` (15360, 15 KiB), the preg calls
of that family are skipped for the rest of the scan (no match contribution) and
detection completes normally. The threshold sits below the ~16.4KB segment-loop
cliff and above the largest conformance corpus content (14725 bytes), so it
holds under either `pcre.jit` setting (ini-independent) and never changes
conformance behavior.

Coverage trade-off: walk and segment patterns are line-scoped, so skipping
above the gate only forgoes their coverage on very long single-line subjects
(15KB or more in one line). All other patterns still scan the full subject, and
probes in shorter lines or multiline bodies are unaffected.


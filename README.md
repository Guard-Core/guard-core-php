# guard-core-php
Guard Core PHP - API Security Core Engine for PHP language

# guard-core-php

Guard Core PHP: the API security core engine for PHP. A framework-agnostic port of the [guard-core](https://github.com/rennf93/guard-core) detection engine that powers the PHP adapters: [psr15-guard](https://github.com/rennf93/psr15-guard), [laravel-guard](https://github.com/rennf93/laravel-guard), [symfony-guard](https://github.com/rennf93/symfony-guard), and [slim-guard](https://github.com/rennf93/slim-guard).

Docs: <https://rennf93.github.io/guard-core-php/>

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


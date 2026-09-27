<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RateLimitCheck;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitOutcome;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

// Geo rate limit tiers end to end: RouteConfig::$geoRateLimits (the
// @geo_rate_limit decorator surface) threaded through RateLimitCheck into
// the handler's geo tier, resolved by a country resolver callable wired on
// RateLimitHandler (constructor arg or setGeoResolver). The resolver is a
// REQUIRED part of the feature: with no resolver configured the geo tier
// is inert and the default limit applies (parity with the guard-core
// Python geo_rate_limit decorator + geo_ip_handler gate, and Go's
// tiersFor countryOfIP nil gate). Runs in-memory by default; pass
// --integration to also exercise the geo tier over a real Redis wire.

final class T
{
    public int $passed = 0;

    public int $failed = 0;

    private string $section = '';

    public function section(string $name): void
    {
        $this->section = $name;
        echo "=== {$name} ===\n";
    }

    public function ok(bool $condition, string $label): void
    {
        if ($condition) {
            $this->passed++;
            echo "  PASS {$label}\n";
        } else {
            $this->failed++;
            echo "  FAIL {$this->section} :: {$label}\n";
        }
    }

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        $ok = $expected === $actual;
        if (!$ok) {
            echo '    expected: ' . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
        }
        $this->ok($ok, $label);
    }

    public function throws(callable $fn, string $class, ?string $contains, string $label): void
    {
        try {
            $fn();
            $this->ok(false, "{$label} (no exception)");
        } catch (\Throwable $e) {
            $ok = $e instanceof $class && ($contains === null || str_contains($e->getMessage(), $contains));
            if (!$ok) {
                echo '    got: ' . get_class($e) . ': ' . $e->getMessage() . "\n";
            }
            $this->ok($ok, $label);
        }
    }

    public function done(string $name): int
    {
        echo "\n{$name}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed;
    }
}

$t = new T();
$integration = in_array('--integration', $argv, true);

const GEO_IP = '198.51.100.7';
const GEO_IP_2 = '198.51.100.8';
const GEO_OTHER_IP = '203.0.113.9';

/**
 * @param array<string, mixed> $configArgs
 * @param (\Closure(string): string)|null $resolver
 */
function makeEngine(array $configArgs = [], ?\Closure $resolver = null): GuardEngine
{
    $configArgs['enableRedis'] = false;
    $engine = new GuardEngine(new SecurityConfig(...$configArgs));
    if ($resolver !== null) {
        $engine->rateLimitHandler()->setGeoResolver($resolver);
    }

    return $engine;
}

/**
 * @param (\Closure(string): string)|null $resolver
 */
function makeMemoryHandler(int $globalLimit, ?\Closure $resolver = null): RateLimitHandler
{
    $handler = new RateLimitHandler(
        new RateLimitConfig(enableRateLimiting: true, rateLimit: $globalLimit, rateLimitWindow: 60)
    );
    if ($resolver !== null) {
        $handler->setGeoResolver($resolver);
    }

    return $handler;
}

function fireRoute(GuardEngine $engine, string $ip, string $path, RouteConfig $routeConfig): ?GuardResponse
{
    $request = new SimpleGuardRequest(urlPath: $path, clientHost: $ip);
    $request->state()->routeConfig = $routeConfig;

    return $engine->execute($request);
}

function makeIntegrationHandler(RateLimitConfig $config, RedisHandler $redis, ?\Closure $geo = null): RateLimitHandler
{
    $GLOBALS['GEO_CLOCK'] = microtime(true);
    $handler = new RateLimitHandler(
        $config,
        static fn (): float => ($GLOBALS['GEO_CLOCK'] += 0.001),
        static function (string $msg): void {
        },
        null,
        $geo
    );
    $handler->initializeRedis($redis);
    $handler->initializeIpBan(new IpBanManager());

    return $handler;
}

$t->section('RouteConfig: geo_rate_limits surface');
$t->same([], (new RouteConfig())->geoRateLimits, 'defaults to an empty map (inert surface is none)');
$limits = ['DE' => ['limit' => 5, 'window' => 30], '*' => ['limit' => 10, 'window' => 60]];
$t->same($limits, (new RouteConfig(geoRateLimits: $limits))->geoRateLimits, 'country + * entries kept verbatim');
$t->same([], (new RouteConfig(geoRateLimits: ['DE' => 'nope']))->geoRateLimits, 'non-array entry dropped');
$t->same([], (new RouteConfig(geoRateLimits: ['FR' => ['limit' => 1]]))->geoRateLimits, 'entry missing window dropped');
$t->same([], (new RouteConfig(geoRateLimits: ['*' => ['window' => 1]]))->geoRateLimits, 'entry missing limit dropped');
$t->same([], (new RouteConfig(geoRateLimits: ['IT' => ['limit' => '2', 'window' => 1]]))->geoRateLimits, 'non-int limit dropped');
$t->same([], (new RouteConfig(geoRateLimits: ['ES' => ['limit' => 1, 'window' => 1.5]]))->geoRateLimits, 'non-int window dropped');
$t->same([], (new RouteConfig(geoRateLimits: ['PT' => ['limit' => 0, 'window' => 1]]))->geoRateLimits, 'limit < 1 dropped');
$t->same([], (new RouteConfig(geoRateLimits: ['GR' => ['limit' => 1, 'window' => 0]]))->geoRateLimits, 'window < 1 dropped');
$t->same([], (new RouteConfig(geoRateLimits: [7 => ['limit' => 1, 'window' => 1]]))->geoRateLimits, 'non-string key dropped');
$mixed = (new RouteConfig(geoRateLimits: ['DE' => ['limit' => 5, 'window' => 30], 'bad' => 'x']))->geoRateLimits;
$t->same(['DE' => ['limit' => 5, 'window' => 30]], $mixed, 'malformed entries dropped, valid siblings kept (decorator-time leniency)');

$t->section('RouteConfig: with() immutability and revision');
$base = new RouteConfig(rateLimit: 10);
$t->same([], $base->geoRateLimits, 'base untouched before with()');
$copy = $base->with(['geoRateLimits' => ['DE' => ['limit' => 2, 'window' => 60]]]);
$t->same(['DE' => ['limit' => 2, 'window' => 60]], $copy->geoRateLimits, 'with() sets geo_rate_limits on the copy');
$t->same([], $base->geoRateLimits, 'with() leaves the original untouched');
$t->same($base->revision() + 1, $copy->revision(), 'with() bumps the revision like sibling fields');
$carried = $copy->with(['rateLimit' => 3]);
$t->same(['DE' => ['limit' => 2, 'window' => 60]], $carried->geoRateLimits, 'with() carries geo_rate_limits forward when changing another field');
$t->throws(static fn (): RouteConfig => $base->with(['geo_rate_limits' => []]), InvalidArgumentException::class, "unknown route config field 'geo_rate_limits'", 'snake_case name rejected like the other fields');

$t->section('handler: country-specific tier enforced at its crossing');
$resolver = static fn (string $ip): string => 'DE';
$h = makeMemoryHandler(100, $resolver);
$reqDe = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['DE' => ['limit' => 2, 'window' => 60], '*' => ['limit' => 10, 'window' => 60]]);
$t->same(null, $h->checkRateLimit($reqDe, '9.0.0.1'), 'DE hit 1 allowed');
$t->same(null, $h->checkRateLimit($reqDe, '9.0.0.1'), 'DE hit 2 allowed');
$blocked = $h->checkRateLimit($reqDe, '9.0.0.1');
$t->same(true, $blocked instanceof RateLimitOutcome, 'DE hit 3 blocked');
$t->same('geo', $blocked?->tier, 'blocked at the geo tier (not global)');
$t->same(3, $blocked?->count, 'blocked count includes the current hit');
$t->same('60', $blocked?->retryAfter(), 'retry-after uses the geo tier window');
$t->same(429, $blocked?->errorResponse()['status'], 'geo block keeps the 429 contract');

$t->section('handler: unknown country falls back to the * entry');
$h = makeMemoryHandler(100, static fn (string $ip): string => 'ZZ');
$reqStar = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['US' => ['limit' => 1, 'window' => 60], '*' => ['limit' => 3, 'window' => 60]]);
$t->same(null, $h->checkRateLimit($reqStar, '9.0.0.2'), 'unknown country hit 1 allowed');
$t->same(null, $h->checkRateLimit($reqStar, '9.0.0.2'), 'unknown country hit 2 allowed');
$t->same(null, $h->checkRateLimit($reqStar, '9.0.0.2'), 'unknown country hit 3 allowed (* limit, US limit would have blocked hit 2)');
$blocked = $h->checkRateLimit($reqStar, '9.0.0.2');
$t->same(true, $blocked !== null && $blocked->tier === 'geo', 'unknown country crossing enforced at the geo tier via * fallback');

$t->section('handler: empty resolver answer takes the * fallback too');
$h = makeMemoryHandler(100, static fn (string $ip): string => '');
$reqEmpty = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['*' => ['limit' => 1, 'window' => 60]]);
$t->same(null, $h->checkRateLimit($reqEmpty, '9.0.0.3'), 'empty country hit 1 allowed');
$blocked = $h->checkRateLimit($reqEmpty, '9.0.0.3');
$t->same(true, $blocked !== null && $blocked->tier === 'geo', 'empty country still enforces the * geo tier (parity: Python country None, Go empty match miss)');

$t->section('handler: no matching entry means no geo tier');
$h = makeMemoryHandler(5, static fn (string $ip): string => 'DE');
$reqNoMatch = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['US' => ['limit' => 1, 'window' => 60]]);
foreach ([1, 2, 3, 4, 5] as $hit) {
    $t->same(null, $h->checkRateLimit($reqNoMatch, '9.0.0.4'), "no match hit {$hit} allowed (US limit 1 never applied)");
}
$blocked = $h->checkRateLimit($reqNoMatch, '9.0.0.4');
$t->same(true, $blocked !== null && $blocked->tier === 'global', 'crossing lands on the global tier when neither country nor * matches');
$h = makeMemoryHandler(100, static fn (string $ip): string => 'US');
$t->same(null, $h->checkRateLimit($reqNoMatch, '9.0.0.5'), 'matching resolver hit 1 allowed');
$blocked = $h->checkRateLimit($reqNoMatch, '9.0.0.5');
$t->same(true, $blocked !== null && $blocked->tier === 'geo', 'same map with a matching resolver blocks at the geo tier on hit 2');

$t->section('handler: country-specific entry beats the * fallback');
$h = makeMemoryHandler(100, static fn (string $ip): string => 'DE');
$reqBoth = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['DE' => ['limit' => 2, 'window' => 30], '*' => ['limit' => 1, 'window' => 60]]);
$t->same(null, $h->checkRateLimit($reqBoth, '9.0.0.6'), 'DE hit 1 allowed (* limit 1 would have blocked)');
$t->same(null, $h->checkRateLimit($reqBoth, '9.0.0.6'), 'DE hit 2 allowed (country-specific limit wins)');
$blocked = $h->checkRateLimit($reqBoth, '9.0.0.6');
$t->same(true, $blocked !== null && $blocked->tier === 'geo' && $blocked->retryAfter() === '30', 'DE crossing reports the country-specific window');

$t->section('handler: the resolver receives the client ip');
$seen = [];
$h = makeMemoryHandler(100, static function (string $ip) use (&$seen): string {
    $seen[] = $ip;

    return 'DE';
});
$h->checkRateLimit(new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['DE' => ['limit' => 5, 'window' => 60]]), '9.9.9.9');
$t->same(['9.9.9.9'], $seen, 'resolver called once with the client ip');
$h->checkRateLimit(new RateLimitRequest(urlPath: '/eu'), '9.9.9.9');
$t->same(['9.9.9.9'], $seen, 'no geo map: resolver never called');

$t->section('handler: no resolver configured means the geo tier is inert');
$h = makeMemoryHandler(3, null);
$reqInert = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['*' => ['limit' => 1, 'window' => 60]]);
$t->same(null, $h->checkRateLimit($reqInert, '9.0.0.7'), 'no resolver hit 1 allowed despite * geo limit 1');
$t->same(null, $h->checkRateLimit($reqInert, '9.0.0.7'), 'no resolver hit 2 allowed (geo tier inert)');
$t->same(null, $h->checkRateLimit($reqInert, '9.0.0.7'), 'no resolver hit 3 allowed (default limit governs)');
$blocked = $h->checkRateLimit($reqInert, '9.0.0.7');
$t->same(true, $blocked !== null && $blocked->tier === 'global', 'no resolver: crossing happens at the global tier (default limit 3)');
$h = makeMemoryHandler(3, static fn (string $ip): string => 'DE');
$t->same(null, $h->checkRateLimit($reqInert, '9.0.0.8'), 'wired hit 1 allowed (fresh bucket)');
$blocked = $h->checkRateLimit($reqInert, '9.0.0.8');
$t->same(true, $blocked !== null && $blocked->tier === 'geo', 'same map wired with a resolver: geo tier blocks on hit 2');

$t->section('handler: setGeoResolver wires (and unwires) the tier after construction');
$h = makeMemoryHandler(100, null);
$reqWire = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['DE' => ['limit' => 2, 'window' => 60]]);
$t->same(null, $h->checkRateLimit($reqWire, '9.0.0.9'), 'unwired hit 1 allowed');
$t->same(null, $h->checkRateLimit($reqWire, '9.0.0.9'), 'unwired hit 2 allowed');
$t->same(null, $h->checkRateLimit($reqWire, '9.0.0.9'), 'unwired hit 3 allowed');
$h->setGeoResolver(static fn (string $ip): string => 'DE');
$t->same(null, $h->checkRateLimit($reqWire, '9.0.0.9'), 'wired hit 4 allowed (geo bucket starts empty)');
$t->same(null, $h->checkRateLimit($reqWire, '9.0.0.9'), 'wired hit 5 allowed (geo limit 2)');
$blocked = $h->checkRateLimit($reqWire, '9.0.0.9');
$t->same(true, $blocked !== null && $blocked->tier === 'geo', 'wired resolver activates the geo tier on the same handler');
$h->setGeoResolver(null);
$t->same(null, $h->checkRateLimit($reqWire, '9.0.0.9'), 'null resolver unsets: next hit allowed again');

$t->section('pipeline: geo tier blocks end to end at its crossing');
$blocks = [];
$engine = makeEngine(
    ['rateLimit' => 100, 'rateLimitWindow' => 60, 'onBlock' => static function (object $request, array $payload) use (&$blocks): void {
        $blocks[] = $payload;
    }],
    static fn (string $ip): string => 'DE'
);
$route = new RouteConfig(geoRateLimits: ['DE' => ['limit' => 2, 'window' => 60], '*' => ['limit' => 10, 'window' => 60]]);
$t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), 'route geo hit 1 allowed');
$t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), 'route geo hit 2 allowed');
$response = fireRoute($engine, GEO_IP, '/eu', $route);
$t->same(429, $response?->statusCode(), 'route geo hit 3 gets 429 (default limit 100 untouched)');
$t->same('Too many requests', $response?->body(), '429 body is the standard rate limit message');
$t->same(1, count($blocks), 'one on_block event fired');
$t->same('rate_limit', $blocks[0]['check_name'] ?? null, 'block attributed to the rate_limit check');
$t->same(true, ($blocks[0]['reason'] ?? '') === 'Rate limit exceeded for IP: ' . GEO_IP . ' (3 requests in 60s window)', 'block reason is the reference log format for the tripped tier');
$response = fireRoute($engine, GEO_IP_2, '/eu', $route);
$t->same(null, $response, 'a different DE client has its own bucket');

$t->section('pipeline: no resolver configured means the default limit governs');
$blocks = [];
$engine = makeEngine([
    'rateLimit' => 3,
    'rateLimitWindow' => 60,
    'onBlock' => static function (object $request, array $payload) use (&$blocks): void {
        $blocks[] = $payload;
    },
]);
$route = new RouteConfig(geoRateLimits: ['DE' => ['limit' => 1, 'window' => 60]]);
foreach ([1, 2, 3] as $hit) {
    $t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), "unwired route hit {$hit} allowed (geo limit 1 inert)");
}
$response = fireRoute($engine, GEO_IP, '/eu', $route);
$t->same(429, $response?->statusCode(), 'unwired crossing still throttles at the default limit');
$t->same(true, ($blocks[0]['reason'] ?? '') === 'Rate limit exceeded for IP: ' . GEO_IP . ' (4 requests in 60s window)', 'unwired block reason is the reference log format for the global tier');

$t->section('pipeline: the same route with a resolver wired blocks at the geo tier');
$blocks = [];
$engine = makeEngine([
    'rateLimit' => 3,
    'rateLimitWindow' => 60,
    'onBlock' => static function (object $request, array $payload) use (&$blocks): void {
        $blocks[] = $payload;
    },
], static fn (string $ip): string => 'DE');
$t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), 'wired route hit 1 allowed');
$response = fireRoute($engine, GEO_IP, '/eu', $route);
$t->same(429, $response?->statusCode(), 'wired route hit 2 blocked at the geo limit');
$t->same(true, ($blocks[0]['reason'] ?? '') === 'Rate limit exceeded for IP: ' . GEO_IP . ' (2 requests in 60s window)', 'wired block reason is the reference log format for the geo tier');

$t->section('pipeline: exempt skip still precedes the geo tier');
$engine = makeEngine(
    ['rateLimit' => 3, 'rateLimitWindow' => 60, 'exemptIps' => [GEO_IP]],
    static fn (string $ip): string => 'DE'
);
$route = new RouteConfig(geoRateLimits: ['DE' => ['limit' => 1, 'window' => 60]]);
foreach ([1, 2, 3, 4, 5] as $hit) {
    $t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), "exempt DE client hit {$hit} past the geo limit still passes");
}
$t->same(null, fireRoute($engine, GEO_OTHER_IP, '/eu', $route), 'non-exempt client hit 1 allowed (own bucket)');
$t->same(429, fireRoute($engine, GEO_OTHER_IP, '/eu', $route)?->statusCode(), 'non-exempt client still throttled at the geo tier');

$t->section('pipeline: whitelist skip still precedes the geo tier');
$engine = makeEngine(
    ['rateLimit' => 3, 'rateLimitWindow' => 60, 'whitelist' => [GEO_IP]],
    static fn (string $ip): string => 'DE'
);
$route = new RouteConfig(geoRateLimits: ['DE' => ['limit' => 1, 'window' => 60], '*' => ['limit' => 1, 'window' => 60]]);
foreach ([1, 2, 3, 4] as $hit) {
    $t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), "whitelisted DE client hit {$hit} past the geo limit still passes");
}
$t->same(403, fireRoute($engine, GEO_OTHER_IP, '/eu', $route)?->statusCode(), 'restrictive whitelist deny path unchanged (403 before any tier)');

$t->section('pipeline: a rate_limit route bypass skips the geo tier');
$engine = makeEngine(['rateLimit' => 3, 'rateLimitWindow' => 60], static fn (string $ip): string => 'DE');
$route = new RouteConfig(geoRateLimits: ['*' => ['limit' => 1, 'window' => 60]], bypassedChecks: ['rate_limit']);
foreach ([1, 2, 3, 4] as $hit) {
    $t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), "bypassed route hit {$hit} allowed (geo tier skipped with the whole check)");
}

$t->section('pipeline: passive mode logs the geo crossing without blocking');
$blocks = [];
$engine = makeEngine([
    'rateLimit' => 100,
    'rateLimitWindow' => 60,
    'passiveMode' => true,
    'onBlock' => static function (object $request, array $payload) use (&$blocks): void {
        $blocks[] = $payload;
    },
], static fn (string $ip): string => 'DE');
$route = new RouteConfig(geoRateLimits: ['DE' => ['limit' => 1, 'window' => 60]]);
$t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), 'passive geo hit 1 allowed');
$t->same(null, fireRoute($engine, GEO_IP, '/eu', $route), 'passive geo crossing returns no response');
$t->same(1, count($blocks), 'passive mode fires the block hook inline once (the reference passive dispatch)');
$t->same(true, ($blocks[0]['passive_mode'] ?? null) === true, 'passive hook payload flags passive_mode');
$t->same(true, array_key_exists('status_code', $blocks[0]) && $blocks[0]['status_code'] === null, 'passive hook status_code is null');

$t->section('appliesTo: route geo config schedules the check');
$config = new SecurityConfig(enableRateLimiting: false);
$check = new RateLimitCheck($config, new GuardResponseFactory(), null, new RouteResolver());
$t->same(false, $check->appliesTo($config, null), 'no route registry, disabled globally: stays dropped (pre-existing PHP gating; Python vacuous-true divergence is deliberate here)');
$t->same(false, $check->appliesTo($config, [new RouteConfig()]), 'plain route, disabled globally: not scheduled');
$t->same(true, $check->appliesTo($config, [new RouteConfig(geoRateLimits: ['*' => ['limit' => 1, 'window' => 60]])]), 'route geo map schedules the check (handler gate still applies)');
$t->same(true, $check->appliesTo($config, [new RouteConfig(rateLimit: 5)]), 'route rate limit schedules the check');
$t->same(false, $check->appliesTo($config, [new RouteConfig(requireHttps: true)]), 'routes carrying unrelated decorators do not schedule the check');
$config = new SecurityConfig(enableRateLimiting: true);
$t->same(true, $check->appliesTo($config, null), 'enabled globally schedules regardless of routes');

if ($integration) {
    $host = getenv('REDIS_HOST') ?: '127.0.0.1';
    $redis = RedisHandler::fromEnv();
    $conn = $redis->connection();
    try {
        $conn->command('FLUSHDB');
    } catch (Throwable $e) {
        echo "SKIP: cannot reach redis at {$host}: {$e->getMessage()}\n";
        exit(2);
    }

    $t->section('integration: DE tier crosses over the wire');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(
        new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60, enableRedis: true),
        $redis,
        static fn (string $ip): string => 'DE'
    );
    $req = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['DE' => ['limit' => 2, 'window' => 60], '*' => ['limit' => 10, 'window' => 60]]);
    $t->same(null, $h->checkRateLimit($req, '40.1.1.1'), 'wire DE hit 1 allowed');
    $t->same(null, $h->checkRateLimit($req, '40.1.1.1'), 'wire DE hit 2 allowed');
    $blocked = $h->checkRateLimit($req, '40.1.1.1');
    $t->same(true, $blocked !== null && $blocked->tier === 'geo' && $blocked->inMemory === false, 'wire DE hit 3 blocked by redis at the geo tier');
    $t->same(3, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:40.1.1.1:' . hash('sha256', '/eu')), 'geo tier writes the hashed bucket (3 hits)');
    $t->same(2, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:40.1.1.1'), 'global tier counted the two allowed hits (blocked hit 3 short-circuited before it)');

    $t->section('integration: unknown country falls back to * over the wire');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(
        new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60, enableRedis: true),
        $redis,
        static fn (string $ip): string => 'ZZ'
    );
    $req = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['US' => ['limit' => 1, 'window' => 60], '*' => ['limit' => 2, 'window' => 60]]);
    $t->same(null, $h->checkRateLimit($req, '40.1.1.2'), 'wire unknown country hit 1 allowed');
    $t->same(null, $h->checkRateLimit($req, '40.1.1.2'), 'wire unknown country hit 2 allowed (* limit)');
    $blocked = $h->checkRateLimit($req, '40.1.1.2');
    $t->same(true, $blocked !== null && $blocked->tier === 'geo', 'wire unknown country hit 3 blocked via * fallback');
    $t->same(3, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:40.1.1.2:' . hash('sha256', '/eu')), '* tier shares the hashed bucket');

    $t->section('integration: no resolver, no geo writes');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60, enableRedis: true), $redis);
    $req = new RateLimitRequest(urlPath: '/eu', geoRateLimits: ['*' => ['limit' => 1, 'window' => 60]]);
    $t->same(null, $h->checkRateLimit($req, '40.1.1.3'), 'wire unwired hit 1 allowed');
    $t->same(0, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:40.1.1.3:' . hash('sha256', '/eu')), 'hashed bucket never created (geo tier inert)');
    $t->same(1, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:40.1.1.3'), 'only the global tier wrote');

    echo "\n";
}

exit($t->done($integration ? 'GEO RATE LIMITS INTEGRATION' : 'GEO RATE LIMITS'));

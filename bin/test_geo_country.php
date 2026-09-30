<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\GeoIp\GeoIpManager;
use RenzoFranceschini\GuardCore\GeoIp\MmdbReader;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/MmdbFixture.php';

// Engine-level acceptance runner for the geo country rules in the
// ip_security check. Semantics mirror the reference _resolve_country_verdict,
// _check_blocked_countries_detail and check_country_access
// (guard_core/_utils/access_control.py plus core/checks/helpers.py):
// the country stage runs after the global IP lists and before the exempt
// flag, a global whitelist match skips the country stage, loopback IPs are
// exempt from the global stage, an unresolved country fails closed in
// allowlist mode and open in blocklist mode, and the exempt flag only sets
// once every deny check passed. Ported from the guard-core-go #23 test
// matrix, including its in-test MMDB fixture builder.

final class GeoT
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

/**
 * Fake resolver answering from a fixed ip => country table; misses mirror
 * the reference get_country returning None.
 */
final class FakeCountryResolver implements CountryResolver
{
    /** @param array<string, string> $table */
    public function __construct(private readonly array $table = [])
    {
    }

    public function getCountry(string $ip): ?string
    {
        return $this->table[$ip] ?? null;
    }
}

final class CountingCountryResolver implements CountryResolver
{
    public int $calls = 0;

    public function __construct(private readonly CountryResolver $inner)
    {
    }

    public function getCountry(string $ip): ?string
    {
        $this->calls++;

        return $this->inner->getCountry($ip);
    }
}

$t = new GeoT();

const GEO_US_IP = '192.0.2.7';
const GEO_BR_IP = '198.51.100.5';


/** @param array<string, mixed> $configArgs */
function geoEngine(array $configArgs): GuardEngine
{
    $configArgs['enableRedis'] = false;

    return new GuardEngine(new SecurityConfig(...$configArgs));
}

function geoFire(GuardEngine $engine, string $ip, string $path = '/', bool $exclusionScoped = false): ?GuardResponse
{
    $request = new SimpleGuardRequest(urlPath: $path, clientHost: $ip);
    if ($exclusionScoped) {
        $request->state()->guardExclusionScoped = true;
    }
    $engine->execute($request);

    return $engine->pipeline()->execute($request) === null && $exclusionScoped === false && $path === '/'
        ? null
        : $engine->pipeline()->execute($request);
}

function geoStashFor(GuardEngine $engine, string $ip): ?array
{
    $request = new SimpleGuardRequest(urlPath: '/', clientHost: $ip);
    $engine->execute($request);

    return $request->state()->guardBlockStash;
}

$t = new GeoT();

$resolver = new FakeCountryResolver([GEO_US_IP => 'US', GEO_BR_IP => 'BR']);

$t->section('config: country list normalization (coerce_country_set)');
$config = new SecurityConfig(blockedCountries: ['us', 'Br', 'US'], geoIpHandler: $resolver);
$t->same(['US', 'BR'], $config->blockedCountries, 'blocked_countries uppercased and deduplicated');
$t->same([], (new SecurityConfig())->whitelistCountries, 'whitelist_countries defaults empty');
$t->same([], (new SecurityConfig())->blockedCountries, 'blocked_countries defaults empty');
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(blockedCountries: ['CN', 42]),
    InvalidArgumentException::class,
    null,
    'non-string country entry fails closed'
);

$t->section('config: resolver-required fail closed');
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(blockedCountries: ['CN']),
    InvalidArgumentException::class,
    'geo_ip_handler is required',
    'blocked_countries without a resolver fails construction'
);
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(whitelistCountries: ['US']),
    InvalidArgumentException::class,
    'geo_ip_handler is required',
    'whitelist_countries without a resolver fails construction'
);

$t->section('config: geo_ip_db_path builds the built-in resolver');
$mmdbPath = buildTestMmdb(['192.0.2.0/24' => 'US']);
$config = new SecurityConfig(blockedCountries: ['CN'], geoIpDbPath: $mmdbPath);
$t->ok($config->geoIpHandler instanceof GeoIpManager, 'geo_ip_db_path resolves to a built-in GeoIpManager');
$t->same('US', $config->geoIpHandler->getCountry(GEO_US_IP), 'built-in resolver resolves the fixture');
$config = new SecurityConfig(blockedCountries: ['CN'], geoIpHandler: $resolver);
$t->same('US', $config->geoIpHandler->getCountry(GEO_US_IP), 'injected resolver satisfies the geo requirement and survives construction');

$t->section('engine: blocked country denies with the reference reason');
$engine = geoEngine(['blockedCountries' => ['US'], 'geoIpHandler' => $resolver]);
$request = new SimpleGuardRequest(urlPath: '/', clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'blocked country denied 403');
$t->same('Forbidden', $response?->body(), 'blocked country body is Forbidden');
$t->same(['reason' => 'IP not allowed: ' . GEO_US_IP . ' - IP from blocked country: US', 'trigger_info' => ''], $request->state()->guardBlockStash, 'block stash carries the reference reason and trigger');
$response = $engine->execute(new SimpleGuardRequest(urlPath: '/', clientHost: GEO_BR_IP));
$t->same(null, $response, 'other country passes untouched');

$t->section('engine: allowlist is restrictive');
$deResolver = new FakeCountryResolver([GEO_US_IP => 'US', GEO_BR_IP => 'DE']);
$engine = geoEngine(['whitelistCountries' => ['DE'], 'geoIpHandler' => $deResolver]);
$response = $engine->execute(new SimpleGuardRequest(clientHost: GEO_BR_IP));
$t->same(null, $response, 'allowed country passes');
$request = new SimpleGuardRequest(clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'unlisted country denied 403');
$t->same('IP not allowed: ' . GEO_US_IP . ' - IP from blocked country: US', $request->state()->guardBlockStash['reason'] ?? null, 'resolved non-allowed country stashes the country reason');
unset($deResolver);

$t->section('engine: unresolved country verdict depends on mode');
$engine = geoEngine(['whitelistCountries' => ['US'], 'geoIpHandler' => new FakeCountryResolver()]);
$request = new SimpleGuardRequest(clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'allowlist mode fails closed on unresolved country');
$t->same('IP not allowed: ' . GEO_US_IP . ' - IP ' . GEO_US_IP . ' not in global allowlist/blocklist', $request->state()->guardBlockStash['reason'] ?? null, 'unresolved allowlist denial stashes the generic reason');
$engine = geoEngine(['blockedCountries' => ['US'], 'geoIpHandler' => new FakeCountryResolver()]);
$response = $engine->execute(new SimpleGuardRequest(clientHost: GEO_US_IP));
$t->same(null, $response, 'blocklist mode fails open on unresolved country');

$t->section('engine: loopback exempt from the global country stage');
$engine = geoEngine(['whitelistCountries' => ['US'], 'geoIpHandler' => new FakeCountryResolver()]);
$response = $engine->execute(new SimpleGuardRequest(clientHost: '127.0.0.1'));
$t->same(null, $response, 'loopback passes the country allowlist');

$t->section('engine: global whitelist match skips the country stage');
$engine = geoEngine(['whitelist' => [GEO_US_IP], 'blockedCountries' => ['US'], 'geoIpHandler' => $resolver]);
$request = new SimpleGuardRequest(clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->same(null, $response, 'whitelisted IP bypasses the country block');
$t->same(true, $request->state()->isWhitelisted, 'whitelist match sets the identity flag');

$t->section('engine: exempt_ips never opens the country gate');
$engine = geoEngine(['exemptIps' => [GEO_US_IP, GEO_BR_IP], 'blockedCountries' => ['US'], 'geoIpHandler' => $resolver]);
$request = new SimpleGuardRequest(clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'exempt IP from a blocked country stays denied');
$t->same(false, $request->state()->isExempt, 'a country-denied request carries no exempt flag');
$request = new SimpleGuardRequest(clientHost: GEO_BR_IP);
$response = $engine->execute($request);
$t->same(null, $response, 'exempt IP from an allowed country passes');
$t->same(true, $request->state()->isExempt, 'exempt flag survives the country stage');

$t->section('engine: the ip bypass skips the country rules');
$engine = geoEngine(['blockedCountries' => ['US'], 'geoIpHandler' => $resolver]);
$request = new SimpleGuardRequest(clientHost: GEO_US_IP);
$request->state()->routeConfig = new RouteConfig(bypassedChecks: ['ip']);
$response = $engine->execute($request);
$t->same(null, $response, 'ip bypass skips the country rules');

$t->section('engine: passive mode fires the hook inline');
$hookPayloads = [];
$engine = geoEngine([
    'blockedCountries' => ['US'],
    'geoIpHandler' => $resolver,
    'passiveMode' => true,
    'onBlock' => function (object $request, array $payload) use (&$hookPayloads): void {
        $hookPayloads[] = $payload;
    },
]);
$request = new SimpleGuardRequest(clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->same(null, $response, 'passive mode does not block');
$t->same(null, $request->state()->guardBlockStash, 'passive mode writes no block stash');
$t->same(1, count($hookPayloads), 'passive mode fires the on_block hook once');
$t->same('IP not allowed: ' . GEO_US_IP . ' - IP from blocked country: US', $hookPayloads[0]['reason'] ?? null, 'passive hook carries the composed reference reason');
$t->same('', $hookPayloads[0]['trigger_info'] ?? null, 'passive hook trigger_info is empty');
$t->same(true, array_key_exists('status_code', $hookPayloads[0]) && $hookPayloads[0]['status_code'] === null, 'passive hook status_code is null');

$t->section('engine: global IP lists keep precedence and the country stage follows');
$engine = geoEngine(['blacklist' => [GEO_US_IP], 'blockedCountries' => ['US'], 'geoIpHandler' => $resolver]);
$request = new SimpleGuardRequest(clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'blacklisted IP still denied');
$t->same(['reason' => 'IP not allowed: ' . GEO_US_IP . ' - IP ' . GEO_US_IP . ' not in global allowlist/blocklist', 'trigger_info' => ''], $request->state()->guardBlockStash, 'blacklist reason matches the reference log format');

$t->section('engine: without country rules the resolver is never consulted');
$counter = new CountingCountryResolver($resolver);
$engine = geoEngine(['geoIpHandler' => $counter]);
$response = $engine->execute(new SimpleGuardRequest(clientHost: GEO_BR_IP));
$t->same(null, $response, 'unlisted IP passes without country rules');
$t->same(0, $counter->calls, 'country rules off never consult the resolver');

$t->section('engine: exclusion-scoped requests keep the global country block');
$engine = geoEngine(['blockedCountries' => ['US'], 'excludePaths' => ['/docs'], 'geoIpHandler' => $resolver]);
$request = new SimpleGuardRequest(urlPath: '/docs/openapi.json', clientHost: GEO_US_IP);
$response = $engine->execute($request);
$t->ok($request->state()->guardExclusionScoped, 'excluded path marked exclusion-scoped');
$t->ok($response !== null && $response->statusCode() === 403, 'exclusion-scoped requests keep the global country block');

$t->section('config: with() immutability');
$base = new SecurityConfig();
$copy = $base->with(['blocked_countries' => ['cn'], 'geo_ip_handler' => $resolver]);
$t->same(['CN'], $copy->blockedCountries, 'with() sets blocked_countries normalized on the copy');
$t->same(1, $copy->revision(), 'with() bumps revision');
$t->throws(
    static fn (): SecurityConfig => $base->with(['whitelist_countries' => ['US']]),
    InvalidArgumentException::class,
    'geo_ip_handler is required',
    'with() re-validates the resolver requirement'
);

$t->section('mmdb: fixture reader resolves prefixes and host routes');
$path = buildTestMmdb(['192.0.2.0/24' => 'US', '198.51.100.0/32' => 'BR']);
$manager = new GeoIpManager($path);
$t->same('US', $manager->getCountry('192.0.2.7'), 'prefix record resolves');
$t->same('US', $manager->getCountry('192.0.2.200'), 'same prefix sibling resolves');
$t->same('BR', $manager->getCountry('198.51.100.0'), 'host route resolves');
$t->same(null, $manager->getCountry('198.51.100.1'), 'outside every fixture prefix misses');
$t->same(null, $manager->getCountry('not-an-ip'), 'unparseable address misses');
$t->same(null, $manager->getCountry('::1'), 'ipv6 address misses in an ipv4 database');
$manager->close();

$t->section('mmdb: missing database fails soft');
$manager = new GeoIpManager(sys_get_temp_dir() . '/guard-core-php-missing-' . bin2hex(random_bytes(4)) . '.mmdb');
$t->same(null, $manager->getCountry(GEO_US_IP), 'lookups against a missing database miss');
$manager->close();

$t->section('mmdb: corrupt database fails soft and is removed');
$path = (string) tempnam(sys_get_temp_dir(), 'mmdb');
file_put_contents($path, 'not a database');
$manager = new GeoIpManager($path);
$t->same(null, $manager->getCountry(GEO_US_IP), 'lookups against a corrupted database miss');
$t->same(false, file_exists($path), 'corrupted database removed like the reference _open_database_or_none');
$manager->close();

$t->section('mmdb: MmdbReader unit behavior');
$path = buildTestMmdb(['10.0.0.0/8' => 'DE']);
$reader = new MmdbReader($path);
$t->same(['country' => 'DE'], $reader->lookup('10.1.2.3'), 'decoded record map carries the top-level country string');
$t->same(null, $reader->lookup('11.0.0.1'), 'uncovered prefix misses');

$t->section('engine: route-level ip_whitelist / ip_blacklist enforcement');

// Regression (spec 4.1.0 corpus pipeline_ip_control/route_ip_whitelist_denies_other_ip):
// a non-whitelisted client on a route with ip_whitelist must be denied 403
// through the public GuardEngine surface, with the reference hook payload.
$hookPayloads = [];
$engine = geoEngine([
    'onBlock' => function (object $request, array $payload) use (&$hookPayloads): void {
        $hookPayloads[] = $payload;
    },
]);
$routeRequest = static function (string $path) use (&$hookPayloads): SimpleGuardRequest {
    $hookPayloads = [];
    $request = new SimpleGuardRequest(urlPath: $path, clientHost: '203.0.113.9');

    return $request;
};

$route = new RouteConfig(ipWhitelist: ['192.0.2.7']);
$request = $routeRequest('/private');
$request->state()->routeConfig = $route;
$request->state()->clientIp = '203.0.113.9';
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'route ip_whitelist denies a non-whitelisted client 403');
$t->same('Forbidden', $response?->body(), 'route ip_whitelist denial body is Forbidden');
$t->same(1, count($hookPayloads), 'route ip_whitelist denial fires the on_block hook');
$t->same('ip_security', $hookPayloads[0]['check_name'] ?? null, 'hook check_name is ip_security');
$t->same('IP not allowed by route config: 203.0.113.9', $hookPayloads[0]['reason'] ?? null, 'hook carries the reference route denial reason');
$t->same('', $hookPayloads[0]['trigger_info'] ?? null, 'hook trigger_info is empty');
$t->same(403, $hookPayloads[0]['status_code'] ?? null, 'hook status_code is 403');

$request = $routeRequest('/private');
$request->state()->routeConfig = $route;
$request->state()->clientIp = '192.0.2.7';
$response = $engine->execute($request);
$t->same(null, $response, 'route ip_whitelist lets a whitelisted client pass');

$blacklistRoute = new RouteConfig(ipBlacklist: ['203.0.113.9']);
$request = $routeRequest('/private');
$request->state()->routeConfig = $blacklistRoute;
$request->state()->clientIp = '203.0.113.9';
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'route ip_blacklist denies its match 403');

// A route whitelist match never relaxes the global lists (the reference
// keeps the global blacklist enforced afterwards).
$engine = geoEngine(['blacklist' => ['192.0.2.7']]);
$request = $routeRequest('/private');
$request->state()->routeConfig = new RouteConfig(ipWhitelist: ['192.0.2.7']);
$request->state()->clientIp = '192.0.2.7';
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'a route whitelist match still hits the global blacklist');

// A route ipWhitelist clears the identity flags for the request (the
// reference _resolve_is_whitelisted/_resolve_is_exempt skip_ip_lists gate).
$engine = geoEngine(['exemptIps' => ['192.0.2.7']]);
$request = $routeRequest('/private');
$request->state()->routeConfig = new RouteConfig(ipWhitelist: ['192.0.2.7']);
$request->state()->clientIp = '192.0.2.7';
$response = $engine->execute($request);
$t->same(null, $response, 'route whitelisted IP passes the deny checks');
$t->same(false, $request->state()->isWhitelisted ?? null, 'route override clears is_whitelisted');
$t->same(false, $request->state()->isExempt ?? null, 'route override clears is_exempt');

exit($t->done('test_geo_country'));

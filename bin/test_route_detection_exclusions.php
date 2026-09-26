<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

// Engine-level acceptance runner for the per-route detection exclusion
// surface. Semantics mirror the reference route_config fields
// (guard_core/decorators/route_config.py) resolved with the _resolve_*
// helpers of guard_core/_utils/detection_config.py and the
// _get_effective_penetration_setting gate of
// guard_core/core/checks/helpers.py, structurally following the
// guard-core-go detection-exclusion resolution: a non-null route set
// replaces the global one, the header exclusion set always merges defaults
// + global + route, a non-null route detection_scan_body skips the body
// surface only, and the route's enable_suspicious_detection wins over the
// global flag for routed requests.

final class RdeT
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

    public function done(string $name): int
    {
        echo "\n{$name}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed;
    }
}

$t = new RdeT();

const SQLI_RAW = '1 OR 1=1';
const XSS_RAW = '<script>alert(1)</script>';
const XSS_JSON = '{"comment": "' . XSS_RAW . '"}';
const ROUTE_IP = '192.0.2.140';

/** @param array<string, mixed> $configArgs */
function rdeEngine(...$configArgs): GuardEngine
{
    $configArgs['enableRedis'] = false;

    return new GuardEngine(new SecurityConfig(...$configArgs));
}

function rdeRequest(string $urlPath = '/', ?RouteConfig $route = null, array $headers = [], string $body = '', array $queryParams = []): SimpleGuardRequest
{
    $request = new SimpleGuardRequest(urlPath: $urlPath, clientHost: ROUTE_IP, headers: $headers, body: $body, queryParams: $queryParams);
    // The engine resolves the client address for adapter requests; the
    // runner pins it directly like the check-level harnesses do.
    $request->state()->clientIp = ROUTE_IP;
    if ($route !== null) {
        $request->state()->routeConfig = $route;
    }

    return $request;
}

function rdeSqliQuery(): array
{
    return ['q' => SQLI_RAW];
}

/** True when the engine allowed the request (no blocked response). */
function rdeAllowed(GuardEngine $engine, SimpleGuardRequest $request): bool
{
    return $engine->execute($request) === null;
}

$t->section('route kill switch: enable_suspicious_detection false disables detection on that route');
$engine = rdeEngine();
$route = new RouteConfig(enableSuspiciousDetection: false);
$openRoute = new RouteConfig();
$t->same(true, rdeAllowed($engine, rdeRequest("/search", $route, queryParams: rdeSqliQuery())), 'payload on the disabled route passes');
$t->same(false, rdeAllowed($engine, rdeRequest("/search", $openRoute, queryParams: rdeSqliQuery())), 'the same payload on a plain route is still blocked');

$t->section('route opt-in: enable_suspicious_detection true enables detection with the global flag off');
// Engine-level scheduling note: the PHP pipeline is built without a route
// registry (adapters attach state->routeConfig per request), so the
// route-aware appliesTo gate is exercised at the factory level exactly
// like the geo rate limit surface (documented scheduling divergence).
$config = new SecurityConfig(enableRedis: false, enablePenetrationDetection: false);
$scheduled = (new CheckFactory(new GuardResponseFactory()))->buildChecks($config, [new RouteConfig(enableSuspiciousDetection: true)]);
$names = array_map(static fn ($c) => $c->checkName(), $scheduled);
$t->same(true, in_array('suspicious_activity', $names, true), 'a route enabling detection schedules the check with the global flag off');
$notScheduled = (new CheckFactory(new GuardResponseFactory()))->buildChecks($config, null);
$names = array_map(static fn ($c) => $c->checkName(), $notScheduled);
$t->same(false, in_array('suspicious_activity', $names, true), 'no routes and global off: the check stays dropped');
$engine = rdeEngine(enablePenetrationDetection: false);
$t->same(true, rdeAllowed($engine, rdeRequest("/search", null, queryParams: rdeSqliQuery())), 'payload without a route config passes while the global flag is off');
// With the check unscheduled (static pipeline build, no route registry) the
// per-request gate alone cannot fire: documented engine-level divergence,
// the per-request gate is pinned at the check level in test_m4/m3b harnesses.
$t->same(true, rdeAllowed($engine, rdeRequest("/search", new RouteConfig(), queryParams: rdeSqliQuery())), 'unscheduled check keeps the routed request unblocked (scheduling divergence)');

$t->section('check-level gate: route true enables detection when the check runs');
$offConfig = new SecurityConfig(enableRedis: false, enablePenetrationDetection: false);
$gateCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck(
    $offConfig,
    new GuardResponseFactory(),
    new RenzoFranceschini\GuardCore\Detection\SusPatterns($offConfig->detectionSemanticThreshold),
    null,
    new RouteResolver()
);
$gated = rdeRequest("/search", new RouteConfig(), queryParams: rdeSqliQuery());
$t->same(false, $gateCheck->check($gated) === null, 'the per-request gate blocks on a routed request even with the global flag off');
$ungated = rdeRequest("/search", null, queryParams: rdeSqliQuery());
$t->same(true, $gateCheck->check($ungated) === null, 'no route config keeps the global-off miss');

$t->section('excluded params: a non-null route set replaces the global one');
$engine = rdeEngine(excludedDetectionParams: ['global_safe']);
$routeKeepsScanning = new RouteConfig(excludedDetectionParams: ['route_only']);
$routeExcludes = new RouteConfig(excludedDetectionParams: ['q']);
$t->same(false, rdeAllowed($engine, rdeRequest("/search", $routeKeepsScanning, queryParams: rdeSqliQuery())), 'the route set replaces the global set: q is no longer excluded');
$t->same(false, rdeAllowed($engine, rdeRequest('/x', $routeKeepsScanning, queryParams: ['global_safe' => SQLI_RAW])), 'the global-only exclusion no longer applies on the route (payload detected)');
$t->same(true, rdeAllowed($engine, rdeRequest("/search", $routeExcludes, queryParams: rdeSqliQuery())), 'the route excluding q skips the payload');

$t->section('excluded body fields: a non-null route set replaces the global one');
$headers = ['Content-Type' => 'application/json'];
$engine = rdeEngine(excludedDetectionBodyFields: ['global_field']);
$routeOverride = new RouteConfig(excludedDetectionBodyFields: ['comment']);
$t->same(true, rdeAllowed($engine, rdeRequest('/api', $routeOverride, $headers, XSS_JSON)), 'the route excluding comment skips the JSON subtree');
$routeOther = new RouteConfig(excludedDetectionBodyFields: ['other']);
$t->same(false, rdeAllowed($engine, rdeRequest('/api', $routeOther, $headers, XSS_JSON)), 'a route excluding another field still scans comment');
$globalOnly = new RouteConfig();
$t->same(true, rdeAllowed($engine, rdeRequest('/api?x=1', $globalOnly, $headers, '{"global_field": "' . SQLI_RAW . '"}')), 'the global body-field exclusion still applies on a plain route');

$t->section('excluded headers: the route set merges, never replaces');
// Reference semantics (the wave that ported excluded_detection_headers):
// excluded headers are not skipped outright; they keep scanning with every
// category except ssrf for address-carrying names or address-chain values.
// A route-excluded header therefore suppresses an ssrf chain value only.
$engine = rdeEngine();
$routeMerge = new RouteConfig(excludedDetectionHeaders: ['X-Forwarded-Chain']);
$t->same(true, rdeAllowed($engine, rdeRequest("/api", $routeMerge, ['X-Forwarded-Chain' => '10.0.0.5, 172.16.0.1'])), 'the route-excluded header skips the ssrf address chain');
$t->same(false, rdeAllowed($engine, rdeRequest("/api", new RouteConfig(), ['X-Forwarded-Chain' => '10.0.0.5, 172.16.0.1'])), 'a plain route still flags the ssrf chain in the header');
$t->same(false, rdeAllowed($engine, rdeRequest("/api", $routeMerge, ['X-Forwarded-Chain' => SQLI_RAW])), 'a non-ssrf payload in the route-excluded header still detects');
$t->same(true, rdeAllowed($engine, rdeRequest("/api", $routeMerge, ['X-Forwarded-For' => '203.0.113.5'])), 'the hardcoded proxy identity defaults still apply on the route');
$t->same(false, rdeAllowed($engine, rdeRequest("/api", $routeMerge, ['Referer' => SQLI_RAW])), 'unlisted headers still scan on the route');

$t->section('enabled categories: a non-null route set replaces the global set');
$engine = rdeEngine();
$xssOnly = new RouteConfig(enabledDetectionCategories: ['xss']);
$t->same(false, rdeAllowed($engine, rdeRequest("/api", $xssOnly, queryParams: ['q' => XSS_RAW])), 'xss still detects on the narrowed route');
$t->same(true, rdeAllowed($engine, rdeRequest("/search", $xssOnly, queryParams: rdeSqliQuery())), 'sqli does not detect on the xss-only route');
$none = new RouteConfig(enabledDetectionCategories: []);
$t->same(true, rdeAllowed($engine, rdeRequest("/search", $none, queryParams: rdeSqliQuery())), 'an empty route category set disables every category');
$all = new RouteConfig(enabledDetectionCategories: ['sqli', 'xss']);
$t->same(false, rdeAllowed($engine, rdeRequest("/search", $all, queryParams: rdeSqliQuery())), 'the route set matching the payload category detects');

$t->section('detection scan body: a false route value skips the body surface only');
$engine = rdeEngine();
$noBodyRoute = new RouteConfig(detectionScanBody: false);
$t->same(true, rdeAllowed($engine, rdeRequest('/api', $noBodyRoute, $headers, XSS_JSON)), 'the body payload passes with route scan_body off');
$t->same(false, rdeAllowed($engine, rdeRequest("/search", $noBodyRoute, queryParams: rdeSqliQuery())), 'the query surface still scans with route scan_body off');
$t->same(false, rdeAllowed($engine, rdeRequest('/api', new RouteConfig(), $headers, XSS_JSON)), 'a plain route still scans the body');
$engine = rdeEngine(detectionScanBody: false);
$t->same(true, rdeAllowed($engine, rdeRequest('/api', new RouteConfig(), $headers, XSS_JSON)), 'the global detection_scan_body off skips the body surface');
$t->same(false, rdeAllowed($engine, rdeRequest("/search", new RouteConfig(), queryParams: rdeSqliQuery())), 'the global detection_scan_body off keeps the query surface');
$overrideRoute = new RouteConfig(detectionScanBody: true);
$t->same(false, rdeAllowed($engine, rdeRequest('/api', $overrideRoute, $headers, XSS_JSON)), 'a route true overrides the global false');

$t->section('interplay: exclusion scoping and bypasses keep precedence');
$engine = rdeEngine();
$excluded = new SimpleGuardRequest(urlPath: '/docs', clientHost: ROUTE_IP);
$excluded->state()->guardExclusionScoped = true;
$excluded->state()->routeConfig = new RouteConfig();
$t->same(true, rdeAllowed($engine, $excluded), 'exclusion-scoped requests still skip the check entirely');
$bypass = new RouteConfig(bypassedChecks: ['penetration'], enableSuspiciousDetection: true);
$t->same(true, rdeAllowed($engine, rdeRequest("/search", $bypass, queryParams: rdeSqliQuery())), 'a route penetration bypass skips the check');

$t->section('config: detection_scan_body default and with() immutability');
$defaults = new SecurityConfig(enableRedis: false);
$t->same(true, $defaults->detectionScanBody, 'detection_scan_body defaults true');
$base = new SecurityConfig(enableRedis: false);
$copy = $base->with(['detection_scan_body' => false]);
$t->same(false, $copy->detectionScanBody, 'with() accepts detection_scan_body');
$t->same(true, $base->detectionScanBody, 'source untouched');

$t->section('route config: field immutability');
$route = new RouteConfig(excludedDetectionParams: ['q'], enabledDetectionCategories: ['xss'], detectionScanBody: false);
$copyRoute = $route->with(['excludedDetectionParams' => ['other']]);
$t->same(['other'], $copyRoute->excludedDetectionParams, 'with() accepts the route exclusion fields');
$t->same(['q'], $route->excludedDetectionParams, 'route source untouched');
$t->same(['xss'], $copyRoute->enabledDetectionCategories, 'untouched route fields carry over');

exit($t->done('test_route_detection_exclusions'));

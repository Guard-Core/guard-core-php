<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Behavior\BehaviorRule;
use RenzoFranceschini\GuardCore\Behavior\BehaviorTracker;
use RenzoFranceschini\GuardCore\Behavior\BehavioralProcessor;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

require __DIR__ . '/../vendor/autoload.php';

// Engine-level acceptance runner for the behavior-rules surface. Semantics
// mirror the reference behavioral cluster (guard_core
// _security_config_field_validators.py, handlers/behavior_handler.py,
// handlers/_behavior_action_dispatch.py, handlers/_behavior_response_pattern.py,
// handlers/_behavior_json_pattern.py, core/behavioral/processor.py),
// structurally following the guard-core-go #26 engine-level test matrix:
// usage/frequency rules track requests the pipeline allowed and dispatch
// their action on threshold excess (strictly greater), return_pattern rules
// run response-side via GuardEngine::processResponse, passive mode only
// logs, and global rules feed only the return stage with the
// correlate_with_detection threshold halving.

final class BehaviorT
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

$t = new BehaviorT();

/** @param array<string, mixed> $configArgs */
function behaviorEngine(...$configArgs): GuardEngine
{
    $configArgs['enableRedis'] = false;

    return new GuardEngine(new SecurityConfig(...$configArgs));
}

/**
 * Collects the engine's log stream through the log closure.
 *
 * @param array<int, array{0: string, 1: string}> $logs
 */
function behaviorLoggingEngine(array &$logs, mixed ...$configArgs): GuardEngine
{
    $configArgs['enableRedis'] = false;

    return new GuardEngine(new SecurityConfig(...$configArgs), log: static function (string $level, string $message, array $context) use (&$logs): void {
        $logs[] = [$level, $message];
    });
}

function behaviorRequest(string $path = '/', ?string $clientHost = '192.0.2.77'): SimpleGuardRequest
{
    $request = new SimpleGuardRequest(urlPath: $path, clientHost: $clientHost);
    $request->state()->routeConfig = new RouteConfig();

    return $request;
}

$t->section('config: defaults and rule validation');
$defaults = new SecurityConfig(enableRedis: false);
$t->same([], $defaults->globalBehaviorRules, 'global_behavior_rules default empty');
$t->same(false, $defaults->behaviorScanResponseBody, 'behavior_scan_response_body default off');
$t->same(262144, $defaults->behaviorMaxResponseBodyInspectBytes, 'inspect bytes default 262144');
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, globalBehaviorRules: [['rule_type' => 'nope', 'threshold' => 1]]),
    InvalidArgumentException::class,
    'rule_type',
    'unknown rule_type fails construction'
);
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, globalBehaviorRules: [['rule_type' => 'usage', 'threshold' => 0]]),
    InvalidArgumentException::class,
    'threshold: must be >= 1',
    'threshold 0 fails construction'
);
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, globalBehaviorRules: [['rule_type' => 'usage', 'threshold' => 1, 'action' => 'explode']]),
    InvalidArgumentException::class,
    'action',
    'unknown action fails construction'
);
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, globalBehaviorRules: [['rule_type' => 'usage', 'threshold' => 1, 'ban_duration' => 0]]),
    InvalidArgumentException::class,
    'ban_duration: must be >= 1',
    'ban_duration 0 fails construction'
);
$rule = new BehaviorRule('usage', 3);
$t->same(3600, $rule->window, 'window default 3600');
$t->same('log', $rule->action, 'action default log');
$rule = new BehaviorRule('usage', 3, window: 0);
$t->same(3600, $rule->window, 'window 0 normalizes to 3600');

$t->section('config: fail-closed return_pattern scan validation');
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, globalBehaviorRules: [
        ['rule_type' => 'return_pattern', 'threshold' => 2, 'pattern' => 'regex:rate.{0,5}limit'],
    ]),
    InvalidArgumentException::class,
    'requires reading the response body, but behavior_scan_response_body is False',
    'body-reading pattern with the scan flag off fails construction'
);
$config = new SecurityConfig(
    enableRedis: false,
    globalBehaviorRules: [['rule_type' => 'return_pattern', 'threshold' => 2, 'pattern' => 'status:404']],
);
$t->ok(true, 'status: pattern passes with the scan flag off');
$config = new SecurityConfig(
    enableRedis: false,
    behaviorScanResponseBody: true,
    globalBehaviorRules: [['rule_type' => 'return_pattern', 'threshold' => 2, 'pattern' => 'regex:denied']],
);
$t->ok(true, 'body-reading pattern passes with the scan flag on');
$t->throws(
    static fn (): SecurityConfig => (new SecurityConfig(
        enableRedis: false,
        behaviorScanResponseBody: false,
        globalBehaviorRules: [['rule_type' => 'return_pattern', 'threshold' => 2, 'pattern' => 'status:404']],
    ))->with(['behavior_scan_response_body' => false, 'global_behavior_rules' => [
        ['rule_type' => 'return_pattern', 'threshold' => 2, 'pattern' => 'needle'],
    ]]),
    InvalidArgumentException::class,
    'would never match',
    'with() re-validates the copy'
);

$t->section('config: inspect-bytes bounds');
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, behaviorMaxResponseBodyInspectBytes: 1023),
    InvalidArgumentException::class,
    'must be between 1024 and 10485760',
    'below the lower bound fails construction'
);
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, behaviorMaxResponseBodyInspectBytes: 10485761),
    InvalidArgumentException::class,
    'must be between 1024 and 10485760',
    'above the upper bound fails construction'
);
$t->same(262144, (new SecurityConfig(enableRedis: false, behaviorMaxResponseBodyInspectBytes: 0))->behaviorMaxResponseBodyInspectBytes, 'zero normalizes to the default');

$t->section('tracker: sliding-window usage threshold (local fallback)');
$config = new SecurityConfig(enableRedis: false);
$tracker = new BehaviorTracker($config, null, null);
$rule = new BehaviorRule('usage', 3, window: 60);
$now = 1000.0;
$endpoint = 'GET:/api';
$t->same(false, $tracker->trackEndpointUsage($endpoint, '10.1.0.1', $rule, $now), 'hit 1 below threshold');
$t->same(false, $tracker->trackEndpointUsage($endpoint, '10.1.0.1', $rule, $now + 1), 'hit 2 below threshold');
$t->same(false, $tracker->trackEndpointUsage($endpoint, '10.1.0.1', $rule, $now + 2), 'hit 3 at threshold is not exceeded (strictly greater)');
$t->same(true, $tracker->trackEndpointUsage($endpoint, '10.1.0.1', $rule, $now + 3), 'hit 4 exceeds the threshold');
$t->same(false, $tracker->trackEndpointUsage($endpoint, '10.1.0.2', $rule, $now), 'another client tracks independently');
$t->same(false, $tracker->trackEndpointUsage($endpoint, '10.1.0.1', $rule, $now + 61 + 61), 'expired hits leave the window');

$t->section('tracker: return-pattern matching');
$config = new SecurityConfig(enableRedis: false, behaviorScanResponseBody: true);
$factory = new GuardResponseFactory();
$tracker = new BehaviorTracker($config, null, null);
$returnRule = new BehaviorRule('return_pattern', 2, window: 60, pattern: 'status:404');
$t->same([true, true], $tracker->checkResponsePattern($factory->createResponse('x', 404), 'status:404'), 'status pattern matches');
$t->same([false, true], $tracker->checkResponsePattern($factory->createResponse('x', 200), 'status:404'), 'status pattern mismatch');
$offTracker = new BehaviorTracker(new SecurityConfig(enableRedis: false), null, null);
$t->same([false, false], $offTracker->checkResponsePattern($factory->createResponse('rate limited', 200), 'rate limited'), 'body pattern with the scan flag off is not evaluated');
$onTracker = new BehaviorTracker(new SecurityConfig(enableRedis: false, behaviorScanResponseBody: true), null, null);
$t->same([true, true], $onTracker->checkResponsePattern($factory->createResponse('You are rate limited', 200), 'rate limited'), 'bare substring matches case-insensitively');
$t->same([true, true], $onTracker->checkResponsePattern($factory->createResponse('err: RATE LIMITED', 200), 'regex:rate\\s+limited'), 'regex matches case-insensitively');
$t->same([false, true], $onTracker->checkResponsePattern($factory->createResponse('all good', 200), 'regex:rate\\s+limited'), 'regex mismatch');
$t->same([true, true], $onTracker->checkResponsePattern($factory->createResponse('{"status": "denied"}', 200), 'json:status==Denied'), 'json leaf match is case-insensitive');
$t->same([true, true], $onTracker->checkResponsePattern($factory->createResponse('{"errors": ["Denied", "other"]}', 200), 'json:errors[]==denied'), 'json array match');
$t->same([false, true], $onTracker->checkResponsePattern($factory->createResponse('{"errors": ["ok"]}', 200), 'json:errors[]==denied'), 'json array mismatch');
$t->same([false, true], $onTracker->checkResponsePattern($factory->createResponse('not json', 200), 'json:status==denied'), 'unparseable body is no-match');
$t->same([false, true], $onTracker->checkResponsePattern($factory->createResponse('{"a": 1}', 200), 'json:a==nope'), 'json structural mismatch');
$t->same([false, true], $onTracker->checkResponsePattern(null, 'status:404'), 'null response evaluates false');

$t->section('tracker: return-pattern window counts only matches');
$tracker = new BehaviorTracker(new SecurityConfig(enableRedis: false, behaviorScanResponseBody: true), null, null);
$rule = new BehaviorRule('return_pattern', 2, window: 60, pattern: 'denied');
$resp = $factory->createResponse('ACCESS DENIED', 200);
$clean = $factory->createResponse('welcome', 200);
$endpoint = 'GET:/login';
$t->same(false, $tracker->trackReturnPattern($endpoint, '10.2.0.1', $clean, $rule, $now), 'clean response does not count');
$t->same(false, $tracker->trackReturnPattern($endpoint, '10.2.0.1', $resp, $rule, $now), 'match 1 below threshold');
$t->same(false, $tracker->trackReturnPattern($endpoint, '10.2.0.1', $resp, $rule, $now + 1), 'match 2 at threshold');
$t->same(true, $tracker->trackReturnPattern($endpoint, '10.2.0.1', $resp, $rule, $now + 2), 'match 3 exceeds the threshold');

$t->section('processor: usage rules ban in active mode');
$banLogs = [];
$logs = [];
$engine = behaviorLoggingEngine($logs, 
    globalBehaviorRules: [],
    enableIpBanning: true,
    autoBanThreshold: 100,
    logSuspiciousLevel: 'WARNING',
);
$request = behaviorRequest('/admin');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'usage', 'threshold' => 2, 'window' => 60, 'action' => 'ban', 'ban_duration' => 120],
]);
$clientIp = '192.0.2.90';
$engine->banManager()->reset();
$engine->behaviorProcessor()->processUsageRules($request, $clientIp, $request->state()->routeConfig, $now);
$engine->behaviorProcessor()->processUsageRules($request, $clientIp, $request->state()->routeConfig, $now + 1);
$t->same(false, $engine->banManager()->isIpBanned($clientIp), 'below threshold no ban');
$engine->behaviorProcessor()->processUsageRules($request, $clientIp, $request->state()->routeConfig, $now + 2);
$t->same(true, $engine->banManager()->isIpBanned($clientIp), 'threshold excess bans the IP');
$banLine = null;
foreach ($logs as [$level, $message]) {
    if (str_contains($message, 'banned for behavioral violation')) {
        $banLine = $message;
    }
}
$t->ok($banLine !== null && str_contains($banLine, "IP {$clientIp} banned for behavioral violation"), 'ban logs at the suspicious level');

$t->section('processor: ban-duration override');
$logs = [];
$engine = behaviorLoggingEngine($logs, enableIpBanning: true);
$request = behaviorRequest('/admin');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'usage', 'threshold' => 1, 'window' => 60, 'action' => 'ban'],
]);
$clientIp = '192.0.2.91';
$engine->banManager()->reset();
$engine->behaviorProcessor()->processUsageRules($request, $clientIp, $request->state()->routeConfig, $now);
$engine->behaviorProcessor()->processUsageRules($request, $clientIp, $request->state()->routeConfig, $now + 1);
$t->same(true, $engine->banManager()->isIpBanned($clientIp), 'default ban fires (threshold strictly greater needs two calls)');

$t->section('processor: passive mode only logs');
$logs = [];
$engine = behaviorLoggingEngine($logs, passiveMode: true, enableIpBanning: true);
$request = behaviorRequest('/admin');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'usage', 'threshold' => 1, 'window' => 60, 'action' => 'ban'],
]);
$clientIp = '192.0.2.92';
$engine->behaviorProcessor()->processUsageRules($request, $clientIp, $request->state()->routeConfig, $now);
$engine->behaviorProcessor()->processUsageRules($request, $clientIp, $request->state()->routeConfig, $now + 1);
$t->same(false, $engine->banManager()->isIpBanned($clientIp), 'passive mode never bans');
$passiveLine = null;
foreach ($logs as [$level, $message]) {
    if (str_contains($message, '[PASSIVE MODE] Would ban IP')) {
        $passiveLine = $message;
    }
}
$t->ok($passiveLine !== null, 'passive mode logs the would-ban line');

$t->section('processor: alert and throttle actions');
$logs = [];
$engine = behaviorLoggingEngine($logs, );
$request = behaviorRequest('/admin');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'frequency', 'threshold' => 1, 'window' => 60, 'action' => 'alert'],
]);
$engine->behaviorProcessor()->processUsageRules($request, '192.0.2.93', $request->state()->routeConfig, $now);
$engine->behaviorProcessor()->processUsageRules($request, '192.0.2.93', $request->state()->routeConfig, $now + 1);
$alertLine = null;
foreach ($logs as [$level, $message]) {
    if (str_contains($message, 'ALERT - Behavioral anomaly')) {
        $alertLine = $message;
    }
}
$t->ok($alertLine !== null, 'alert action logs the ALERT line');
$request = behaviorRequest('/admin');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'usage', 'threshold' => 1, 'window' => 60, 'action' => 'throttle'],
]);
$engine->behaviorProcessor()->processUsageRules($request, '192.0.2.94', $request->state()->routeConfig, $now);
$engine->behaviorProcessor()->processUsageRules($request, '192.0.2.94', $request->state()->routeConfig, $now + 1);
$throttleLine = null;
foreach ($logs as [$level, $message]) {
    if (str_contains($message, 'Throttling IP')) {
        $throttleLine = $message;
    }
}
$t->ok($throttleLine !== null, 'throttle action logs the throttling line');

$t->section('processor: exclusion-scoped requests never track');
$logs = [];
$engine = behaviorLoggingEngine($logs, );
$request = behaviorRequest('/docs');
$request->state()->guardExclusionScoped = true;
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'usage', 'threshold' => 1, 'window' => 60, 'action' => 'ban'],
]);
$engine->behaviorProcessor()->processUsageRules($request, '192.0.2.95', $request->state()->routeConfig, $now);
$t->same([], array_filter($logs, static fn (array $l): bool => str_contains($l[1], 'behavioral')), 'no violation while exclusion-scoped');

$t->section('engine: usage rules run on allowed requests');
$logs = [];
$engine = behaviorLoggingEngine($logs, );
$request = behaviorRequest('/api', '192.0.2.96');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'usage', 'threshold' => 2, 'window' => 60, 'action' => 'log'],
]);
$engine->execute($request);
$engine->execute($request);
$engine->execute($request);
$usageLine = null;
foreach ($logs as [$level, $message]) {
    if (str_contains($message, 'Behavioral usage threshold exceeded')) {
        $usageLine = $message;
    }
}
$t->ok($usageLine !== null, 'the third allowed request trips the usage rule');

$t->section('engine: blocked requests do not track usage');
$logs = [];
$engine = behaviorLoggingEngine($logs, blacklist: ['203.0.113.9']);
$request = behaviorRequest('/api');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'usage', 'threshold' => 1, 'window' => 60, 'action' => 'log'],
]);
$response = $engine->execute(new SimpleGuardRequest(urlPath: '/api', clientHost: '203.0.113.9'));
$t->ok($response !== null && $response->statusCode() === 403, 'blacklisted IP is blocked');
$t->same([], array_filter($logs, static fn (array $l): bool => str_contains($l[1], 'behavioral')), 'blocked requests never track usage');

$t->section('engine: processResponse runs route and global return rules');
$logs = [];
$engine = behaviorLoggingEngine($logs, 
    behaviorScanResponseBody: true,
    globalBehaviorRules: [['rule_type' => 'return_pattern', 'threshold' => 2, 'window' => 60, 'pattern' => 'status:429', 'action' => 'log']],
);
$request = behaviorRequest('/api');
$request->state()->routeConfig = new RouteConfig(behaviorRules: [
    ['rule_type' => 'return_pattern', 'threshold' => 2, 'window' => 60, 'pattern' => 'quota exceeded', 'action' => 'log'],
]);
$resp = (new GuardResponseFactory())->createResponse('quota exceeded for today', 429);
$engine->processResponse($request, $resp);
$engine->processResponse($request, $resp);
$engine->processResponse($request, $resp);
$routeLine = null;
foreach ($logs as [$level, $message]) {
    if (str_contains($message, "Return pattern threshold exceeded: 2 for 'quota exceeded'")) {
        $routeLine = $message;
    }
}
$t->ok($routeLine !== null, 'the route return rule trips on the third match (strictly greater)');
$globalLine = null;
foreach ($logs as [$level, $message]) {
    if (str_contains($message, 'Global return pattern threshold exceeded')) {
        $globalLine = $message;
    }
}
$t->ok($globalLine !== null, 'the global return rule trips on its own window');
$t->same('quota exceeded for today', $resp->body(), 'return rules never modify the response');

$t->section('processor: correlate_with_detection halves the global threshold');
$logs = [];
$engine = behaviorLoggingEngine($logs, 
    behaviorScanResponseBody: true,
    globalBehaviorRules: [['rule_type' => 'return_pattern', 'threshold' => 4, 'window' => 60, 'pattern' => 'denied', 'action' => 'log', 'correlate_with_detection' => true]],
);
// Fire one penetration detection for the client IP (the shared suspicious
// count store), so correlation halves the effective threshold 4 -> 2.
$suspicious = new SimpleGuardRequest(
    urlPath: "/api?q=" . rawurlencode("' OR '1'='1"),
    clientHost: '192.0.2.98'
);
$engine->execute($suspicious);
$request = behaviorRequest('/api', '192.0.2.98');
$request->state()->clientIp = '192.0.2.98';
$denied = (new GuardResponseFactory())->createResponse('ACCESS DENIED', 200);
$engine->processResponse($request, $denied);
$engine->processResponse($request, $denied);
$correlatedLine = null;
$engine->processResponse($request, $denied);
foreach ($logs as [$level, $message]) {
    if (str_contains($message, 'Global return pattern threshold exceeded') && str_contains($message, '(correlated)')) {
        $correlatedLine = $message;
    }
}
$t->ok($correlatedLine !== null, 'the halved threshold (2 of 4) trips with the correlated marker');

$t->section('processor: endpoint id');
$processor = new BehavioralProcessor(new SecurityConfig(enableRedis: false), null, null);
$request = behaviorRequest('/users/42?token=secret');
$t->same('GET:/users/42?token=[REDACTED]', $processor->getEndpointId($request), 'endpoint id is METHOD:path with sensitive params redacted');
$request->state()->scratch['guard_endpoint_id'] = 'custom:endpoint';
$t->same('custom:endpoint', $processor->getEndpointId($request), 'runtime guard_endpoint_id wins');

$t->section('tracker: redis-backed sliding window (shared key layout)');
$redis = new RenzoFranceschini\GuardCore\Redis\RedisHandler(
    enableRedis: true,
    prefix: 'guard_core_test:',
    host: getenv('REDIS_HOST') ?: '127.0.0.1',
    port: (int) (getenv('REDIS_PORT') ?: 6379)
);
$redisUp = false;
try {
    $redis->initialize();
    $redisUp = true;
} catch (Throwable $e) {
    echo "  SKIP redis unavailable: {$e->getMessage()}\n";
}
if ($redisUp) {
    $tracker = new BehaviorTracker(new SecurityConfig(enableRedis: true), $redis, null);
    $rule = new BehaviorRule('usage', 3, window: 60);
    $endpoint = 'GET:/api/redis';
    $ip = '10.9.9.9';
    $now = microtime(true);
    $results = [
        $tracker->trackEndpointUsage($endpoint, $ip, $rule, $now),
        $tracker->trackEndpointUsage($endpoint, $ip, $rule, $now + 1),
        $tracker->trackEndpointUsage($endpoint, $ip, $rule, $now + 2),
        $tracker->trackEndpointUsage($endpoint, $ip, $rule, $now + 3),
    ];
    $t->same([false, false, false, true], $results, 'redis window trips on the fourth hit (strictly greater)');
    $keys = $redis->keys('behavior_usage:behavior:usage:*');
    $t->ok($keys !== [], 'shared behavior_usage key layout present under the namespace');
    $redis->deletePattern('behavior_usage:behavior:usage:*');
}

$t->section('engine: zero rules means zero behavior change');
$logs = [];
$engine = behaviorLoggingEngine($logs, );
$response = $engine->execute(behaviorRequest('/'));
$t->same(null, $response, 'plain request passes');
$engine->processResponse(behaviorRequest('/'), $factory->createResponse('anything', 200));
$t->same([], array_filter($logs, static fn (array $l): bool => str_contains($l[1], 'behavioral')), 'no behavior logs without rules');

exit($t->done('test_behavior'));

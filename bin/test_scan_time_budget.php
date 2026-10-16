<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

// Port of tests/test_scan_time_budget.py (guard-core 4.3.x, detection_max_scan_seconds):
// the per-request cap on summed regex scan CPU time, checked between
// patterns. The event-loop-yield half of the reference change does not
// apply to PHP (a scan never shares a loop with other requests).

final class T
{
    public int $passed = 0;
    public int $failed = 0;

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
            echo '  expected: ' . var_export($expected, true) . "\n";
            echo '  actual:   ' . var_export($actual, true) . "\n";
        }
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

ini_set('error_log', '/dev/null');

/** A fake CPU clock: every read advances by $step seconds (mirrors _FakeClock). */
function fakeClock(float $step): void
{
    $now = 0.0;
    SusPatterns::$cpuClock = static function () use (&$now, $step): float {
        $now += $step;

        return $now;
    };
}

function makeCheck(SecurityConfig $config, float $threshold = 1.0): SuspiciousActivityCheck
{
    return new SuspiciousActivityCheck(
        $config,
        new GuardResponseFactory(),
        new SusPatterns($config->detectionSemanticThreshold, threatScoreThreshold: $threshold),
        null,
        new RouteResolver()
    );
}

/** @return array{0: bool, 1: string} [blocked, block reason] */
function run(SuspiciousActivityCheck $check, string $path = '/items', array $headers = []): array
{
    $request = new SimpleGuardRequest(urlPath: $path, method: 'GET', headers: $headers);
    $request->state()->clientIp = '9.9.9.9';
    $response = $check->check($request);

    return [$response instanceof GuardResponse, (string) ($request->state()->guardBlockStash['reason'] ?? '')];
}

const BUDGET_PATTERN = 'scan_time_budget_exhausted';
const BUDGET_MESSAGE = "Pattern exceeded scan time budget: 'scan_time_budget_exhausted'";

$t = new T();

$t->section('config: detection_max_scan_seconds default and bounds');
$t->same(10.0, (new SecurityConfig())->detectionMaxScanSeconds, 'default is 10.0');
$t->same(0.1, (new SecurityConfig(detectionMaxScanSeconds: 0.1))->detectionMaxScanSeconds, 'lower bound 0.1 accepted');
$t->same(60.0, (new SecurityConfig(detectionMaxScanSeconds: 60.0))->detectionMaxScanSeconds, 'upper bound 60.0 accepted');
foreach ([0.0, 0.09, 60.1] as $bad) {
    $message = null;
    try {
        new SecurityConfig(detectionMaxScanSeconds: $bad);
    } catch (\InvalidArgumentException $e) {
        $message = $e->getMessage();
    }
    $t->same('detection_max_scan_seconds must be within [0.1, 60.0]', $message, "{$bad} rejects naming the field");
}
$t->same(2.5, (new SecurityConfig())->with(['detection_max_scan_seconds' => 2.5])->detectionMaxScanSeconds, 'with() carries the field');

$t->section('detect() is unbounded outside a request scan');
fakeClock(1.0);
$sus = new SusPatterns();
$result = $sus->detect('hello world', '9.9.9.9', 'query_param:q');
$names = array_column($result['threats'], 'pattern');
$t->same(false, in_array(BUDGET_PATTERN, $names, true), 'no budget threat without beginScan');
$t->same(false, $result['is_threat'], 'benign value is not a threat');

$t->section('exhausted budget: threat shape');
fakeClock(1.0);
$sus = new SusPatterns();
$sus->beginScan(0.1);
$result = $sus->detect('hello world', '9.9.9.9', 'query_param:q');
$sus->endScan();
$budget = array_values(array_filter($result['threats'], static fn (array $th): bool => $th['pattern'] === BUDGET_PATTERN));
$t->same(1, count(array_filter($budget, static fn (array $th): bool => $th['type'] === 'pattern_timeout')) >= 1 ? 1 : 0, 'a pattern_timeout budget threat is present');
$t->same(
    ['type' => 'pattern_timeout', 'pattern' => BUDGET_PATTERN, 'match' => '', 'position' => 0, 'execution_time' => 0.0, 'category' => 'custom', 'weight' => 1.0],
    $budget[0] ?? null,
    'threat has the reference shape and weight 1.0'
);
$t->same(true, in_array(BUDGET_PATTERN, $result['timeouts'], true), 'budget pattern is reported in timeouts');
$t->same(true, $result['is_threat'], 'default threshold 1.0 flags the request');

$t->section('exhausted budget: remaining patterns are skipped');
$calls = 0;
$now = 0.0;
SusPatterns::$cpuClock = static function () use (&$calls, &$now): float {
    $calls++;

    return $now += 1.0;
};
$sus = new SusPatterns();
$sus->beginScan(0.1);
$sus->detect('hello world', '9.9.9.9', 'query_param:q');
$sus->endScan();
$t->same(true, $calls < 40, "clock is read a handful of times, not once per catalog pattern ({$calls})");

$t->section('CPU clock is read a small constant number of times per pass');
$reads = 0;
SusPatterns::$cpuClock = static function () use (&$reads): float {
    $reads++;

    return 0.0;
};
$sus = new SusPatterns();
$sus->beginScan(60.0);
$sus->detect('hello world', '9.9.9.9', 'query_param:q');
$sus->endScan();
$t->same(true, $reads >= 2 && $reads <= 12, "one open read and one close read per pass, plus slice charges ({$reads} reads over several hundred patterns)");
$reads = 0;
$sus = new SusPatterns();
$sus->detect('hello world', '9.9.9.9', 'query_param:q');
$t->same(0, $reads, 'no CPU clock read outside a request scan');

$t->section('a long pass stops at the budget within about one slice');
// One fake clock shared by wall and CPU: every wall read (one per pattern)
// advances 1 ms, so a 50 ms cap is spent after about 50 patterns, and the
// scan may overshoot it by at most one 2 ms slice plus one pattern.
$fakeNs = 0;
SusPatterns::$wallClockNs = static function () use (&$fakeNs): int {
    return $fakeNs += 1_000_000;
};
SusPatterns::$cpuClock = static function () use (&$fakeNs): float {
    return $fakeNs / 1e9;
};
$sus = new SusPatterns();
$sus->beginScan(0.05);
$result = $sus->detect('hello world', '9.9.9.9', 'query_param:q');
$spent = (new ReflectionProperty($sus, 'scanSpent'))->getValue($sus);
$sus->endScan();
SusPatterns::$wallClockNs = null;
$t->same(true, in_array(BUDGET_PATTERN, array_column($result['threats'], 'pattern'), true), 'budget threat is recorded');
$t->same(true, $spent >= 0.05 && $spent <= 0.05 + 0.002 + 0.001, "stopped within about one slice plus one pattern of the cap (charged {$spent} s for a 0.05 s cap)");

$t->section('a budget spent by the last catalog pattern stops before the registry patterns');
// Every wall read crosses a slice and every CPU read adds one second, so the
// first pass spends one second per scanned catalog pattern. The smallest cap
// that still lets the registry pattern run marks the pass's catalog size.
$wallNs = 0;
SusPatterns::$wallClockNs = static function () use (&$wallNs): int {
    return $wallNs += 2_000_000;
};
$probe = 'zzregistryprobe';
$scanWithCap = static function (float $cap) use ($probe): array {
    fakeClock(1.0);
    $sus = new SusPatterns();
    $sus->addPattern($probe, true);
    $sus->beginScan($cap);
    $result = $sus->detect($probe, '9.9.9.9', 'unknown');
    $sus->endScan();

    return array_column($result['threats'], 'pattern');
};
$catalogScanned = 0;
for ($k = 1; $k <= 1000; $k++) {
    if (in_array($probe, $scanWithCap($k + 0.5), true)) {
        $catalogScanned = $k;
        break;
    }
}
$patterns = $scanWithCap($catalogScanned - 0.5);
SusPatterns::$wallClockNs = null;
$t->same(true, $catalogScanned > 1, "the first pass scans the catalog before the registry ({$catalogScanned} patterns)");
$t->same(true, in_array(BUDGET_PATTERN, $patterns, true), 'budget threat is recorded when the last catalog pattern spends it');
$t->same(false, in_array($probe, $patterns, true), 'the registry pattern is not scanned once the budget is spent');

$t->section('budget is shared across values of one request scan');
fakeClock(1.0);
$sus = new SusPatterns();
$sus->beginScan(2.5);
$first = $sus->detect('hello', '9.9.9.9', 'query_param:a');
$second = $sus->detect('world', '9.9.9.9', 'query_param:b');
$sus->endScan();
$names = array_merge(array_column($first['threats'], 'pattern'), array_column($second['threats'], 'pattern'));
$t->same(true, in_array(BUDGET_PATTERN, $names, true), 'budget threat appears');
$t->same(true, $second['is_threat'], 'the second value is flagged from the already spent budget');

$t->section('beginScan resets the spent time');
fakeClock(0.0);
$sus = new SusPatterns();
$sus->beginScan(0.1);
$clean = $sus->detect('hello', '9.9.9.9', 'query_param:q');
$sus->endScan();
$t->same(false, $clean['is_threat'], 'zero-cost clock never exhausts the budget');

$t->section('within budget: unaffected');
SusPatterns::$cpuClock = null;
$sus = new SusPatterns();
$sus->beginScan(10.0);
$benign = $sus->detect('page=2', '9.9.9.9', 'query_param:q');
$attack = $sus->detect("1' OR '1'='1", '9.9.9.9', 'query_param:q');
$sus->endScan();
$t->same(false, $benign['is_threat'], 'benign value under the real clock is not a threat');
$t->same(true, $attack['is_threat'], 'attack value is still detected');
$t->same(false, in_array(BUDGET_PATTERN, array_column($attack['threats'], 'pattern'), true), 'no budget threat within budget');

$t->section('threshold wiring: benign request, exhausted budget');
fakeClock(1.0);
$config = new SecurityConfig(detectionMaxScanSeconds: 0.1);
[$blocked, $reason] = run(makeCheck($config, 1.0));
$t->same(true, $blocked, 'threshold 1.0 blocks (weight 1.0 reaches it)');
$t->same(true, str_contains($reason, "URL path: " . BUDGET_MESSAGE), 'reason carries the budget text');
fakeClock(1.0);
[$blocked, $reason] = run(makeCheck(new SecurityConfig(detectionMaxScanSeconds: 0.1, detectionThreatScoreThreshold: 5.0), 5.0));
$t->same(false, $blocked, 'threshold 5.0 does not block');
$t->same('', $reason, 'no block reason at threshold 5.0');

$t->section('threshold wiring through GuardEngine (config field reaches the verdict)');
foreach ([[1.0, true], [5.0, false]] as [$threshold, $expectBlock]) {
    fakeClock(1.0);
    $engine = new GuardEngine(new SecurityConfig(detectionMaxScanSeconds: 0.1, detectionThreatScoreThreshold: $threshold, enableRateLimiting: false, enableIpBanning: false));
    $request = new SimpleGuardRequest(urlPath: '/items', method: 'GET', headers: ['x-forwarded-for' => '9.9.9.9'], clientHost: '9.9.9.9');
    $response = $engine->execute($request);
    $t->same($expectBlock, $response instanceof GuardResponse, "engine threshold {$threshold} blocks={$expectBlock}");
}

$t->section('reason text: budget threat first, and appended after another threat');
fakeClock(1.0);
[, $reason] = run(makeCheck($config), '/items', ['x-pad' => 'hello']);
$t->same(false, str_contains($reason, '; ' . BUDGET_MESSAGE), 'budget threat alone has no appended form');
// Calibrate: how many patterns does an attack header scan across every view?
// Every wall read crosses a 2 ms slice, so the CPU is charged once per
// pattern and each pattern costs one clock step, as before per-pass charging.
$attackHeader = "1' OR '1'='1 UNION SELECT password FROM users--";
$wallNs = 0;
SusPatterns::$wallClockNs = static function () use (&$wallNs): int {
    return $wallNs += 2_000_000;
};
$wallNs = 0;
SusPatterns::$cpuClock = static fn (): float => 0.0;
run(makeCheck(new SecurityConfig(detectionMaxScanSeconds: 60.0)), '/items', ['x-attack' => $attackHeader]);
$scanned = intdiv($wallNs, 2_000_000);
// Each pattern costs $step; the 60 s cap is spent late in the request scan,
// after the attack header has already been scanned.
$step = 60.0 / ($scanned * 0.85);
$now = 0.0;
SusPatterns::$cpuClock = static function () use (&$now, $step): float {
    return $now += $step;
};
$check = makeCheck(new SecurityConfig(detectionMaxScanSeconds: 60.0));
[$blocked, $reason] = run($check, '/items', ['x-attack' => $attackHeader]);
SusPatterns::$wallClockNs = null;
$t->same(true, $blocked, 'attack header with a mid-scan exhausted budget blocks');
$t->same(true, str_ends_with($reason, '; ' . BUDGET_MESSAGE), 'reason is "<first threat message>; <budget message>"');
$t->same(true, str_contains($reason, "Value matched pattern"), 'the first threat message leads the reason');

$t->section('budget spent exactly after the catalog stops the registry additions too');
// A one-second step with an integer cap spends the budget after exactly that
// many patterns; sweeping the cap lands one inside the registry scan loop.
$withRegistry = 0;
for ($cap = 1; $cap <= 400; $cap++) {
    fakeClock(1.0);
    $sus = new SusPatterns();
    $sus->addPattern('zzregistryprobe\\d+', true);
    $sus->beginScan((float) $cap);
    $result = $sus->detect('hello', '9.9.9.9', 'query_param:q');
    $sus->endScan();
    if (in_array(BUDGET_PATTERN, array_column($result['threats'], 'pattern'), true)) {
        $withRegistry++;
    }
}
$t->same(true, $withRegistry > 0, 'budget threats are recorded across the cap sweep with a registry pattern present');

$t->section('check() leaves the scan unbounded afterwards');
SusPatterns::$cpuClock = null;
$shared = new SusPatterns();
$check = new SuspiciousActivityCheck(new SecurityConfig(), new GuardResponseFactory(), $shared, null, new RouteResolver());
run($check);
fakeClock(1.0);
$after = $shared->detect('hello', '9.9.9.9', 'query_param:q');
$t->same(false, in_array(BUDGET_PATTERN, array_column($after['threats'], 'pattern'), true), 'a direct detect() after check() has no cap');

$t->section('default clock: process CPU time, not wall time');
SusPatterns::$cpuClock = null;
$before = SusPatterns::cpuSeconds();
usleep(200000);
$slept = SusPatterns::cpuSeconds() - $before;
$t->same(true, $slept < 0.1, 'a 200 ms sleep costs almost no CPU time (' . round($slept, 4) . 's)');
$before = SusPatterns::cpuSeconds();
$deadline = hrtime(true) + 50_000_000;
while (hrtime(true) < $deadline) {
}
$t->same(true, SusPatterns::cpuSeconds() - $before > 0.02, 'a 50 ms busy loop is counted');

$t->same(3.5, SusPatterns::cpuSecondsFrom(['ru_utime.tv_sec' => 1, 'ru_stime.tv_sec' => 2, 'ru_utime.tv_usec' => 250000, 'ru_stime.tv_usec' => 250000]), 'getrusage user plus system seconds and microseconds add up');
$wall = SusPatterns::cpuSecondsFrom(false);
$t->same(true, $wall > 0.0 && abs($wall - hrtime(true) / 1e9) < 1.0, 'without getrusage the monotonic wall clock stands in');

echo "\n{$t->passed} passed, {$t->failed} failed\n";
exit($t->failed === 0 ? 0 : 1);

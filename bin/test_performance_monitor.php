<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\MonitorAnomalies;
use RenzoFranceschini\GuardCore\Detection\MonitorReporting;
use RenzoFranceschini\GuardCore\Detection\PatternStats;
use RenzoFranceschini\GuardCore\Detection\PerformanceMetric;
use RenzoFranceschini\GuardCore\Detection\PerformanceMonitor;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;

require __DIR__ . '/../vendor/autoload.php';

// Spec 04 "Performance monitoring": the reference PerformanceMonitor ported
// with its constants and clamps, the anomaly-detection trio
// (timeout / slow_execution / statistical_anomaly), cooldown-gated agent
// emission with the reservation taken even when the send fails, always
// sanitized callbacks (callback errors become callback_error events and
// never propagate), and the reporting surface. The clock is injected so the
// cooldown behaviour is deterministic.

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

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }

    public function finish(string $label): int
    {
        echo "\n{$label}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed === 0 ? 0 : 1;
    }
}

final class RecordingAgent
{
    /** @var list<SecurityEvent> */
    public array $events = [];

    public bool $failNext = false;

    public bool $alwaysFail = false;

    public function sendEvent(SecurityEvent $event): void
    {
        if ($this->alwaysFail || $this->failNext) {
            $this->failNext = false;
            throw new RuntimeException('agent down');
        }
        $this->events[] = $event;
    }
}

$t = new T();

// ---------------------------------------------------------------------
// 1. Constants and clamps
// ---------------------------------------------------------------------

$t->section('constants and clamps');
$m = new PerformanceMonitor();
$t->same(3.0, $m->anomalyThreshold, 'anomaly threshold default');
$t->same(0.1, $m->slowPatternThreshold, 'slow threshold default');
$t->same(1000, $m->historySize, 'history size default');
$t->same(1000, $m->maxTrackedPatterns, 'max tracked patterns default');
$t->same(60.0, $m->anomalyEmissionCooldown, 'cooldown default');
$t->same(30, $m->minSamplesForAnomaly, 'min samples default');
$clamped = new PerformanceMonitor(0.5, 0.001, 10, 10, 0.5, 5);
$t->same(1.0, $clamped->anomalyThreshold, 'anomaly threshold clamped to 1.0');
$t->same(0.01, $clamped->slowPatternThreshold, 'slow threshold clamped to 0.01');
$t->same(100, $clamped->historySize, 'history size clamped to 100');
$t->same(100, $clamped->maxTrackedPatterns, 'max tracked patterns clamped to 100');
$t->same(1.0, $clamped->anomalyEmissionCooldown, 'cooldown clamped to 1.0');
$t->same(10, $clamped->minSamplesForAnomaly, 'min samples clamped to 10');
$high = new PerformanceMonitor(99.0, 99.0, 99999, 99999, 99999.0, 9999);
$t->same(10.0, $high->anomalyThreshold, 'anomaly threshold clamped to 10.0');
$t->same(10.0, $high->slowPatternThreshold, 'slow threshold clamped to 10.0');
$t->same(10000, $high->historySize, 'history size clamped to 10000');
$t->same(5000, $high->maxTrackedPatterns, 'max tracked patterns clamped to 5000');
$t->same(3600.0, $high->anomalyEmissionCooldown, 'cooldown clamped to 3600.0');
$t->same(1000, $high->minSamplesForAnomaly, 'min samples clamped to 1000');

// ---------------------------------------------------------------------
// 2. recordMetric: truncation, normalization, windows, eviction
// ---------------------------------------------------------------------

$t->section('record metric bookkeeping');
$m = new PerformanceMonitor(minSamplesForAnomaly: 10);
$long = str_repeat('p', 150);
$m->recordMetric($long, 0.5, -1, true);
$stats = $m->patternStats[str_repeat('p', 100) . '...[truncated]'] ?? null;
$t->truthy($stats !== null, 'long patterns tracked under the truncated key');
$t->same(1, $stats->totalExecutions, 'execution counted');
$t->same(1, $stats->totalMatches, 'match counted');
$m->recordMetric('short', -5.0, 10, false);
$short = $m->patternStats['short'];
$t->same(0.0, $short->maxExecutionTime, 'negative execution time normalized to 0.0');
$t->same([0.0], $short->recentTimes, 'recent time recorded');

$t->section('recent times window and min/max/avg');
$m = new PerformanceMonitor(minSamplesForAnomaly: 10);
for ($i = 1; $i <= 120; $i++) {
    $m->recordMetric('windowed', (float) $i, 10, false);
}
$stats = $m->patternStats['windowed'];
$t->same(100, count($stats->recentTimes), 'recent times bounded at the 100 window');
$t->same(120.0, $stats->recentTimes[99], 'oldest samples dropped (deque semantics)');
$t->same(120.0, $stats->maxExecutionTime, 'max over the window');
$t->same(1.0, $stats->minExecutionTime, 'min kept over the lifetime (the reference code keeps lifetime min)');
$t->same(70.5, $stats->avgExecutionTime, 'average over the window');

$t->section('timeout metrics never enter recent times');
$m = new PerformanceMonitor(minSamplesForAnomaly: 10);
$m->recordMetric('mixed', 0.5, 10, false);
$m->recordMetric('mixed', 9.9, 10, false, timeout: true);
$stats = $m->patternStats['mixed'];
$t->same([0.5], $stats->recentTimes, 'timeout sample excluded from recent times');
$t->same(1, $stats->totalTimeouts, 'timeout counted');
$t->same(0.5, $stats->maxExecutionTime, 'max unchanged by the timeout sample');

$t->section('tracked pattern FIFO eviction');
$m = new PerformanceMonitor(maxTrackedPatterns: 100, minSamplesForAnomaly: 10);
for ($i = 0; $i < 105; $i++) {
    $m->recordMetric('pattern-' . $i, 0.001, 10, false);
}
$t->same(100, count($m->patternStats), 'tracking evicted at max_tracked_patterns');
$t->truthy(!isset($m->patternStats['pattern-0']), 'oldest pattern evicted first');
$t->truthy(isset($m->patternStats['pattern-104']), 'newest pattern retained');

$t->section('history window');
$m = new PerformanceMonitor(historySize: 100, minSamplesForAnomaly: 10);
for ($i = 0; $i < 150; $i++) {
    $m->recordMetric('h', 0.001, 10, false);
}
$t->same(100, count($m->recentMetrics), 'recent metrics bounded at history_size');

// ---------------------------------------------------------------------
// 3. Anomaly trio
// ---------------------------------------------------------------------

$t->section('anomaly trio');
$now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
$timeoutMetric = new PerformanceMetric('p', 0.1, 10, $now, false, true);
$t->truthy(MonitorAnomalies::detectTimeoutAnomaly($timeoutMetric) !== null, 'timeout anomaly detected');
$t->same(null, MonitorAnomalies::detectSlowExecutionAnomaly($timeoutMetric, 0.01), 'slow not checked on a timeout metric');

$slowMetric = new PerformanceMetric('p', 0.5, 10, $now, false);
$t->same(null, MonitorAnomalies::detectTimeoutAnomaly($slowMetric), 'no timeout anomaly without timeout');
$t->truthy(MonitorAnomalies::detectSlowExecutionAnomaly($slowMetric, 0.1) !== null, 'slow anomaly over threshold');
$t->same(null, MonitorAnomalies::detectSlowExecutionAnomaly(new PerformanceMetric('p', 0.05, 10, $now, false), 0.1), 'no slow anomaly under threshold');

$stats = new PatternStats('p');
for ($i = 0; $i < 40; $i++) {
    $stats->appendRecentTime($i % 2 === 0 ? 0.001 : 0.002, 100);
}
$spiky = new PerformanceMetric('p', 0.1, 10, $now, false);
$anomaly = MonitorAnomalies::detectStatisticalAnomaly($spiky, $stats, 30, 3.0);
$t->truthy($anomaly !== null, 'statistical anomaly over the z threshold');
$t->truthy(($anomaly['z_score'] ?? 0) > 3.0, 'z score above the threshold');
$t->same(null, MonitorAnomalies::detectStatisticalAnomaly(new PerformanceMetric('p', 0.001, 10, $now, false), $stats, 30, 3.0), 'no statistical anomaly at the mean');
$t->same(null, MonitorAnomalies::detectStatisticalAnomaly($spiky, $stats, 50, 3.0), 'statistical anomaly requires min samples');

// ---------------------------------------------------------------------
// 4. Agent emission: cooldown gating, send failures, event shapes
// ---------------------------------------------------------------------

$t->section('agent emission and cooldown');
$clock = 1000.0;
$agent = new RecordingAgent();
$m = new PerformanceMonitor(anomalyEmissionCooldown: 60.0, slowPatternThreshold: 0.01, minSamplesForAnomaly: 10, clock: static function () use (&$clock): float {
    return $clock;
});
$m->recordMetric('slow-pattern', 0.5, 10, false, agentHandler: $agent);
$t->same(1, count($agent->events), 'slow anomaly sent to the agent');
$event = $agent->events[0];
$t->same(EventTypes::EVENT_PATTERN_ANOMALY_SLOW_EXECUTION, $event->eventType, 'slow anomaly event type');
$t->same('system', $event->ipAddress, 'anomaly events come from system');
$t->same('anomaly_detected', $event->actionTaken, 'anomaly event action');
$t->same('PerformanceMonitor', $event->metadata['component'], 'anomaly event component');
$m->recordMetric('slow-pattern', 0.5, 10, false, agentHandler: $agent);
$t->same(1, count($agent->events), 'second anomaly inside the cooldown is suppressed');
$clock += 61.0;
$m->recordMetric('slow-pattern', 0.5, 10, false, agentHandler: $agent);
$t->same(2, count($agent->events), 'anomaly after the cooldown is sent');

$t->section('timeout and statistical event types');
$agent = new RecordingAgent();
$m = new PerformanceMonitor(slowPatternThreshold: 0.01, minSamplesForAnomaly: 10, clock: static fn (): float => 2000.0);
$m->recordMetric('timeouts-a-lot', 0.5, 10, false, timeout: true, agentHandler: $agent);
$t->same(EventTypes::EVENT_PATTERN_ANOMALY_TIMEOUT, $agent->events[0]->eventType, 'timeout anomaly event type');
$stats = $m->patternStats['timeouts-a-lot'];
$stats->lastAnomalyEmittedAt = null;
for ($i = 0; $i < 30; $i++) {
    $stats->appendRecentTime(0.001, 100);
}
$stats->avgExecutionTime = 0.001;
$stats->maxExecutionTime = 0.001;
$stats->minExecutionTime = 0.001;
$m->recordMetric('timeouts-a-lot', 0.2, 10, false, timeout: false, agentHandler: $agent);
$types = array_map(static fn (SecurityEvent $e): string => $e->eventType, $agent->events);
$t->truthy(in_array(EventTypes::EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY, $types, true), 'statistical anomaly event type');
$t->truthy(in_array(EventTypes::EVENT_PATTERN_ANOMALY_SLOW_EXECUTION, $types, true), 'slow anomaly rides alongside the statistical one');

$t->section('send failures are logged, never raised, reservation kept');
$agent = new RecordingAgent();
$agent->failNext = true;
$clock = 3000.0;
$m = new PerformanceMonitor(slowPatternThreshold: 0.01, minSamplesForAnomaly: 10, clock: static function () use (&$clock): float {
    return $clock;
});
$m->recordMetric('failing-send', 0.5, 10, false, agentHandler: $agent);
$t->same(0, count($agent->events), 'failed send recorded nothing');
$clock += 30.0;
$agent->failNext = false;
$m->recordMetric('failing-send', 0.5, 10, false, agentHandler: $agent);
$t->same(0, count($agent->events), 'second anomaly still inside the cooldown despite the failed send');
$clock += 31.0;
$m->recordMetric('failing-send', 0.5, 10, false, agentHandler: $agent);
$t->same(1, count($agent->events), 'a later send succeeds after the cooldown');

$t->section('sanitized callback data and callback error events');
$agent = new RecordingAgent();
$clock = 4000.0;
$m = new PerformanceMonitor(slowPatternThreshold: 0.01, minSamplesForAnomaly: 10, clock: static function () use (&$clock): float {
    return $clock;
});
$received = [];
$m->registerAnomalyCallback(static function (array $anomaly) use (&$received): void {
    $received[] = $anomaly;
});
$m->registerAnomalyCallback(static function (array $anomaly): void {
    throw new RuntimeException('callback exploded');
});
$m->recordMetric(str_repeat('x', 120), 0.5, 10, false, agentHandler: $agent);
$t->same(1, count($received), 'callbacks receive every anomaly');
$t->truthy(mb_strlen((string) $received[0]['pattern']) <= 53, 'callback pattern sanitized to 50 chars');
$t->truthy(str_ends_with($received[0]['pattern'], '...'), 'sanitized pattern truncation marker');
$t->truthy(isset($received[0]['pattern_hash']) && strlen((string) $received[0]['pattern_hash']) === 8, 'sanitized pattern hash present');
$t->same(2, count($agent->events), 'the anomaly event plus the callback error event');
$t->same(EventTypes::EVENT_PATTERN_ANOMALY_SLOW_EXECUTION, $agent->events[0]->eventType, 'the anomaly event itself went through first');
$t->same(EventTypes::EVENT_DETECTION_ENGINE_CALLBACK_ERROR, $agent->events[1]->eventType, 'callback error event type');
$t->same('logged', $agent->events[1]->actionTaken, 'callback error action');
$t->truthy(str_contains($agent->events[1]->reason, 'callback exploded'), 'callback error carries the reason');

$t->section('callbacks run without an agent handler');
$m = new PerformanceMonitor(slowPatternThreshold: 0.01, minSamplesForAnomaly: 10);
$seen = [];
$m->registerAnomalyCallback(static function (array $anomaly) use (&$seen): void {
    $seen[] = $anomaly['type'];
});
$m->recordMetric('no-agent', 0.5, 10, false);
$t->same(['slow_execution'], $seen, 'callbacks still notified without an agent handler');

// ---------------------------------------------------------------------
// 5. Reporting surface
// ---------------------------------------------------------------------

$t->section('pattern report');
$stats = new PatternStats('report-me');
$stats->totalExecutions = 10;
$stats->totalMatches = 4;
$stats->totalTimeouts = 2;
$stats->avgExecutionTime = 0.0123456;
$stats->maxExecutionTime = 0.5;
$stats->minExecutionTime = INF;
$report = MonitorReporting::buildPatternReport('report-me', $stats);
$t->same('report-me', $report['pattern'], 'report pattern');
$t->truthy(isset($report['pattern_hash']) && strlen((string) $report['pattern_hash']) === 8, 'report pattern hash');
$t->same(0.4, $report['match_rate'], 'match rate');
$t->same(0.2, $report['timeout_rate'], 'timeout rate');
$t->same(0.0123, $report['avg_execution_time'], 'avg rounded to 4');
$t->same(0.5, $report['max_execution_time'], 'max rounded');
$t->same(0.0, $report['min_execution_time'], 'infinite min reported as 0.0');

$t->section('problematic and slow patterns');
$m = new PerformanceMonitor(slowPatternThreshold: 0.01, minSamplesForAnomaly: 10);
for ($i = 0; $i < 10; $i++) {
    $m->recordMetric('timeout-heavy', 0.001, 10, false, timeout: $i < 3);
}
for ($i = 0; $i < 10; $i++) {
    $m->recordMetric('always-slow', 0.5, 10, false);
}
$m->recordMetric('healthy', 0.001, 10, false);
$problematic = $m->getProblematicPatterns();
$issues = [];
foreach ($problematic as $report) {
    $issues[$report['pattern']] = $report['issue'];
}
$t->same('high_timeout_rate', $issues['timeout-heavy'], 'timeout rate over 0.1 flags high_timeout_rate');
$t->same('consistently_slow', $issues['always-slow'], 'avg over the slow threshold flags consistently_slow');
$t->truthy(!isset($issues['healthy']), 'healthy pattern not flagged');
$m->recordMetric('matchy', 0.9, 10, true);
$m->recordMetric('matchy', 0.3, 10, false);
$slow = $m->getSlowPatterns(1);
$t->same('matchy', $slow[0]['pattern'], 'slow patterns ordered by avg execution time');

$t->section('summary stats');
$m->clearStats();
$t->same(MonitorReporting::emptySummary(), (new PerformanceMonitor())->getSummaryStats(), 'empty monitor yields the empty summary');
$m = new PerformanceMonitor(minSamplesForAnomaly: 10);
$m->recordMetric('s', 0.4, 10, true);
$m->recordMetric('s', 0.2, 10, false, timeout: true);
$summary = $m->getSummaryStats();
$t->same(2, $summary['total_executions'], 'summary total');
$t->same(1, $summary['total_patterns'], 'summary pattern count');
$t->same(0.5, $summary['timeout_rate'], 'summary timeout rate');
$t->same(0.5, $summary['match_rate'], 'summary match rate');
$t->same(0.4, $summary['avg_execution_time'], 'summary avg over non-timeout samples');
$t->same(0.4, $summary['max_execution_time'], 'summary max');
$t->same(0.4, $summary['min_execution_time'], 'summary min');
$m->removePatternStats('s');
$t->truthy(!isset($m->patternStats['s']), 'removePatternStats drops the pattern');

$t->section('untracked pattern report');
$t->same(null, (new PerformanceMonitor())->getPatternReport('nope'), 'untracked pattern has no report');

// ---------------------------------------------------------------------
// 6. Engine integration: metrics recorded through detect()
// ---------------------------------------------------------------------

$t->section('suspatterns records per-pattern and overall metrics');
$factory = new CheckFactory(
    new RenzoFranceschini\GuardCore\Request\GuardResponseFactory(),
    new RenzoFranceschini\GuardCore\Routing\RouteResolver()
);
$config = new RenzoFranceschini\GuardCore\Config\SecurityConfig();
$check = $factory->buildChecks($config);
$susCheck = null;
foreach ($check as $c) {
    if ($c->checkName() === 'suspicious_activity') {
        $susCheck = $c;
        break;
    }
}
$t->truthy($susCheck !== null, 'suspicious activity check built');
$m = new PerformanceMonitor(minSamplesForAnomaly: 10);
$susPatterns = new SusPatterns(0.7, $m);
$detection = $susPatterns->detect("1' OR '1'='1", '203.0.113.7', 'query_param');
$t->truthy($detection['is_threat'], 'detection verdict unchanged with the monitor attached');
$t->truthy(isset($m->patternStats['overall_detection']), 'overall_detection metric recorded');
$t->truthy(count($m->patternStats) > 1, 'per-pattern metrics recorded');
$report = $m->getPatternReport('overall_detection');
$t->truthy($report !== null && $report['total_executions'] >= 1, 'overall report available');


// ---------------------------------------------------------------------
// 7. Remaining monitor arms
// ---------------------------------------------------------------------

$t->section('timeout-only pattern keeps its average');
$m = new PerformanceMonitor(minSamplesForAnomaly: 10);
$m->recordMetric('timeout-only', 0.3, 10, false, timeout: true);
$stats = $m->patternStats['timeout-only'];
$t->same(0.0, $stats->avgExecutionTime, 'no recent times means the average stays 0.0');

$t->section('pattern report truncation');
$m = new PerformanceMonitor(minSamplesForAnomaly: 10);
$longPattern = str_repeat('y', 150);
$m->recordMetric($longPattern, 0.2, 10, false);
$report = $m->getPatternReport($longPattern);
$t->truthy($report !== null, 'the truncated key resolves the report');
$t->truthy(str_ends_with((string) $report['pattern'], '...'), 'report pattern truncated');

$t->section('cooldown reservation query');
$m = new PerformanceMonitor(anomalyEmissionCooldown: 60.0, slowPatternThreshold: 0.01, minSamplesForAnomaly: 10, clock: static fn (): float => 100.0);
$t->truthy($m->reserveAnomalyEmission('never-recorded'), 'an untracked pattern reserves freely');
$m->recordMetric('reserved', 0.5, 10, false);
$t->truthy($m->reserveAnomalyEmission('reserved'), 'the reservation from record expired instantly on the injected clock');
$m2 = new PerformanceMonitor(anomalyEmissionCooldown: 60.0, slowPatternThreshold: 0.01, minSamplesForAnomaly: 10, clock: static fn (): float => 2000.0);
$m2->recordMetric('reserved', 0.5, 10, false, agentHandler: new RecordingAgent());
$t->truthy(!$m2->reserveAnomalyEmission('reserved'), 'a fresh reservation blocks inside the cooldown');

$t->section('callback error send failure is swallowed');
$agent = new RecordingAgent();
$agent->alwaysFail = true;
$m = new PerformanceMonitor(slowPatternThreshold: 0.01, minSamplesForAnomaly: 10, clock: static fn (): float => 3000.0);
$m->registerAnomalyCallback(static function (array $anomaly): void {
    throw new RuntimeException('callback exploded');
});
$m->recordMetric('double-failure', 0.5, 10, false, agentHandler: $agent);
$t->same(0, count($agent->events), 'both sends failed and nothing propagated');

$t->section('problematic patterns skip unexecuted stats');
$m = new PerformanceMonitor(slowPatternThreshold: 0.01, minSamplesForAnomaly: 10);
$m->patternStats['empty'] = new PatternStats('empty');
$t->same([], $m->getProblematicPatterns(), 'a zero-execution pattern is not flagged');

$t->section('statistical anomaly degenerate arms');
$oneSample = new PatternStats('p');
$oneSample->appendRecentTime(0.5, 100);
$t->same(null, MonitorAnomalies::detectStatisticalAnomaly(new PerformanceMetric('p', 0.9, 10, $now, false), $oneSample, 1, 3.0), 'a single sample has no variance');
$constant = new PatternStats('p');
for ($i = 0; $i < 40; $i++) {
    $constant->appendRecentTime(0.001, 100);
}
$t->same(null, MonitorAnomalies::detectStatisticalAnomaly(new PerformanceMetric('p', 0.9, 10, $now, false), $constant, 30, 3.0), 'zero variance yields no anomaly');

$t->section('unknown anomaly type rejected');
$threw = false;
try {
    MonitorAnomalies::buildAnomalyEventData(['type' => 'nope'], null);
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'an unknown anomaly type cannot build an event');

exit($t->finish('PERFORMANCE MONITOR'));

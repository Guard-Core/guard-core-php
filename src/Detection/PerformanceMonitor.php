<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Events\SecurityEvent;

/**
 * The pattern performance monitor, ported from the reference monitor.py
 * (spec 04 "Performance monitoring"): per-pattern statistics over a bounded
 * recent window, the anomaly-detection trio, per-pattern cooldown-gated
 * agent emission, always-sanitized callbacks, and the reporting surface.
 *
 * Normative constants with their clamps (monitor.py __init__):
 * anomaly_threshold 3.0 [1, 10], slow_pattern_threshold 0.1 [0.01, 10],
 * history_size 1000 [100, 10000], max_tracked_patterns 1000 [100, 5000],
 * anomaly_emission_cooldown 60.0 [1, 3600], min_samples_for_anomaly 30
 * [10, 1000], recent_times window 100 = max(min_samples, 100).
 *
 * PHP runtime model: the reference guards its state with an asyncio lock;
 * PHP request execution is single-threaded, so the lock is unnecessary.
 * The monitor is per-request state in classic FPM (specs/impl/php.md) and
 * per-worker state under long-lived runtimes. Tracking keys truncate
 * patterns over 100 chars to pattern[:100] + "...[truncated]"; timeout
 * metrics never enter recent_times; tracking evicts FIFO at
 * max_tracked_patterns. The $clock injection point (monotonic seconds)
 * exists for tests; the default is hrtime.
 */
final class PerformanceMonitor
{
    private const MAX_PATTERN_LENGTH = 100;

    public float $anomalyThreshold;

    public float $slowPatternThreshold;

    public int $historySize;

    public int $maxTrackedPatterns;

    public float $anomalyEmissionCooldown;

    public int $minSamplesForAnomaly;

    private int $recentTimesMaxlen;

    /** @var array<string, PatternStats> */
    public array $patternStats = [];

    /** @var list<PerformanceMetric> */
    public array $recentMetrics = [];

    /** @var list<callable(array<string, mixed>): void> */
    public array $anomalyCallbacks = [];

    /** @var \Closure(): float */
    private \Closure $clock;

    public function __construct(
        float $anomalyThreshold = 3.0,
        float $slowPatternThreshold = 0.1,
        int $historySize = 1000,
        int $maxTrackedPatterns = 1000,
        float $anomalyEmissionCooldown = 60.0,
        int $minSamplesForAnomaly = 30,
        ?\Closure $clock = null
    ) {
        $this->anomalyThreshold = max(1.0, min(10.0, $anomalyThreshold));
        $this->slowPatternThreshold = max(0.01, min(10.0, $slowPatternThreshold));
        $this->historySize = max(100, min(10000, $historySize));
        $this->maxTrackedPatterns = max(100, min(5000, $maxTrackedPatterns));
        $this->anomalyEmissionCooldown = max(1.0, min(3600.0, $anomalyEmissionCooldown));
        $this->minSamplesForAnomaly = max(10, min(1000, $minSamplesForAnomaly));
        $this->recentTimesMaxlen = max($this->minSamplesForAnomaly, PatternStats::DEFAULT_RECENT_TIMES_WINDOW);
        $this->clock = $clock ?? static fn (): float => hrtime(true) / 1e9;
    }

    public function registerAnomalyCallback(callable $callback): void
    {
        $this->anomalyCallbacks[] = $callback;
    }

    /**
     * The agent handler is duck-typed: anything with sendEvent(object) works,
     * mirroring the reference's AgentHandlerProtocol.
     */
    public function recordMetric(
        string $pattern,
        float $executionTime,
        int $contentLength,
        bool $matched,
        bool $timeout = false,
        ?object $agentHandler = null,
        ?string $correlationId = null
    ): void {
        if (mb_strlen($pattern) > self::MAX_PATTERN_LENGTH) {
            $pattern = mb_substr($pattern, 0, self::MAX_PATTERN_LENGTH) . '...[truncated]';
        }
        $executionTime = max(0.0, $executionTime);
        $contentLength = max(0, $contentLength);

        $metric = new PerformanceMetric(
            pattern: $pattern,
            executionTime: $executionTime,
            contentLength: $contentLength,
            timestamp: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            matched: $matched,
            timeout: $timeout
        );

        $this->recentMetrics[] = $metric;
        if (count($this->recentMetrics) > $this->historySize) {
            array_shift($this->recentMetrics);
        }

        if (!isset($this->patternStats[$pattern])) {
            if (count($this->patternStats) >= $this->maxTrackedPatterns) {
                $oldest = array_key_first($this->patternStats);
                unset($this->patternStats[$oldest]);
            }
            $this->patternStats[$pattern] = new PatternStats($pattern);
        }

        $stats = $this->patternStats[$pattern];
        $stats->totalExecutions++;
        if ($matched) {
            $stats->totalMatches++;
        }
        if ($timeout) {
            $stats->totalTimeouts++;
        } else {
            $stats->appendRecentTime($executionTime, $this->recentTimesMaxlen);
            $stats->maxExecutionTime = max($stats->maxExecutionTime, $executionTime);
            $stats->minExecutionTime = min($stats->minExecutionTime, $executionTime);
            // appendRecentTime guarantees a non-empty window.
            $stats->avgExecutionTime = MonitorReporting::fsum($stats->recentTimes) / count($stats->recentTimes);
        }

        $statisticalAnomaly = MonitorAnomalies::detectStatisticalAnomaly(
            $metric,
            $stats,
            $this->minSamplesForAnomaly,
            $this->anomalyThreshold
        );

        $this->checkAnomalies($metric, $statisticalAnomaly, $agentHandler, $correlationId);
    }

    public function getPatternReport(string $pattern): ?array
    {
        if (mb_strlen($pattern) > self::MAX_PATTERN_LENGTH) {
            $pattern = mb_substr($pattern, 0, self::MAX_PATTERN_LENGTH) . '...[truncated]';
        }
        $stats = $this->patternStats[$pattern] ?? null;
        if ($stats === null) {
            return null;
        }

        return MonitorReporting::buildPatternReport($pattern, $stats);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function getSlowPatterns(int $limit = 10): array
    {
        return MonitorReporting::collectSlowPatterns($this->patternStats, $limit);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function getProblematicPatterns(): array
    {
        return MonitorReporting::collectProblematicPatterns($this->patternStats, $this->slowPatternThreshold);
    }

    /**
     * @return array<string, mixed>
     */
    public function getSummaryStats(): array
    {
        if ($this->recentMetrics === []) {
            return MonitorReporting::emptySummary();
        }

        [$recentTimes, $timeouts, $matches] = MonitorReporting::extractMetricComponents($this->recentMetrics);

        return MonitorReporting::buildSummaryDict(
            count($this->recentMetrics),
            count($this->patternStats),
            $recentTimes,
            $timeouts,
            $matches
        );
    }

    public function clearStats(): void
    {
        $this->patternStats = [];
        $this->recentMetrics = [];
    }

    public function removePatternStats(string $pattern): void
    {
        unset($this->patternStats[$pattern]);
    }

    /**
     * The cooldown reservation is taken even when the send then fails.
     */
    public function reserveAnomalyEmission(string $pattern): bool
    {
        $now = ($this->clock)();
        $stats = $this->patternStats[$pattern] ?? null;
        if ($stats === null) {
            return true;
        }
        if ($stats->lastAnomalyEmittedAt !== null
            && $now - $stats->lastAnomalyEmittedAt < $this->anomalyEmissionCooldown) {
            return false;
        }
        $stats->lastAnomalyEmittedAt = $now;

        return true;
    }

    /**
     * @param array<string, mixed>|null $statisticalAnomaly
     */
    private function checkAnomalies(PerformanceMetric $metric, ?array $statisticalAnomaly, ?object $agentHandler, ?string $correlationId): void
    {
        $anomalies = [];

        $timeoutAnomaly = MonitorAnomalies::detectTimeoutAnomaly($metric);
        if ($timeoutAnomaly !== null) {
            $anomalies[] = $timeoutAnomaly;
        } else {
            $slowAnomaly = MonitorAnomalies::detectSlowExecutionAnomaly($metric, $this->slowPatternThreshold);
            if ($slowAnomaly !== null) {
                $anomalies[] = $slowAnomaly;
            }
        }
        if ($statisticalAnomaly !== null) {
            $anomalies[] = $statisticalAnomaly;
        }

        if ($agentHandler !== null && $anomalies !== [] && $this->reserveAnomalyEmission($metric->pattern)) {
            foreach ($anomalies as $anomaly) {
                $this->sendAnomalyEvent($anomaly, $agentHandler, $correlationId);
            }
        }

        foreach ($anomalies as $anomaly) {
            $this->notifyCallbacks($anomaly, $agentHandler, $correlationId);
        }
    }

    /**
     * @param array<string, mixed> $anomaly
     */
    private function sendAnomalyEvent(array $anomaly, object $agentHandler, ?string $correlationId): void
    {
        $event = MonitorAnomalies::buildAnomalyEventData($anomaly, $correlationId);
        try {
            $agentHandler->sendEvent($event);
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to send anomaly event to agent: ' . $e->getMessage());
        }
    }

    /**
     * Callbacks always receive sanitized anomaly data; a callback error
     * becomes a callback_error event and never propagates.
     *
     * @param array<string, mixed> $anomaly
     */
    private function notifyCallbacks(array $anomaly, ?object $agentHandler, ?string $correlationId): void
    {
        $safeAnomaly = MonitorAnomalies::sanitizeAnomalyData($anomaly);
        foreach ($this->anomalyCallbacks as $callback) {
            try {
                $callback($safeAnomaly);
            } catch (\Throwable $e) {
                if ($agentHandler !== null) {
                    $this->sendCallbackErrorEvent($e, $safeAnomaly, $agentHandler, $correlationId);
                }
            }
        }
    }

    /**
     * @param array<string, mixed> $safeAnomaly
     */
    private function sendCallbackErrorEvent(\Throwable $error, array $safeAnomaly, object $agentHandler, ?string $correlationId): void
    {
        $event = MonitorAnomalies::buildCallbackErrorEventData($error, $safeAnomaly, $correlationId);
        try {
            $agentHandler->sendEvent($event);
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to send anomaly event to agent: ' . $e->getMessage());
        }
    }
}

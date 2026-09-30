<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;

/**
 * The anomaly-detection trio and the anomaly event builders, ported from
 * monitor_anomalies.py:
 *
 * 1. timeout - the scan timed out;
 * 2. slow_execution - not a timeout and execution time over the slow
 *    threshold (only checked when there is no timeout anomaly);
 * 3. statistical_anomaly - the execution time's z-score over the pattern's
 *    recent non-timeout times exceeds the threshold; requires at least
 *    min_samples_for_anomaly samples (and >= 2 for variance).
 *
 * Sanitized anomaly data redacts the pattern source to a 50-char prefix
 * plus an 8-char pattern_hash. The reference's _redact_pattern_source
 * (sensitive-field scanning) is not ported; the reference hash is
 * process-randomized and spec 04 marks it diagnostic-only, so the port
 * hashes deterministically instead.
 */
final class MonitorAnomalies
{
    /**
     * @return array<string, mixed>|null
     */
    public static function detectTimeoutAnomaly(PerformanceMetric $metric): ?array
    {
        if ($metric->timeout) {
            return [
                'type' => 'timeout',
                'pattern' => $metric->pattern,
                'content_length' => $metric->contentLength,
            ];
        }

        return null;
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function detectSlowExecutionAnomaly(PerformanceMetric $metric, float $slowPatternThreshold): ?array
    {
        if (!$metric->timeout && $metric->executionTime > $slowPatternThreshold) {
            return [
                'type' => 'slow_execution',
                'pattern' => $metric->pattern,
                'execution_time' => $metric->executionTime,
                'content_length' => $metric->contentLength,
            ];
        }

        return null;
    }

    /**
     * @param PatternStats|null $stats
     * @return array<string, mixed>|null
     */
    public static function detectStatisticalAnomaly(
        PerformanceMetric $metric,
        ?PatternStats $stats,
        int $minSamplesForAnomaly,
        float $anomalyThreshold
    ): ?array {
        if ($stats === null || count($stats->recentTimes) < $minSamplesForAnomaly) {
            return null;
        }
        $recentTimes = $stats->recentTimes;
        $sampleCount = count($recentTimes);
        if ($sampleCount < 2) {
            return null;
        }
        $avgTime = MonitorReporting::fsum($recentTimes) / $sampleCount;
        if ($anomalyThreshold >= 0 && $metric->executionTime <= $avgTime) {
            return null;
        }
        $variance = 0.0;
        foreach ($recentTimes as $t) {
            $variance += ($t - $avgTime) ** 2;
        }
        $variance /= ($sampleCount - 1);
        $stdTime = sqrt($variance);
        if ($stdTime <= 0) {
            return null;
        }
        $zScore = ($metric->executionTime - $avgTime) / $stdTime;
        if ($zScore > $anomalyThreshold) {
            return [
                'type' => 'statistical_anomaly',
                'pattern' => $metric->pattern,
                'execution_time' => $metric->executionTime,
                'z_score' => $zScore,
                'avg_time' => $avgTime,
                'std_time' => $stdTime,
            ];
        }

        return null;
    }

    /**
     * Callbacks always receive sanitized data: the pattern redacted to a
     * 50-char prefix plus an 8-char pattern_hash.
     *
     * @param array<string, mixed> $anomaly
     * @return array<string, mixed>
     */
    public static function sanitizeAnomalyData(array $anomaly): array
    {
        $safeAnomaly = $anomaly;
        if (array_key_exists('pattern', $safeAnomaly)) {
            $pattern = (string) $safeAnomaly['pattern'];
            $truncated = mb_strlen($pattern) > 50
                ? mb_substr($pattern, 0, 50) . '...'
                : $pattern;
            $safeAnomaly['pattern'] = $truncated;
            $safeAnomaly['pattern_hash'] = substr(md5($truncated), 0, 8);
        }

        return $safeAnomaly;
    }

    /**
     * @param array<string, mixed> $anomaly
     */
    public static function buildAnomalyEventData(array $anomaly, ?string $correlationId): SecurityEvent
    {
        $eventType = match ($anomaly['type']) {
            'timeout' => EventTypes::EVENT_PATTERN_ANOMALY_TIMEOUT,
            'slow_execution' => EventTypes::EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
            'statistical_anomaly' => EventTypes::EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
            default => throw new \InvalidArgumentException('unknown anomaly type'),
        };
        $safeAnomaly = $anomaly;
        if (array_key_exists('pattern', $safeAnomaly)) {
            $safeAnomaly['pattern'] = (string) $safeAnomaly['pattern'];
        }

        return new SecurityEvent(
            timestamp: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            eventType: $eventType,
            ipAddress: 'system',
            actionTaken: 'anomaly_detected',
            reason: "Pattern performance anomaly: {$anomaly['type']}",
            handlerName: null,
            metadata: [
                'component' => 'PerformanceMonitor',
                'correlation_id' => $correlationId,
                ...$safeAnomaly,
            ]
        );
    }

    /**
     * @param array<string, mixed> $safeAnomaly
     */
    public static function buildCallbackErrorEventData(\Throwable $error, array $safeAnomaly, ?string $correlationId): SecurityEvent
    {
        return new SecurityEvent(
            timestamp: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            eventType: EventTypes::EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
            ipAddress: 'system',
            actionTaken: 'logged',
            reason: 'Anomaly callback failed: ' . $error->getMessage(),
            handlerName: null,
            metadata: [
                'component' => 'PerformanceMonitor',
                'correlation_id' => $correlationId,
                'callback_error' => $error->getMessage(),
                'anomaly_type' => $safeAnomaly['type'] ?? 'unknown',
            ]
        );
    }
}

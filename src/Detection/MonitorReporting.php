<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * Monitor reporting, ported from monitor_reporting.py: per-pattern reports
 * (totals, rates, recent-window times), the problematic-pattern flags
 * (timeout rate > 0.1 -> high_timeout_rate, avg time over the slow
 * threshold -> consistently_slow), the top-N slow patterns, and the
 * summary over the recent history.
 */
final class MonitorReporting
{
    /**
     * Python math.fsum: exactly rounded summation (Neumaier compensated
     * sum). The statistical-anomaly verdict and the reported averages read
     * these sums, and naive accumulation changes the zero-variance verdict
     * on constant samples, so the exact algorithm is normative here.
     *
     * @param list<float> $values
     */
    public static function fsum(array $values): float
    {
        $sum = 0.0;
        $compensation = 0.0;
        foreach ($values as $value) {
            $next = $sum + $value;
            if (abs($sum) >= abs($value)) {
                $compensation += ($sum - $next) + $value;
            } else {
                $compensation += ($value - $next) + $sum;
            }
            $sum = $next;
        }

        return $sum + $compensation;
    }

    /**
     * @return array<string, mixed>
     */
    public static function buildPatternReport(string $pattern, PatternStats $stats): array
    {
        $safePattern = mb_strlen($pattern) > 50 ? mb_substr($pattern, 0, 50) . '...' : $pattern;

        return [
            'pattern' => $safePattern,
            'pattern_hash' => substr(md5($pattern), 0, 8),
            'total_executions' => $stats->totalExecutions,
            'total_matches' => $stats->totalMatches,
            'total_timeouts' => $stats->totalTimeouts,
            'match_rate' => $stats->totalMatches / max($stats->totalExecutions, 1),
            'timeout_rate' => $stats->totalTimeouts / max($stats->totalExecutions, 1),
            'avg_execution_time' => round($stats->avgExecutionTime, 4),
            'max_execution_time' => round($stats->maxExecutionTime, 4),
            'min_execution_time' => round(
                $stats->minExecutionTime === INF ? 0.0 : $stats->minExecutionTime,
                4
            ),
        ];
    }

    /**
     * @param array<string, PatternStats> $patternStats
     * @return list<array<string, mixed>>
     */
    public static function collectSlowPatterns(array $patternStats, int $limit): array
    {
        $patternsWithTimes = [];
        foreach ($patternStats as $pattern => $stats) {
            if ($stats->recentTimes !== []) {
                $patternsWithTimes[$pattern] = $stats->avgExecutionTime;
            }
        }
        arsort($patternsWithTimes);
        $reports = [];
        foreach (array_slice(array_keys($patternsWithTimes), 0, $limit, true) as $pattern) {
            $reports[] = self::buildPatternReport((string) $pattern, $patternStats[$pattern]);
        }

        return $reports;
    }

    /**
     * @param array<string, PatternStats> $patternStats
     * @return list<array<string, mixed>>
     */
    public static function collectProblematicPatterns(array $patternStats, float $slowPatternThreshold): array
    {
        $problematic = [];
        foreach ($patternStats as $pattern => $stats) {
            if ($stats->totalExecutions === 0) {
                continue;
            }
            $timeoutRate = $stats->totalTimeouts / $stats->totalExecutions;
            if ($timeoutRate > 0.1) {
                $report = self::buildPatternReport((string) $pattern, $stats);
                $report['issue'] = 'high_timeout_rate';
                $problematic[] = $report;
            } elseif ($stats->avgExecutionTime > $slowPatternThreshold) {
                $report = self::buildPatternReport((string) $pattern, $stats);
                $report['issue'] = 'consistently_slow';
                $problematic[] = $report;
            }
        }

        return $problematic;
    }

    /**
     * @return array<string, mixed>
     */
    public static function emptySummary(): array
    {
        return [
            'total_executions' => 0,
            'avg_execution_time' => 0.0,
            'timeout_rate' => 0.0,
            'match_rate' => 0.0,
        ];
    }

    /**
     * @param list<PerformanceMetric> $recentMetrics
     * @return array{0: list<float>, 1: int, 2: int}
     */
    public static function extractMetricComponents(array $recentMetrics): array
    {
        $recentTimes = [];
        $timeouts = 0;
        $matches = 0;
        foreach ($recentMetrics as $metric) {
            if (!$metric->timeout) {
                $recentTimes[] = $metric->executionTime;
            } else {
                $timeouts++;
            }
            if ($metric->matched) {
                $matches++;
            }
        }

        return [$recentTimes, $timeouts, $matches];
    }

    /**
     * @param list<float> $recentTimes
     * @return array<string, mixed>
     */
    public static function buildSummaryDict(int $totalMetrics, int $totalPatterns, array $recentTimes, int $timeouts, int $matches): array
    {
        return [
            'total_executions' => $totalMetrics,
            'avg_execution_time' => $recentTimes === [] ? 0.0 : self::fsum($recentTimes) / count($recentTimes),
            'max_execution_time' => $recentTimes === [] ? 0.0 : max($recentTimes),
            'min_execution_time' => $recentTimes === [] ? 0.0 : min($recentTimes),
            'timeout_rate' => $timeouts / $totalMetrics,
            'match_rate' => $matches / $totalMetrics,
            'total_patterns' => $totalPatterns,
        ];
    }
}

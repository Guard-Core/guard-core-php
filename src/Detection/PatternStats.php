<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * Per-pattern statistics, ported from monitor_types.py PatternStats. The
 * recent-times window is a bounded FIFO deque of at most
 * DEFAULT_RECENT_TIMES_WINDOW samples; timeout samples never enter it.
 */
final class PatternStats
{
    public const DEFAULT_RECENT_TIMES_WINDOW = 100;

    public float $avgExecutionTime = 0.0;

    public float $maxExecutionTime = 0.0;

    public float $minExecutionTime = INF;

    public int $totalExecutions = 0;

    public int $totalMatches = 0;

    public int $totalTimeouts = 0;

    public ?float $lastAnomalyEmittedAt = null;

    /** @var list<float> */
    public array $recentTimes = [];

    public function __construct(public readonly string $pattern)
    {
    }

    /** Deque append: bounded by $maxlen, oldest dropped. */
    public function appendRecentTime(float $time, int $maxlen): void
    {
        $this->recentTimes[] = $time;
        if (count($this->recentTimes) > $maxlen) {
            array_shift($this->recentTimes);
        }
    }
}

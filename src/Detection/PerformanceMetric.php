<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection;

/**
 * One measured scan, ported from monitor_types.py PerformanceMetric.
 */
final class PerformanceMetric
{
    public function __construct(
        public readonly string $pattern,
        public readonly float $executionTime,
        public readonly int $contentLength,
        public readonly \DateTimeImmutable $timestamp,
        public readonly bool $matched,
        public readonly bool $timeout = false
    ) {
    }
}

<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * The metric envelope, ported from the reference SecurityMetric telemetry
 * model (spec 12 "Metric envelope"): timestamp, metric_type, value, tags.
 */
final class SecurityMetric
{
    /**
     * @param array<string, string> $tags
     */
    public function __construct(
        public readonly \DateTimeImmutable $timestamp,
        public readonly string $metricType,
        public readonly float $value,
        public readonly array $tags = []
    ) {
    }
}

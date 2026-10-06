<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;

/**
 * The enrichment dependency bag, ported from the reference enricher.py
 * EnrichmentContext. PHP has no import-time optional dependencies here: the
 * dynamic rule handler and the behavior tracker are duck-typed collaborators
 * (matchEvent / getRecentEventCount), and the optional clock makes the
 * behavior-bucket correlation deterministic in tests. The agent handler is
 * carried for surface parity; the enricher itself never calls it (the
 * reference only enriches, sending stays the bus/composite's job).
 */
final class EnrichmentContext
{
    /** @var (\Closure(): float)|null */
    private readonly ?\Closure $clock;

    /**
     * @param (\Closure(): float)|null $clock unix-seconds float provider; defaults to microtime(true)
     */
    public function __construct(
        public readonly SecurityConfig $config,
        public readonly ?object $agentHandler = null,
        public readonly ?object $dynamicRuleHandler = null,
        public readonly ?object $behaviorTracker = null,
        ?\Closure $clock = null
    ) {
        $this->clock = $clock;
    }

    public function now(): float
    {
        return $this->clock !== null ? ($this->clock)() : microtime(true);
    }
}

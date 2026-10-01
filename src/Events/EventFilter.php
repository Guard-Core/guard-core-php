<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * Suppresses events and metrics by exact identifier, ported from
 * event_types.py EventFilter.
 */
final class EventFilter
{
    /** @var array<string, true> */
    private array $mutedEventTypes;

    /** @var array<string, true> */
    private array $mutedMetricTypes;

    /**
     * @param list<string> $mutedEventTypes
     * @param list<string> $mutedMetricTypes
     */
    public function __construct(array $mutedEventTypes = [], array $mutedMetricTypes = [])
    {
        $this->mutedEventTypes = array_fill_keys($mutedEventTypes, true);
        $this->mutedMetricTypes = array_fill_keys($mutedMetricTypes, true);
    }

    public function isEventAllowed(string $eventType): bool
    {
        return !isset($this->mutedEventTypes[$eventType]);
    }

    public function isMetricAllowed(string $metricType): bool
    {
        return !isset($this->mutedMetricTypes[$metricType]);
    }
}

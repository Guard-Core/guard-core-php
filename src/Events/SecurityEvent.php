<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * The security event envelope, ported from the reference's SecurityEvent
 * telemetry model (spec 12 "Event envelope fields"): the bus and the
 * handler-direct emitters build this record and forward it one-way to the
 * agent handler. Send failures are logged, never raised.
 */
final class SecurityEvent
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly \DateTimeImmutable $timestamp,
        public readonly string $eventType,
        public readonly string $ipAddress,
        public readonly ?string $country = null,
        public readonly ?string $userAgent = null,
        public readonly string $actionTaken = '',
        public readonly string $reason = '',
        public readonly ?string $endpoint = null,
        public readonly ?string $method = null,
        public readonly ?float $responseTime = null,
        public readonly ?string $decoratorType = null,
        public readonly ?string $ruleType = null,
        public readonly ?string $handlerName = null,
        public readonly array $metadata = []
    ) {
    }
}

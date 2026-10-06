<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;

/**
 * The event/metric enrichment pass, ported from the reference enricher.py
 * EventEnricher (spec: the guard.* metadata family). Four steps, always in
 * this order, any failure logs and leaves the input unenriched:
 *
 *  1. identity (project id when configured, service name always,
 *     deployment.environment when present in otel_resource_attributes)
 *  2. deterministic threat score from the event_type
 *  3. dynamic-rule correlation (rule id + version via matchEvent)
 *  4. behavior correlation (recent event count over the 300s window plus a
 *     privacy-preserving sha256(ip|service|bucket)[:16] correlation key)
 *
 * PHP divergence from the reference: SecurityEvent/SecurityMetric are
 * immutable records, so enrichment returns a copy carrying the enriched
 * metadata/tags instead of mutating in place; the composite handler sends
 * the returned instance to every sink. Enrichment is synchronous here (the
 * collaborators are plain calls, not coroutines).
 */
final class EventEnricher
{
    public const BEHAVIOR_CORRELATION_WINDOW_SECONDS = 300;

    public function __construct(private readonly EnrichmentContext $context)
    {
    }

    public function enrichEvent(SecurityEvent $event): SecurityEvent
    {
        try {
            $metadata = $event->metadata;
            $this->applyIdentity($metadata);
            $this->applyThreatScore($event, $metadata);
            $this->applyRuleCorrelation($event, $metadata);
            $this->applyBehaviorCorrelation($event, $metadata);
            if ($metadata === $event->metadata) {
                return $event;
            }

            return new SecurityEvent(
                timestamp: $event->timestamp,
                eventType: $event->eventType,
                ipAddress: $event->ipAddress,
                country: $event->country,
                userAgent: $event->userAgent,
                actionTaken: $event->actionTaken,
                reason: $event->reason,
                endpoint: $event->endpoint,
                method: $event->method,
                responseTime: $event->responseTime,
                decoratorType: $event->decoratorType,
                ruleType: $event->ruleType,
                handlerName: $event->handlerName,
                metadata: $metadata
            );
        } catch (\Throwable $e) {
            error_log('[guard_core.enricher] event enrichment failed; event will be sent unenriched: ' . $e->getMessage());

            return $event;
        }
    }

    public function enrichMetric(SecurityMetric $metric): SecurityMetric
    {
        try {
            $tags = $metric->tags;
            $this->applyIdentity($tags);
            if ($tags === $metric->tags) {
                return $metric;
            }

            return new SecurityMetric(
                timestamp: $metric->timestamp,
                metricType: $metric->metricType,
                value: $metric->value,
                tags: $tags
            );
        } catch (\Throwable $e) {
            error_log('[guard_core.enricher] metric enrichment failed; metric will be sent unenriched: ' . $e->getMessage());

            return $metric;
        }
    }

    /**
     * Mirrors _apply_identity: the bag always gains guard.service.name;
     * guard.project_id and guard.deployment.environment only when
     * configured.
     *
     * @param array<string, mixed> $bag
     */
    private function applyIdentity(array &$bag): void
    {
        $config = $this->context->config;
        if ($config->agentProjectId !== null && $config->agentProjectId !== '') {
            $bag[EventTypes::ENRICHMENT_KEY_PROJECT_ID] = $config->agentProjectId;
        }
        $bag[EventTypes::ENRICHMENT_KEY_SERVICE_NAME] = $config->otelServiceName;
        $env = $config->otelResourceAttributes['deployment.environment'] ?? null;
        if ($env !== null && $env !== '') {
            $bag[EventTypes::ENRICHMENT_KEY_DEPLOYMENT_ENV] = $env;
        }
    }

    /**
     * @param array<string, mixed> $bag
     */
    private function applyThreatScore(SecurityEvent $event, array &$bag): void
    {
        if ($event->eventType === '') {
            return;
        }
        $bag[EventTypes::ENRICHMENT_KEY_THREAT_SCORE] = ThreatScorer::scoreFor($event->eventType);
    }

    /**
     * Mirrors _apply_rule_correlation: the handler is optional and
     * duck-typed (method matchEvent returning [ruleId, version] or null).
     *
     * @param array<string, mixed> $bag
     */
    private function applyRuleCorrelation(SecurityEvent $event, array &$bag): void
    {
        $ruleHandler = $this->context->dynamicRuleHandler;
        if ($ruleHandler === null || !method_exists($ruleHandler, 'matchEvent')) {
            return;
        }
        $match = $ruleHandler->matchEvent($event);
        if ($match === null) {
            return;
        }
        $bag[EventTypes::ENRICHMENT_KEY_RULE_ID] = $match[0];
        $bag[EventTypes::ENRICHMENT_KEY_RULE_VERSION] = $match[1];
    }

    /**
     * Mirrors _apply_behavior_correlation: the tracker is optional and
     * duck-typed (method getRecentEventCount(ip, windowSeconds)); the
     * correlation key hashes ip|service|floor(time/window) and truncates to
     * 16 hex chars so the IP never reaches the wire.
     *
     * @param array<string, mixed> $bag
     */
    private function applyBehaviorCorrelation(SecurityEvent $event, array &$bag): void
    {
        $tracker = $this->context->behaviorTracker;
        $ip = $event->ipAddress;
        if ($tracker === null || $ip === '') {
            return;
        }
        if (!method_exists($tracker, 'getRecentEventCount')) {
            return;
        }
        $windowSeconds = self::BEHAVIOR_CORRELATION_WINDOW_SECONDS;
        $count = $tracker->getRecentEventCount($ip, $windowSeconds);
        $bag[EventTypes::ENRICHMENT_KEY_RECENT_EVENT_COUNT] = $count;
        $bucket = (int) floor($this->context->now() / $windowSeconds);
        $service = $this->context->config->otelServiceName;
        $bag[EventTypes::ENRICHMENT_KEY_BEHAVIOR_KEY] = substr(
            hash('sha256', $ip . '|' . $service . '|' . $bucket),
            0,
            16
        );
    }
}

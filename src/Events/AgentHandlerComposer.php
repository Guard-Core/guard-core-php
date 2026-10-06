<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;

/**
 * The agent-handler assembly seam, ported from the reference
 * handler_initializer.py build_enricher + build_composite_handler: the
 * sink list is [agent handler] + OtelHandler (enable_otel) + LogfireHandler
 * (enable_logfire), the enricher is built when enable_enrichment is set and
 * wired into the composite so every sink observes the same enriched
 * instance.
 *
 * The collaborators stay duck-typed and optional: the dynamic rule handler
 * needs matchEvent, the behavior tracker needs getRecentEventCount
 * (GuardCore's own BehaviorTracker implements both shapes). When
 * enable_enrichment is true but no tracker is supplied, enrichment still
 * runs - identity and threat score apply, behavior correlation is skipped
 * (the reference falls back to constructing its own tracker; the PHP
 * tracker needs redis/ban wiring the engine owns, so the fallback is the
 * caller's job here).
 */
final class AgentHandlerComposer
{
    public static function compose(
        SecurityConfig $config,
        ?object $agentHandler = null,
        ?object $dynamicRuleHandler = null,
        ?object $behaviorTracker = null,
        ?EventFilter $eventFilter = null,
        ?OtlpTransport $otelTransport = null,
        ?object $logfireClient = null,
        ?\Closure $clock = null
    ): CompositeAgentHandler {
        $handlers = [];
        if ($agentHandler !== null) {
            $handlers[] = $agentHandler;
        }
        if ($config->enableOtel) {
            $handlers[] = new OtelHandler($config, $otelTransport ?? new OtlpHttpTransport());
        }
        if ($config->enableLogfire) {
            $handlers[] = new LogfireHandler($config, $logfireClient);
        }
        $enricher = null;
        if ($config->enableEnrichment) {
            $enricher = new EventEnricher(new EnrichmentContext(
                config: $config,
                agentHandler: $agentHandler,
                dynamicRuleHandler: $dynamicRuleHandler,
                behaviorTracker: $behaviorTracker,
                clock: $clock
            ));
        }

        return new CompositeAgentHandler($handlers, $eventFilter, $enricher);
    }
}

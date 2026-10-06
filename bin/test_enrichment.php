<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Behavior\BehaviorTracker;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\AgentHandlerComposer;
use RenzoFranceschini\GuardCore\Events\CompositeAgentHandler;
use RenzoFranceschini\GuardCore\Events\EnrichmentContext;
use RenzoFranceschini\GuardCore\Events\EventEnricher;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\Events\SecurityMetric;
use RenzoFranceschini\GuardCore\Events\ThreatScorer;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

require __DIR__ . '/../vendor/autoload.php';

// B2 parity: the EventEnricher/ThreatScorer enrichment layer (reference
// core/events/enricher.py + event_types.py ENRICHMENT_KEY_*): the
// deterministic threat-score map, the guard.* identity stamping, the
// dynamic-rule and behavior correlations, the unenriched-on-failure
// semantics, and the enrichment keys' exact strings. The composite fan-out
// test lives in bin/test_composite_handlers.php; this suite also drives the
// engine event bus through a composed composite end to end.
//
// Run: php bin/test_enrichment.php

final class EnrichT
{
    public int $passed = 0;

    public int $failed = 0;

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
            echo '  expected: ' . var_export($expected, true) . "\n";
            echo '  actual:   ' . var_export($actual, true) . "\n";
        }
    }

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }

    public function finish(string $label): int
    {
        echo "\n{$label}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed === 0 ? 0 : 1;
    }
}

final class RuleHandlerFake
{
    /** @var list<object> */
    public array $asked = [];

    public function __construct(private readonly ?array $match = null)
    {
    }

    /**
     * @return array{0: string, 1: string}|null
     */
    public function matchEvent(object $event): ?array
    {
        $this->asked[] = $event;

        return $this->match;
    }
}

final class TrackerFake
{
    public function __construct(private readonly int $count = 0)
    {
    }

    public function getRecentEventCount(string $ip, int $windowSeconds): int
    {
        return $this->count;
    }
}

final class ExplodingTracker
{
    public function getRecentEventCount(string $ip, int $windowSeconds): int
    {
        throw new RuntimeException('tracker exploded');
    }
}

function enrichEvent(string $eventType = EventTypes::EVENT_IP_BLOCKED, string $ip = '203.0.113.7'): SecurityEvent
{
    return new SecurityEvent(
        timestamp: new DateTimeImmutable('2026-10-06T00:00:00Z'),
        eventType: $eventType,
        ipAddress: $ip,
        actionTaken: 'request_blocked',
        reason: 'denied',
        endpoint: '/pay',
        method: 'POST',
    );
}

$t = new EnrichT();

// ---------------------------------------------------------------------
// 1. Enrichment key constants
// ---------------------------------------------------------------------

$t->section('enrichment keys');
$t->same('guard.project_id', EventTypes::ENRICHMENT_KEY_PROJECT_ID, 'project id key');
$t->same('guard.service.name', EventTypes::ENRICHMENT_KEY_SERVICE_NAME, 'service name key');
$t->same('guard.deployment.environment', EventTypes::ENRICHMENT_KEY_DEPLOYMENT_ENV, 'deployment env key');
$t->same('guard.threat_score', EventTypes::ENRICHMENT_KEY_THREAT_SCORE, 'threat score key');
$t->same('guard.rule.id', EventTypes::ENRICHMENT_KEY_RULE_ID, 'rule id key');
$t->same('guard.rule.version', EventTypes::ENRICHMENT_KEY_RULE_VERSION, 'rule version key');
$t->same('guard.behavior.correlation_key', EventTypes::ENRICHMENT_KEY_BEHAVIOR_KEY, 'behavior key');
$t->same('guard.behavior.recent_event_count', EventTypes::ENRICHMENT_KEY_RECENT_EVENT_COUNT, 'recent count key');

// ---------------------------------------------------------------------
// 2. ThreatScorer
// ---------------------------------------------------------------------

$t->section('threat scorer');
$t->same(90, ThreatScorer::scoreFor(EventTypes::EVENT_PENETRATION_ATTEMPT), 'penetration attempt scores 90');
$t->same(70, ThreatScorer::scoreFor(EventTypes::EVENT_IP_BANNED), 'ip banned scores 70');
$t->same(60, ThreatScorer::scoreFor(EventTypes::EVENT_EMERGENCY_MODE), 'emergency mode scores 60');
$t->same(50, ThreatScorer::scoreFor(EventTypes::EVENT_IP_BLOCKED), 'ip blocked scores 50');
$t->same(50, ThreatScorer::scoreFor(EventTypes::EVENT_BEHAVIOR_VIOLATION), 'behavior violation scores 50');
$t->same(50, ThreatScorer::scoreFor(EventTypes::EVENT_SUSPICIOUS_REQUEST), 'suspicious request scores 50');
$t->same(40, ThreatScorer::scoreFor(EventTypes::EVENT_REDIS_ERROR), 'redis error scores 40');
$t->same(40, ThreatScorer::scoreFor(EventTypes::EVENT_PATTERN_ANOMALY_TIMEOUT), 'pattern anomaly timeout scores 40');
$t->same(30, ThreatScorer::scoreFor(EventTypes::EVENT_ACCESS_DENIED), 'access denied scores 30');
$t->same(30, ThreatScorer::scoreFor(EventTypes::EVENT_USER_AGENT_BLOCKED), 'user agent blocked scores 30');
$t->same(20, ThreatScorer::scoreFor(EventTypes::EVENT_RATE_LIMITED), 'rate limited scores 20');
$t->same(10, ThreatScorer::scoreFor(EventTypes::EVENT_IP_UNBANNED), 'ip unbanned scores 10');
$t->same(10, ThreatScorer::scoreFor(EventTypes::EVENT_SECURITY_HEADERS_APPLIED), 'headers applied scores 10');
$t->same(20, ThreatScorer::scoreFor('totally_unknown_type'), 'unknown types take the default 20');
$allMapped = true;
foreach (EventTypes::EVENT_TYPE_VALUES as $type) {
    if (ThreatScorer::scoreFor($type) < 10 || ThreatScorer::scoreFor($type) > 90) {
        $allMapped = false;
    }
}
$t->truthy($allMapped, 'every known event type carries a 10-90 score');

// ---------------------------------------------------------------------
// 3. Identity stamping
// ---------------------------------------------------------------------

$t->section('identity');
$plainConfig = new SecurityConfig();
$plainEnricher = new EventEnricher(new EnrichmentContext(config: $plainConfig));
$enriched = $plainEnricher->enrichEvent(enrichEvent());
$t->same('guard-core', $enriched->metadata[EventTypes::ENRICHMENT_KEY_SERVICE_NAME], 'service name always stamped');
$t->truthy(!isset($enriched->metadata[EventTypes::ENRICHMENT_KEY_PROJECT_ID]), 'no project id when unset');
$t->truthy(!isset($enriched->metadata[EventTypes::ENRICHMENT_KEY_DEPLOYMENT_ENV]), 'no deployment env by default');

$identityConfig = new SecurityConfig(
    agentProjectId: 'proj-42',
    otelServiceName: 'checkout-api',
    otelResourceAttributes: ['deployment.environment' => 'production', 'service.version' => '4.3.1']
);
$identityEnricher = new EventEnricher(new EnrichmentContext(config: $identityConfig));
$enriched = $identityEnricher->enrichEvent(enrichEvent());
$t->same('proj-42', $enriched->metadata[EventTypes::ENRICHMENT_KEY_PROJECT_ID], 'project id stamped when configured');
$t->same('checkout-api', $enriched->metadata[EventTypes::ENRICHMENT_KEY_SERVICE_NAME], 'configured service name stamped');
$t->same('production', $enriched->metadata[EventTypes::ENRICHMENT_KEY_DEPLOYMENT_ENV], 'deployment env stamped from resource attributes');
$t->truthy(!isset($identityEnricher->enrichEvent(enrichEvent())->metadata['service.version']), 'non-guard resource attributes stay out of the bag');

$metricEnriched = $identityEnricher->enrichMetric(new SecurityMetric(
    timestamp: new DateTimeImmutable('2026-10-06T00:00:00Z'),
    metricType: EventTypes::METRIC_RESPONSE_TIME,
    value: 0.25,
    tags: ['endpoint' => '/pay']
));
$t->same('proj-42', $metricEnriched->tags[EventTypes::ENRICHMENT_KEY_PROJECT_ID] ?? null, 'metric tags get project id');
$t->same('checkout-api', $metricEnriched->tags[EventTypes::ENRICHMENT_KEY_SERVICE_NAME] ?? null, 'metric tags get service name');
$t->truthy(!isset($metricEnriched->tags[EventTypes::ENRICHMENT_KEY_THREAT_SCORE]), 'metrics carry no threat score');

// ---------------------------------------------------------------------
// 4. Threat score + rule correlation
// ---------------------------------------------------------------------

$t->section('threat score + rule correlation');
$enriched = $plainEnricher->enrichEvent(enrichEvent(EventTypes::EVENT_PENETRATION_ATTEMPT));
$t->same(90, $enriched->metadata[EventTypes::ENRICHMENT_KEY_THREAT_SCORE], 'threat score follows the event type');

$ruleEnricher = new EventEnricher(new EnrichmentContext(
    config: $plainConfig,
    dynamicRuleHandler: new RuleHandlerFake(['rule-7', 'v3'])
));
$enriched = $ruleEnricher->enrichEvent(enrichEvent());
$t->same('rule-7', $enriched->metadata[EventTypes::ENRICHMENT_KEY_RULE_ID], 'rule id stamped on match');
$t->same('v3', $enriched->metadata[EventTypes::ENRICHMENT_KEY_RULE_VERSION], 'rule version stamped on match');

$nullMatchEnricher = new EventEnricher(new EnrichmentContext(
    config: $plainConfig,
    dynamicRuleHandler: new RuleHandlerFake(null)
));
$enriched = $nullMatchEnricher->enrichEvent(enrichEvent());
$t->truthy(!isset($enriched->metadata[EventTypes::ENRICHMENT_KEY_RULE_ID]), 'null match leaves rule keys out');

$duckMissing = new EventEnricher(new EnrichmentContext(config: $plainConfig, dynamicRuleHandler: new stdClass()));
$enriched = $duckMissing->enrichEvent(enrichEvent());
$t->truthy(!isset($enriched->metadata[EventTypes::ENRICHMENT_KEY_RULE_ID]), 'handler without matchEvent is skipped (duck-typed)');

// ---------------------------------------------------------------------
// 5. Behavior correlation
// ---------------------------------------------------------------------

$t->section('behavior correlation');
$clock = static fn (): float => 1_000_000.0;
$trackerEnricher = new EventEnricher(new EnrichmentContext(
    config: new SecurityConfig(otelServiceName: 'svc'),
    behaviorTracker: new TrackerFake(7),
    clock: $clock
));
$enriched = $trackerEnricher->enrichEvent(enrichEvent(ip: '198.51.100.9'));
$t->same(7, $enriched->metadata[EventTypes::ENRICHMENT_KEY_RECENT_EVENT_COUNT], 'recent event count stamped from the tracker');
$expectedKey = substr(hash('sha256', '198.51.100.9|svc|' . (int) floor(1_000_000.0 / 300)), 0, 16);
$t->same($expectedKey, $enriched->metadata[EventTypes::ENRICHMENT_KEY_BEHAVIOR_KEY], 'correlation key is sha256(ip|service|bucket)[:16]');

$enriched = $trackerEnricher->enrichEvent(enrichEvent(ip: ''));
$t->truthy(!isset($enriched->metadata[EventTypes::ENRICHMENT_KEY_RECENT_EVENT_COUNT]), 'empty ip skips behavior correlation');

$noTracker = new EventEnricher(new EnrichmentContext(config: $plainConfig, clock: $clock));
$enriched = $noTracker->enrichEvent(enrichEvent());
$t->truthy(!isset($enriched->metadata[EventTypes::ENRICHMENT_KEY_RECENT_EVENT_COUNT]), 'no tracker skips behavior correlation');

$noMethod = new EventEnricher(new EnrichmentContext(config: $plainConfig, behaviorTracker: new stdClass(), clock: $clock));
$enriched = $noMethod->enrichEvent(enrichEvent());
$t->truthy(!isset($enriched->metadata[EventTypes::ENRICHMENT_KEY_RECENT_EVENT_COUNT]), 'tracker without getRecentEventCount is skipped');

$exploding = new EventEnricher(new EnrichmentContext(config: $identityConfig, behaviorTracker: new ExplodingTracker()));
$input = enrichEvent();
$enriched = $exploding->enrichEvent($input);
$t->same($input, $enriched, 'correlation failure returns the event unenriched (atomic copy semantics)');

// ---------------------------------------------------------------------
// 6. BehaviorTracker.getRecentEventCount
// ---------------------------------------------------------------------

$t->section('behavior tracker recent counts');
$trackerConfig = new SecurityConfig();
$tracker = new BehaviorTracker($trackerConfig, null, null);
$rule = new RenzoFranceschini\GuardCore\Behavior\BehaviorRule('usage', 5, 60);
$tracker->trackEndpointUsage('/a', '203.0.113.7', $rule, 100.0);
$tracker->trackEndpointUsage('/b', '203.0.113.7', $rule, 200.0);
$tracker->trackEndpointUsage('/a', '203.0.113.8', $rule, 150.0);
$t->same(2, $tracker->getRecentEventCount('203.0.113.7', 300, 250.0), 'counts across endpoint buckets in window');
$t->same(1, $tracker->getRecentEventCount('203.0.113.7', 60, 250.0), 'stale hits fall outside the window');
$t->same(0, $tracker->getRecentEventCount('', 300, 250.0), 'empty ip counts zero');
$t->same(0, $tracker->getRecentEventCount('9.9.9.9', 300, 250.0), 'unknown ip counts zero');

// ---------------------------------------------------------------------
// 7. End to end: engine bus -> composed composite -> enriched sink
// ---------------------------------------------------------------------

$t->section('engine bus through the composite');

final class CaptureSink
{
    /** @var list<SecurityEvent> */
    public array $events = [];

    public function sendEvent(SecurityEvent $event): void
    {
        $this->events[] = $event;
    }

    public function healthCheck(): bool
    {
        return true;
    }
}

$engineConfig = new SecurityConfig(blacklist: ['203.0.113.99']);
$engine = new GuardEngine($engineConfig);
$sink = new CaptureSink();
$composite = AgentHandlerComposer::compose(
    new SecurityConfig(enableEnrichment: true, otelServiceName: 'edge-svc'),
    agentHandler: $sink,
    behaviorTracker: new TrackerFake(3),
    clock: static fn (): float => 5_000.0
);
$engine->setAgentHandler($composite);
$blocked = new SimpleGuardRequest(method: 'GET', urlPath: '/data', headers: [], clientHost: '203.0.113.99');
$engine->execute($blocked);
$t->same(1, count($sink->events), 'blocked request emitted exactly one event');
$emitted = $sink->events[0] ?? null;
$t->truthy($emitted !== null && isset($emitted->metadata[EventTypes::ENRICHMENT_KEY_THREAT_SCORE]), 'emitted event carries a threat score');
$t->truthy($emitted !== null && ($emitted->metadata[EventTypes::ENRICHMENT_KEY_THREAT_SCORE] ?? 0) === ThreatScorer::scoreFor($emitted->eventType), 'emitted threat score matches the event type map');
$t->truthy($emitted !== null && ($emitted->metadata[EventTypes::ENRICHMENT_KEY_SERVICE_NAME] ?? '') === 'edge-svc', 'emitted event carries the service name');
$t->truthy($emitted !== null && ($emitted->metadata[EventTypes::ENRICHMENT_KEY_RECENT_EVENT_COUNT] ?? 0) === 3, 'emitted event carries the tracker count');

// The plain (non-composite) handler path stays enrichment-free, exactly
// like the reference where enrichment lives in the composite only.
$bareSink = new CaptureSink();
$bareEngine = new GuardEngine(new SecurityConfig(blacklist: ['203.0.113.99']));
$bareEngine->setAgentHandler($bareSink);
$bareEngine->execute(new SimpleGuardRequest(method: 'GET', urlPath: '/data', headers: [], clientHost: '203.0.113.99'));
$t->truthy(isset($bareSink->events[0]) && !isset($bareSink->events[0]->metadata[EventTypes::ENRICHMENT_KEY_THREAT_SCORE]), 'bare handler path stays unenriched');

// ---------------------------------------------------------------------
// 8. Composer wiring
// ---------------------------------------------------------------------

$t->section('composer wiring');
$compositeOnlyAgent = AgentHandlerComposer::compose(new SecurityConfig(), agentHandler: $sink);
$t->truthy($compositeOnlyAgent instanceof CompositeAgentHandler, 'composer returns a composite');
$full = AgentHandlerComposer::compose(
    new SecurityConfig(enableEnrichment: true, enableOtel: true, enableLogfire: true),
    agentHandler: $sink,
    logfireClient: new class {
        public function configured(): bool
        {
            return false;
        }

        public function configure(string $serviceName): void
        {
        }

        public function span(string $name, array $attributes): void
        {
        }

        public function info(string $template, array $fields): void
        {
        }

        public function shutdown(): void
        {
        }
    }
);
$t->truthy($full->healthCheck(), 'composed handler chain reports healthy');

exit($t->finish('enrichment'));

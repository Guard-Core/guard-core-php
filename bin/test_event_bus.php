<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventFilter;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\MetricsCollector;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\Events\SecurityMetric;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Rules\DynamicRuleManager;
use RenzoFranceschini\GuardCore\Rules\DynamicRules;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/FakeRespConnection.php';

// Spec 12: the security event bus (envelope, gating, trace forwarding,
// queueable delivery), the metrics collector, and the dynamic-rules
// surface with its transactional (fail-closed) application, last-known
// persistence and hydration, and the event correlation.

final class BusT
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

final class BusAgent
{
    /** @var list<object> */
    public array $received = [];

    public bool $alwaysFail = false;

    public function sendEvent(object $event): void
    {
        if ($this->alwaysFail) {
            throw new RuntimeException('agent down');
        }
        $this->received[] = $event;
    }

    /** @var list<SecurityMetric> */
    public array $metrics = [];

    public function sendMetric(SecurityMetric $metric): void
    {
        if ($this->alwaysFail) {
            throw new RuntimeException('agent down');
        }
        $this->metrics[] = $metric;
    }
}

function busRequest(string $path = '/pay?secret=1', string $method = 'POST'): SimpleGuardRequest
{
    return new SimpleGuardRequest(
        method: $method,
        urlPath: $path,
        headers: [
            'user-agent' => 'test-agent/1.0',
            'traceparent' => '00-trace-span-01',
        ],
        clientHost: '203.0.113.7'
    );
}

$t = new BusT();
$config = new SecurityConfig();

// ---------------------------------------------------------------------
// 1. Event bus gating and queueing
// ---------------------------------------------------------------------

$t->section('event bus gating');
$bus = new EventBus(null, $config);
$bus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, busRequest(), 'request_blocked', 'ip denied');
$t->same(1, count($bus->drain()), 'events queue with no handler attached');

$quietConfig = new SecurityConfig(agentEnableEvents: false);
$quietBus = new EventBus(new BusAgent(), $quietConfig);
$quietBus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, busRequest(), 'request_blocked', 'denied');
$t->same([], $quietBus->drain(), 'agent_enable_events false drops events');

$filteredAgent = new BusAgent();
$filteredBus = new EventBus($filteredAgent, $config, new EventFilter(mutedEventTypes: [EventTypes::EVENT_IP_BLOCKED]));
$filteredBus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, busRequest(), 'request_blocked', 'denied');
$filteredBus->sendMiddlewareEvent(EventTypes::EVENT_RATE_LIMITED, busRequest(), 'request_blocked', 'rate');
$filteredTypes = array_map(static fn (object $e): string => $e->eventType, $filteredAgent->received);
$t->truthy(!in_array(EventTypes::EVENT_IP_BLOCKED, $filteredTypes, true), 'muted event types drop their own type');
$t->truthy(in_array(EventTypes::EVENT_RATE_LIMITED, $filteredTypes, true), 'unmuted events still flow');

$t->section('event envelope and trace forwarding');
$agent = new BusAgent();
$bus = new EventBus($agent, $config, countryResolver: static fn (string $ip): ?string => $ip === '203.0.113.7' ? 'US' : null);
$bus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, busRequest(), 'request_blocked', 'ip denied', ['check_name' => 'ip_security']);
$t->same(1, count($agent->received), 'event delivered');
$event = $agent->received[0];
$t->truthy($event instanceof SecurityEvent, 'SecurityEvent envelope');
$t->same(EventTypes::EVENT_IP_BLOCKED, $event->eventType, 'event type');
$t->same('203.0.113.7', $event->ipAddress, 'client ip');
$t->same('US', $event->country, 'country resolved');
$t->same('request_blocked', $event->actionTaken, 'action taken');
$t->same('ip denied', $event->reason, 'reason');
$t->truthy(str_contains((string) $event->endpoint, '/pay'), 'endpoint path (redacted)');
$t->same('POST', $event->method, 'method');
$t->same('middleware', $event->handlerName, 'bus handler name');
$t->same('00-trace-span-01', $event->metadata['traceparent'], 'trace header forwarded');
$t->truthy(!isset($event->metadata['tracestate']), 'absent trace header not invented');
$t->truthy(str_contains((string) $event->reason, 'ip denied'), 'reason sanity');

$t->section('country lookup failure still sends');
$agent = new BusAgent();
$bus = new EventBus($agent, $config, countryResolver: static function (string $ip): ?string {
    throw new RuntimeException('geo down');
});
$bus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, busRequest(), 'request_blocked', 'denied');
$t->same(1, count($agent->received), 'the event still sends');
$t->same(null, $agent->received[0]->country, 'country null on lookup failure');

$t->section('send failures are logged, never raised');
$agent = new BusAgent();
$agent->alwaysFail = true;
$bus = new EventBus($agent, $config);
$bus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, busRequest(), 'request_blocked', 'denied');
$t->same(0, count($agent->received), 'failed send recorded nothing');

$t->section('handler attach flushes the queue');
$bus = new EventBus(null, $config);
$bus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, busRequest(), 'request_blocked', 'one');
$bus->sendMiddlewareEvent(EventTypes::EVENT_RATE_LIMITED, busRequest(), 'request_blocked', 'two');
$agent = new BusAgent();
$bus->setAgentHandler($agent);
$t->same(2, count($agent->received), 'queued events flushed on attach');
$t->same([], $bus->drain(), 'queue drained by the flush');

// ---------------------------------------------------------------------
// 2. HTTPS violation dispatch
// ---------------------------------------------------------------------

$t->section('https violation dispatch');
$agent = new BusAgent();
$bus = new EventBus($agent, $config);
$routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig(requireHttps: true);
$bus->sendHttpsViolationEvent(busRequest('/x', 'GET'), $routeConfig);
$t->same(EventTypes::EVENT_DECORATOR_VIOLATION, $agent->received[0]->eventType, 'route-level require_https is a decorator violation');
$t->same('authentication', $agent->received[0]->metadata['decorator_type'], 'decorator type');
$t->same('require_https', $agent->received[0]->metadata['violation_type'], 'violation type');
$bus->sendHttpsViolationEvent(busRequest('/x', 'GET'), null);
$t->same(EventTypes::EVENT_HTTPS_ENFORCED, $agent->received[1]->eventType, 'global enforcement event type');
$t->truthy(str_starts_with((string) $agent->received[1]->metadata['redirect_url'], 'https://'), 'redirect url https-swapped');

// ---------------------------------------------------------------------
// 3. Metrics collector
// ---------------------------------------------------------------------

$t->section('metrics collector');
$agent = new BusAgent();
$collector = new MetricsCollector($agent, $config);
$collector->collectRequestMetrics(busRequest('/orders'), 0.125, 503);
$t->same(3, count($agent->metrics), 'three metrics per errored response');
$t->same(EventTypes::METRIC_RESPONSE_TIME, $agent->metrics[0]->metricType, 'response_time metric');
$t->same(0.125, $agent->metrics[0]->value, 'response_time value');
$t->same('503', $agent->metrics[0]->tags['status'], 'response_time status tag');
$t->truthy(str_contains($agent->metrics[0]->tags['endpoint'], '/orders'), 'response_time endpoint tag');
$t->same(EventTypes::METRIC_REQUEST_COUNT, $agent->metrics[1]->metricType, 'request_count metric');
$t->same(1.0, $agent->metrics[1]->value, 'request_count value');
$t->same(EventTypes::METRIC_ERROR_RATE, $agent->metrics[2]->metricType, 'error_rate metric on 5xx');
$agent->metrics = [];
$collector->collectRequestMetrics(busRequest('/orders'), 0.01, 200);
$t->same(2, count($agent->metrics), 'no error_rate on a 2xx');

$t->section('metrics gating and filtering');
$quietCollector = new MetricsCollector(new BusAgent(), new SecurityConfig(agentEnableMetrics: false));
$quietCollector->collectRequestMetrics(busRequest(), 0.01, 200);
$t->same(0, count($quietCollector->drain()), 'agent_enable_metrics false drops metrics');
$mutedAgent = new BusAgent();
$mutedCollector = new MetricsCollector($mutedAgent, $config, new EventFilter(mutedMetricTypes: [EventTypes::METRIC_ERROR_RATE]));
$mutedCollector->collectRequestMetrics(busRequest(), 0.01, 500);
$types = array_map(static fn (SecurityMetric $m): string => $m->metricType, $mutedAgent->metrics);
$t->truthy(!in_array(EventTypes::METRIC_ERROR_RATE, $types, true), 'muted metric types drop their own type');
$t->truthy(in_array(EventTypes::METRIC_RESPONSE_TIME, $types, true), 'unmuted metrics still flow');
$queuedCollector = new MetricsCollector(null, $config);
$queuedCollector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$t->same(1, count($queuedCollector->drain()), 'metrics queue with no handler');
$failingAgent = new BusAgent();
$failingAgent->alwaysFail = true;
$failCollector = new MetricsCollector($failingAgent, $config);
$failCollector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$t->same(0, count($failingAgent->metrics), 'failed metric send recorded nothing');

// ---------------------------------------------------------------------
// 4. Dynamic rules DTO and snapshot
// ---------------------------------------------------------------------

$t->section('dynamic rules parse');
$rules = DynamicRules::fromArray([
    'rule_id' => 'r-1',
    'version' => 3,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'ip_blacklist' => ['10.0.0.1'],
    'blocked_countries' => ['br', 'ru'],
    'global_rate_limit' => 100,
    'global_rate_window' => 60,
    'endpoint_rate_limits' => ['/api' => [5, 60]],
    'emergency_mode' => true,
]);
$t->same('r-1', $rules->ruleId, 'rule id');
$t->same(3, $rules->version, 'version');
$t->same(['BR', 'RU'], $rules->blockedCountries, 'country codes upper-cased');
$t->same(['/api' => [5, 60]], $rules->endpointRateLimits, 'endpoint rate limits');
$t->truthy($rules->emergencyMode, 'emergency mode');
$threw = false;
try {
    DynamicRules::fromArray(['version' => 1, 'timestamp' => '2026-01-01T00:00:00+00:00']);
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'missing rule_id rejected');

$t->section('snapshot round trip and strictness');
$snapshot = $rules->dumpSnapshot();
$restored = DynamicRules::loadSnapshot($snapshot);
$t->same($rules->ruleId, $restored->ruleId, 'snapshot round trip id');
$t->same($rules->blockedCountries, $restored->blockedCountries, 'snapshot round trip countries');
$t->same(DynamicRules::LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION, 1, 'snapshot schema version pinned');
$threw = false;
try {
    DynamicRules::loadSnapshot((string) json_encode(['schema_version' => 99, 'rules' => []]));
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'wrong schema version rejected');
$threw = false;
try {
    DynamicRules::loadSnapshot((string) json_encode(['schema_version' => 1, 'rules' => ['nonsense_field' => 1]]));
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'unknown snapshot fields rejected');

// ---------------------------------------------------------------------
// 5. Dynamic rule manager
// ---------------------------------------------------------------------

$t->section('update flow gates');
$config = new SecurityConfig(enableDynamicRules: true);
$agent = new BusAgent();
$logs = [];
$logger = static function (string $level, string $message) use (&$logs): void {
    $logs[] = $level . ': ' . $message;
};
$clock = 1700000000;
$manager = new DynamicRuleManager(
    config: $config,
    agentHandler: null,
    eventBus: new EventBus($agent, $config),
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->same([], $agent->received, 'no agent handler means no fetch');

$payloadAgent = new class {
    public array $rules = [];

    public function getDynamicRules(): ?array
    {
        return $this->rules;
    }
};
$manager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($agent, $config),
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->same([], $agent->received, 'an empty payload is a no-op');

$t->section('staleness gate and transactional apply');
$payloadAgent->rules = [
    'rule_id' => 'rule-a',
    'version' => 1,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'global_rate_limit' => 5,
];
$installed = [];
$manager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($agent, $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->same(1, count($installed), 'first rule installed');
$t->same(5, $installed[0]->rateLimit, 'global rate limit applied');
$t->truthy($manager->currentRules() !== null && $manager->currentRules()->ruleId === 'rule-a', 'current rules recorded');
$types = array_map(static fn (object $e): string => $e->eventType, $agent->received);
$t->truthy(in_array(EventTypes::EVENT_DYNAMIC_RULE_UPDATED, $types, true), 'dynamic_rule_updated emitted');
$t->truthy(in_array(EventTypes::EVENT_DYNAMIC_RULE_APPLIED, $types, true), 'dynamic_rule_applied emitted');

$agent->received = [];
$payloadAgent->rules = ['rule_id' => 'rule-a', 'version' => 1, 'timestamp' => '2026-01-01T00:00:00+00:00', 'global_rate_limit' => 9];
$manager->updateRules();
$t->same([], $agent->received, 'same id and version is stale, nothing applied');

$t->section('fail-closed application');
$payloadAgent->rules = [
    'rule_id' => 'rule-bad',
    'version' => 2,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'blocked_countries' => ['BR'],
];
$installed = [];
$manager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($agent, $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->truthy(count($installed) <= 1, 'at most the base snapshot was re-installed (never the candidate)');
$t->truthy(count($installed) === 0 || $installed[count($installed) - 1]->blockedCountries === [], 'the currently installed config is the base (fail closed)');
$t->truthy($manager->currentRules() === null, 'failed application leaves no current rules');
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'Failed to apply dynamic rules')), 'the failure is logged');

$t->section('ip, country, cloud and ua rule application');
$geoConfig = new SecurityConfig(enableDynamicRules: true, geoIpDbPath: 'country.mmdb');
$payloadAgent->rules = [
    'rule_id' => 'rule-full',
    'version' => 3,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'ip_blacklist' => ['10.0.0.9'],
    'blocked_countries' => ['br'],
    'blocked_cloud_providers' => ['AWS'],
    'blocked_user_agents' => ['[a-z]+bot'],
    'auto_ban_threshold' => 10,
];
$installed = [];
$manager = new DynamicRuleManager(
    config: $geoConfig,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($agent, $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->truthy(in_array('10.0.0.9', $installed[0]->blacklist, true), 'ip blacklist merged');
$t->truthy(in_array('BR', $installed[0]->blockedCountries, true), 'countries applied');
$t->truthy(in_array('AWS', $installed[0]->blockCloudProviders, true), 'cloud providers applied');
$t->truthy(in_array('[a-z]+bot', $installed[0]->blockedUserAgents, true), 'validated user-agent patterns applied');

$t->section('redos-validated user-agent patterns are rejected with a warning');
$payloadAgent->rules = [
    'rule_id' => 'rule-redos',
    'version' => 4,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'blocked_user_agents' => ['(.+)+'],
];
$installed = [];
$logs = [];
$manager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($agent, $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->truthy(!isset($installed[0]) || $installed[0]->blockedUserAgents === [], 'the catastrophic pattern is rejected');
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'Rejected blocked_user_agents pattern')), 'the rejection is warned');

$t->section('emergency mode halves the auto-ban threshold');
$payloadAgent->rules = [
    'rule_id' => 'rule-emergency',
    'version' => 5,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'expires_at' => '2040-01-01T00:00:00+00:00',
    'emergency_mode' => true,
    'emergency_whitelist' => ['10.0.0.1', '10.0.0.2'],
    'auto_ban_threshold' => 10,
];
$installed = [];
$manager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($agent, $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->truthy($installed[0]->emergencyMode, 'emergency mode applied');
$t->same(['10.0.0.1', '10.0.0.2'], $installed[0]->emergencyWhitelist, 'emergency whitelist applied');
$t->same(5, $installed[0]->autoBanThreshold, 'auto-ban threshold halved');
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'Emergency lockdown')), 'emergency lockdown logged');

$t->section('expiry restores the base config');
$clock += 700000000;
$manager->updateRules();
$t->truthy($manager->currentRules() === null, 'expired rule cleared');
$installed = [];
$payloadAgent->rules = [
    'rule_id' => 'rule-emergency',
    'version' => 6,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'emergency_mode' => false,
    'auto_ban_threshold' => 10,
];
$manager->updateRules();
$t->truthy(!isset($installed[0]) || !$installed[0]->emergencyMode, 'base config restored on expiry');
$t->same(10, $installed[0]->autoBanThreshold ?? 0, 'base auto-ban threshold restored');

$t->section('already-expired payloads are ignored');
$agent->received = [];
$payloadAgent->rules = [
    'rule_id' => 'rule-late',
    'version' => 9,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'expires_at' => '2020-01-01T00:00:00+00:00',
    'global_rate_limit' => 3,
];
$installed = [];
$manager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($agent, $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->same([], $installed, 'an already-expired payload applies nothing');
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'already expired on receipt')), 'the skip is warned once');

// ---------------------------------------------------------------------
// 6. Last-known persistence and hydration (redis fail-closed)
// ---------------------------------------------------------------------

$t->section('last-known persistence and hydration');
$fake = new FakeRespConnection();
$redis = new RedisHandler(true, 'guard_core_rules:', connection: $fake);
$cachePath = tempnam(sys_get_temp_dir(), 'dynrules');
$payloadAgent->rules = [
    'rule_id' => 'rule-persist',
    'version' => 2,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'global_rate_limit' => 42,
];
$installed = [];
$manager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true, dynamicRulesCachePath: $cachePath),
    agentHandler: $payloadAgent,
    redisHandler: $redis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$manager->updateRules();
$t->same('rule-persist', $manager->currentRules()->ruleId, 'rule applied');
$t->truthy($redis->getKey('dynamic_rules', 'last_known') !== null, 'snapshot persisted to redis');
$t->truthy(is_file($cachePath) && str_contains((string) file_get_contents($cachePath), 'rule-persist'), 'snapshot persisted to the file');

$hydratedInstalled = [];
$hydratingManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true, dynamicRulesCachePath: $cachePath),
    agentHandler: null,
    redisHandler: $redis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$hydratedInstalled): void {
        $hydratedInstalled[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$hydratingManager->hydrateLastKnownRules();
$t->truthy($hydratingManager->currentRules() !== null && $hydratingManager->currentRules()->ruleId === 'rule-persist', 'last-known rules hydrated from redis');

$t->section('expired snapshots are skipped');
$fake->seed('guard_core_rules:dynamic_rules:last_known', (string) json_encode([
    'schema_version' => 1,
    'rules' => [
        'rule_id' => 'rule-old',
        'version' => 1,
        'timestamp' => '2020-01-01T00:00:00+00:00',
        'expires_at' => '2020-06-01T00:00:00+00:00',
    ],
]));
$hydratingManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true),
    agentHandler: null,
    redisHandler: $redis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$hydratedInstalled): void {
        $hydratedInstalled[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$hydratedInstalled = [];
$hydratingManager->hydrateLastKnownRules();
$t->truthy($hydratingManager->currentRules() === null, 'an expired snapshot is discarded, base config kept (fail closed)');

$t->section('no readable store keeps the base config');
$hydratingManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true),
    agentHandler: null,
    redisHandler: null,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$hydratedInstalled): void {
        $hydratedInstalled[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$hydratingManager->hydrateLastKnownRules();
$t->truthy($hydratingManager->currentRules() === null, 'no stores means no rules');

// ---------------------------------------------------------------------
// 7. match_event correlation
// ---------------------------------------------------------------------

$t->section('match_event correlation');
$rules = DynamicRules::fromArray([
    'rule_id' => 'rule-m',
    'version' => 1,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'ip_blacklist' => ['10.0.0.9'],
    'blocked_countries' => ['BR'],
    'global_rate_limit' => 5,
    'blocked_cloud_providers' => ['AWS'],
    'blocked_user_agents' => ['bot'],
]);
$configWithGeo = new SecurityConfig(enableDynamicRules: true, geoIpDbPath: 'country.mmdb');
$manager = new DynamicRuleManager(config: $configWithGeo, agentHandler: null, logger: $logger);
$apply = new ReflectionMethod($manager, 'applyRules');
$apply->setAccessible(true);
$apply->invoke($manager, $rules);
$currentRulesProp = new ReflectionProperty($manager, 'currentRules');
$currentRulesProp->setValue($manager, $rules);
$makeEvent = static fn (string $type, string $ip = '', ?string $country = null): object => new class($type, $ip, $country) {
    public function __construct(
        public readonly string $eventType,
        public readonly string $ipAddress,
        public readonly ?string $country
    ) {
    }
};
$t->same(['rule-m', 1], $manager->matchEvent($makeEvent(EventTypes::EVENT_IP_BLOCKED, '10.0.0.9')), 'blacklisted ip correlates');
$t->same(['rule-m', 1], $manager->matchEvent($makeEvent(EventTypes::EVENT_COUNTRY_BLOCKED, 'x', 'BR')), 'blocked country correlates');
$t->same(['rule-m', 1], $manager->matchEvent($makeEvent(EventTypes::EVENT_RATE_LIMITED, 'x')), 'rate-limited event correlates');
$t->same(['rule-m', 1], $manager->matchEvent($makeEvent(EventTypes::EVENT_CLOUD_BLOCKED, 'x')), 'cloud-blocked event correlates');
$t->same(['rule-m', 1], $manager->matchEvent($makeEvent(EventTypes::EVENT_USER_AGENT_BLOCKED, 'x')), 'ua-blocked event correlates');
$t->same(null, $manager->matchEvent($makeEvent(EventTypes::EVENT_IP_BLOCKED, '8.8.8.8')), 'unrelated events do not correlate');

// ---------------------------------------------------------------------
// 8. Engine wiring: on_block through the bus, dynamic config seam
// ---------------------------------------------------------------------

$t->section('engine on_block emits through the bus');
$engine = new GuardEngine(new SecurityConfig(enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60, enableRedis: false));
$engineAgent = new BusAgent();
$engine->eventBus()->setAgentHandler($engineAgent);
$request = new SimpleGuardRequest(method: 'GET', urlPath: '/a', headers: [], clientHost: '203.0.113.9');
$t->same(null, $engine->execute($request), 'first request passes');
$t->same(429, $engine->execute($request)?->statusCode(), 'second request rate limited');
$types = array_map(static fn (object $e): string => $e->eventType, $engineAgent->received);
$t->truthy(in_array(EventTypes::EVENT_RATE_LIMITED, $types, true), 'rate limit block emitted rate_limited through the bus');
$t->same(EventTypes::EVENT_RATE_LIMITED, SecurityCheckPipeline::blockEventType('rate_limit'), 'check-to-event mapping: rate_limit');
$t->same(EventTypes::EVENT_PENETRATION_ATTEMPT, SecurityCheckPipeline::blockEventType('custom'), 'check-to-event mapping default');

$t->section('authentication block emits through the bus');
$authAgent = new BusAgent();
$authEngine = new GuardEngine(new SecurityConfig(enableRedis: false, authVerifier: static fn (object $request, string $credential): bool => $credential === 'good-token'));
$authEngine->eventBus()->setAgentHandler($authAgent);
$authRequest = new SimpleGuardRequest(method: 'GET', urlPath: '/private', headers: [], clientHost: '203.0.113.21');
$authRequest->state()->routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig(authRequired: 'bearer');
$t->same(401, $authEngine->execute($authRequest)?->statusCode(), 'an authentication failure blocks');
$authTypes = array_map(static fn (object $e): string => $e->eventType, $authAgent->received);
$t->truthy(in_array(EventTypes::EVENT_AUTHENTICATION_FAILED, $authTypes, true), 'the authentication block emitted authentication_failed through the bus');
$t->same(EventTypes::EVENT_AUTHENTICATION_FAILED, SecurityCheckPipeline::blockEventType('authentication'), 'check-to-event mapping: authentication');

$t->section('emergency mode block emits through the bus');
$emergencyAgent = new BusAgent();
$emergencyEngine = new GuardEngine(new SecurityConfig(enableRedis: false, emergencyMode: true, emergencyWhitelist: ['10.0.0.1']));
$emergencyEngine->eventBus()->setAgentHandler($emergencyAgent);
$allowedEmergencyRequest = new SimpleGuardRequest(method: 'GET', urlPath: '/status', headers: [], clientHost: '10.0.0.1');
$t->same(null, $emergencyEngine->execute($allowedEmergencyRequest), 'a whitelisted ip passes emergency mode');
$t->same([], $emergencyAgent->received, 'the whitelisted pass emitted nothing');
$emergencyRequest = new SimpleGuardRequest(method: 'GET', urlPath: '/status', headers: [], clientHost: '203.0.113.22');
$t->same(503, $emergencyEngine->execute($emergencyRequest)?->statusCode(), 'emergency mode blocks non-whitelisted ips');
$emergencyTypes = array_map(static fn (object $e): string => $e->eventType, $emergencyAgent->received);
$t->truthy(in_array(EventTypes::EVENT_EMERGENCY_MODE_BLOCK, $emergencyTypes, true), 'the emergency block emitted emergency_mode_block through the bus');
$t->same(EventTypes::EVENT_EMERGENCY_MODE_BLOCK, SecurityCheckPipeline::blockEventType('emergency_mode'), 'check-to-event mapping: emergency_mode');

$t->section('engine dynamic config seam rebuilds the pipeline');
$engine = new GuardEngine(new SecurityConfig(enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60, enableRedis: false));
$request = new SimpleGuardRequest(method: 'GET', urlPath: '/a', headers: [], clientHost: '203.0.113.10');
$engine->execute($request);
$engine->applyDynamicConfig($engine->config()->with(['rate_limit' => 100]));
$t->same(null, $engine->execute($request), 'the raised limit applies after the seam swap');
$t->same(100, $engine->config()->rateLimit, 'the engine config swapped');

$t->section('redis-enabled dynamic config seam wires the rate limit stack');
$seamFake = new FakeRespConnection();
$redisEngine = new GuardEngine(
    new SecurityConfig(enableRedis: true, enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60),
    new RedisHandler(true, 'guard_core_dynseam:', connection: $seamFake)
);
$redisEngine->applyDynamicConfig($redisEngine->config()->with(['rate_limit' => 100]));
$seamRedisWiring = new ReflectionProperty(RateLimitHandler::class, 'redisHandler');
$seamBanWiring = new ReflectionProperty(RateLimitHandler::class, 'ipBanManager');
$t->truthy($seamRedisWiring->getValue($redisEngine->rateLimitHandler()) === $redisEngine->redis(), 'the rebuilt handler is wired to the engine redis');
$t->truthy($seamBanWiring->getValue($redisEngine->rateLimitHandler()) === $redisEngine->banManager(), 'the rebuilt handler is wired to the ban manager');
$t->truthy($redisEngine->rateLimitHandler()->scriptSha() !== null, 'the rate limit script loaded through the engine redis');
$t->same(100, $redisEngine->config()->rateLimit, 'the redis-enabled engine config swapped');

$t->section('processResponse without a behavior processor');
$bareEngine = (new ReflectionClass(GuardEngine::class))->newInstanceWithoutConstructor();
$processorSlot = new ReflectionProperty(GuardEngine::class, 'behavioralProcessor');
$processorSlot->setValue($bareEngine, null);
$t->same(null, $bareEngine->behaviorProcessor(), 'the engine reports no behavior processor');
$bareRequest = new SimpleGuardRequest(method: 'GET', urlPath: '/x', headers: [], clientHost: '203.0.113.23');
$bareEngine->processResponse($bareRequest, null);
$t->truthy(true, 'processResponse with no processor returns cleanly');


// ---------------------------------------------------------------------
// 9. Remaining bus and dynamic-rule arms
// ---------------------------------------------------------------------

$t->section('bus envelope build failures are logged, never raised');
$agent = new BusAgent();
$bus = new EventBus($agent, $config);
$hostileRequest = new class {
    public function state(): object
    {
        throw new RuntimeException('state exploded');
    }
};
$bus->sendMiddlewareEvent(EventTypes::EVENT_IP_BLOCKED, $hostileRequest, 'request_blocked', 'denied');
$t->same(0, count($agent->received), 'a build failure sends nothing and does not propagate');
$t->same([], $bus->drain(), 'a build failure queues nothing');

$t->section('metrics collector handler attach flushes');
$collector = new MetricsCollector(null, $config);
$collector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$collector->sendMetric(EventTypes::METRIC_RESPONSE_TIME, 0.5, []);
$mAgent = new BusAgent();
$collector->setAgentHandler($mAgent);
$t->same(2, count($mAgent->metrics), 'queued metrics flushed on attach');
$t->same([], $collector->drain(), 'metric queue drained by the flush');
$quietCollector = new MetricsCollector(new BusAgent(), new SecurityConfig(agentEnableMetrics: false));
$quietCollector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$t->same(0, count($quietCollector->drain()), 'the enable gate drops direct sends too');

$t->section('metrics collector redis persistence');
$metricsRedis = new RedisHandler(true, 'guard_core_metrics_t:', connection: new FakeRespConnection());
$persistingCollector = new MetricsCollector(null, $config, new EventFilter(), $metricsRedis);
$persistingCollector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, ['endpoint' => '/x']);
$persistingCollector->sendMetric(EventTypes::METRIC_RESPONSE_TIME, 0.25, ['endpoint' => '/x']);
$backlog = json_decode((string) $metricsRedis->getKey('metrics', 'pending'), true, 512, JSON_THROW_ON_ERROR);
$t->same(2, count($backlog), 'metrics persist to the pending backlog across requests');
$t->same(EventTypes::METRIC_REQUEST_COUNT, $backlog[0]['metric_type'], 'backlog metric type');
$t->same(0.25, $backlog[1]['value'], 'backlog metric value');
$t->same('/x', $backlog[0]['tags']['endpoint'], 'backlog metric tags');

$flushAgent = new BusAgent();
$persistingCollector->setAgentHandler($flushAgent);
$t->same(2, count($flushAgent->metrics), 'the persisted backlog flushes on handler attach');
$t->same(0.25, $flushAgent->metrics[1]->value, 'flushed value round trips');
$t->same('/x', $flushAgent->metrics[0]->tags['endpoint'], 'flushed tags round trip');
$t->truthy(
    $flushAgent->metrics[0]->timestamp->format(DateTimeInterface::ATOM) === $backlog[0]['timestamp'],
    'the persisted timestamp round trips'
);
$t->truthy($metricsRedis->getKey('metrics', 'pending') === null, 'the backlog key is cleared by the flush');

$drainingCollector = new MetricsCollector(null, $config, new EventFilter(), $metricsRedis);
$drainingCollector->sendMetric(EventTypes::METRIC_ERROR_RATE, 1.0, ['endpoint' => '/y']);
$drainedBacklog = $drainingCollector->drain();
$t->same(1, count($drainedBacklog), 'drain absorbs the persisted backlog');
$t->same(EventTypes::METRIC_ERROR_RATE, $drainedBacklog[0]->metricType, 'drained metric type');
$t->truthy($metricsRedis->getKey('metrics', 'pending') === null, 'drain clears the backlog key');
$t->same([], $drainingCollector->drain(), 'draining an empty backlog drains empty');

$failPersistFake = new FakeRespConnection();
$failPersistFake->failWrites = true;
$failPersistRedis = new RedisHandler(true, 'guard_core_metrics_f:', connection: $failPersistFake);
$failPersistCollector = new MetricsCollector(null, $config, new EventFilter(), $failPersistRedis);
$failPersistCollector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$failPersistFake->failWrites = false;
$t->truthy($failPersistRedis->getKey('metrics', 'pending') === null, 'a failed persist stores nothing');
$t->same([], $failPersistCollector->drain(), 'a failed persist drops the metric without raising');

$corruptFake = new FakeRespConnection();
$corruptRedis = new RedisHandler(true, 'guard_core_metrics_c:', connection: $corruptFake);
$corruptFake->seed('guard_core_metrics_c:metrics:pending', 'this is not json');
$corruptCollector = new MetricsCollector(null, $config, new EventFilter(), $corruptRedis);
$t->same([], $corruptCollector->drain(), 'a corrupted backlog drains empty (fail closed)');

$nonListFake = new FakeRespConnection();
$nonListRedis = new RedisHandler(true, 'guard_core_metrics_n:', connection: $nonListFake);
$nonListFake->seed('guard_core_metrics_n:metrics:pending', '{}');
$nonListCollector = new MetricsCollector(null, $config, new EventFilter(), $nonListRedis);
$t->same([], $nonListCollector->drain(), 'a non-list backlog payload drains empty');

$scalarPendingFake = new FakeRespConnection();
$scalarPendingRedis = new RedisHandler(true, 'guard_core_metrics_s:', connection: $scalarPendingFake);
$scalarPendingFake->seed('guard_core_metrics_s:metrics:pending', '5');
$scalarPendingCollector = new MetricsCollector(null, $config, new EventFilter(), $scalarPendingRedis);
$scalarPendingCollector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$t->truthy($scalarPendingRedis->getKey('metrics', 'pending') === null || $scalarPendingRedis->getKey('metrics', 'pending') === '5', 'a non-list pending payload never accumulates new metrics');
$t->same([], $scalarPendingCollector->drain(), 'a scalar pending payload drains empty');

$entriesFake = new FakeRespConnection();
$entriesRedis = new RedisHandler(true, 'guard_core_metrics_e:', connection: $entriesFake);
$entriesFake->seed('guard_core_metrics_e:metrics:pending', (string) json_encode([
    ['metric_type' => 'bogus'],
    ['metric_type' => EventTypes::METRIC_REQUEST_COUNT, 'value' => 2.0, 'tags' => [0 => 5], 'timestamp' => '2026-01-01T00:00:00+00:00'],
], JSON_THROW_ON_ERROR));
$entriesCollector = new MetricsCollector(null, $config, new EventFilter(), $entriesRedis);
$entriesDrained = $entriesCollector->drain();
$t->same(1, count($entriesDrained), 'malformed backlog entries are skipped individually');
$t->same(2.0, $entriesDrained[0]->value, 'the valid entry survives');
$t->same(['0' => '5'], $entriesDrained[0]->tags, 'backlog tag entries are coerced back to string maps');

$quietPersist = new MetricsCollector(null, new SecurityConfig(agentEnableMetrics: false), new EventFilter(), $metricsRedis);
$quietPersist->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$t->truthy($metricsRedis->getKey('metrics', 'pending') === null, 'the metrics gate also gates persistence');

$disabledRedis = new RedisHandler(false, 'guard_core_metrics_d:', connection: new FakeRespConnection());
$disabledCollector = new MetricsCollector(null, $config, new EventFilter(), $disabledRedis);
$disabledCollector->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, []);
$t->same(1, count($disabledCollector->drain()), 'a disabled redis handler falls back to the in-memory queue');

$t->section('dynamic rules manager query surface');
$disabledManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: false),
    agentHandler: $payloadAgent,
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$disabledManager->updateRules();
$t->same(0.0, $disabledManager->lastUpdate(), 'a disabled manager never updates');
$payloadAgent->rules = ['rule_id' => 'rule-upd', 'version' => 1, 'timestamp' => '2026-01-01T00:00:00+00:00'];
$enabledManager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$enabledManager->updateRules();
$t->truthy($enabledManager->lastUpdate() > 0, 'lastUpdate stamped on a successful update');

$t->section('hydration failure is logged, never raised');
$failInstalled = [];
$failManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true, dynamicRulesCachePath: $cachePath),
    agentHandler: null,
    redisHandler: $redis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$failInstalled): void {
        throw new RuntimeException('apply exploded');
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$failManager->hydrateLastKnownRules();
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'Failed to hydrate last-known dynamic rules')), 'the hydration failure is logged');

$t->section('full rule field application');
$geoConfig = new SecurityConfig(enableDynamicRules: true, geoIpDbPath: 'country.mmdb');
$payloadAgent->rules = [
    'rule_id' => 'rule-all',
    'version' => 20,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'ip_whitelist' => ['10.9.9.9'],
    'whitelist_countries' => ['de'],
    'global_rate_window' => 120,
    'endpoint_rate_limits' => ['/x' => [7, 30]],
    'enable_penetration_detection' => false,
    'enable_ip_banning' => false,
    'enable_rate_limiting' => true,
    'enable_rate_limit_auto_ban' => false,
    'auto_ban_duration' => 7200,
    'suspicious_patterns' => ['evil'],
];
$installed = [];
$logs = [];
$fullManager = new DynamicRuleManager(
    config: $geoConfig,
    agentHandler: $payloadAgent,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$fullManager->updateRules();
$candidate = $installed[count($installed) - 1] ?? null;
$t->truthy($candidate !== null && in_array('10.9.9.9', $candidate->whitelist ?? [], true), 'ip whitelist merged');
$t->truthy(in_array('DE', $candidate->whitelistCountries, true), 'whitelist countries applied');
$t->same(120, $candidate->rateLimitWindow, 'global rate window applied');
$t->truthy(($candidate->endpointRateLimits['/x']['limit'] ?? null) === 7, 'endpoint rate limits merged in the config format');
$t->same(false, $candidate->enablePenetrationDetection, 'penetration toggle applied');
$t->same(false, $candidate->enableIpBanning, 'ip banning toggle applied');
$t->same(true, $candidate->enableRateLimiting, 'rate limiting toggle applied');
$t->same(false, $candidate->enableRateLimitAutoBan, 'rate limit auto ban toggle applied');
$t->same(7200, $candidate->autoBanDuration, 'auto ban duration applied');
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'suspicious_patterns from dynamic rules are skipped')), 'suspicious patterns warned and skipped');

$t->section('already-known cloud providers are not re-applied');
$payloadAgent->rules = [
    'rule_id' => 'rule-dup',
    'version' => 21,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'blocked_cloud_providers' => ['AWS'],
];
$cloudyBase = new SecurityConfig(enableDynamicRules: true, blockCloudProviders: ['AWS']);
$dupInstalled = [];
$dupManager = new DynamicRuleManager(
    config: $cloudyBase,
    agentHandler: $payloadAgent,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$dupInstalled): void {
        $dupInstalled[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$dupManager->updateRules();
$t->truthy(count($dupInstalled) <= 1, 'a rule with only known values still builds a candidate cleanly');

$t->section('parse error arms');
$parseCases = [
    [['rule_id' => 'r', 'version' => 1, 'timestamp' => 'garbage'], 'unparseable timestamp rejected'],
    [['rule_id' => 'r', 'version' => 1, 'timestamp' => '2026-01-01T00:00:00+00:00', 'expires_at' => 'garbage'], 'unparseable expires_at rejected'],
    [['rule_id' => 'r', 'version' => 1, 'timestamp' => '2026-01-01T00:00:00+00:00', 'endpoint_rate_limits' => ['/x' => 'nope']], 'malformed endpoint rate limits rejected'],
    [['rule_id' => 'r', 'version' => 1, 'timestamp' => '2026-01-01T00:00:00+00:00', 'ip_blacklist' => 'nope'], 'non-array list rejected'],
    [['rule_id' => 'r', 'version' => 1, 'timestamp' => '2026-01-01T00:00:00+00:00', 'ip_whitelist' => [1.5]], 'non-string list entries rejected'],
];
foreach ($parseCases as [$payload, $label]) {
    $threw = false;
    try {
        DynamicRules::fromArray($payload);
    } catch (InvalidArgumentException) {
        $threw = true;
    }
    $t->truthy($threw, $label);
}
$t->truthy(str_starts_with((new DynamicRules('r', 1, new DateTimeImmutable()))->dumpSnapshot(), '{'), 'snapshot encoding of valid rules succeeds');

$t->section('store failure arms');
$fakeBroken = new FakeRespConnection();
$fakeBroken->failWrites = true;
$brokenRedis = new RedisHandler(true, 'guard_core_rules2:', connection: $fakeBroken);
$brokenInstalled = [];
$brokenManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true),
    agentHandler: null,
    redisHandler: $brokenRedis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c) use (&$brokenInstalled): void {
        $brokenInstalled[] = $c;
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$brokenManager->hydrateLastKnownRules();
$t->truthy($brokenManager->currentRules() === null, 'a failing redis read degrades to no rules');
$fake10 = new FakeRespConnection();
$fake10->seed('guard_core_rules3:dynamic_rules:last_known', '');
$emptyRedis = new RedisHandler(true, 'guard_core_rules3:', connection: $fake10);
$emptyManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true),
    agentHandler: null,
    redisHandler: $emptyRedis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c): void {
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$emptyManager->hydrateLastKnownRules();
$t->truthy($emptyManager->currentRules() === null, 'an empty redis payload falls through');
$fakeMalformed = new FakeRespConnection();
$fakeMalformed->seed('guard_core_rules_malformed:dynamic_rules:last_known', 'this is not json');
$malformedRedis = new RedisHandler(true, 'guard_core_rules_malformed:', connection: $fakeMalformed);
$badPayloadManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true),
    agentHandler: null,
    redisHandler: $malformedRedis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c): void {
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$badPayloadManager->hydrateLastKnownRules();
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'Discarding unusable last-known dynamic rules payload')), 'an unusable snapshot is discarded with a log');

$t->section('unreadable cache file and failed persistence');
$unreadable = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true, dynamicRulesCachePath: '/proc/self/mem'),
    agentHandler: null,
    redisHandler: null,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c): void {
    },
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$unreadable->hydrateLastKnownRules();
$t->truthy((bool) array_filter($logs, static fn (string $l): bool => str_contains($l, 'Discarding unusable last-known dynamic rules payload')), 'an unreadable cache file yields a discarded empty payload with a log');
$persistFailLogs = [];
$persistFailManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true, dynamicRulesCachePath: '/dev/null/impossible.json'),
    agentHandler: null,
    redisHandler: $brokenRedis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c): void {
    },
    logger: static function (string $level, string $message) use (&$persistFailLogs): void {
        $persistFailLogs[] = $message;
    },
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$persistApply = new ReflectionMethod($persistFailManager, 'persistLastKnownRules');
$persistApply->setAccessible(true);
$persistApply->invoke($persistFailManager, DynamicRules::fromArray([
    'rule_id' => 'rule-persist-fail',
    'version' => 1,
    'timestamp' => '2026-01-01T00:00:00+00:00',
]));
$t->truthy((bool) array_filter($persistFailLogs, static fn (string $l): bool => str_contains($l, 'Failed to persist dynamic rules to Redis')), 'the redis persistence failure is logged');
$t->truthy((bool) array_filter($persistFailLogs, static fn (string $l): bool => str_contains($l, 'Failed to persist dynamic rules to cache file')), 'the file persistence failure is logged');


$t->section('snapshot encode failure and match without rules');
$threw = false;
try {
    (new DynamicRules("\xB1\xB1", 1, new DateTimeImmutable()))->dumpSnapshot();
} catch (JsonException) {
    $threw = true;
}
$t->truthy($threw, 'a snapshot that cannot encode rejects');
$noRulesManager = new DynamicRuleManager(config: $config, agentHandler: null, logger: $logger);
$t->same(null, $noRulesManager->matchEvent($makeEvent(EventTypes::EVENT_IP_BLOCKED, '10.0.0.9')), 'no active rules means no correlation');

$t->section('update gates on disabled configs and expiry checks');
$disabledHydrator = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: false),
    agentHandler: null,
    redisHandler: $redis,
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$disabledHydrator->hydrateLastKnownRules();
$t->truthy($disabledHydrator->currentRules() === null, 'a disabled config never hydrates');
$expiryManager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    logger: $logger,
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$expiryManager->updateRules();
$t->truthy($expiryManager->currentRules() !== null, 'the no-expiry rule applied');
$expiryManager->updateRules();
$t->truthy($expiryManager->currentRules() !== null, 'the no-expiry rule survives the expiry check');


$t->section('unexpired rules survive the expiry check');
$freshClock = 1700000000;
$futureManager = new DynamicRuleManager(
    config: $config,
    agentHandler: $payloadAgent,
    logger: $logger,
    clock: static function () use (&$freshClock): int {
        return $freshClock;
    }
);
$payloadAgent->rules = [
    'rule_id' => 'rule-future',
    'version' => 30,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'expires_at' => '2040-01-01T00:00:00+00:00',
    'global_rate_limit' => 7,
];
$futureManager->updateRules();
$futureManager->updateRules();
$t->truthy($futureManager->currentRules() !== null, 'an unexpired rule survives the expiry check');

$t->section('snapshot build failure keeps the old snapshot');
$persistFailManager = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true),
    agentHandler: null,
    redisHandler: $brokenRedis,
    eventBus: new EventBus(new BusAgent(), $config),
    applyConfig: static function (SecurityConfig $c): void {
    },
    logger: static function (string $level, string $message) use (&$persistFailLogs): void {
        $persistFailLogs[] = $message;
    },
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$persistFailLogs = [];
$persistApply->invoke($persistFailManager, new DynamicRules("\xB1\xB1", 1, new DateTimeImmutable()));
$t->truthy((bool) array_filter($persistFailLogs, static fn (string $l): bool => str_contains($l, 'Failed to build last-known dynamic rules snapshot')), 'the snapshot build failure is logged');

exit($t->finish('EVENT BUS'));

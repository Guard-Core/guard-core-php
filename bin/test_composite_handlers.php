<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Events\AgentHandlerComposer;
use RenzoFranceschini\GuardCore\Events\CompositeAgentHandler;
use RenzoFranceschini\GuardCore\Events\EventEnricher;
use RenzoFranceschini\GuardCore\Events\EnrichmentContext;
use RenzoFranceschini\GuardCore\Events\EventFilter;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\LogfireHandler;
use RenzoFranceschini\GuardCore\Events\OtelHandler;
use RenzoFranceschini\GuardCore\Events\OtlpHttpTransport;
use RenzoFranceschini\GuardCore\Events\OtlpTransport;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\Events\SecurityMetric;

require __DIR__ . '/../vendor/autoload.php';

// B3 parity: CompositeAgentHandler (the multi-sink fan-out with filter,
// single enrichment pass and per-sink failure isolation), the OTEL export
// handler speaking OTLP/HTTP JSON through an injectable transport, and the
// Logfire handler delegating to an injected duck-typed client (reference
// composite_handler.py / otel_handler.py / logfire_handler.py). No real
// network anywhere: the OTLP transport is a capturing fake.
//
// Run: php bin/test_composite_handlers.php

final class CompT
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

final class Sink
{
    /** @var list<SecurityEvent> */
    public array $events = [];

    /** @var list<SecurityMetric> */
    public array $metrics = [];

    public array $redis = [];

    public int $started = 0;

    public int $stopped = 0;

    public int $flushed = 0;

    public bool $healthy = true;

    public bool $failEvent = false;

    public bool $failMetric = false;

    public bool $failRedis = false;

    public bool $failStop = false;

    public bool $failFlush = false;

    public function __construct(public readonly string $name = 'Sink')
    {
    }

    public function sendEvent(SecurityEvent $event): void
    {
        if ($this->failEvent) {
            throw new RuntimeException("{$this->name} down");
        }
        $this->events[] = $event;
    }

    public function sendMetric(SecurityMetric $metric): void
    {
        if ($this->failMetric) {
            throw new RuntimeException("{$this->name} metric down");
        }
        $this->metrics[] = $metric;
    }

    public function initializeRedis(object $redisHandler): void
    {
        if ($this->failRedis) {
            throw new RuntimeException("{$this->name} redis down");
        }
        $this->redis[] = $redisHandler;
    }

    public function start(): void
    {
        $this->started++;
    }

    public function stop(): void
    {
        if ($this->failStop) {
            throw new RuntimeException("{$this->name} stop down");
        }
        $this->stopped++;
    }

    public function flushBuffer(): void
    {
        if ($this->failFlush) {
            throw new RuntimeException("{$this->name} flush down");
        }
        $this->flushed++;
    }

    public function getDynamicRules(): mixed
    {
        return null;
    }

    public function healthCheck(): bool
    {
        return $this->healthy;
    }
}

final class RulesSink
{
    public function __construct(private readonly mixed $rules = null, private readonly bool $throw = false)
    {
    }

    public function getDynamicRules(): mixed
    {
        if ($this->throw) {
            throw new RuntimeException('rules unavailable');
        }

        return $this->rules;
    }

    public function sendEvent(SecurityEvent $event): void
    {
    }
}

final class TransportFake implements OtlpTransport
{
    /** @var list<array{endpoint: string, payload: string}> */
    public array $exports = [];

    public bool $fail = false;

    public function export(string $endpoint, string $payload): bool
    {
        if ($this->fail) {
            return false;
        }
        $this->exports[] = ['endpoint' => $endpoint, 'payload' => $payload];

        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function decoded(int $index): array
    {
        $decoded = json_decode($this->exports[$index]['payload'], true);
        if (!is_array($decoded)) {
            return [];
        }

        return $decoded;
    }
}

final class LogfireFake
{
    public bool $configuredState = false;

    public int $configureCalls = 0;

    public int $shutdownCalls = 0;

    /** @var list<array{name: string, attributes: array<string, mixed>}> */
    public array $spans = [];

    /** @var list<array{template: string, fields: array<string, mixed>}> */
    public array $infos = [];

    public function configured(): bool
    {
        return $this->configuredState;
    }

    public function configure(string $serviceName): void
    {
        $this->configureCalls++;
        $this->configuredState = true;
        $this->configuredService = $serviceName;
    }

    /** @param array<string, mixed> $attributes */
    public function span(string $name, array $attributes): void
    {
        $this->spans[] = ['name' => $name, 'attributes' => $attributes];
    }

    /** @param array<string, mixed> $fields */
    public function info(string $template, array $fields): void
    {
        $this->infos[] = ['template' => $template, 'fields' => $fields];
    }

    public function shutdown(): void
    {
        $this->shutdownCalls++;
    }
}

function evt(string $type = EventTypes::EVENT_IP_BLOCKED): SecurityEvent
{
    return new SecurityEvent(
        timestamp: new DateTimeImmutable('2026-10-06T00:00:00Z'),
        eventType: $type,
        ipAddress: '203.0.113.7',
        actionTaken: 'request_blocked',
        reason: 'denied',
        endpoint: '/pay',
        method: 'POST',
        metadata: ['traceparent' => '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', 'guard.project_id' => 'proj-9', 'custom' => 'x']
    );
}

function met(string $type = EventTypes::METRIC_RESPONSE_TIME, float $value = 0.5): SecurityMetric
{
    return new SecurityMetric(
        timestamp: new DateTimeImmutable('2026-10-06T00:00:00Z'),
        metricType: $type,
        value: $value,
        tags: ['endpoint' => '/pay', 'value' => 'bogus']
    );
}

function enrichingEnricher(): EventEnricher
{
    return new EventEnricher(new EnrichmentContext(config: new SecurityConfig(agentProjectId: 'p1')));
}

$t = new CompT();
$config = new SecurityConfig();

// ---------------------------------------------------------------------
// 1. Composite fan-out, filter, enrichment, isolation
// ---------------------------------------------------------------------

$t->section('composite fan-out');
$a = new Sink('A');
$b = new Sink('B');
$composite = new CompositeAgentHandler([$a, $b], null, enrichingEnricher());
$composite->sendEvent(evt());
$t->same(1, count($a->events), 'first sink received the event');
$t->same(1, count($b->events), 'second sink received the event');
$t->truthy(isset($a->events[0]->metadata[EventTypes::ENRICHMENT_KEY_PROJECT_ID]), 'sink A event was enriched');
$t->truthy(isset($b->events[0]->metadata[EventTypes::ENRICHMENT_KEY_PROJECT_ID]), 'sink B event was enriched');
$t->same($a->events[0], $b->events[0], 'both sinks observe the same enriched instance');

$muted = new CompositeAgentHandler([$a, $b], new EventFilter(mutedEventTypes: [EventTypes::EVENT_IP_BLOCKED], mutedMetricTypes: [EventTypes::METRIC_ERROR_RATE]));
$muted->sendEvent(evt());
$t->same(1, count($a->events), 'muted event type reached no sink');
$muted->sendMetric(new SecurityMetric(new DateTimeImmutable(), EventTypes::METRIC_ERROR_RATE, 1.0));
$t->same(0, count($a->metrics), 'muted metric type reached no sink');

$t->section('composite failure isolation');
$a->failEvent = true;
$composite->sendEvent(evt(EventTypes::EVENT_RATE_LIMITED));
$t->same(2, count($b->events), 'a dead sink does not stop the fan-out');
$a->failEvent = false;

$t->section('composite metric failure isolation');
$a->failMetric = true;
$composite->sendMetric(met());
$t->same(1, count($b->metrics), 'a failing metric sink does not stop the metric fan-out');
$t->truthy(isset($b->metrics[0]->tags[EventTypes::ENRICHMENT_KEY_PROJECT_ID]), 'the metric fan-out sees the enriched instance');
$a->failMetric = false;

$t->section('composite lifecycle');
$lifecycle = new CompositeAgentHandler([$a, $b]);
$t->truthy(!$lifecycle->started(), 'composite starts unstarted');
$lifecycle->start();
$t->truthy($lifecycle->started(), 'start marks started');
$t->same([], $lifecycle->failedHandlers(), 'no failed handlers when all start');
$t->truthy(!$lifecycle->degraded(), 'not degraded when all start');
$t->same(1, $a->started, 'sink A start called');
$t->same(1, $b->started, 'sink B start called');

final class BadStartSink
{
    public function start(): void
    {
        throw new RuntimeException('cannot start');
    }

    public function sendEvent(SecurityEvent $event): void
    {
    }
}
$degraded = new CompositeAgentHandler([new BadStartSink(), $b]);
$degraded->start();
$t->truthy($degraded->degraded(), 'degraded when a sink fails to start');
$t->same([BadStartSink::class], $degraded->failedHandlers(), 'failed handler names recorded');
$t->truthy($degraded->started(), 'degraded composite is still started');

$lifecycle->stop();
$t->same(1, $a->stopped, 'stop fans out');
$lifecycle->flushBuffer();
$t->same(1, $a->flushed, 'flush fans out');
$redisMarker = new stdClass();
$lifecycle->initializeRedis($redisMarker);
$t->same([$redisMarker], $a->redis, 'initialize_redis fans out');

$t->section('lifecycle failure isolation');
$a->failRedis = true;
$lifecycle->initializeRedis(new stdClass());
$t->same(2, count($b->redis), 'a failing redis sink does not stop the redis fan-out');
$a->failRedis = false;
$a->failStop = true;
$lifecycle->stop();
$t->same(2, $b->stopped, 'a failing stop does not stop the other sinks');
$a->failStop = false;
$a->failFlush = true;
$lifecycle->flushBuffer();
$t->same(2, $b->flushed, 'a failing flush does not stop the other sinks');
$a->failFlush = false;

$t->section('composite dynamic rules + health');
$rules = new CompositeAgentHandler([new RulesSink(null, true), new RulesSink(['k' => 'v']), new RulesSink('second')]);
$t->same(['k' => 'v'], $rules->getDynamicRules(), 'first non-null answer wins, throwers skipped');
$t->same(null, (new CompositeAgentHandler([new RulesSink(null)]))->getDynamicRules(), 'all-null stays null');
$t->truthy((new CompositeAgentHandler([]))->healthCheck(), 'empty composite is healthy');
$t->truthy($rules->healthCheck() === false, 'unhealthy sink fails the composite');
$healthy = new CompositeAgentHandler([$a, $b]);
$t->truthy($healthy->healthCheck(), 'all-healthy composite reports healthy');

// ---------------------------------------------------------------------
// 2. OtelHandler
// ---------------------------------------------------------------------

$t->section('otel endpoint derivation');
$t->same('https://collector:4318/v1/traces', OtelHandler::otlpSignalEndpoint('https://collector:4318', '/v1/traces'), 'base url gains the traces path');
$t->same('https://collector:4318/v1/metrics', OtelHandler::otlpSignalEndpoint('https://collector:4318', '/v1/metrics'), 'base url gains the metrics path');
$t->same('https://collector:4318/v1/traces', OtlpHandlerHelper::traces('https://collector:4318/v1/metrics'), 'a pre-set signal path is replaced');
$t->same('https://collector:4318/v1/traces', OtlpHandlerHelper::traces('https://collector:4318/'), 'trailing slash trimmed');
$t->same('https://collector:4318/v1/traces', OtlpHandlerHelper::traces('https://collector:4318/v1/logs'), 'logs suffix replaced too');

$t->section('otel handler span export');
$transport = new TransportFake();
$otel = new OtelHandler(new SecurityConfig(
    otelServiceName: 'edge-svc',
    otelExporterEndpoint: 'https://collector:4318',
    otelResourceAttributes: ['deployment.environment' => 'prod']
), $transport);
$otel->sendEvent(evt());
$t->same(0, count($transport->exports), 'no export before start');
$otel->start();
$otel->start();
$otel->sendEvent(evt());
$t->same(1, count($transport->exports), 'sendEvent only exports after start (start idempotent does not double-emit)');
$t->same('https://collector:4318/v1/traces', $transport->exports[0]['endpoint'], 'export went to the traces endpoint');
$payload = $transport->decoded(0);
$rs = $payload['resourceSpans'][0] ?? [];
$resourceAttrs = [];
foreach (($rs['resource']['attributes'] ?? []) as $attr) {
    $resourceAttrs[$attr['key']] = $attr['value']['stringValue'] ?? null;
}
$t->same('edge-svc', $resourceAttrs['service.name'] ?? null, 'resource carries service.name');
$t->same('prod', $resourceAttrs['deployment.environment'] ?? null, 'resource carries extra attributes');
$span = $rs['scopeSpans'][0]['spans'][0] ?? [];
$t->same('guard.event.ip_blocked', $span['name'] ?? null, 'span name is guard.event.<type>');
$t->same('4bf92f3577b34da6a3ce929d0e0e4736', $span['traceId'] ?? null, 'traceId taken from the metadata traceparent');
$t->same('00f067aa0ba902b7', $span['parentSpanId'] ?? null, 'parentSpanId taken from the metadata traceparent');
$spanAttrs = [];
foreach (($span['attributes'] ?? []) as $attr) {
    $spanAttrs[$attr['key']] = $attr['value'];
}
$t->same('ip_blocked', $spanAttrs['guard.event_type']['stringValue'] ?? null, 'guard.event_type attribute set');
$t->same('203.0.113.7', $spanAttrs['guard.ip_address']['stringValue'] ?? null, 'guard.ip_address attribute set');
$t->same('request_blocked', $spanAttrs['guard.action_taken']['stringValue'] ?? null, 'guard.action_taken attribute set');
$t->same('denied', $spanAttrs['guard.reason']['stringValue'] ?? null, 'guard.reason attribute set');
$t->same('/pay', $spanAttrs['guard.endpoint']['stringValue'] ?? null, 'guard.endpoint attribute set');
$t->same('POST', $spanAttrs['guard.method']['stringValue'] ?? null, 'guard.method attribute set');
$t->truthy(!isset($spanAttrs['guard.status_code']), 'status_code omitted when unset');
$t->same('proj-9', $spanAttrs[EventTypes::ENRICHMENT_KEY_PROJECT_ID]['stringValue'] ?? null, 'guard.* metadata forwarded (enrichment)');
$t->truthy(!isset($spanAttrs['traceparent']), 'traceparent never forwarded as an attribute');
$t->truthy(!isset($spanAttrs['custom']), 'non-guard metadata not forwarded');
$t->same('guard_core.otel', $rs['scopeSpans'][0]['scope']['name'] ?? null, 'scope name is guard_core.otel');

$t->section('otel traceparent parenting');
$otel->sendEvent(evt());
$span2 = $transport->decoded(1)['resourceSpans'][0]['scopeSpans'][0]['spans'][0] ?? [];
$t->same('4bf92f3577b34da6a3ce929d0e0e4736', $span2['traceId'] ?? null, 'traceId taken from the traceparent');
$t->same('00f067aa0ba902b7', $span2['parentSpanId'] ?? null, 'parentSpanId taken from the traceparent');

final class TruncatedTraceparentSink extends Exception
{
}
$badTpEvent = new SecurityEvent(
    timestamp: new DateTimeImmutable(),
    eventType: EventTypes::EVENT_RATE_LIMITED,
    ipAddress: '203.0.113.7',
    metadata: ['traceparent' => 'not-a-traceparent']
);
$otel->sendEvent($badTpEvent);
$span3 = $transport->decoded(2)['resourceSpans'][0]['scopeSpans'][0]['spans'][0] ?? [];
$t->same(32, strlen($span3['traceId'] ?? ''), 'malformed traceparent falls back to a generated traceId');
$t->truthy(!isset($span3['parentSpanId']), 'malformed traceparent leaves no parent');

$t->section('otel metric export');
$otel->sendMetric(new SecurityMetric(
    timestamp: new DateTimeImmutable(),
    metricType: EventTypes::METRIC_RESPONSE_TIME,
    value: 0.75,
    tags: ['endpoint' => '/pay', 'method' => 'GET']
));
$metricPayload = $transport->decoded(count($transport->exports) - 1)['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0] ?? [];
$t->same('guard.request.duration', $metricPayload['name'] ?? null, 'response_time maps to the duration histogram');
$t->same('s', $metricPayload['unit'] ?? null, 'histogram unit is seconds');
$histogramPoint = $metricPayload['histogram']['dataPoints'][0] ?? [];
$t->same(1, $histogramPoint['count'] ?? 0, 'histogram point counts one observation');
$t->same(0.75, $histogramPoint['sum'] ?? 0, 'histogram point sums the value');
$metricAttrs = [];
foreach (($histogramPoint['attributes'] ?? []) as $attr) {
    $metricAttrs[$attr['key']] = $attr['value']['stringValue'] ?? null;
}
$t->same('/pay', $metricAttrs['endpoint'] ?? null, 'metric attributes carry the endpoint');
$t->same('GET', $metricAttrs['method'] ?? null, 'extra tags join the metric attributes');
$t->truthy(!isset($metricAttrs['value']), 'the value tag is not echoed into attributes');

$otel->sendMetric(met(EventTypes::METRIC_REQUEST_COUNT, 3.0));
$sumPayload = $transport->decoded(4)['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0] ?? [];
$t->same('guard.request.count', $sumPayload['name'] ?? null, 'request_count maps to the request counter');
$t->same(3.0, $sumPayload['sum']['dataPoints'][0]['asDouble'] ?? 0, 'counter records the value');

$otel->sendMetric(met(EventTypes::METRIC_ERROR_RATE, 0.1));
$t->same('guard.error.count', $transport->decoded(5)['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0]['name'] ?? null, 'error_rate maps to the error counter');

$beforeUnknown = count($transport->exports);
$otel->sendMetric(met('not_a_metric', 1.0));
$t->same($beforeUnknown, count($transport->exports), 'unknown metric type exports nothing');

$t->section('otel enrichment attribute types + no-op surface');
$typedEvent = new SecurityEvent(
    timestamp: new DateTimeImmutable(),
    eventType: EventTypes::EVENT_SUSPICIOUS_REQUEST,
    ipAddress: '203.0.113.7',
    metadata: [
        'guard.threat_score' => 50,
        'guard.ratio' => 0.5,
        'guard.flag' => true,
        'guard.absent' => null,
        'traceparent' => 123,
    ]
);
$otel->sendEvent($typedEvent);
$typedSpan = $transport->decoded(count($transport->exports) - 1)['resourceSpans'][0]['scopeSpans'][0]['spans'][0] ?? [];
$typedAttrs = [];
foreach (($typedSpan['attributes'] ?? []) as $attr) {
    $typedAttrs[$attr['key']] = $attr['value'];
}
$t->same(50, $typedAttrs[EventTypes::ENRICHMENT_KEY_THREAT_SCORE]['intValue'] ?? null, 'int metadata forwards as intValue');
$t->same(0.5, $typedAttrs['guard.ratio']['doubleValue'] ?? null, 'float metadata forwards as doubleValue');
$t->truthy(isset($typedAttrs['guard.flag']['boolValue']), 'bool metadata forwards as boolValue');
$t->truthy(!isset($typedAttrs['guard.absent']), 'null metadata entries are skipped');
$t->truthy(!isset($typedAttrs['traceparent']), 'a non-string traceparent is ignored for parenting');
$t->same(32, strlen($typedSpan['traceId'] ?? ''), 'non-string traceparent falls back to a generated traceId');

$t->same(null, $otel->getDynamicRules(), 'otel getDynamicRules is null');
$otel->initializeRedis(new stdClass());
$otel->flushBuffer();
$t->truthy(true, 'otel redis/flush are no-ops');

$t->section('otel stop + failure tolerance');
$exportsBeforeStop = count($transport->exports);
$otel->stop();
$otel->sendEvent(evt());
$t->same($exportsBeforeStop, count($transport->exports), 'no export after stop');
$failingTransport = new TransportFake();
$failingTransport->fail = true;
$failing = new OtelHandler(new SecurityConfig(otelExporterEndpoint: 'https://collector:4318'), $failingTransport);
$failing->start();
$failing->sendEvent(evt());
$failing->sendMetric(met());
$t->truthy(true, 'transport failures never throw');
$t->same(0, count($failingTransport->exports), 'failed exports leave the transport unrecorded');

// ---------------------------------------------------------------------
// 3. LogfireHandler
// ---------------------------------------------------------------------

$t->section('logfire lifecycle');
$client = new LogfireFake();
$logfire = new LogfireHandler(new SecurityConfig(logfireServiceName: 'edge-logfire'), $client);
$logfire->start();
$t->same(1, $client->configureCalls, 'start configures the client');
$t->truthy(isset($client->configuredService) && $client->configuredService === 'edge-logfire', 'configure received the service name');
$logfire->start();
$t->same(1, $client->configureCalls, 'start is idempotent');

$preConfigured = new LogfireFake();
$preConfigured->configuredState = true;
$already = new LogfireHandler(new SecurityConfig(logfireServiceName: 'never-applied'), $preConfigured);
$already->start();
$t->same(0, $preConfigured->configureCalls, 'already-configured client is not reconfigured');
$already->stop();
$t->same(0, $preConfigured->shutdownCalls, 'guard does not shut down a host-configured client');

$logfire->stop();
$t->same(1, $client->shutdownCalls, 'guard-configured client shuts down on stop');

$orphan = new LogfireHandler(new SecurityConfig(), null);
$orphan->start();
$orphan->sendEvent(evt());
$orphan->sendMetric(met());
$orphan->stop();
$t->truthy(!$orphan->healthCheck(), 'no client means unhealthy handler and full no-op');

$t->section('logfire emission');
$emitClient = new LogfireFake();
$emitter = new LogfireHandler(new SecurityConfig(), $emitClient);
$emitter->start();
$emitter->sendEvent(evt());
$span = $emitClient->spans[0] ?? ['name' => null, 'attributes' => []];
$t->same('guard.event.ip_blocked', $span['name'], 'span name is guard.event.<type>');
$t->same('ip_blocked', $span['attributes']['event_type'] ?? null, 'event_type attribute');
$t->same('203.0.113.7', $span['attributes']['ip_address'] ?? null, 'ip_address attribute');
$t->same('request_blocked', $span['attributes']['action_taken'] ?? null, 'action_taken attribute');
$t->same('denied', $span['attributes']['reason'] ?? null, 'reason attribute');
$t->same('/pay', $span['attributes']['endpoint'] ?? null, 'endpoint attribute');
$t->same('POST', $span['attributes']['method'] ?? null, 'method attribute');
$t->same(0, $span['attributes']['status_code'] ?? null, 'status_code defaults to 0');
$t->same('proj-9', $span['attributes'][EventTypes::ENRICHMENT_KEY_PROJECT_ID] ?? null, 'guard.* metadata forwarded');
$t->truthy(!isset($span['attributes']['traceparent']), 'traceparent never forwarded');
$t->truthy(!isset($span['attributes']['custom']), 'non-guard metadata not forwarded');

$emitter->sendMetric(new SecurityMetric(
    timestamp: new DateTimeImmutable(),
    metricType: EventTypes::METRIC_ERROR_RATE,
    value: 0.25,
    tags: ['endpoint' => '/pay', 'method' => 'GET']
));
$info = $emitClient->infos[0] ?? ['template' => null, 'fields' => []];
$t->same('guard.metric.error_rate', $info['template'], 'metric template is guard.metric.<type>');
$t->same(0.25, $info['fields']['value'] ?? null, 'metric value field');
$t->same('/pay', $info['fields']['endpoint'] ?? null, 'metric endpoint field');
$t->same('GET', $info['fields']['method'] ?? null, 'extra tags join the metric fields');
$t->truthy(!isset($info['fields']['value']) || $info['fields']['value'] === 0.25, 'the value tag does not overwrite the metric value');

$emitter->initializeRedis(new stdClass());
$emitter->flushBuffer();
$t->same(null, $emitter->getDynamicRules(), 'logfire getDynamicRules is null');
$t->truthy(true, 'logfire redis/flush are no-ops');

// ---------------------------------------------------------------------
// 4. Default transport shape
// ---------------------------------------------------------------------

$t->section('default transport');
$default = new OtlpHttpTransport(timeoutSeconds: 0.5);
$ok = $default->export('http://127.0.0.1:1/v1/traces', '{}');
$t->truthy($ok === false, 'unreachable collector returns false (never throws)');

// ---------------------------------------------------------------------
// 5. Composer wiring
// ---------------------------------------------------------------------

$t->section('composer');
$plain = AgentHandlerComposer::compose(new SecurityConfig(), agentHandler: new Sink('agent'));
$ref = new ReflectionObject($plain);
$prop = $ref->getProperty('handlers');
$prop->setAccessible(true);
$handlers = $prop->getValue($plain);
$t->same(1, count($handlers), 'no flags: only the agent handler');

$everything = AgentHandlerComposer::compose(
    new SecurityConfig(enableOtel: true, enableLogfire: true, enableEnrichment: true, agentProjectId: 'p'),
    agentHandler: new Sink('agent'),
    logfireClient: new LogfireFake()
);
$allHandlers = $prop->getValue($everything);
$t->same(3, count($allHandlers), 'agent + otel + logfire composed');
$t->truthy($allHandlers[0] instanceof Sink, 'agent handler first');
$t->truthy($allHandlers[1] instanceof OtelHandler, 'otel handler second');
$t->truthy($allHandlers[2] instanceof LogfireHandler, 'logfire handler third');
$enricherProp = $ref->getProperty('enricher');
$enricherProp->setAccessible(true);
$t->truthy($enricherProp->getValue($everything) instanceof EventEnricher, 'enricher wired when enable_enrichment');

$noEnrich = AgentHandlerComposer::compose(new SecurityConfig(enableOtel: true), agentHandler: new Sink('agent'));
$t->truthy($enricherProp->getValue($noEnrich) === null, 'no enricher without enable_enrichment');

class OtlpHandlerHelper
{
    public static function traces(string $endpoint): string
    {
        return OtelHandler::otlpSignalEndpoint($endpoint, '/v1/traces');
    }
}

exit($t->finish('composite handlers'));

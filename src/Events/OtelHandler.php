<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;

/**
 * The OpenTelemetry export handler, ported from the reference
 * otel_handler.py OtelHandler. PHP has no opentelemetry-sdk to lean on, so
 * this port speaks OTLP/HTTP JSON directly through the injectable
 * OtlpTransport (tests use a capturing fake; production defaults to
 * OtlpHttpTransport). Faithful to the reference semantics:
 *
 * - start() builds the resource (service.name + otel_resource_attributes),
 *   derives the per-signal endpoints from otel_exporter_endpoint with the
 *   exact _otlp_signal_endpoint suffix logic, is idempotent, and records
 *   nothing on a second call.
 * - sendEvent() emits one span named guard.event.{event_type} (default
 *   "unknown") with the guard.* attribute family (ip_address, action_taken,
 *   reason, endpoint, method; status_code only when set) and forwards every
 *   guard.* metadata entry (enrichment) except traceparent/tracestate.
 * - the W3C traceparent metadata becomes the span's remote parent:
 *   traceId/parentSpanId are taken from the traceparent; tracestate
 *   participates in context only and is not re-emitted, like the reference
 *   propagator extraction.
 * - sendMetric() maps response_time onto the guard.request.duration
 *   histogram (unit s) and request_count/error_rate onto the
 *   guard.request.count / guard.error.count sums; an unknown metric type
 *   logs and records nothing.
 * - send failures (transport false) are logged, never raised.
 *
 * Divergence (documented): the reference "claims" the global tracer/meter
 * providers once per process and disables itself when a host already
 * installed one. PHP has no global OTel registry in this port - each
 * handler owns its transport, so the claim/shutdown dance is
 * inapplicable-idiom; repeated start() on one instance stays idempotent.
 */
final class OtelHandler
{
    private const KNOWN_SIGNAL_PATHS = ['/v1/traces', '/v1/metrics', '/v1/logs'];

    private const EVENT_SPAN_ATTRS = [
        'guard.ip_address' => 'ipAddress',
        'guard.action_taken' => 'actionTaken',
        'guard.reason' => 'reason',
        'guard.endpoint' => 'endpoint',
        'guard.method' => 'method',
    ];

    private bool $started = false;

    /** @var array<string, string> */
    private array $resourceAttributes = [];

    private ?string $tracesEndpoint = null;

    private ?string $metricsEndpoint = null;

    public function __construct(
        private readonly SecurityConfig $config,
        private readonly OtlpTransport $transport = new OtlpHttpTransport()
    ) {
    }

    public function start(): void
    {
        if ($this->started) {
            return;
        }
        $this->resourceAttributes = ['service.name' => $this->config->otelServiceName];
        foreach ($this->config->otelResourceAttributes as $key => $value) {
            $this->resourceAttributes[(string) $key] = (string) $value;
        }
        $endpoint = $this->config->otelExporterEndpoint;
        $this->tracesEndpoint = $endpoint === null ? null : self::otlpSignalEndpoint($endpoint, '/v1/traces');
        $this->metricsEndpoint = $endpoint === null ? null : self::otlpSignalEndpoint($endpoint, '/v1/metrics');
        $this->started = true;
    }

    public function stop(): void
    {
        $this->started = false;
        $this->tracesEndpoint = null;
        $this->metricsEndpoint = null;
        $this->resourceAttributes = [];
    }

    public function sendEvent(SecurityEvent $event): void
    {
        if (!$this->started || $this->tracesEndpoint === null) {
            return;
        }
        $eventType = $event->eventType !== '' ? $event->eventType : 'unknown';
        $attributes = [
            ['key' => 'guard.event_type', 'value' => ['stringValue' => $eventType]],
        ];
        foreach (self::EVENT_SPAN_ATTRS as $attrKey => $eventField) {
            $value = $event->{$eventField} ?? '';
            $attributes[] = ['key' => $attrKey, 'value' => ['stringValue' => (string) $value]];
        }
        $statusCode = isset($event->statusCode) ? $event->statusCode : 0;
        if ($statusCode) {
            $attributes[] = ['key' => 'guard.status_code', 'value' => ['intValue' => (int) $statusCode]];
        }
        foreach ($this->enrichmentEntries($event->metadata) as $key => $value) {
            $attributes[] = ['key' => (string) $key, 'value' => $this->attrValue($value)];
        }

        $parent = $this->extractParentContext($event->metadata);
        $nowNano = (string) (int) round(microtime(true) * 1e9);
        $span = [
            'traceId' => $parent['traceId'] ?? bin2hex(random_bytes(16)),
            'spanId' => bin2hex(random_bytes(8)),
            'name' => 'guard.event.' . $eventType,
            'kind' => 1,
            'startTimeUnixNano' => $nowNano,
            'endTimeUnixNano' => $nowNano,
            'attributes' => $attributes,
        ];
        if (isset($parent['spanId'])) {
            $span['parentSpanId'] = $parent['spanId'];
        }

        $payload = json_encode([
            'resourceSpans' => [[
                'resource' => ['attributes' => $this->resourceAttrJson()],
                'scopeSpans' => [[
                    'scope' => ['name' => 'guard_core.otel'],
                    'spans' => [$span],
                ]],
            ]],
        ], JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION);
        if ($payload === false) {
            error_log('[guard_core] OTEL span encoding failed: ' . (json_last_error_msg() ?: 'unknown error'));

            return;
        }
        if (!$this->transport->export($this->tracesEndpoint, $payload)) {
            error_log('[guard_core] OTEL trace export failed (transport returned false)');
        }
    }

    public function sendMetric(SecurityMetric $metric): void
    {
        if (!$this->started || $this->metricsEndpoint === null) {
            return;
        }
        $attributes = [['key' => 'endpoint', 'value' => ['stringValue' => (string) ($metric->tags['endpoint'] ?? '')]]];
        foreach ($metric->tags as $key => $value) {
            if ($key === 'endpoint' || $key === 'value') {
                continue;
            }
            $attributes[] = ['key' => (string) $key, 'value' => $this->attrValue($value)];
        }
        $nowNano = (string) (int) round(microtime(true) * 1e9);
        $dataPoint = [
            'startTimeUnixNano' => $nowNano,
            'timeUnixNano' => $nowNano,
            'attributes' => $attributes,
        ];
        switch ($metric->metricType) {
            case EventTypes::METRIC_RESPONSE_TIME:
                $metricJson = [
                    'name' => 'guard.request.duration',
                    'unit' => 's',
                    'histogram' => [
                        'dataPoints' => [[...$dataPoint, 'count' => 1, 'sum' => $metric->value, 'bucketCounts' => [1], 'explicitBounds' => []]],
                        'aggregationTemporality' => 2,
                    ],
                ];
                break;
            case EventTypes::METRIC_REQUEST_COUNT:
                $metricJson = [
                    'name' => 'guard.request.count',
                    'sum' => ['dataPoints' => [['asDouble' => $metric->value, ...$dataPoint]], 'aggregationTemporality' => 2, 'isMonotonic' => true],
                ];
                break;
            case EventTypes::METRIC_ERROR_RATE:
                $metricJson = [
                    'name' => 'guard.error.count',
                    'sum' => ['dataPoints' => [['asDouble' => $metric->value, ...$dataPoint]], 'aggregationTemporality' => 2, 'isMonotonic' => true],
                ];
                break;
            default:
                error_log("[guard_core] Unknown OTEL metric type {$metric->metricType} - no instrument recorded");

                return;
        }

        $payload = json_encode([
            'resourceMetrics' => [[
                'resource' => ['attributes' => $this->resourceAttrJson()],
                'scopeMetrics' => [[
                    'scope' => ['name' => 'guard_core.otel'],
                    'metrics' => [$metricJson],
                ]],
            ]],
        ], JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION);
        if ($payload === false) {
            error_log('[guard_core] OTEL metric encoding failed: ' . (json_last_error_msg() ?: 'unknown error'));

            return;
        }
        if (!$this->transport->export($this->metricsEndpoint, $payload)) {
            error_log('[guard_core] OTEL metric export failed (transport returned false)');
        }
    }

    public function initializeRedis(object $redisHandler): void
    {
    }

    public function flushBuffer(): void
    {
    }

    public function getDynamicRules(): mixed
    {
        return null;
    }

    public function healthCheck(): bool
    {
        return $this->transport !== null;
    }

    /**
     * Mirrors _otlp_signal_endpoint: strip the trailing slash, remove a
     * known signal suffix when the host pre-configured one, append the
     * requested signal path.
     */
    public static function otlpSignalEndpoint(string $endpoint, string $signalPath): string
    {
        $base = rtrim($endpoint, '/');
        foreach (self::KNOWN_SIGNAL_PATHS as $known) {
            if (str_ends_with($base, $known)) {
                $base = substr($base, 0, -strlen($known));
                break;
            }
        }

        return $base . $signalPath;
    }

    /**
     * Mirrors _extract_parent_context + the W3C propagator extraction: the
     * traceparent metadata (version-traceId-spanId-flags) becomes the
     * remote parent; tracestate participates in context only. A malformed
     * traceparent yields no parent (extraction swallowed).
     *
     * @param array<string, mixed> $metadata
     *
     * @return array{traceId?: string, spanId?: string}|array<empty, empty>
     */
    private function extractParentContext(array $metadata): array
    {
        $traceparent = $metadata['traceparent'] ?? null;
        if (!is_string($traceparent) || $traceparent === '') {
            return [];
        }
        $parts = explode('-', trim($traceparent));
        if (count($parts) < 4) {
            return [];
        }
        [, $traceId, $spanId] = $parts;
        if (!self::isHexOfLength($traceId, 32) || !self::isHexOfLength($spanId, 16)) {
            return [];
        }

        return ['traceId' => strtolower($traceId), 'spanId' => strtolower($spanId)];
    }

    private static function isHexOfLength(string $value, int $length): bool
    {
        return strlen($value) === $length && preg_match('/^[0-9a-fA-F]+$/', $value) === 1;
    }

    /**
     * Mirrors _forward_enrichment_metadata: every guard.* metadata entry
     * except traceparent/tracestate and null values.
     *
     * @param array<string, mixed> $metadata
     *
     * @return array<string, mixed>
     */
    private function enrichmentEntries(array $metadata): array
    {
        $out = [];
        foreach ($metadata as $key => $value) {
            if (!str_starts_with((string) $key, 'guard.') || $value === null) {
                continue;
            }
            if ($key === 'traceparent' || $key === 'tracestate') {
                continue;
            }
            $out[$key] = $value;
        }

        return $out;
    }

    private function attrValue(mixed $value): array
    {
        if (is_int($value)) {
            return ['intValue' => $value];
        }
        if (is_float($value)) {
            return ['doubleValue' => $value];
        }
        if (is_bool($value)) {
            return ['boolValue' => $value];
        }

        return ['stringValue' => (string) $value];
    }

    /** @return list<array{key: string, value: array<string, string>}> */
    private function resourceAttrJson(): array
    {
        $out = [];
        foreach ($this->resourceAttributes as $key => $value) {
            $out[] = ['key' => $key, 'value' => ['stringValue' => $value]];
        }

        return $out;
    }
}

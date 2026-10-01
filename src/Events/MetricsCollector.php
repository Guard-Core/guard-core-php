<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogRedactor;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

/**
 * The metrics collector, ported from the reference core/events/metrics.py
 * (spec 12 "Metrics"): gated by an agent handler and
 * agent_enable_metrics, suppressed by the EventFilter's muted metric
 * types, emitting response_time / request_count / error_rate per outbound
 * response. Send failures are logged, never raised. Queueable like the
 * event bus: with no handler the metrics queue and flush on attach.
 *
 * Redis persistence (the PHP shared-nothing runtime model): with no
 * handler and a wired RedisHandler the queue lives under
 * `{prefix}metrics:pending` (a JSON list of SecurityMetric payloads) so
 * metrics survive across requests; attaching a handler (or drain())
 * flushes the backlog in order and clears the key. Redis failures are
 * logged, never raised.
 */
final class MetricsCollector
{
    private const PENDING_NAMESPACE = 'metrics';

    private const PENDING_KEY = 'pending';

    private ?object $agentHandler;

    /** @var list<SecurityMetric> */
    private array $queued = [];

    public function __construct(
        ?object $agentHandler,
        private readonly SecurityConfig $config,
        private readonly EventFilter $eventFilter = new EventFilter(),
        private readonly ?RedisHandler $redisHandler = null
    ) {
        $this->agentHandler = $agentHandler;
    }

    public function setAgentHandler(object $agentHandler): void
    {
        $this->agentHandler = $agentHandler;
        foreach ($this->queued as $metric) {
            $this->dispatch($metric);
        }
        $this->queued = [];
        foreach ($this->takePersisted() as $metric) {
            $this->dispatch($metric);
        }
    }

    /** @return list<SecurityMetric> */
    public function drain(): array
    {
        $drained = $this->queued;
        $this->queued = [];

        return [...$drained, ...$this->takePersisted()];
    }

    /**
     * @param array<string, string> $tags
     */
    public function sendMetric(string $metricType, float $value, array $tags = []): void
    {
        if (!$this->config->agentEnableMetrics) {
            return;
        }
        if (!$this->eventFilter->isMetricAllowed($metricType)) {
            return;
        }
        $metric = new SecurityMetric(
            timestamp: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            metricType: $metricType,
            value: $value,
            tags: $tags
        );
        $this->dispatch($metric);
    }

    public function collectRequestMetrics(object $request, float $responseTime, int $statusCode): void
    {
        if (!$this->config->agentEnableMetrics) {
            return;
        }
        $endpoint = LogRedactor::redactUrlForDisplay(
            $request->urlPath(),
            $this->config->logSensitiveParams,
            $this->config->logSensitiveBodyFields,
            $this->config->logSensitiveHeaders
        );
        $method = $request->method();

        $this->sendMetric(EventTypes::METRIC_RESPONSE_TIME, $responseTime, [
            'endpoint' => $endpoint,
            'method' => $method,
            'status' => (string) $statusCode,
        ]);
        $this->sendMetric(EventTypes::METRIC_REQUEST_COUNT, 1.0, [
            'endpoint' => $endpoint,
            'method' => $method,
        ]);
        if ($statusCode >= 400) {
            $this->sendMetric(EventTypes::METRIC_ERROR_RATE, 1.0, [
                'endpoint' => $endpoint,
                'method' => $method,
                'status' => (string) $statusCode,
            ]);
        }
    }

    private function dispatch(SecurityMetric $metric): void
    {
        if ($this->agentHandler !== null) {
            try {
                $this->agentHandler->sendMetric($metric);
            } catch (\Throwable $e) {
                error_log('[guard_core] Failed to send metric to agent: ' . $e->getMessage());
            }

            return;
        }
        if ($this->redisHandler !== null && $this->redisHandler->isEnabled()) {
            $this->persist($metric);

            return;
        }
        $this->queued[] = $metric;
    }

    /**
     * Appends the metric to the pending backlog under
     * `{prefix}metrics:pending`. A read-modify-write JSON list: shared
     * workers accumulate one bounded backlog; telemetry ordering is
     * best-effort, so no lock is taken.
     */
    private function persist(SecurityMetric $metric): void
    {
        try {
            $payload = $this->readPending();
            $payload[] = self::serialize($metric);
            $this->redisHandler->setKey(
                self::PENDING_NAMESPACE,
                self::PENDING_KEY,
                (string) json_encode($payload, JSON_THROW_ON_ERROR)
            );
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to persist metric to Redis: ' . $e->getMessage());
        }
    }

    /**
     * Takes the persisted backlog: the pending key is read, decoded and
     * deleted; an unusable payload is discarded with a log (fail closed to
     * an empty backlog, never raised).
     *
     * @return list<SecurityMetric>
     */
    private function takePersisted(): array
    {
        if ($this->redisHandler === null || !$this->redisHandler->isEnabled()) {
            return [];
        }
        try {
            $raw = $this->redisHandler->getKey(self::PENDING_NAMESPACE, self::PENDING_KEY);
            $this->redisHandler->delete(self::PENDING_NAMESPACE, self::PENDING_KEY);
            if ($raw === null || $raw === '') {
                return [];
            }
            $payload = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($payload) || $payload === [] || !array_is_list($payload)) {
                throw new \UnexpectedValueException('not a metric list');
            }
        } catch (\Throwable $e) {
            error_log('[guard_core] Discarding unusable persisted metrics payload: ' . $e->getMessage());

            return [];
        }
        $metrics = [];
        foreach ($payload as $entry) {
            try {
                $metrics[] = self::deserialize($entry);
            } catch (\Throwable $e) {
                error_log('[guard_core] Discarding unusable persisted metric entry: ' . $e->getMessage());
            }
        }

        return $metrics;
    }

    /** @return list<array<string, mixed>> */
    private function readPending(): array
    {
        $raw = $this->redisHandler->getKey(self::PENDING_NAMESPACE, self::PENDING_KEY);
        if ($raw === null || $raw === '') {
            return [];
        }
        $payload = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($payload) || !array_is_list($payload)) {
            throw new \UnexpectedValueException('pending metrics payload is not a list');
        }

        return $payload;
    }

    /** @return array<string, mixed> */
    private static function serialize(SecurityMetric $metric): array
    {
        return [
            'timestamp' => $metric->timestamp->format(\DateTimeInterface::ATOM),
            'metric_type' => $metric->metricType,
            'value' => $metric->value,
            'tags' => $metric->tags,
        ];
    }

    /**
     * @param mixed $entry
     */
    private static function deserialize(mixed $entry): SecurityMetric
    {
        if (!is_array($entry)
            || !is_string($entry['timestamp'] ?? null)
            || !is_string($entry['metric_type'] ?? null)
            || !is_numeric($entry['value'] ?? null)
            || !is_array($entry['tags'] ?? null)) {
            throw new \UnexpectedValueException('metric entry is malformed');
        }
        $timestamp = new \DateTimeImmutable($entry['timestamp']);
        $tags = [];
        foreach ($entry['tags'] as $name => $value) {
            $tags[(string) $name] = (string) $value;
        }

        return new SecurityMetric(
            timestamp: $timestamp,
            metricType: $entry['metric_type'],
            value: (float) $entry['value'],
            tags: $tags
        );
    }
}

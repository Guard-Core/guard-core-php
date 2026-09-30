<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogRedactor;

/**
 * The metrics collector, ported from the reference core/events/metrics.py
 * (spec 12 "Metrics"): gated by an agent handler and
 * agent_enable_metrics, suppressed by the EventFilter's muted metric
 * types, emitting response_time / request_count / error_rate per outbound
 * response. Send failures are logged, never raised. Queueable like the
 * event bus: with no handler the metrics queue and flush on attach.
 */
final class MetricsCollector
{
    private ?object $agentHandler;

    /** @var list<SecurityMetric> */
    private array $queued = [];

    public function __construct(
        ?object $agentHandler,
        private readonly SecurityConfig $config,
        private readonly EventFilter $eventFilter = new EventFilter()
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
    }

    /** @return list<SecurityMetric> */
    public function drain(): array
    {
        $drained = $this->queued;
        $this->queued = [];

        return $drained;
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
        if ($this->agentHandler === null) {
            $this->queued[] = $metric;

            return;
        }
        try {
            $this->agentHandler->sendMetric($metric);
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to send metric to agent: ' . $e->getMessage());
        }
    }
}

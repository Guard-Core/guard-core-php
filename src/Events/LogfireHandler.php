<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;

/**
 * The Logfire handler, ported from the reference logfire_handler.py
 * LogfireHandler. Logfire's SDK is Python-side; the PHP port keeps the
 * handler's exact lifecycle and emission shape while delegating the actual
 * emission to an injected duck-typed client (the host installs its Logfire
 * client or any compatible facade):
 *
 *   configured(): bool            - the client already owns a configured instance
 *   configure(string $service): void
 *   span(string $name, array $attributes): void
 *   info(string $template, array $fields): void
 *   shutdown(): void
 *
 * Lifecycle mirrors the reference: start() is a no-op when no client is
 * injected (warning logged, like the not-installed SDK path), skips
 * configuration when the client is already configured (warning names the
 * logfire_service_name that will NOT be applied), otherwise configures and
 * remembers that guard configured it; stop() shuts down only when guard
 * did the configuring.
 *
 * sendEvent() emits a span guard.event.{event_type} with the event fields
 * plus every guard.* metadata entry except traceparent/tracestate (the
 * enrichment forward); sendMetric() emits info guard.metric.{type} with
 * value, endpoint and the tags minus value/endpoint.
 */
final class LogfireHandler
{
    private bool $started = false;

    private bool $configuredByGuard = false;

    public function __construct(
        private readonly SecurityConfig $config,
        private readonly ?object $logfire = null
    ) {
    }

    public function start(): void
    {
        if ($this->logfire === null) {
            error_log('[guard_core] logfire client not injected, Logfire handler disabled');

            return;
        }
        if ($this->started) {
            return;
        }
        if ($this->logfire->configured()) {
            $this->started = true;
            error_log('[guard_core] logfire is already configured for this process (by a host application or an earlier guard_core instance); guard_core will not apply its logfire_service_name ' . $this->config->logfireServiceName);

            return;
        }
        $this->logfire->configure($this->config->logfireServiceName);
        $this->configuredByGuard = true;
        $this->started = true;
    }

    public function stop(): void
    {
        if ($this->logfire === null) {
            return;
        }
        if ($this->configuredByGuard) {
            $this->logfire->shutdown();
            $this->configuredByGuard = false;
        }
        $this->started = false;
    }

    public function sendEvent(SecurityEvent $event): void
    {
        if ($this->logfire === null) {
            return;
        }
        $eventType = $event->eventType !== '' ? $event->eventType : 'unknown';
        $attributes = [
            'event_type' => $eventType,
            'ip_address' => $event->ipAddress ?? '',
            'action_taken' => $event->actionTaken ?? '',
            'reason' => $event->reason ?? '',
            'endpoint' => $event->endpoint ?? '',
            'method' => $event->method ?? '',
            'status_code' => isset($event->statusCode) ? $event->statusCode : 0,
        ];
        $metadata = $event->metadata;
        if (is_array($metadata)) {
            foreach ($metadata as $key => $value) {
                if (!str_starts_with((string) $key, 'guard.') || $value === null) {
                    continue;
                }
                if ($key === 'traceparent' || $key === 'tracestate') {
                    continue;
                }
                $attributes[(string) $key] = $value;
            }
        }
        $this->logfire->span('guard.event.' . $eventType, $attributes);
    }

    public function sendMetric(SecurityMetric $metric): void
    {
        if ($this->logfire === null) {
            return;
        }
        $fields = [
            'value' => $metric->value,
            'endpoint' => (string) ($metric->tags['endpoint'] ?? ''),
        ];
        foreach ($metric->tags as $key => $value) {
            if ($key === 'value' || $key === 'endpoint') {
                continue;
            }
            $fields[(string) $key] = $value;
        }
        $this->logfire->info('guard.metric.' . $metric->metricType, $fields);
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
        return $this->logfire !== null;
    }
}

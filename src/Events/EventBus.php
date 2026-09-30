<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogRedactor;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

/**
 * The security event bus, ported from the reference
 * core/events/middleware_events.py SecurityEventBus (spec 12 "Event bus"):
 * it builds SecurityEvent envelopes and forwards them one-way to the agent
 * handler. Gating: no handler or agent_enable_events false means no event;
 * the EventFilter suppresses by exact event_type string; send failures are
 * logged, never raised.
 *
 * Queueable (specs/impl/php.md runtime model): with no handler attached the
 * built events queue in-core and flush when one attaches - FPM adapters can
 * also drain() the queue and deliver it themselves.
 *
 * Envelope fields: timestamp (UTC), event_type, ip_address, country (the
 * optional countryResolver; lookup failures log and the event still sends),
 * user_agent (redacted), action_taken, reason, endpoint (redacted path),
 * method, decorator_type, rule_type, handler_name ("middleware" on the bus
 * path), metadata (the kwargs plus forwarded traceparent/tracestate request
 * headers when present and not already set).
 */
final class EventBus
{
    private ?object $agentHandler;

    /** @var list<SecurityEvent> */
    private array $queued = [];

    /** @var \Closure(string): ?string|null */
    private ?\Closure $countryResolver;

    public function __construct(
        ?object $agentHandler,
        private readonly SecurityConfig $config,
        private readonly EventFilter $eventFilter = new EventFilter(),
        ?callable $countryResolver = null
    ) {
        $this->agentHandler = $agentHandler;
        $this->countryResolver = $countryResolver === null ? null : $countryResolver(...);
    }

    public function setAgentHandler(object $agentHandler): void
    {
        $this->agentHandler = $agentHandler;
        foreach ($this->queued as $event) {
            $this->dispatch($event);
        }
        $this->queued = [];
    }

    /** @return list<SecurityEvent> */
    public function drain(): array
    {
        $drained = $this->queued;
        $this->queued = [];

        return $drained;
    }

    public function sendMiddlewareEvent(
        string $eventType,
        object $request,
        string $actionTaken,
        string $reason,
        array $metadata = []
    ): void {
        if (!$this->config->agentEnableEvents) {
            return;
        }
        if (!$this->eventFilter->isEventAllowed($eventType)) {
            return;
        }

        try {
            $clientIp = $request->state()->clientIp ?? $request->clientHost() ?? '';
            $country = $this->lookupCountry($clientIp);
            $metadata = $this->forwardTraceHeaders($request, $metadata);
            $this->dispatch($this->buildEvent(
                $eventType,
                $request,
                $clientIp,
                $country,
                $actionTaken,
                $reason,
                $metadata
            ));
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to send security event to agent: ' . $e->getMessage());
        }
    }

    /**
     * HTTPS violation dispatch: a route-level require_https emits
     * decorator_violation (decorator_type authentication, violation_type
     * require_https); global enforcement emits https_enforced - both with
     * action https_redirect and the https-swapped redirect url.
     */
    public function sendHttpsViolationEvent(object $request, ?RouteConfig $routeConfig): void
    {
        $httpsUrl = LogRedactor::redactUrlForDisplay(
            $request->urlReplaceScheme('https'),
            $this->config->logSensitiveParams,
            $this->config->logSensitiveBodyFields,
            $this->config->logSensitiveHeaders
        );
        if ($routeConfig !== null && $routeConfig->requireHttps) {
            $this->sendMiddlewareEvent(
                EventTypes::EVENT_DECORATOR_VIOLATION,
                $request,
                'https_redirect',
                'Route requires HTTPS but request was HTTP',
                [
                    'decorator_type' => 'authentication',
                    'violation_type' => 'require_https',
                    'original_scheme' => $request->urlScheme(),
                    'redirect_url' => $httpsUrl,
                ]
            );

            return;
        }
        $this->sendMiddlewareEvent(
            EventTypes::EVENT_HTTPS_ENFORCED,
            $request,
            'https_redirect',
            'HTTP request redirected to HTTPS for security',
            [
                'original_scheme' => $request->urlScheme(),
                'redirect_url' => $httpsUrl,
            ]
        );
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function buildEvent(
        string $eventType,
        object $request,
        string $clientIp,
        ?string $country,
        string $actionTaken,
        string $reason,
        array $metadata
    ): SecurityEvent {
        $rawUserAgent = $request->headers()->get('User-Agent');

        return new SecurityEvent(
            timestamp: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            eventType: $eventType,
            ipAddress: $clientIp,
            country: $country,
            userAgent: $rawUserAgent !== null && $rawUserAgent !== ''
                ? LogRedactor::redactBlob(
                    $rawUserAgent,
                    LogRedactor::sensitiveNames(
                        $this->config->logSensitiveParams,
                        $this->config->logSensitiveBodyFields,
                        $this->config->logSensitiveHeaders
                    )
                )
                : $rawUserAgent,
            actionTaken: $actionTaken,
            reason: $reason,
            endpoint: LogRedactor::redactUrlForDisplay(
                $request->urlPath(),
                $this->config->logSensitiveParams,
                $this->config->logSensitiveBodyFields,
                $this->config->logSensitiveHeaders
            ),
            method: $request->method(),
            handlerName: 'middleware',
            metadata: $metadata
        );
    }

    private function lookupCountry(string $clientIp): ?string
    {
        if ($this->countryResolver === null) {
            return null;
        }
        try {
            return ($this->countryResolver)($clientIp);
        } catch (\Throwable $e) {
            error_log('[guard_core] GeoIP lookup failed for ' . $clientIp . ': ' . $e->getMessage());

            return null;
        }
    }

    /**
     * @param array<string, mixed> $metadata
     * @return array<string, mixed>
     */
    private function forwardTraceHeaders(object $request, array $metadata): array
    {
        foreach (['traceparent', 'tracestate'] as $header) {
            $value = $request->headers()->get($header);
            if ($value !== null && $value !== '' && !isset($metadata[$header])) {
                $metadata[$header] = $value;
            }
        }

        return $metadata;
    }

    private function dispatch(SecurityEvent $event): void
    {
        if ($this->agentHandler === null) {
            $this->queued[] = $event;

            return;
        }
        try {
            $this->agentHandler->sendEvent($event);
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to send security event to agent: ' . $e->getMessage());
        }
    }
}

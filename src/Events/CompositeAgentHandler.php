<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * The multi-sink fan-out agent handler, ported from the reference
 * composite_handler.py CompositeAgentHandler: one SecurityEventBus-facing
 * handler that applies the event/metric filter, enriches once (the sinks
 * all see the same enriched instance), then fans out to every inner
 * handler. Sink failures are logged and never propagate - one dead sink
 * cannot take down the others (degraded, not dead).
 *
 * Lifecycle mirrors the reference: start() records which handlers failed to
 * start (started/degraded()/failedHandlers()), stop()/flushBuffer() are
 * best-effort across all sinks, getDynamicRules() returns the first
 * non-null answer, healthCheck() is all() across the sinks (true when
 * empty).
 */
final class CompositeAgentHandler
{
    /** @var list<object> */
    private array $handlers;

    private EventFilter $eventFilter;

    private ?EventEnricher $enricher;

    private bool $started = false;

    /** @var list<string> */
    private array $failedHandlers = [];

    /**
     * @param list<object> $handlers duck-typed agent handlers (sendEvent /
     *        sendMetric / start / stop / flushBuffer / getDynamicRules /
     *        healthCheck as available on the concrete sinks)
     */
    public function __construct(
        array $handlers,
        ?EventFilter $eventFilter = null,
        ?EventEnricher $enricher = null
    ) {
        $this->handlers = array_values($handlers);
        $this->eventFilter = $eventFilter ?? new EventFilter();
        $this->enricher = $enricher;
    }

    public function started(): bool
    {
        return $this->started;
    }

    public function degraded(): bool
    {
        return $this->started && $this->failedHandlers !== [];
    }

    /** @return list<string> */
    public function failedHandlers(): array
    {
        return $this->failedHandlers;
    }

    public function sendEvent(SecurityEvent $event): void
    {
        if (!$this->eventFilter->isEventAllowed($event->eventType)) {
            return;
        }
        if ($this->enricher !== null) {
            $event = $this->enricher->enrichEvent($event);
        }
        foreach ($this->handlers as $handler) {
            try {
                $handler->sendEvent($event);
            } catch (\Throwable $e) {
                error_log('[guard_core] handler.sendEvent failed: ' . $e->getMessage());
            }
        }
    }

    public function sendMetric(SecurityMetric $metric): void
    {
        if (!$this->eventFilter->isMetricAllowed($metric->metricType)) {
            return;
        }
        if ($this->enricher !== null) {
            $metric = $this->enricher->enrichMetric($metric);
        }
        foreach ($this->handlers as $handler) {
            try {
                $handler->sendMetric($metric);
            } catch (\Throwable $e) {
                error_log('[guard_core] handler.sendMetric failed: ' . $e->getMessage());
            }
        }
    }

    public function initializeRedis(object $redisHandler): void
    {
        foreach ($this->handlers as $handler) {
            try {
                $handler->initializeRedis($redisHandler);
            } catch (\Throwable $e) {
                error_log('[guard_core] handler.initializeRedis failed: ' . $e->getMessage());
            }
        }
    }

    public function start(): void
    {
        $this->failedHandlers = [];
        foreach ($this->handlers as $handler) {
            $handlerName = $handler::class;
            try {
                $handler->start();
            } catch (\Throwable $e) {
                $this->failedHandlers[] = $handlerName;
                error_log("[guard_core] Handler {$handlerName} failed to start: " . $e->getMessage());
            }
        }
        $this->started = true;
    }

    public function stop(): void
    {
        foreach ($this->handlers as $handler) {
            try {
                $handler->stop();
            } catch (\Throwable $e) {
                error_log('[guard_core] handler.stop failed: ' . $e->getMessage());
            }
        }
    }

    public function flushBuffer(): void
    {
        foreach ($this->handlers as $handler) {
            try {
                $handler->flushBuffer();
            } catch (\Throwable $e) {
                error_log('[guard_core] handler.flushBuffer failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * First non-null dynamic-rules answer wins (the reference walks the
     * handlers in order and short-circuits on the first result).
     */
    public function getDynamicRules(): mixed
    {
        foreach ($this->handlers as $handler) {
            try {
                $result = $handler->getDynamicRules();
                if ($result !== null) {
                    return $result;
                }
            } catch (\Throwable $e) {
                error_log('[guard_core] handler.getDynamicRules failed: ' . $e->getMessage());
            }
        }

        return null;
    }

    public function healthCheck(): bool
    {
        if ($this->handlers === []) {
            return true;
        }
        $results = [];
        foreach ($this->handlers as $handler) {
            try {
                $results[] = (bool) $handler->healthCheck();
            } catch (\Throwable $e) {
                error_log('[guard_core] handler.healthCheck failed: ' . $e->getMessage());
                $results[] = false;
            }
        }

        return !in_array(false, $results, true);
    }
}

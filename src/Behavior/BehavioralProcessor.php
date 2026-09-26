<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Behavior;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogRedactor;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

/**
 * Mirrors guard_core/core/behavioral/processor.py: usage/frequency rules run
 * on the request path (process_usage_rules, for requests the pipeline
 * allowed), return_pattern rules run on the response path
 * (process_return_rules over the route's rules, process_global_return_rules
 * over the config's global rules), and get_endpoint_id resolves the
 * endpoint identity. The reference's decorator-violation bus events ride
 * the same deferral as the rest of the event surface: the violation
 * surfaces here as the action dispatch's log stream.
 */
final class BehavioralProcessor
{
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly ?BehaviorTracker $tracker,
        private readonly ?SuspiciousCountStore $counts,
        private readonly ?\Closure $log = null
    ) {
    }

    /**
     * Mirrors get_endpoint_id: a runtime-provided guard_endpoint_id (the
     * request state scratch bag) wins, else "METHOD:redacted-path".
     */
    public function getEndpointId(GuardRequest $request): string
    {
        $endpointId = $request->state()->scratch['guard_endpoint_id'] ?? null;
        if (is_string($endpointId) && $endpointId !== '') {
            return $endpointId;
        }
        $safePath = LogRedactor::redactUrlForDisplay(
            $request->urlPath(),
            $this->config->logSensitiveParams,
            $this->config->logSensitiveBodyFields,
            $this->config->logSensitiveHeaders
        );

        return $request->method() . ':' . $safePath;
    }

    /**
     * Mirrors process_usage_rules: evaluates the route's usage and
     * frequency rules for this request and dispatches the configured action
     * on threshold excess. Exclusion-scoped requests never track (the
     * reference's _behavior_tracker returns None for them); requests
     * without a route config have no usage rules (global rules feed only
     * the return stage, like the reference).
     */
    public function processUsageRules(GuardRequest $request, string $clientIp, ?RouteConfig $routeConfig, float $now): void
    {
        if ($this->tracker === null || $this->skipped($request) || $routeConfig === null || $routeConfig->behaviorRules === []) {
            return;
        }
        $endpointId = $this->getEndpointId($request);
        foreach ($routeConfig->behaviorRules as $rule) {
            if ($rule->ruleType !== 'usage' && $rule->ruleType !== 'frequency') {
                continue;
            }
            if (!$this->tracker->trackEndpointUsage($endpointId, $clientIp, $rule, $now)) {
                continue;
            }
            $details = "{$rule->threshold} calls in {$rule->window}s";
            $this->logViolation(
                "Behavioral {$rule->ruleType} threshold exceeded: {$details}",
                $endpointId,
                $rule
            );
            $this->tracker->applyAction($rule, $clientIp, $endpointId, "Usage threshold exceeded: {$details}");
        }
    }

    /**
     * Mirrors process_return_rules for the route's return_pattern rules.
     */
    public function processReturnRules(GuardRequest $request, ?GuardResponse $response, string $clientIp, ?RouteConfig $routeConfig, float $now): void
    {
        if ($this->tracker === null || $this->skipped($request) || $routeConfig === null) {
            return;
        }
        $endpointId = $this->getEndpointId($request);
        foreach ($routeConfig->behaviorRules as $rule) {
            if ($rule->ruleType !== 'return_pattern') {
                continue;
            }
            if (!$this->tracker->trackReturnPattern($endpointId, $clientIp, $response, $rule, $now)) {
                continue;
            }
            $details = "{$rule->threshold} for '{$rule->pattern}' in {$rule->window}s";
            $this->logViolation("Return pattern threshold exceeded: {$details}", $endpointId, $rule);
            $this->tracker->applyAction($rule, $clientIp, $endpointId, "Return pattern threshold exceeded: {$details}");
        }
    }

    /**
     * Mirrors process_global_return_rules over the config's global rules,
     * including the correlate_with_detection threshold halving driven by
     * the suspicious-activity counts for the client IP.
     */
    public function processGlobalReturnRules(GuardRequest $request, ?GuardResponse $response, string $clientIp, float $now): void
    {
        if ($this->tracker === null || $this->skipped($request) || $this->config->globalBehaviorRules === []) {
            return;
        }
        $endpointId = $this->getEndpointId($request);
        $correlatedCategories = $this->counts !== null ? $this->counts->correlatedCategories($clientIp) : [];
        foreach ($this->config->globalBehaviorRules as $rule) {
            if ($rule->ruleType !== 'return_pattern') {
                continue;
            }
            $correlationActive = $rule->correlateWithDetection && $correlatedCategories !== [];
            $effectiveThreshold = $rule->threshold;
            if ($correlationActive) {
                $effectiveThreshold = max(1, intdiv($rule->threshold, 2));
            }
            if (!$this->tracker->trackReturnPattern($endpointId, $clientIp, $response, $rule, $now, $effectiveThreshold)) {
                continue;
            }
            $correlated = $correlationActive ? ' (correlated)' : '';
            $details = "{$effectiveThreshold} for '{$rule->pattern}' in {$rule->window}s{$correlated}";
            $this->logViolation("Global return pattern threshold exceeded: {$details}", $endpointId, $rule);
            $this->tracker->applyAction($rule, $clientIp, $endpointId, "Global return pattern threshold exceeded: {$details}");
        }
    }

    private function skipped(GuardRequest $request): bool
    {
        return $request->state()->guardExclusionScoped === true;
    }

    private function logViolation(string $reason, string $endpointId, BehaviorRule $rule): void
    {
        if ($this->log === null) {
            return;
        }
        ($this->log)(
            'debug',
            'behavioral_action_triggered: ' . $reason,
            ['endpoint' => $endpointId, 'action' => $rule->action, 'rule_type' => $rule->ruleType]
        );
    }
}

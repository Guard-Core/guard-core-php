<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Behavior;

/**
 * Behavior-rule surface, ported from the reference BehaviorRuleConfig model
 * (guard_core/_security_config_field_validators.py). One class carries both
 * the configured and the runtime rule (the reference config_to_rule copies
 * field by field with no transformation).
 */
final class BehaviorRule
{
    public const RULE_TYPES = ['usage', 'return_pattern', 'frequency'];

    public const ACTIONS = ['ban', 'log', 'throttle', 'alert'];

    /** Reference BehaviorRuleConfig.window default; a 0 normalizes to it. */
    public const DEFAULT_WINDOW = 3600;

    /** Reference BehaviorRuleConfig.action default. */
    public const DEFAULT_ACTION = 'log';

    /**
     * Mirrors _execute_ban_action's fallback when a ban rule carries no
     * ban_duration (the reference None).
     */
    public const DEFAULT_BAN_DURATION = 3600;

    public readonly string $ruleType;

    public readonly int $threshold;

    public readonly int $window;

    public readonly ?string $pattern;

    public readonly string $action;

    public readonly ?int $banDuration;

    public readonly bool $correlateWithDetection;

    public function __construct(
        string $ruleType,
        int $threshold,
        ?int $window = null,
        ?string $pattern = null,
        ?string $action = null,
        ?int $banDuration = null,
        bool $correlateWithDetection = false
    ) {
        if (!in_array($ruleType, self::RULE_TYPES, true)) {
            throw new \InvalidArgumentException(
                'behavior rule rule_type: must be one of usage, return_pattern, frequency (got "' . $ruleType . '")'
            );
        }
        if ($threshold < 1) {
            throw new \InvalidArgumentException("behavior rule threshold: must be >= 1, got {$threshold}");
        }
        $window ??= self::DEFAULT_WINDOW;
        if ($window === 0) {
            $window = self::DEFAULT_WINDOW;
        }
        if ($window < 1) {
            throw new \InvalidArgumentException("behavior rule window: must be >= 1, got {$window}");
        }
        if ($pattern !== null && !is_string($pattern)) {
            throw new \InvalidArgumentException('behavior rule pattern: must be a string or null');
        }
        $action ??= self::DEFAULT_ACTION;
        if (!in_array($action, self::ACTIONS, true)) {
            throw new \InvalidArgumentException(
                'behavior rule action: must be one of ban, log, throttle, alert (got "' . $action . '")'
            );
        }
        if ($banDuration !== null && $banDuration < 1) {
            throw new \InvalidArgumentException("behavior rule ban_duration: must be >= 1, got {$banDuration}");
        }
        $this->ruleType = $ruleType;
        $this->threshold = $threshold;
        $this->window = $window;
        $this->pattern = $pattern;
        $this->action = $action;
        $this->banDuration = $banDuration;
        $this->correlateWithDetection = $correlateWithDetection;
    }

    /**
     * Builds a rule from the reference-shaped dict. Keys: rule_type,
     * threshold, window, pattern, action, ban_duration,
     * correlate_with_detection.
     *
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        $ruleType = $config['rule_type'] ?? null;
        $threshold = $config['threshold'] ?? null;
        if (!is_string($ruleType) || !is_int($threshold)) {
            throw new \InvalidArgumentException('behavior rule: needs a string rule_type and an int threshold');
        }

        return new self(
            ruleType: $ruleType,
            threshold: $threshold,
            window: isset($config['window']) && is_int($config['window']) ? $config['window'] : null,
            pattern: isset($config['pattern']) && is_string($config['pattern']) ? $config['pattern'] : null,
            action: isset($config['action']) && is_string($config['action']) ? $config['action'] : null,
            banDuration: isset($config['ban_duration']) && is_int($config['ban_duration']) ? $config['ban_duration'] : null,
            correlateWithDetection: ($config['correlate_with_detection'] ?? null) === true
        );
    }

    /**
     * Mirrors return_pattern_requires_response_body: every pattern that is
     * not a status: pattern needs the response body to evaluate.
     */
    public function requiresResponseBody(): bool
    {
        return $this->pattern !== null && !str_starts_with($this->pattern, 'status:');
    }
}

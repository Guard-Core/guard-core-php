<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Behavior;

/**
 * Mirrors _validate_return_pattern_requires_scan via
 * _validate_global_behavior_rule_assignment: a return_pattern rule whose
 * pattern needs the response body is rejected when
 * behavior_scan_response_body is false, because it would silently never
 * match. status: patterns are unaffected by the flag.
 */
final class BehaviorRuleValidation
{
    /** @param list<BehaviorRule> $rules */
    public static function validateRulesAgainstScanFlag(array $rules, bool $scanResponseBody, string $fieldName): void
    {
        foreach ($rules as $rule) {
            if ($rule->ruleType !== 'return_pattern' || $rule->pattern === null || $rule->pattern === '') {
                continue;
            }
            if (!$rule->requiresResponseBody() || $scanResponseBody) {
                continue;
            }
            throw new \InvalidArgumentException(
                "{$fieldName}: return_pattern rule with pattern '{$rule->pattern}' requires reading the "
                . 'response body, but behavior_scan_response_body is False. This rule '
                . 'would never match: set behavior_scan_response_body=True to enable '
                . 'response-body inspection, or use a status: pattern instead.'
            );
        }
    }
}

<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection\Redos;

/**
 * The section 04 pattern safety gates, ported from the guard-core reference
 * (compiler.py validate_pattern_safety over _redos_structural_prefilters.py
 * and _redos_cost_arbiter.py):
 *
 *   1. the dangerous-construct regex gate (unconditional, no timing);
 *   2. the compile check (a pattern that cannot compile is rejected, never
 *      raised, in batch validation);
 *   3. the structural safety checks the port carries (nested unbounded
 *      quantifier, adjacent broad unbounded quantifiers) when test strings
 *      were supplied;
 *   4. the probe: each supplied test string is executed against the pattern
 *      with a per-string CPU threshold and an overall wall-clock deadline;
 *      a deadline trip, a failure, or malformed output REJECTS the pattern
 *      (fail closed);
 *   5. without test strings, the cost arbiter (CostArbiter::costVerdict).
 */
final class Prefilters
{
    private const INNER_UNBOUNDED_QUANTIFIER = '(?:\*|\+|\{[0-9]+,\})';
    private const OUTER_UNBOUNDED_QUANTIFIER = '(?:\+|\{[0-9]+,\})';

    private const FIRST_STRUCTURAL_CHECK_MESSAGES = [
        'Pattern contains nested unbounded quantifier: ',
        'Pattern contains adjacent broad unbounded quantifiers: ',
    ];

    /**
     * The reference's _DANGEROUS_CONSTRUCT_PATTERNS, verbatim: an inner
     * unbounded quantifier applied to `.` or a non-`)` class inside an outer
     * unbounded quantifier, or two or more consecutive `.*`-style unbounded
     * units. Rejection is unconditional.
     */
    public static function dangerousConstructViolation(string $pattern): ?string
    {
        $dangerous = [
            '\(\.' . self::INNER_UNBOUNDED_QUANTIFIER . '\)' . self::OUTER_UNBOUNDED_QUANTIFIER,
            '\([^)]*' . self::INNER_UNBOUNDED_QUANTIFIER . '\)' . self::OUTER_UNBOUNDED_QUANTIFIER,
            '(?:\.' . self::INNER_UNBOUNDED_QUANTIFIER . '){2,}',
        ];
        foreach ($dangerous as $construct) {
            if (self::searchPatternSource($construct, $pattern)) {
                return "Pattern contains dangerous construct: {$construct}";
            }
        }

        return null;
    }

    /**
     * The five structural safety checks run in order, first finding wins
     * (_STRUCTURAL_SAFETY_CHECKS); this port carries the first two, whose
     * reference implementations are source-only scans. A violation found
     * here is a rejection on the interactive (test strings) path and a
     * logged disagreement the timed probe overrules on the cost path.
     *
     * @return string|null the violation message, or null
     */
    public static function firstStructuralSafetyViolation(string $pattern): ?string
    {
        $checks = [
            Structure::detectNestedUnboundedQuantifier(...),
            Structure::detectAdjacentBroadUnboundedQuantifiers(...),
        ];
        foreach ($checks as $i => $check) {
            $finding = $check($pattern);
            if ($finding !== null) {
                return self::FIRST_STRUCTURAL_CHECK_MESSAGES[$i] . $finding;
            }
        }

        return null;
    }

    /**
     * The compile check: the pattern must compile under the requested flags;
     * failure rejects with the reference's message shape
     * ("Pattern validation failed: <error>"). PHP compiles lazily, so an
     * empty-subject match triggers the compile; the PHP warning carries the
     * PCRE error text and is captured, not emitted.
     *
     * @return string|null the rejection reason, or null when it compiles
     */
    public static function compileViolation(string $pattern, bool $ignoreCase = true): ?string
    {
        $compiled = self::compileForValidation($pattern, $ignoreCase);
        if (is_string($compiled)) {
            return null;
        }

        return 'Pattern validation failed: ' . ($compiled['error'] ?? 'unknown compile error');
    }

    /** @return string|array{error: string} the compiled pattern or the PCRE error */
    public static function compileForValidation(string $pattern, bool $ignoreCase = true): string|array
    {
        $translated = str_replace('\\Z', '\\z', $pattern);
        $delim = str_contains($translated, "\x01") ? "\x02" : "\x01";
        $compiled = $delim . '(*UCP)' . $translated . $delim . 'u' . ($ignoreCase ? 'i' : '');
        $error = null;
        set_error_handler(static function (int $no, string $message) use (&$error): bool {
            $error = $message;

            return true;
        });
        try {
            $ok = @preg_match($compiled, '');
        } finally {
            restore_error_handler();
        }
        if ($ok === false) {
            $detail = preg_last_error_msg();
            if ($error !== null) {
                $detail = preg_replace('/^preg_match\(\): /', '', (string) $error) ?? $detail;
            }

            return ['error' => $detail !== '' ? $detail : "PCRE error {$code}"];
        }

        return $compiled;
    }

    /**
     * compiler.py validate_pattern_safety, in the reference's exact gate
     * order: dangerous constructs, compile check, then (with test strings)
     * the structural checks and the interactive probe, or (without) the
     * cost arbiter. Returns [safe, reason].
     *
     * @param list<string>|null $testStrings
     * @return array{0: bool, 1: string}
     */
    public static function validatePatternSafety(
        string $pattern,
        ?array $testStrings = null,
        ?int $maxContentLength = null,
        bool $ignoreCase = true
    ): array {
        $dangerousViolation = self::dangerousConstructViolation($pattern);
        if ($dangerousViolation !== null) {
            return [false, $dangerousViolation];
        }
        $compileViolation = self::compileViolation($pattern, $ignoreCase);
        if ($compileViolation !== null) {
            return [false, $compileViolation];
        }
        if ($testStrings !== null) {
            $structuralViolation = self::firstStructuralSafetyViolation($pattern);
            if ($structuralViolation !== null) {
                return [false, $structuralViolation];
            }

            return CostArbiter::probeWithTestStrings($pattern, $testStrings, $ignoreCase);
        }

        return CostArbiter::costVerdict($pattern, $maxContentLength, $ignoreCase);
    }

    /** Raw PCRE search over a pattern's source text (no flags, no UCP). */
    private static function searchPatternSource(string $needleRegex, string $haystack): bool
    {
        $delim = str_contains($needleRegex, "\x01") ? "\x02" : "\x01";

        return @preg_match($delim . $needleRegex . $delim, $haystack) === 1;
    }
}

<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection\Redos;

/**
 * Structural analysis of a regex pattern's SOURCE text, ported from the
 * guard-core reference (spec 04 "Pattern safety gates"):
 *
 *   _redos_structure_primitives.py  (primitives)
 *   _redos_structure_rules.py       (_detect_nested_unbounded_quantifier,
 *                                    _detect_adjacent_broad_unbounded_quantifiers)
 *   _redos_reach_probe.py           (_synthesize_reaching_probe)
 *   _redos_ambiguous_tail.py        (_representative_char_for_atom, printable
 *                                    alphabet path only)
 *
 * Everything here is cheap string scanning over the pattern source; no match
 * is ever executed against a subject. The reference implements three further
 * structural checks (unreachable terminator, ambiguous literal boundary,
 * ambiguous optional tail) on top of its parse-slot/interval machinery; that
 * machinery is reference-internal (spec 04, open questions) and is NOT
 * ported. The cost arbiter's timed probe is the fail-closed backstop for
 * patterns those checks would have flagged, which mirrors the reference's
 * own rule that a surviving timed probe ACCEPTS a structurally flagged
 * pattern.
 */
final class Structure
{
    public const MAX_GROUP_NESTING_DEPTH = 20;

    public const NESTING_DEPTH_REJECTION_REASON =
        'pattern exceeds the maximum group nesting depth of 20 the ReDoS '
        . 'structural analyzer supports';

    private const BROAD_SHORTHAND_ESCAPE_LETTERS = ['S' => true, 'W' => true, 'D' => true];

    private const REACH_STRESS_LEN = 4000;
    private const REACH_BOUNDED_CAP = 4000;
    private const REACH_TOTAL_BUDGET = 12000;
    private const REACH_MAX_LENGTH = 24000;
    private const REACH_GROUP_REPEAT_CAP = 3;
    private const REACH_BREAK_CHAR_CANDIDATES = "\x01\x02\x03\x04\x05\x06\x07\x08";

    /**
     * Python string.printable, in its exact order: digits, ascii_letters,
     * punctuation, whitespace. The order decides which representative char a
     * class atom resolves to, so it is load-bearing for probe parity.
     */
    private const PRINTABLE_ALPHABET = '0123456789'
        . 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        . '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
        . " \t\n\r\x0b\x0c";

    // ---------------------------------------------------------------------
    // Primitives (_redos_structure_primitives.py)
    // ---------------------------------------------------------------------

    /** Index just past the `]` closing the class opened at $i (or strlen). */
    public static function skipCharClass(string $text, int $i): int
    {
        $n = strlen($text);
        $j = $i + 1;
        while ($j < $n && $text[$j] !== ']') {
            if ($text[$j] === '\\' && $j + 1 < $n) {
                $j += 2;

                continue;
            }
            $j++;
        }

        return $j < $n ? $j + 1 : $j;
    }

    /** Every escape sequence and character class collapsed to a literal "X". */
    public static function stripEscapesAndCharClasses(string $pattern): string
    {
        $out = '';
        $i = 0;
        $n = strlen($pattern);
        while ($i < $n) {
            $c = $pattern[$i];
            if ($c === '\\' && $i + 1 < $n) {
                $out .= 'X';
                $i += 2;

                continue;
            }
            if ($c === '[') {
                $i = self::skipCharClass($pattern, $i);
                $out .= 'X';

                continue;
            }
            $out .= $c;
            $i++;
        }

        return $out;
    }

    /** @return int|null null on unbalanced groups */
    public static function findGroupEnd(string $text, int $start): ?int
    {
        $n = strlen($text);
        $depth = 1;
        $j = $start + 1;
        while ($j < $n && $depth > 0) {
            $skipTo = self::advancePastEscapeOrCharClass($text, $j);
            if ($skipTo !== null) {
                $j = $skipTo;

                continue;
            }
            $c = $text[$j];
            if ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth--;
            }
            $j++;
        }

        return $depth === 0 ? $j : null;
    }

    public static function advancePastEscapeOrCharClass(string $text, int $i): ?int
    {
        if ($text[$i] === '\\' && $i + 1 < strlen($text)) {
            return $i + 2;
        }
        if ($text[$i] === '[') {
            return self::skipCharClass($text, $i);
        }

        return null;
    }

    /** Strip the group's `(?...)` header; null when the group is opaque. */
    public static function normalizeGroupInner(string $inner): ?string
    {
        if (str_starts_with($inner, '?:')) {
            return substr($inner, 2);
        }
        if (str_starts_with($inner, '?P=')) {
            return null;
        }
        if (str_starts_with($inner, '?P<')) {
            $endName = strpos($inner, '>');

            return $endName === false ? null : substr($inner, $endName + 1);
        }

        return $inner;
    }

    public static function unwrapTransparentWrapper(string $text): string
    {
        while (str_starts_with($text, '(')) {
            $end = self::findGroupEnd($text, 0);
            if ($end === null || $end !== strlen($text)) {
                break;
            }
            $candidate = self::normalizeGroupInner(substr($text, 1, $end - 2));
            if ($candidate === null) {
                break;
            }
            $text = $candidate;
        }

        return $text;
    }

    /** Byte length of the unbounded quantifier (*, +, {n,}) at $k, or 0. */
    public static function outerQuantifierLen(string $text, int $k): int
    {
        $n = strlen($text);
        if ($k < $n && ($text[$k] === '*' || $text[$k] === '+')) {
            return 1;
        }
        if ($k < $n && $text[$k] === '{') {
            $endBrace = strpos($text, '}', $k);
            if ($endBrace !== false) {
                $braceInner = substr($text, $k + 1, $endBrace - $k - 1);
                $parts = explode(',', $braceInner, 2);
                if (count($parts) === 2 && $parts[1] === '') {
                    return $endBrace - $k + 1;
                }
            }
        }

        return 0;
    }

    /**
     * @param list<string> $branches
     */
    public static function branchesOverlap(array $branches): bool
    {
        $n = count($branches);
        for ($a = 0; $a < $n; $a++) {
            for ($b = $a + 1; $b < $n; $b++) {
                $x = $branches[$a];
                $y = $branches[$b];
                if ($x === $y || str_starts_with($x, $y) || str_starts_with($y, $x)) {
                    return true;
                }
            }
        }

        return false;
    }

    public static function isPureLiteralBranch(string $branch): bool
    {
        if ($branch === '') {
            return false;
        }
        $meta = "()[]{}.*+?^$|\\";
        for ($i = 0, $n = strlen($branch); $i < $n; $i++) {
            if (strpos($meta, $branch[$i]) !== false) {
                return false;
            }
        }

        return true;
    }

    /** @return list<string> */
    public static function splitTopLevelAlternations(string $inner): array
    {
        $branches = [];
        $depth = 0;
        $start = 0;
        $k = 0;
        $n = strlen($inner);
        while ($k < $n) {
            $skipTo = self::advancePastEscapeOrCharClass($inner, $k);
            if ($skipTo !== null) {
                $k = $skipTo;

                continue;
            }
            $c = $inner[$k];
            if ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth--;
            } elseif ($c === '|' && $depth === 0) {
                $branches[] = substr($inner, $start, $k - $start);
                $start = $k + 1;
            }
            $k++;
        }
        $branches[] = substr($inner, $start);

        return $branches;
    }

    public static function overlappingLiteralBranches(string $inner): bool
    {
        $literalBranches = array_values(array_filter(
            self::splitTopLevelAlternations($inner),
            self::isPureLiteralBranch(...)
        ));

        return count($literalBranches) >= 2 && self::branchesOverlap($literalBranches);
    }

    // ---------------------------------------------------------------------
    // Rule 1: nested unbounded quantifier (_redos_structure_rules.py)
    // ---------------------------------------------------------------------

    /** @return list<array{0: int, 1: int, 2: string}> */
    public static function iterQuantifiedGroupBodies(string $pattern): array
    {
        return self::iterQuantifiedGroupBodiesAt($pattern, 0, 0);
    }

    /**
     * @return list<array{0: int, 1: int, 2: string}>
     */
    private static function iterQuantifiedGroupBodiesAt(string $pattern, int $base, int $depth): array
    {
        if ($depth > self::MAX_GROUP_NESTING_DEPTH) {
            throw new StructureNestingTooDeep();
        }
        $out = [];
        $i = 0;
        $n = strlen($pattern);
        while ($i < $n) {
            if ($pattern[$i] !== '(') {
                $i++;

                continue;
            }
            $j = self::findGroupEnd($pattern, $i);
            if ($j === null) {
                $i++;

                continue;
            }
            $rawInner = substr($pattern, $i + 1, $j - $i - 2);
            foreach (self::iterQuantifiedGroupBodiesAt($rawInner, $base + $i + 1, $depth + 1) as $nested) {
                $out[] = $nested;
            }
            $inner = self::normalizeGroupInner($rawInner);
            if ($inner !== null) {
                $inner = self::unwrapTransparentWrapper($inner);
                $qlen = self::outerQuantifierLen($pattern, $j);
                if ($qlen > 0) {
                    $out[] = [$base + $i, $base + $j + $qlen, $inner];
                }
            }
            $i = $j;
        }

        return $out;
    }

    public static function nestedBodyIsUnbounded(string $inner): bool
    {
        $stripped = self::stripEscapesAndCharClasses($inner);
        foreach (explode('|', $stripped) as $branch) {
            if (self::branchIsUnboundedSingle($branch)) {
                return true;
            }
        }

        return self::overlappingLiteralBranches($inner);
    }

    private static function branchIsUnboundedSingle(string $branch): bool
    {
        $len = strlen($branch);
        if ($len === 2 && ($branch[1] === '*' || $branch[1] === '+')) {
            return true;
        }
        if ($len > 3 && $branch[1] === '{') {
            return @preg_match('/^.\{[0-9]+,\}$/', $branch) === 1;
        }

        return false;
    }

    /** @return string|null the offending quantified group span */
    public static function detectNestedUnboundedQuantifier(string $pattern): ?string
    {
        try {
            foreach (self::iterQuantifiedGroupBodies($pattern) as [$start, $end, $inner]) {
                if (self::nestedBodyIsUnbounded($inner)) {
                    return substr($pattern, $start, $end - $start);
                }
            }
        } catch (StructureNestingTooDeep) {
            return self::NESTING_DEPTH_REJECTION_REASON;
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // Rule 2: adjacent broad unbounded quantifiers
    // ---------------------------------------------------------------------

    private static function isBroadCharClassInner(string $inner): bool
    {
        if (str_starts_with($inner, '^')) {
            $excluded = substr($inner, 1);

            return preg_match('/\\\\[SWD]/', $excluded) !== 1;
        }

        return $inner === '\\s\\S' || $inner === '\\S\\s';
    }

    /** @return array{0: int, 1: bool} next index and whether the atom is broad */
    private static function broadAtomSpan(string $pattern, int $i): array
    {
        $n = strlen($pattern);
        $c = $pattern[$i];
        if ($c === '\\' && $i + 1 < $n) {
            return [$i + 2, isset(self::BROAD_SHORTHAND_ESCAPE_LETTERS[$pattern[$i + 1]])];
        }
        if ($c === '[') {
            $j = self::skipCharClass($pattern, $i);

            return [$j, self::isBroadCharClassInner(substr($pattern, $i + 1, $j - $i - 2))];
        }
        if ($c === '.') {
            return [$i + 1, true];
        }

        return [$i + 1, false];
    }

    /** @return array{0: int, 1: list<string>} */
    private static function broadUnboundedRunAt(string $pattern, int $depth): array
    {
        if ($depth > self::MAX_GROUP_NESTING_DEPTH) {
            throw new StructureNestingTooDeep();
        }
        $count = 0;
        $spans = [];
        $i = 0;
        $n = strlen($pattern);
        while ($i < $n) {
            if ($pattern[$i] === '(') {
                $j = self::findGroupEnd($pattern, $i);
                if ($j === null) {
                    $i++;

                    continue;
                }
                $inner = self::normalizeGroupInner(substr($pattern, $i + 1, $j - $i - 2));
                if ($inner !== null) {
                    $bestCount = -1;
                    $bestSpans = [];
                    foreach (self::splitTopLevelAlternations($inner) as $branch) {
                        [$branchCount, $branchSpans] = self::broadUnboundedRunAt($branch, $depth + 1);
                        if ($branchCount > $bestCount) {
                            $bestCount = $branchCount;
                            $bestSpans = $branchSpans;
                        }
                    }
                    if ($bestCount > 0) {
                        $count += $bestCount;
                        foreach ($bestSpans as $span) {
                            $spans[] = $span;
                        }
                    }
                }
                $i = $j;

                continue;
            }
            [$atomEnd, $isBroad] = self::broadAtomSpan($pattern, $i);
            if ($isBroad && self::outerQuantifierLen($pattern, $atomEnd) > 0) {
                $count++;
                $spans[] = substr($pattern, $i, $atomEnd - $i);
            }
            $i = $atomEnd;
        }

        return [$count, $spans];
    }

    /** @return string|null " and ".join of the first two broad spans */
    public static function detectAdjacentBroadUnboundedQuantifiers(string $pattern): ?string
    {
        try {
            [$count, $spans] = self::broadUnboundedRunAt($pattern, 0);
        } catch (StructureNestingTooDeep) {
            return self::NESTING_DEPTH_REJECTION_REASON;
        }
        if ($count >= 2) {
            return implode(' and ', array_slice($spans, 0, 2));
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // Reaching-probe synthesis (_redos_reach_probe.py)
    // ---------------------------------------------------------------------

    /**
     * Build a concrete subject that reaches every quantified region of the
     * pattern (the reference's _synthesize_reaching_probe). Returns null
     * when no such subject can be constructed: the caller must then reject
     * rather than certify, per spec 04.
     */
    public static function synthesizeReachingProbe(string $pattern): ?string
    {
        $state = ['chars' => [], 'budget' => self::REACH_TOTAL_BUDGET, 'groups' => [], 'counter' => 0];
        [$body, $ok] = self::synthesizeSegment($pattern, $state, 0);
        if (!$ok) {
            return null;
        }
        $breaking = null;
        for ($i = 0, $n = strlen(self::REACH_BREAK_CHAR_CANDIDATES); $i < $n; $i++) {
            $ch = self::REACH_BREAK_CHAR_CANDIDATES[$i];
            if (!isset($state['chars'][$ch])) {
                $breaking = $ch;
                break;
            }
        }

        return $breaking === null ? null : $body . $breaking;
    }

    /**
     * @param array{chars: array<string, true>, budget: int, groups: array<int, string>, counter: int} $state
     * @return array{0: string, 1: bool}
     */
    private static function synthesizeSegment(string $text, array &$state, int $depth): array
    {
        if ($depth > self::MAX_GROUP_NESTING_DEPTH) {
            return ['', false];
        }
        $out = '';
        $length = 0;
        $i = 0;
        $n = strlen($text);
        while ($i < $n) {
            if ($text[$i] === '^' || $text[$i] === '$') {
                $i++;

                continue;
            }
            try {
                $result = self::synthNextAtom($text, $i, $state, $depth);
            } catch (ReachProbeOverflow) {
                return ['', false];
            }
            if ($result === null) {
                return ['', false];
            }
            [$piece, $i] = $result;
            $length += strlen($piece);
            if ($length > self::REACH_MAX_LENGTH) {
                return ['', false];
            }
            $out .= $piece;
        }

        return [$out, true];
    }

    /**
     * @param array{chars: array<string, true>, budget: int, groups: array<int, string>, counter: int} $state
     * @return array{0: string, 1: int}|null
     */
    private static function synthNextAtom(string $text, int $i, array &$state, int $depth): ?array
    {
        return match ($text[$i]) {
            '\\' => self::synthEscapeAtom($text, $i, $state),
            '[' => self::synthCharClassAtom($text, $i, $state),
            '.' => self::synthStressFill($text, $i + 1, 'a', $state),
            '(' => self::synthGroupAtom($text, $i, $state, $depth),
            default => self::synthStressFill($text, $i + 1, $text[$i], $state),
        };
    }

    /**
     * @param array{chars: array<string, true>, budget: int, groups: array<int, string>, counter: int} $state
     * @return array{0: string, 1: int}|null
     */
    private static function synthEscapeAtom(string $text, int $i, array &$state): ?array
    {
        $n = strlen($text);
        if ($i + 1 >= $n) {
            return null;
        }
        $letter = $text[$i + 1];
        $isHex = $letter === 'x' && $i + 3 < $n
            && ctype_xdigit($text[$i + 2]) && ctype_xdigit($text[$i + 3]);
        $tokenEnd = $isHex ? $i + 4 : $i + 2;
        if (strpos('AZbB', $letter) !== false) {
            return ['', $tokenEnd];
        }
        if ($letter >= '0' && $letter <= '9') {
            $backref = $state['groups'][(int) $letter] ?? null;
            if ($backref === null) {
                return null;
            }

            return self::synthStressFill($text, $tokenEnd, $backref, $state);
        }
        $rep = $isHex
            ? chr((int) hexdec(substr($text, $i + 2, 2)))
            : self::representativeCharForAtom(substr($text, $i, $tokenEnd - $i));
        if ($rep === null) {
            return null;
        }

        return self::synthStressFill($text, $tokenEnd, $rep, $state);
    }

    /**
     * @param array{chars: array<string, true>, budget: int, groups: array<int, string>, counter: int} $state
     * @return array{0: string, 1: int}|null
     */
    private static function synthCharClassAtom(string $text, int $i, array &$state): ?array
    {
        $end = self::skipCharClass($text, $i);
        $rep = self::representativeCharForAtom(substr($text, $i, $end - $i));
        if ($rep === null) {
            return null;
        }

        return self::synthStressFill($text, $end, $rep, $state);
    }

    /**
     * @param array{chars: array<string, true>, budget: int, groups: array<int, string>, counter: int} $state
     * @return array{0: string, 1: int}|null
     */
    private static function synthGroupAtom(string $text, int $i, array &$state, int $depth): ?array
    {
        $groupEnd = self::findGroupEnd($text, $i);
        if ($groupEnd === null) {
            return null;
        }
        $rawInner = substr($text, $i + 1, $groupEnd - $i - 2);
        $reservedNumber = null;
        if ($rawInner === '' || $rawInner[0] !== '?' || str_starts_with($rawInner, '?P<')) {
            $state['counter']++;
            $reservedNumber = $state['counter'];
        }
        [$walkInner, $skip] = self::groupWalkTarget($rawInner);
        if ($skip) {
            return ['', $groupEnd];
        }
        if ($walkInner === null) {
            return null;
        }
        $firstBranch = self::splitTopLevelAlternations($walkInner)[0];
        [$subText, $subOk] = self::synthesizeSegment($firstBranch, $state, $depth + 1);
        if (!$subOk) {
            return null;
        }
        if ($reservedNumber !== null) {
            $state['groups'][$reservedNumber] = $subText;
        }
        [$low, $high, $nextI] = self::quantifierRepeatRange($text, $groupEnd);
        $high = max($low, min($high, self::REACH_GROUP_REPEAT_CAP));
        $count = self::budgetClampedCount($state, strlen($subText), $low, $high);
        $state['budget'] -= strlen($subText) * $count;

        return [str_repeat($subText, $count), $nextI];
    }

    /** @return array{0: string|null, 1: bool} inner text to walk, or a skip flag */
    private static function groupWalkTarget(string $rawInner): array
    {
        if ($rawInner === '' || $rawInner[0] !== '?') {
            return [$rawInner, false];
        }
        if (str_starts_with($rawInner, '?:')) {
            return [substr($rawInner, 2), false];
        }
        if (str_starts_with($rawInner, '?P<')) {
            $close = strpos($rawInner, '>');

            return [$close === false ? null : substr($rawInner, $close + 1), false];
        }
        foreach (['?=', '?!', '?<=', '?<!'] as $look) {
            if (str_starts_with($rawInner, $look)) {
                return [null, true];
            }
        }
        if (str_starts_with($rawInner, '?#')) {
            return [null, true];
        }
        if (preg_match('/^\?[aiLmsux]*(?:-[aiLmsux]+)?:/', $rawInner, $m) === 1) {
            return [substr($rawInner, strlen($m[0])), false];
        }
        if (preg_match('/^\?[aiLmsux]*(?:-[aiLmsux]+)?$/', $rawInner) === 1) {
            return [null, true];
        }

        return [null, false];
    }

    /**
     * @param array{chars: array<string, true>, budget: int, groups: array<int, string>, counter: int} $state
     * @return array{0: string, 1: int}|null
     */
    private static function synthStressFill(string $text, int $tokenEnd, string $rep, array &$state): ?array
    {
        [$low, $high, $nextI] = self::quantifierRepeatRange($text, $tokenEnd);
        $count = self::budgetClampedCount($state, strlen($rep), $low, $high);
        $state['budget'] -= strlen($rep) * $count;
        $state['chars'][$rep] = true;

        return [str_repeat($rep, $count), $nextI];
    }

    /** @return array{0: int, 1: int, 2: int} low, high, next index */
    private static function quantifierRepeatRange(string $text, int $k): array
    {
        $n = strlen($text);
        if ($k >= $n) {
            return [1, 1, $k];
        }
        $c = $text[$k];
        $end = $k + 1;
        if ($end < $n && $text[$end] === '?') {
            $end++;
        }
        if ($c === '*') {
            return [0, self::REACH_STRESS_LEN, $end];
        }
        if ($c === '+') {
            return [1, self::REACH_STRESS_LEN, $end];
        }
        if ($c === '?') {
            return [0, 1, $end];
        }
        if ($c !== '{') {
            return [1, 1, $k];
        }
        $endBrace = strpos($text, '}', $k);
        if ($endBrace === false) {
            return [1, 1, $k];
        }
        $parts = explode(',', substr($text, $k + 1, $endBrace - $k - 1));
        if (!ctype_digit($parts[0])) {
            return [1, 1, $k];
        }
        $low = (int) $parts[0];
        if (count($parts) === 1) {
            $high = $low;
        } elseif ($parts[1] === '') {
            $high = self::REACH_STRESS_LEN;
        } elseif (ctype_digit($parts[1])) {
            $high = (int) $parts[1];
        } else {
            return [1, 1, $k];
        }
        $end = $endBrace + 1;
        if ($end < $n && $text[$end] === '?') {
            $end++;
        }

        return [$low, max($low, min($high, self::REACH_BOUNDED_CAP)), $end];
    }

    /**
     * @param array{chars: array<string, true>, budget: int, groups: array<int, string>, counter: int} $state
     * @return int
     */
    private static function budgetClampedCount(array &$state, int $unitLen, int $low, int $high): int
    {
        if ($unitLen <= 0) {
            return $high;
        }
        if ($low > intdiv(self::REACH_MAX_LENGTH, $unitLen)) {
            throw new ReachProbeOverflow();
        }
        $affordable = max(0, $state['budget']) / $unitLen;

        return max($low, min($high, (int) $affordable));
    }

    /**
     * The printable character an atom can match, by full-matching every
     * Python-string.printable character against the atom under DOTALL
     * (_representative_char_for_atom). The reference's fallback to
     * non-printable candidate characters (its parse-slot machinery) is not
     * ported: an atom matching no printable character yields null and the
     * probe synthesis fails, which rejects fail-closed.
     */
    public static function representativeCharForAtom(string $atomText): ?string
    {
        $anchored = self::compileAnchoredAtom($atomText);
        if ($anchored === null) {
            return null;
        }
        foreach (str_split(self::PRINTABLE_ALPHABET) as $ch) {
            if (@preg_match($anchored, $ch) === 1) {
                return $ch;
            }
        }

        return null;
    }

    /**
     * The first literal character a pattern can match at all (the reference
     * _extract_literal_chars' head): escape/class atoms resolve through
     * their representative character, plain literal atoms contribute
     * themselves, and quantifier/meta characters are skipped. Drives the
     * cost arbiter's adversarial literal-run probe unit. Null when the
     * pattern has no resolvable literal.
     */
    public static function firstLiteralChar(string $pattern): ?string
    {
        $i = 0;
        $n = strlen($pattern);
        while ($i < $n) {
            $c = $pattern[$i];
            if ($c === '\\' && $i + 1 < $n) {
                $rep = self::representativeCharForAtom(substr($pattern, $i, 2));
                if ($rep !== null) {
                    return $rep;
                }
                $i += 2;

                continue;
            }
            if ($c === '[') {
                $atomEnd = self::skipCharClass($pattern, $i);
                $rep = self::representativeCharForAtom(substr($pattern, $i, $atomEnd - $i));
                if ($rep !== null) {
                    return $rep;
                }
                $i = $atomEnd;

                continue;
            }
            if (ctype_alnum($c) || strpos('_-./:@~ ', $c) !== false) {
                return $c;
            }
            $i++;
        }

        return null;
    }

    private static function compileAnchoredAtom(string $atomText): ?string
    {
        $delim = str_contains($atomText, "\x01") ? "\x02" : "\x01";
        $pattern = $delim . '\\A(?:' . $atomText . ')\\z' . $delim . 's';

        return @preg_match($pattern, '') === false ? null : $pattern;
    }
}

final class StructureNestingTooDeep extends \RuntimeException
{
}

final class ReachProbeOverflow extends \RuntimeException
{
}

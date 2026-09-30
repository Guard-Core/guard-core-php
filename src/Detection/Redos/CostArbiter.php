<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection\Redos;

/**
 * The ReDoS cost arbiter, ported from the guard-core reference
 * (_redos_cost_arbiter.py): verdict deadlines scaled by a measured host load
 * factor, the timed reach-probe ladder (sizes 4000..32000), the verdict
 * rule (min at 32000 and 16000 normalized by the load factor, growth per
 * doubling forced to 1.0 under the noise floor, extrapolation to the
 * content cap against the 0.05 s budget, one confirming retry), and the
 * interactive probe over supplied test strings (0.05 s per-string
 * threshold, 2.0 s overall deadline, fail closed).
 *
 * Port adaptations: the reference times probes in killable subprocesses on
 * CPU clocks; PHP times them inline on the monotonic hrtime clock (wall
 * clock) and bounds every probe match with the ScanGuard
 * pcre.backtrack_limit budget, so a catastrophic pattern trips the engine
 * limit instead of hanging the request. The observable contract is the
 * normative part (reject slow patterns, fail closed, bounded time); the
 * subprocess plumbing itself is not portable.
 */
final class CostArbiter
{
    public const PROBE_TIMEOUT_SECONDS = 2.0;
    public const PROBE_PER_STRING_THRESHOLD_SECONDS = 0.05;

    /** @var list<int> */
    public const REACH_PROBE_SIZES = [4000, 8000, 16000, 32000];

    /** @var list<int> */
    public const REACH_VERDICT_PROBE_SIZES = [16000, 32000];

    public const REACH_PROBE_BUDGET_SECONDS = 0.05;

    /** The reference's load-probe scan (?i inline flag, source form). */
    public const REFERENCE_SCAN_PATTERN_SOURCE
        = '(?i)/[0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|CONCAT|CHAR|UPDATE)\b';
    public const REFERENCE_SCAN_PROBE_LENGTH = 32000;
    public const REFERENCE_SCAN_SECONDS = 0.00229;
    public const LOAD_FACTOR_FLOOR = 0.25;
    public const LOAD_FACTOR_CEILING = 8.0;

    public const REACH_PROBE_NOISE_FLOOR_SECONDS = 0.001;
    public const REACH_PROBE_SAMPLE_COUNT = 5;
    public const REACH_PROBE_LARGE_SAMPLE_SECONDS = 0.2;
    public const REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS = self::REACH_PROBE_NOISE_FLOOR_SECONDS;

    public const PATTERN_SAFETY_DEFAULT_CAP = 262144;
    public const MAX_TIMED_PROBE_SETS = 512;
    public const REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS = 240.0;
    public const REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS = 5.0;

    /** 2.0 s probe timeout * 4 sizes * 5 samples. */
    public const REACH_PROBE_COMBINED_TIMEOUT_SECONDS = 40.0;

    /** Prefix cut lengths for the probe-unit builders (_REACH_PROBE_PREFIX_CUT_LENGTHS). */
    public const REACH_PROBE_PREFIX_CUT_LENGTHS = [20, 30, 50];

    /** Large bounded repeat threshold (_redos_repeat_alphabet.py). */
    public const LARGE_BOUNDED_REPEAT_LIMIT = 4096;

    // ------------------------------------------------------------------
    // Load factor and deadlines
    // ------------------------------------------------------------------

    public static function loadFactor(float $referenceSeconds): float
    {
        $raw = $referenceSeconds / self::REFERENCE_SCAN_SECONDS;

        return min(max($raw, self::LOAD_FACTOR_FLOOR), self::LOAD_FACTOR_CEILING);
    }

    /**
     * The reference scans a fixed pattern on a 32000-char probe in a
     * subprocess with a 5 s timeout and defaults to 1.0 on any failure. The
     * port times the same scan inline (it is linear, millisecond-scale);
     * any preg failure or exceeded wall budget falls back to 1.0.
     * $sampleScan and $wallBudgetSeconds are injection points for tests:
     * the callable replaces the reference scan (returning a sample's
     * seconds, or false on failure), and the budget replaces the 5 s wall.
     */
    public static function measureHostLoadFactor(?\Closure $sampleScan = null, ?float $wallBudgetSeconds = null, ?string $referencePattern = null): float
    {
        $probe = '/' . str_repeat('0', self::REFERENCE_SCAN_PROBE_LENGTH);
        $referencePattern ??= self::REFERENCE_SCAN_PATTERN_SOURCE;
        $sampleScan ??= static function () use ($probe, $referencePattern): float|false {
            $t0 = hrtime(true);
            if (@preg_match("\x01" . $referencePattern . "\x01", $probe) === false) {
                return false;
            }

            return (hrtime(true) - $t0) / 1e9;
        };
        $wallBudget = $wallBudgetSeconds ?? self::REFERENCE_LOAD_PROBE_TIMEOUT_SECONDS;
        $times = [];
        $start = hrtime(true);
        for ($i = 0; $i < self::REACH_PROBE_SAMPLE_COUNT; $i++) {
            $sample = $sampleScan();
            if ($sample === false) {
                return 1.0;
            }
            $times[] = $sample;
            if ((hrtime(true) - $start) / 1e9 > $wallBudget) {
                break;
            }
        }

        return self::loadFactor(min($times));
    }

    public static function scaledProbeDeadlineSeconds(float $loadFactor): float
    {
        return min(
            self::REACH_PROBE_COMBINED_TIMEOUT_SECONDS * max($loadFactor, 1.0),
            self::REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS
        );
    }

    // ------------------------------------------------------------------
    // Interactive probe (test strings supplied)
    // ------------------------------------------------------------------

    /**
     * The reference's subprocess probe, ported inline: compile, then run
     * each test string with a per-string threshold and an overall deadline.
     * A compile failure, engine-budget trip, threshold trip, or deadline
     * trip REJECTS (fail closed). Reasons mirror the reference's strings.
     * $deadlineNs is an injection point for tests; the default is the
     * reference's 2.0 s overall timeout.
     *
     * @param list<string> $testStrings
     * @return array{0: bool, 1: string} [safe, reason]
     */
    public static function probeWithTestStrings(string $pattern, array $testStrings, bool $ignoreCase = true, ?int $deadlineNs = null): array
    {
        $compiled = Prefilters::compileForValidation($pattern, $ignoreCase);
        if (!is_string($compiled)) {
            return [false, 'Pattern validation failed: ' . $compiled['error']];
        }
        $deadline = $deadlineNs ?? hrtime(true) + (int) (self::PROBE_TIMEOUT_SECONDS * 1e9);
        foreach ($testStrings as $testString) {
            if (hrtime(true) >= $deadline) {
                return [false, 'Pattern validation probe exceeded the '
                    . sprintf('%.1fs', self::PROBE_TIMEOUT_SECONDS) . ' killable-subprocess timeout'];
            }
            $result = ScanGuard::runBounded(
                static fn (): int|false => @preg_match($compiled, $testString),
                ScanGuard::STOCK_BACKTRACK_BUDGET
            );
            $elapsed = $result->elapsedSeconds;
            if ($result->timedOut || ($elapsed !== null && $elapsed > self::PROBE_PER_STRING_THRESHOLD_SECONDS)) {
                return [false, 'Pattern timed out on test string of length ' . strlen($testString)];
            }
        }

        return [true, 'Pattern appears safe'];
    }

    // ------------------------------------------------------------------
    // Cost verdict (no test strings)
    // ------------------------------------------------------------------

    /**
     * The reference's _reach_probe_verdict_from_samples: take min at 32000
     * and min at 16000 normalized by the load factor, force the growth
     * ratio to 1.0 while min16 sits at or under the noise floor,
     * extrapolate min32 * ratio^log2(cap/32000), and flag over-budget when
     * the extrapolation exceeds the 0.05 s safety budget.
     *
     * @param list<list<float>> $samplesBySize per-size buckets of sorted times
     * @return array{0: bool, 1: float, 2: float, 3: float, 4: float} over, extrapolated, ratio, min32, median32
     */
    public static function verdictFromSamples(array $samplesBySize, int $cap, float $loadFactor = 1.0): array
    {
        $last = $samplesBySize[count($samplesBySize) - 1];
        $previous = $samplesBySize[count($samplesBySize) - 2];
        $median32 = $last[intdiv(count($last), 2)] / $loadFactor;
        $min16 = $previous[0] / $loadFactor;
        $min32 = $last[0] / $loadFactor;
        $ratio = $min16 > self::REACH_PROBE_NOISE_FLOOR_SECONDS
            ? max($min32 / $min16, 1.0)
            : 1.0;
        $doublings = log(max($cap, 1) / self::REACH_PROBE_SIZES[3], 2);
        $extrapolated = $min32 * ($ratio ** $doublings);
        $overBudget = $extrapolated > self::REACH_PROBE_BUDGET_SECONDS;

        return [$overBudget, $extrapolated, $ratio, $min32, $median32];
    }

    /** The reference's _reach_probe_cost_reason message shape. */
    public static function costReason(
        ?string $structuralViolation,
        float $extrapolated,
        float $ratio,
        int $cap,
        float $min32,
        float $median32,
        float $loadFactor
    ): string {
        if ($structuralViolation !== null) {
            return $structuralViolation;
        }

        return sprintf(
            'Pattern extrapolated CPU cost at cap (%d chars) is %.3fs, exceeding the '
            . '%.2fs safety budget (growth ratio %.2fx per doubling, CPU time at 32000 '
            . 'chars: min %.4fs, median %.4fs over %d runs, normalized by host load '
            . 'factor %.2f)',
            $cap,
            $extrapolated,
            self::REACH_PROBE_BUDGET_SECONDS,
            $ratio,
            $min32,
            $median32,
            self::REACH_PROBE_SAMPLE_COUNT,
            $loadFactor
        );
    }

    public static function unreachableReason(?string $structuralViolation): string
    {
        if ($structuralViolation !== null) {
            return $structuralViolation;
        }

        return 'Pattern validation probe could not construct a test string that '
            . 'reaches every quantified region of this pattern; rejecting rather '
            . 'than certifying safety on an unreachable probe';
    }

    /**
     * The no-test-strings cost verdict (_reach_probe_cost_verdict):
     * synthesize a probe that reaches every quantified region (reject when
     * none can be built), extract repeatable probe units, time the verdict
     * ladder (the full size ladder when a structural rule or a large
     * bounded repeat already flagged the pattern), and reject on a
     * confirmed over-budget extrapolation. A pattern with no extractable
     * trigger is accepted without timing even when a structural rule
     * flagged it: the timed probe overrules the structural heuristic, and
     * the disagreement is reported via the costReason structural message on
     * any rejection and via error_log for accepts. $deadlineNs and $timer
     * are injection points for tests; the defaults are the load-scaled
     * verdict deadline and real hrtime timing.
     *
     * @return array{0: bool, 1: string} [safe, reason]
     */
    public static function costVerdict(string $pattern, ?int $maxContentLength = null, bool $ignoreCase = true, ?int $deadlineNs = null, ?\Closure $timer = null): array
    {
        $loadFactor = self::measureHostLoadFactor();
        $deadline = $deadlineNs ?? hrtime(true) + (int) (self::scaledProbeDeadlineSeconds($loadFactor) * 1e9);
        $cap = $maxContentLength !== null && $maxContentLength > 0
            ? $maxContentLength
            : self::PATTERN_SAFETY_DEFAULT_CAP;
        $structuralViolation = Prefilters::firstStructuralSafetyViolation($pattern);
        $boundedRepeatRisk = self::hasLargeBoundedRepeat($pattern);

        $compiled = Prefilters::compileForValidation($pattern, $ignoreCase);
        if (!is_string($compiled)) {
            return [false, 'Pattern validation failed: ' . $compiled['error']];
        }

        $probeUnit = Structure::synthesizeReachingProbe($pattern);
        if ($probeUnit === null) {
            return [false, self::unreachableReason($structuralViolation)];
        }
        if (hrtime(true) >= $deadline) {
            return [false, 'Pattern validation probe construction exceeded its deadline'];
        }

        $builders = self::probeUnitBuilders($probeUnit, $pattern);
        if ($builders === []) {
            return [true, 'Pattern appears safe'];
        }

        $sizes = $structuralViolation !== null || $boundedRepeatRisk
            ? self::REACH_PROBE_SIZES
            : self::REACH_VERDICT_PROBE_SIZES;
        $stray = self::chooseProbeStray($pattern, $ignoreCase);
        $probeSets = self::strideSampledProbeSets(self::uniqueProbeSets($builders, $sizes, $stray));

        foreach ($probeSets as $probes) {
            $timing = self::timeProbes($compiled, $probes, $deadline, $timer);
            if ($timing === null) {
                return [false, $structuralViolation
                    ?? 'Pattern validation probe exceeded the killable-subprocess '
                    . 'timeout while measuring reach-probe cost at scale'];
            }
            [$overBudget, $extrapolated, $ratio, $min32, $median32] =
                self::verdictFromSamples($timing['samples'], $cap, $timing['loadFactor']);
            if ($overBudget && hrtime(true) < $deadline) {
                $retry = self::timeProbes($compiled, $probes, $deadline, $timer);
                if ($retry !== null) {
                    $timing = $retry;
                    [$overBudget, $extrapolated, $ratio, $min32, $median32] =
                        self::verdictFromSamples($retry['samples'], $cap, $retry['loadFactor']);
                }
            }
            if ($overBudget) {
                return [false, self::costReason(
                    $structuralViolation,
                    $extrapolated,
                    $ratio,
                    $cap,
                    $min32,
                    $median32,
                    $timing['loadFactor']
                )];
            }
        }

        if ($structuralViolation !== null) {
            // The timed probe overrules the structural heuristic; the
            // disagreement is logged, and the pattern is accepted
            // (_log_structural_disagreement).
            error_log('[guard_core] pattern safety: structural rule flagged a pattern '
                . '(' . $structuralViolation . ') but the timed reach-probe measured '
                . 'it under budget and linear at cap ' . $cap . '; accepting');
        }

        return [true, 'Pattern appears safe'];
    }

    /**
     * Probe-unit builders mirroring the reference's builder families
     * (_reach_probe_prefix_builders plus _literal_run_builders): the
     * synthesized probe's body repeated to each target size, its first
     * 20/30/50 characters as repeat units when long enough, and the
     * pattern's first literal character as the adversarial literal run -
     * that unit is what produces FAILING probes for shapes like (a+)+b
     * (a run of a's with no terminator), which is where a backtracking
     * engine actually explodes.
     *
     * @return list<string>
     */
    public static function probeUnitBuilders(string $probe, string $pattern): array
    {
        $bodyOnly = str_replace('?', '', substr($probe, 0, -1));
        if ($bodyOnly === '') {
            return [];
        }
        $builders = [$bodyOnly];
        foreach (self::REACH_PROBE_PREFIX_CUT_LENGTHS as $cut) {
            $prefix = substr($bodyOnly, 0, $cut);
            if (strlen($prefix) >= 2) {
                $builders[] = $prefix;
            }
        }
        $literalRun = Structure::firstLiteralChar($pattern);
        if ($literalRun !== null && !in_array($literalRun, $builders, true)) {
            $builders[] = $literalRun;
        }

        return $builders;
    }

    /**
     * A character the pattern cannot match (the reference's stray/breaking
     * char candidates, _PROBE_REACH_BREAK_CHAR_CANDIDATES): repeated probes
     * end in it, so timing measures the expensive failing path instead of a
     * trivial early match. Falls back to "\x01" for patterns that match
     * every candidate (their probes then measure the matching path, which
     * can only under-report cost).
     */
    public static function chooseProbeStray(string $pattern, bool $ignoreCase): string
    {
        $compiled = Prefilters::compileForValidation($pattern, $ignoreCase);
        if (is_string($compiled)) {
            for ($i = 1; $i <= 8; $i++) {
                $ch = chr($i);
                if (@preg_match($compiled, $ch) === 0) {
                    return $ch;
                }
            }
        }

        return "\x01";
    }

    /**
     * @param list<string> $builders
     * @param list<int> $sizes
     * @return list<list<string>>
     */
    public static function uniqueProbeSets(array $builders, array $sizes, string $stray = "\x01"): array
    {
        $seen = [];
        $sets = [];
        foreach ($builders as $builder) {
            $probes = [];
            foreach ($sizes as $size) {
                $probes[] = self::repeatToLength($builder, $size, $stray);
            }
            $digest = md5(implode("\x00", $probes));
            if (isset($seen[$digest])) {
                continue;
            }
            $seen[$digest] = true;
            $sets[] = $probes;
        }

        return $sets;
    }

    /**
     * Stride-sample to at most MAX_TIMED_PROBE_SETS unique sets
     * (_stride_sampled_probe_sets).
     *
     * @param list<list<string>> $probeSets
     * @return list<list<string>>
     */
    public static function strideSampledProbeSets(array $probeSets): array
    {
        $total = count($probeSets);
        if ($total <= self::MAX_TIMED_PROBE_SETS) {
            return $probeSets;
        }
        $stride = (int) ceil($total / self::MAX_TIMED_PROBE_SETS);
        $sampled = [];
        for ($i = 0; $i < $total; $i += $stride) {
            $sampled[] = $probeSets[$i];
        }

        return $sampled;
    }

    /**
     * Time one probe set: one sample per probe, extended toward the full
     * sample count while the first sample reaches the full-sample trigger,
     * aborting past the large-sample seconds (the reference timing child's
     * loop). Returns null when any probe trips its engine budget - the
     * fail-closed analogue of a killed timing subprocess. $timer is the
     * per-match timing injection point for tests.
     *
     * @param list<string> $probes
     * @return array{samples: list<list<float>>, loadFactor: float}|null
     */
    private static function timeProbes(string $compiled, array $probes, int $deadlineNs, ?\Closure $timer = null): ?array
    {
        $samplesBySize = [];
        foreach ($probes as $probe) {
            if (hrtime(true) >= $deadlineNs) {
                return null;
            }
            $sample = self::timedSearch($compiled, $probe, $timer);
            if ($sample === null) {
                return null;
            }
            $probeTimes = [$sample];
            if ($probeTimes[0] >= self::REACH_PROBE_FULL_SAMPLE_TRIGGER_SECONDS) {
                for ($i = 0; $i < self::REACH_PROBE_SAMPLE_COUNT - 1; $i++) {
                    $sample = self::timedSearch($compiled, $probe, $timer);
                    if ($sample === null) {
                        return null;
                    }
                    $probeTimes[] = $sample;
                    if ($sample > self::REACH_PROBE_LARGE_SAMPLE_SECONDS) {
                        break;
                    }
                }
            }
            sort($probeTimes);
            $samplesBySize[] = $probeTimes;
        }

        return ['samples' => $samplesBySize, 'loadFactor' => self::measureHostLoadFactor()];
    }

    /** One hrtime-bounded probe match; null when the engine budget trips. */
    private static function timedSearch(string $compiled, string $probe, ?\Closure $timer = null): ?float
    {
        if ($timer !== null) {
            return $timer($probe);
        }
        $result = ScanGuard::runBounded(
            static fn (): int|false => @preg_match($compiled, $probe),
            ScanGuard::STOCK_BACKTRACK_BUDGET
        );
        if ($result->timedOut || $result->elapsedSeconds === null) {
            return null;
        }

        return $result->elapsedSeconds;
    }

    private static function repeatToLength(string $unit, int $size, string $stray): string
    {
        if ($unit === '') {
            return '';
        }
        $repeats = max(1, intdiv($size, strlen($unit)));

        return str_repeat($unit, $repeats) . $stray;
    }

    /**
     * The reference gates the full probe ladder on a large bounded repeat
     * (a variable {n,m} quantifier with m >= 4096). The reference's
     * slot-level parse is not ported; this source-level scan is a
     * deliberate superset that can only widen the timed evidence, never
     * change the verdict rule.
     */
    public static function hasLargeBoundedRepeat(string $pattern): bool
    {
        if (@preg_match_all('/\{(\d+),(\d+)\}/', $pattern, $m) !== 1) {
            return false;
        }
        foreach ($m[1] as $i => $low) {
            if ($low === $m[2][$i]) {
                continue;
            }
            if ((int) $m[2][$i] >= self::LARGE_BOUNDED_REPEAT_LIMIT) {
                return true;
            }
        }

        return false;
    }
}

<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Detection\Redos;

use RenzoFranceschini\GuardCore\Detection\PregFailure;

/**
 * Per-scan safety gates for the PCRE-backed detection scans (spec 04 scan
 * execution, ported to PHP's engine model):
 *
 * - pcre.backtrack_limit budget: every guarded scan runs with the engine's
 *   stock backtrack limit set via ini_set, and the previous limit is
 *   restored afterwards (a harness or deployment may have raised it).
 * - fail-closed limit trips: a scan that aborts with
 *   PREG_BACKTRACK_LIMIT_ERROR, PREG_RECURSION_LIMIT_ERROR, or
 *   PREG_JIT_STACKLIMIT_ERROR is classified as a scan timeout, translated
 *   by the caller into the exact reference timeout semantics
 *   (threats-logged-and-miss: a pattern_timeout threat with the pattern's
 *   category weight is emitted and the match itself is missed). The three
 *   codes are the one engine-exhaustion phenomenon - backtracking budget,
 *   native stack, JIT stack - and the reference times all of them out.
 *   Other preg failures (bad UTF-8, internal errors) keep the engine's
 *   fail-secure behavior.
 * - wall-clock deadline: an optional hrtime deadline; a scan that exceeds
 *   it reports timedOut with its (partial) result discarded, mirroring the
 *   reference's cancelled pool future. PHP cannot preempt a running
 *   preg_match, so the deadline arms after the call returns; the backtrack
 *   budget bounds the call itself.
 * - consecutive-timeout accounting: the reference replaces its shared
 *   4-worker pool after 4 consecutive scan timeouts because the wedged
 *   futures would otherwise occupy it forever. PHP has no worker pool to
 *   wedge (each preg call is bounded by the budget above); the counter and
 *   its warning are kept as the observable behaviour, and the reset is.
 */
final class ScanGuard
{
    /** The engine's stock pcre.backtrack_limit (also the per-scan budget). */
    public const STOCK_BACKTRACK_BUDGET = 1000000;

    /**
     * preg error codes that mean the engine exhausted a resource while
     * scanning: the one phenomenon behind backtracking budget, native
     * recursion stack, and JIT stack. Each is a scan timeout here.
     */
    private const EXHAUSTION_CODES = [
        PREG_BACKTRACK_LIMIT_ERROR => true,
        PREG_RECURSION_LIMIT_ERROR => true,
        PREG_JIT_STACKLIMIT_ERROR => true,
    ];

    /** Shared-executor worker count == consecutive-timeout threshold. */
    public const CONSECUTIVE_TIMEOUT_POOL_REPLACEMENT = 4;

    /** A single canary probe already over this budget means catastrophic. */
    private const CANARY_OVER_BUDGET_SECONDS = 0.05;

    /** @var int */
    private static int $consecutiveTimeouts = 0;

    /**
     * Runs $scan() under the backtrack budget and the optional wall-clock
     * deadline. On a limit trip the scan reports timedOut (fail closed);
     * any other preg failure propagates.
     */
    public static function runBounded(callable $scan, ?int $backtrackBudget = null, ?float $deadlineSeconds = null): ScanResult
    {
        $budget = $backtrackBudget ?? self::STOCK_BACKTRACK_BUDGET;
        $previousLimit = ini_get('pcre.backtrack_limit');
        $isRaised = $previousLimit !== false && (int) $previousLimit > $budget;
        if ($isRaised) {
            ini_set('pcre.backtrack_limit', (string) $budget);
        }
        $started = hrtime(true);
        $timedOut = false;
        $thrown = null;
        try {
            try {
                $value = $scan();
                if ($value === false) {
                    // Raw preg closures signal engine failure with a bare
                    // false; an exhaustion trip is a scan timeout, fail
                    // closed (Preg-based scans throw PregFailure and take
                    // the catch below).
                    if (isset(self::EXHAUSTION_CODES[preg_last_error()])) {
                        $timedOut = true;
                        $value = null;
                    }
                }
            } catch (PregFailure $failure) {
                if (isset(self::EXHAUSTION_CODES[$failure->pregErrorCode])) {
                    $timedOut = true;
                    $value = null;
                } else {
                    throw $failure;
                }
            }
        } catch (\Throwable $e) {
            $thrown = $e;
        } finally {
            if ($isRaised) {
                ini_set('pcre.backtrack_limit', (string) $previousLimit);
            }
            $elapsedSeconds = (hrtime(true) - $started) / 1e9;
        }
        if ($thrown !== null) {
            throw $thrown;
        }
        if (!$timedOut && $deadlineSeconds !== null && $elapsedSeconds > $deadlineSeconds) {
            $timedOut = true;
            $value = null;
        }
        if ($timedOut) {
            self::reportScanTimeout();
        } else {
            self::reportScanSuccess();
        }

        return new ScanResult($timedOut, $timedOut ? null : $value, $elapsedSeconds);
    }

    /**
     * The reference's report_scan_timeout: increment the consecutive
     * counter; at the pool-worker threshold reset it and warn that a slow
     * pattern may have occupied the whole pool (in PHP: bounded scans that
     * keep tripping the budget).
     */
    public static function reportScanTimeout(): void
    {
        self::$consecutiveTimeouts++;
        if (self::$consecutiveTimeouts < self::CONSECUTIVE_TIMEOUT_POOL_REPLACEMENT) {
            return;
        }
        $staleCount = self::$consecutiveTimeouts;
        self::$consecutiveTimeouts = 0;
        error_log('[guard_core] guard_core shared regex scan pool replaced after '
            . $staleCount . ' consecutive timeouts; a slow pattern may have '
            . 'permanently occupied all workers');
    }

    /** The reference's report_scan_success: any success resets the counter. */
    public static function reportScanSuccess(): void
    {
        if (self::$consecutiveTimeouts !== 0) {
            self::$consecutiveTimeouts = 0;
        }
    }

    public static function consecutiveTimeouts(): int
    {
        return self::$consecutiveTimeouts;
    }

    /**
     * The canary gate for a plain pattern about to scan a large subject:
     * run the pattern on doubling prefixes (4096, 8192 bytes) under the
     * stock backtrack budget, then apply the arbiter's verdict arithmetic
     * (canaryExtrapolatesOverBudget) against the scan's wall budget (0.9x
     * the compiler timeout, the reference's timeout arm). A canary that
     * trips its engine budget is already catastrophic: skip the full scan.
     *
     * Returns true when the full scan must be skipped (predicted over
     * budget, fail closed), false when the scan may run.
     */
    public static function probeBeforeScan(string $compiled, string $subject, float $scanBudgetSeconds): bool
    {
        $length = strlen($subject);
        $probeSize = 4096;
        if ($length <= $probeSize * 2) {
            return false;
        }
        $first = self::canarySeconds($compiled, $subject, $probeSize);
        if ($first === null || $first > self::CANARY_OVER_BUDGET_SECONDS) {
            return true;
        }

        return self::canaryExtrapolatesOverBudget(
            $first,
            self::canarySeconds($compiled, $subject, min($probeSize * 2, $length)),
            $length,
            $scanBudgetSeconds
        );
    }

    /**
     * The arbiter's verdict arithmetic applied to the two canary samples:
     * a second canary that tripped its engine budget is catastrophic
     * (fail closed); otherwise growth per doubling above the noise floor,
     * extrapolated from the 8192-byte probe to the full subject, against
     * the scan's wall budget.
     */
    public static function canaryExtrapolatesOverBudget(float $first, ?float $second, int $length, float $scanBudgetSeconds): bool
    {
        if ($second === null) {
            return true;
        }
        $ratio = $first > CostArbiter::REACH_PROBE_NOISE_FLOOR_SECONDS
            ? max($second / $first, 1.0)
            : 1.0;
        $doublings = log($length / 8192, 2);
        $extrapolated = $second * ($ratio ** $doublings);

        return $extrapolated > $scanBudgetSeconds;
    }

    private static function canarySeconds(string $compiled, string $subject, int $length): ?float
    {
        $result = self::runBounded(
            static fn (): int|false => @preg_match($compiled, substr($subject, 0, $length)),
            self::STOCK_BACKTRACK_BUDGET
        );
        if ($result->timedOut || $result->elapsedSeconds === null) {
            return null;
        }

        return $result->elapsedSeconds;
    }
}

final class ScanResult
{
    public function __construct(
        public readonly bool $timedOut,
        public readonly mixed $value,
        public readonly ?float $elapsedSeconds
    ) {
    }
}

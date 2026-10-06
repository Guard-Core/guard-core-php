<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Behavior;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

/**
 * Ported from guard_core/handlers/behavior_handler.py: sliding-window usage
 * counts and return-pattern hits per (endpoint, client), backed by Redis
 * when available (the shared behavior_usage/behavior_returns key layout
 * with SHA-256-harded identity segments) and by bounded local maps
 * otherwise, plus the action dispatch of
 * handlers/_behavior_action_dispatch.py (passive mode only logs, active mode
 * bans with the rule's ban_duration or the 3600s fallback, alerts or logs).
 */
final class BehaviorTracker
{
    /**
     * Tracker bounds mirror _MAX_TRACKED_ENDPOINTS and
     * _MAX_TRACKED_CLIENTS_PER_ENDPOINT (behavior_handler.py): the local
     * stores hold at most this many endpoint buckets and client rows per
     * endpoint.
     */
    private const MAX_TRACKED_ENDPOINTS = 10000;

    private const MAX_TRACKED_CLIENTS_PER_ENDPOINT = 10000;

    /** @var array<string, array<string, list<float>>> */
    private array $usageCounts = [];

    /** @var array<string, array<string, list<float>>> */
    private array $returnPatterns = [];

    public function __construct(
        private readonly SecurityConfig $config,
        private readonly ?RedisHandler $redis,
        private readonly ?IpBanManager $ban,
        private readonly ?\Closure $log = null
    ) {
    }

    /**
     * SHA-256 identity segment, mirroring _hash_identity_segment so the two
     * engines share the behavior_usage/behavior_returns key layout.
     */
    public static function hashIdentitySegment(string $value): string
    {
        return hash('sha256', $value);
    }

    /**
     * Mirrors track_endpoint_usage: records one hit and reports whether the
     * rule threshold is now exceeded (strictly greater, like the
     * reference). $now is a float unix timestamp like time.time().
     */
    public function trackEndpointUsage(string $endpointId, string $clientIp, BehaviorRule $rule, float $now): bool
    {
        $windowStart = $now - $rule->window;
        if ($this->redis !== null && $this->redis->isEnabled()) {
            $key = 'behavior:usage:' . self::hashIdentitySegment($endpointId) . ':' . self::hashIdentitySegment($clientIp);
            try {
                $count = $this->redis->recordSlidingWindowHit('behavior_usage', $key, $now, $windowStart, $rule->window);

                return $count > $rule->threshold;
            } catch (GuardRedisException $e) {
                if (!$this->config->redisFailOpen) {
                    // Fail closed like the pipeline's redis handling: an
                    // unavailable store must not quietly disable the rule.
                    $this->log('warning', 'behavior tracking: redis unavailable (' . $e->getMessage() . ')', []);

                    return false;
                }
            }
        }
        $count = $this->trackLocal($this->usageCounts, $endpointId, $clientIp, $now, $windowStart);

        return $count > $rule->threshold;
    }

    /**
     * Mirrors track_return_pattern: the pattern must match first; only
     * matching responses advance the sliding window.
     * $effectiveThreshold <= 0 means "use the rule threshold".
     */
    public function trackReturnPattern(string $endpointId, string $clientIp, ?GuardResponse $response, BehaviorRule $rule, float $now, int $effectiveThreshold = 0): bool
    {
        if ($rule->pattern === null || $rule->pattern === '') {
            return false;
        }
        if ($effectiveThreshold <= 0) {
            $effectiveThreshold = $rule->threshold;
        }
        [$matched, $evaluated] = $this->checkResponsePattern($response, $rule->pattern);
        if (!$evaluated || !$matched) {
            return false;
        }
        $windowStart = $now - $rule->window;
        if ($this->redis !== null && $this->redis->isEnabled()) {
            $key = 'behavior:return:' . self::hashIdentitySegment($endpointId) . ':' . self::hashIdentitySegment($clientIp)
                . ':' . self::hashIdentitySegment($rule->pattern);
            try {
                $count = $this->redis->recordSlidingWindowHit('behavior_returns', $key, $now, $windowStart, $rule->window);

                return $count > $effectiveThreshold;
            } catch (GuardRedisException $e) {
                if (!$this->config->redisFailOpen) {
                    $this->log('warning', 'behavior tracking: redis unavailable (' . $e->getMessage() . ')', []);

                    return false;
                }
            }
        }
        $patternKey = $endpointId . ':' . $rule->pattern;
        $count = $this->trackLocal($this->returnPatterns, $patternKey, $clientIp, $now, $windowStart);

        return $count > $effectiveThreshold;
    }

    /**
     * Mirrors get_recent_event_count (behavior_handler.py): the total
     * in-window usage hits recorded for one client across every endpoint
     * bucket (local stores only - the redis-backed windows are not walked,
     * matching the reference which only reads its local map). Used by the
     * event enrichment's behavior correlation. $now defaults to
     * microtime(true) like the reference's time.time().
     */
    public function getRecentEventCount(string $ip, int $windowSeconds, ?float $now = null): int
    {
        if ($ip === '') {
            return 0;
        }
        $cutoff = ($now ?? microtime(true)) - $windowSeconds;
        $count = 0;
        foreach ($this->usageCounts as $endpointBucket) {
            foreach ($endpointBucket[$ip] ?? [] as $ts) {
                if ($ts >= $cutoff) {
                    $count++;
                }
            }
        }

        return $count;
    }

    /**
     * Prunes and appends one timestamp in the bounded local store and
     * returns the new in-window count. Python evicts LRU-first via
     * _lru_pop_or_create; the PHP array keeps insertion order, so the
     * oldest-tracked entry is dropped, which bounds memory identically even
     * though the victim choice differs.
     *
     * @param array<string, array<string, list<float>>> $store
     */
    private function trackLocal(array &$store, string $bucket, string $key, float $now, float $windowStart): int
    {
        if (!isset($store[$bucket])) {
            if (count($store) >= self::MAX_TRACKED_ENDPOINTS) {
                unset($store[array_key_first($store)]);
            }
            $store[$bucket] = [];
        }
        $rows = &$store[$bucket];
        if (!isset($rows[$key]) && count($rows) >= self::MAX_TRACKED_CLIENTS_PER_ENDPOINT) {
            unset($rows[array_key_first($rows)]);
        }
        $timestamps = array_values(array_filter(
            $rows[$key] ?? [],
            static fn (float $ts): bool => $ts >= $windowStart
        ));
        $timestamps[] = $now;
        $rows[$key] = $timestamps;

        return count($timestamps);
    }

    /**
     * Mirrors _check_response_pattern (_behavior_response_pattern.py). The
     * second return value mirrors the reference's tri-state:
     * evaluated=false stands for the None outcome (the body could not be
     * inspected, so the hit is not counted), evaluated=true carries the
     * match verdict.
     *
     * @return array{bool, bool}
     */
    public function checkResponsePattern(?GuardResponse $response, string $pattern): array
    {
        try {
            if (str_starts_with($pattern, 'status:')) {
                $expected = filter_var(substr($pattern, 7), FILTER_VALIDATE_INT);
                if ($expected === false) {
                    return [false, true];
                }

                return [$response !== null && $response->statusCode() === $expected, true];
            }

            if (!$this->config->behaviorScanResponseBody) {
                // The reference returns None before touching the body: with
                // the scan flag off, non-status patterns are not evaluated
                // at all (config construction rejects such rules, so this
                // is a defensive path for runtime-built rules).
                return [false, false];
            }
            $maxBytes = $this->config->behaviorMaxResponseBodyInspectBytes;
            if ($response === null || $response->body() === null || $response->body() === '') {
                return [false, true];
            }
            $body = substr($response->body(), 0, $maxBytes);

            if (str_starts_with($pattern, 'json:')) {
                $parsed = json_decode($body, true);
                if (!is_array($parsed) && $parsed !== null && !is_scalar($parsed)) {
                    return [false, true];
                }
                if ($parsed === null && trim($body) !== '' && json_last_error() !== JSON_ERROR_NONE) {
                    return [false, true];
                }

                return [$this->matchJsonPattern($parsed, substr($pattern, 5)), true];
            }

            if (str_starts_with($pattern, 'regex:')) {
                $result = @preg_match('~' . str_replace('~', '\\~', substr($pattern, 6)) . '~i', $body);
                if ($result === false) {
                    $this->log('error', 'Error checking response pattern: preg_match failed for the return_pattern regex', []);

                    return [false, true];
                }

                return [$result === 1, true];
            }

            return [str_contains(strtolower($body), strtolower($pattern)), true];
        } catch (\Throwable $e) {
            $this->log('error', 'Error checking response pattern: ' . $e->getMessage(), []);

            return [false, true];
        }
    }

    /**
     * Mirrors BehaviorJsonPatternMixin._match_json_pattern:
     * "path.to.field==expected" with case-insensitive comparison, a "[]"
     * segment matching any array element, and any structural mismatch or
     * parse failure counting as no-match.
     */
    private function matchJsonPattern(mixed $data, string $pattern): bool
    {
        if (!str_contains($pattern, '==')) {
            return false;
        }
        [$path, $expected] = explode('==', $pattern, 2);
        $path = trim($path);
        $expected = trim(trim($expected), "\"'");

        $current = $data;
        foreach (explode('.', $path) as $part) {
            if (str_ends_with($part, '[]')) {
                return $this->matchJsonArray($current, substr($part, 0, -2), $expected);
            }
            if (!is_array($current) || !array_key_exists($part, $current)) {
                return false;
            }
            $current = $current[$part];
        }

        return strtolower($this->jsonScalarToString($current)) === strtolower($expected);
    }

    private function matchJsonArray(mixed $current, string $part, string $expected): bool
    {
        if (!is_array($current) || !array_key_exists($part, $current) || !is_array($current[$part])) {
            return false;
        }
        foreach ($current[$part] as $item) {
            if (strtolower($this->jsonScalarToString($item)) === strtolower($expected)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Mirrors Python str() over the JSON-decoded scalar: booleans as
     * lowercase true/false, null as the empty string (json_decode of
     * "null" yields PHP null which renders like Python's str(None) only in
     * the reference's Python-land; the JSON-walk leaves are always strings
     * here, so null only shows for a literal JSON null, rendered "" like a
     * decoded null field), and floats via PHP's shortest round-trip
     * formatting.
     */
    private function jsonScalarToString(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return '';
        }

        return (string) $value;
    }

    /**
     * Mirrors the BehaviorActionDispatchMixin: passive mode only logs,
     * active mode bans (ban_duration override, else 3600s, reason
     * "behavioral_violation"), alerts, or logs. The reference additionally
     * emits agent security events, which this port does not model (the
     * agent surface stays fail-closed).
     */
    public function applyAction(BehaviorRule $rule, string $clientIp, string $endpointId, string $details): void
    {
        if ($this->config->passiveMode) {
            $this->logPassiveModeAction($rule, $clientIp, $details);

            return;
        }
        switch ($rule->action) {
            case 'ban':
                $duration = $rule->banDuration ?? BehaviorRule::DEFAULT_BAN_DURATION;
                $applied = $this->ban !== null && $this->ban->ban($clientIp, $duration, 'behavioral_violation');
                if (!$applied) {
                    return;
                }
                $this->logAtSuspiciousLevel("IP {$clientIp} banned for behavioral violation: {$details}");
                break;
            case 'alert':
                $this->log('critical', "ALERT - Behavioral anomaly: {$details}", ['ip' => $clientIp, 'endpoint' => $endpointId]);
                break;
            case 'log':
                $this->logAtSuspiciousLevel("Behavioral anomaly detected: {$details}");
                break;
            case 'throttle':
                $this->logAtSuspiciousLevel("Throttling IP {$clientIp}: {$details}");
                break;
        }
    }

    private function logPassiveModeAction(BehaviorRule $rule, string $clientIp, string $details): void
    {
        $prefix = '[PASSIVE MODE] ';
        if ($rule->action === 'alert') {
            $this->log('critical', "{$prefix}ALERT - Behavioral anomaly: {$details}", ['ip' => $clientIp]);

            return;
        }
        switch ($rule->action) {
            case 'ban':
                $this->logAtSuspiciousLevel("{$prefix}Would ban IP {$clientIp} for behavioral violation: {$details}");
                break;
            case 'log':
                $this->logAtSuspiciousLevel("{$prefix}Behavioral anomaly detected: {$details}");
                break;
            case 'throttle':
                $this->logAtSuspiciousLevel("{$prefix}Would throttle IP {$clientIp}: {$details}");
                break;
        }
    }

    /**
     * Mirrors _log_at_level over log_suspicious_level; the PHP config
     * defaults the level to WARNING (never None), so the level name
     * annotates the line.
     */
    private function logAtSuspiciousLevel(string $message): void
    {
        $this->log(strtolower($this->config->logSuspiciousLevel ?? 'warning'), $message, []);
    }

    /** @param array<string, mixed> $context */
    private function log(string $level, string $message, array $context): void
    {
        if ($this->log !== null) {
            ($this->log)($level, $message, $context);

            return;
        }
        error_log('[guard_core:' . strtoupper($level) . '] ' . $message);
    }
}

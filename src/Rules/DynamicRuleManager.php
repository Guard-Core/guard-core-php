<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Rules;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Cloud\CloudProviderRegistry;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\Redos\Prefilters;
use RenzoFranceschini\GuardCore\Detection\Redos\ValidationCache;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

/**
 * The dynamic rule manager, ported from the reference
 * dynamic_rule_handler.py plus its application and snapshot mixins (spec
 * 12 "Dynamic rules"): the update flow (expiry, staleness gate,
 * already-expired rejection, updated/applied events), the application of
 * every rule field exactly as _dynamic_rule_application.py does (timed bans
 * for ip_blacklist, unbans for ip_whitelist, replace semantics for the
 * country, cloud, user-agent and endpoint rate limit lists, the emergency
 * halving), the overlay (guard-core #169: every new rule version is applied
 * over the BASE config, never over the previous version, so changes do not
 * compound or accumulate), the last-known persistence (Redis
 * `dynamic_rules:last_known`, no TTL, plus an optional atomic file copy)
 * and the hydration, and match_event.
 *
 * Application surface: the reference mutates a mutable config and keeps a
 * deep-copied base snapshot; the PHP config is immutable, so the manager
 * builds the candidate config with SecurityConfig::with() on the base (full
 * validation runs there) and hands it to the $applyConfig callable. The
 * base is the config as it was before the first active rule
 * (activeBaseSnapshot); a failed application leaves the previously
 * installed config in place (the previous version, or the base) and
 * re-throws, expiry installs the base again.
 *
 * Update schedule: the reference runs a background loop calling
 * update_rules every dynamic_rule_interval seconds, first at agent init.
 * PHP request processes have no background task, so maybeUpdate() is the
 * equivalent: called per request, it runs updateRules() when the interval
 * has elapsed (and on the first call), with the same period.
 *
 * Redis fail-closed: the last-known store is Redis first, then the
 * optional file; when neither store is readable the manager refuses to
 * resurrect stale rules and keeps the base config, and persistence
 * failures are logged with the applied rules still in effect for this
 * process only.
 */
final class DynamicRuleManager
{
    public const DYNAMIC_RULES_REDIS_NAMESPACE = 'dynamic_rules';

    public const LAST_KNOWN_RULES_KEY = 'last_known';

    /** The reference _MAX_USER_AGENT_MATCH_LENGTH used by the user-agent rule validator. */
    private const MAX_USER_AGENT_MATCH_LENGTH = 512;

    private const HANDLER_NAME = 'dynamic_rules';

    private ?DynamicRules $currentRules = null;

    private float $lastUpdate = 0;

    private ?SecurityConfig $activeBaseSnapshot = null;

    /** The config this manager last handed to $applyConfig (the live state). */
    private SecurityConfig $installed;

    /** Highest config revision installed so far; candidates always exceed it so the pipeline rebuilds. */
    private int $maxRevision;

    private ?string $lastSkippedExpiredRule = null;

    private bool $hydratedLastKnownRules = false;

    private ?int $nextPollAt = null;

    /** @var \Closure(): int */
    private \Closure $clock;

    private ?ValidationCache $validationCache;

    /**
     * @param object|null $agentHandler duck-typed getDynamicRules(): DynamicRules|array|object|null
     * @param (\Closure(SecurityConfig): void)|null $applyConfig installs a
     *        validated config (the engine swaps it and rebuilds the
     *        pipeline); null records the rules without installing
     * @param SusPatterns|null $susPatterns the engine's detection engine:
     *        suspicious_patterns rules register here (the reference's
     *        _apply_pattern_rules over the singleton); null leaves the
     *        patterns unapplied with a warning
     * @param (\Closure(): int)|null $clock
     * @param IpBanManager|null $banManager the engine's ban manager:
     *        ip_blacklist rules ban through it for ip_ban_duration seconds,
     *        ip_whitelist rules unban; null leaves the IP rules unapplied
     *        with a warning
     * @param (\Closure(string, string): void)|null $logger (level, message)
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly ?object $agentHandler = null,
        private readonly ?RedisHandler $redisHandler = null,
        private readonly ?EventBus $eventBus = null,
        private readonly ?\Closure $applyConfig = null,
        private readonly ?\Closure $logger = null,
        ?\Closure $clock = null,
        private readonly ?SusPatterns $susPatterns = null,
        private readonly ?IpBanManager $banManager = null
    ) {
        $this->clock = $clock ?? static fn (): int => time();
        $this->installed = $config;
        $this->maxRevision = $config->revision();
        // _apply_user_agent_rules builds its validator with the config's
        // disk-backed validation cache, so re-certifying user-agent
        // patterns across update passes reuses prior cost verdicts.
        $this->validationCache = $config->detectionPatternValidationCachePath !== null
            ? new ValidationCache($config->detectionPatternValidationCachePath)
            : null;
    }

    private function log(string $level, string $message): void
    {
        if ($this->logger !== null) {
            ($this->logger)($level, $message);
        }
    }

    /** Python list repr, for log lines that mirror the reference text. */
    private static function pyList(array $items): string
    {
        return '[' . implode(', ', array_map(static fn (string $item): string => "'{$item}'", $items)) . ']';
    }

    public function currentRules(): ?DynamicRules
    {
        return $this->currentRules;
    }

    public function lastUpdate(): float
    {
        return $this->lastUpdate;
    }

    /**
     * The config as it was before the first active rule (the reference
     * _active_base_snapshot); null while no rule is active.
     */
    public function activeBaseSnapshot(): ?SecurityConfig
    {
        return $this->activeBaseSnapshot;
    }

    /**
     * The per-request stand-in for the reference update loop: runs one
     * update pass on the first call and then whenever dynamic_rule_interval
     * seconds have elapsed since the previous pass.
     */
    public function maybeUpdate(): void
    {
        if (!$this->config->dynamicRulesEnabled || $this->agentHandler === null) {
            return;
        }
        $now = ($this->clock)();
        if ($this->nextPollAt !== null && $now < $this->nextPollAt) {
            return;
        }
        $this->nextPollAt = $now + $this->config->dynamicRuleInterval;
        $this->updateRules();
    }

    /**
     * One update pass (the reference update_rules): expire, fetch, reject
     * already-expired payloads, gate on staleness, emit updated, apply
     * transactionally, persist, emit applied.
     */
    public function updateRules(): void
    {
        if (!$this->config->dynamicRulesEnabled || $this->agentHandler === null) {
            return;
        }

        try {
            $this->checkRuleExpiry();

            $payload = $this->agentHandler->getDynamicRules();
            if ($payload === null || $payload === []) {
                return;
            }
            $rules = match (true) {
                $payload instanceof DynamicRules => $payload,
                is_array($payload) => DynamicRules::fromArray($payload),
                is_object($payload) => DynamicRules::fromObject($payload),
                default => throw new \InvalidArgumentException('the agent returned an unusable dynamic rules payload'),
            };

            if ($this->rejectIfAlreadyExpired($rules)) {
                return;
            }
            if (!$this->shouldUpdateRules($rules)) {
                return;
            }

            $this->eventBus?->sendHandlerEvent(
                EventTypes::EVENT_DYNAMIC_RULE_UPDATED,
                self::HANDLER_NAME,
                'system',
                'rules_received',
                "Received updated rules {$rules->ruleId} v{$rules->version}",
                [
                    'rule_id' => $rules->ruleId,
                    'version' => $rules->version,
                    'previous_version' => $this->currentRules?->version ?? 0,
                ]
            );
            $this->log('info', 'Applying dynamic rules: ' . $rules->ruleId . ' v' . $rules->version);
            $this->applyRules($rules);

            $this->currentRules = $rules;
            $this->lastUpdate = (float) ($this->clock)();

            $this->eventBus?->sendHandlerEvent(
                EventTypes::EVENT_DYNAMIC_RULE_APPLIED,
                self::HANDLER_NAME,
                'system',
                'rules_updated',
                "Applied dynamic rules {$rules->ruleId} v{$rules->version}",
                [
                    'rule_id' => $rules->ruleId,
                    'version' => $rules->version,
                    'ip_bans' => count($rules->ipBlacklist),
                    'country_blocks' => count($rules->blockedCountries),
                    'emergency_mode' => $rules->emergencyMode,
                ]
            );
        } catch (\Throwable $e) {
            $this->log('error', 'Failed to update dynamic rules: ' . $e->getMessage());
        }
    }

    /**
     * Hydrates the last-known snapshot once before the update schedule
     * starts (Redis first, then the cache file); expired or unparseable
     * payloads are skipped, and with no readable store the base config
     * stays - stale rules are never resurrected.
     */
    public function hydrateLastKnownRules(): void
    {
        if ($this->hydratedLastKnownRules || !$this->config->dynamicRulesEnabled) {
            return;
        }
        $this->hydratedLastKnownRules = true;
        try {
            $rules = $this->loadLastKnownRules();
            if ($rules === null) {
                return;
            }
            $this->applyRules($rules);
            $this->currentRules = $rules;
            $this->lastUpdate = (float) ($this->clock)();
            $this->log('info', 'Hydrated last-known dynamic rules ' . $rules->ruleId
                . ' v' . $rules->version . ' before the update loop started');
        } catch (\Throwable $e) {
            $this->log('error', 'Failed to hydrate last-known dynamic rules: ' . $e->getMessage());
        }
    }

    /**
     * The event-to-rule correlation (the reference match_event): the
     * event's ip in the rule's lists, its country blocked, or a type the
     * active rule governs.
     *
     * @return array{0: string, 1: int}|null [rule_id, version]
     */
    public function matchEvent(object $event): ?array
    {
        $rules = $this->currentRules;
        if ($rules === null) {
            return null;
        }
        $ip = $event->ipAddress ?? null;
        $ipMatch = $ip !== null && $ip !== ''
            && (in_array($ip, $rules->ipBlacklist, true) || in_array($ip, $rules->ipWhitelist, true));
        $country = $event->country ?? null;
        $countryMatch = $country !== null && in_array($country, $rules->blockedCountries, true);
        $type = $event->eventType ?? null;
        $typeMatch = ($type === EventTypes::EVENT_RATE_LIMITED
                && ($rules->globalRateLimit !== null || $rules->endpointRateLimits !== []))
            || ($type === EventTypes::EVENT_CLOUD_BLOCKED && $rules->blockedCloudProviders !== [])
            || ($type === EventTypes::EVENT_USER_AGENT_BLOCKED && $rules->blockedUserAgents !== []);
        if ($ipMatch || $countryMatch || $typeMatch) {
            return [$rules->ruleId, $rules->version];
        }

        return null;
    }

    private function shouldUpdateRules(DynamicRules $rules): bool
    {
        $current = $this->currentRules;
        if ($current === null) {
            return true;
        }

        return !($rules->ruleId === $current->ruleId && $rules->version <= $current->version);
    }

    private function checkRuleExpiry(): void
    {
        $rules = $this->currentRules;
        if ($rules === null || $rules->expiresAt === null) {
            return;
        }
        $now = new \DateTimeImmutable('@' . ($this->clock)());
        if ($now <= $rules->expiresAt) {
            return;
        }
        if ($this->activeBaseSnapshot !== null) {
            $this->installConfig($this->activeBaseSnapshot);
        }
        $this->currentRules = null;
        $this->activeBaseSnapshot = null;
        $this->log('info', 'Dynamic rule ' . $rules->ruleId . ' v' . $rules->version
            . ' expired; restored base config');
    }

    private function rejectIfAlreadyExpired(DynamicRules $rules): bool
    {
        if ($rules->expiresAt === null) {
            return false;
        }
        $now = new \DateTimeImmutable('@' . ($this->clock)());
        if ($now <= $rules->expiresAt) {
            return false;
        }
        $key = $rules->ruleId . '|' . $rules->version;
        if ($this->lastSkippedExpiredRule !== $key) {
            $this->lastSkippedExpiredRule = $key;
            $this->log('warning', 'Dynamic rule ' . $rules->ruleId . ' v' . $rules->version
                . ' already expired on receipt; ignoring');
        }

        return true;
    }

    /**
     * The transactional application (_apply_rules): the candidate is built
     * over the active base (the base config before the first active rule),
     * never over the previously applied version. A failure before the
     * install leaves the installed config untouched (the previous version,
     * or the base) and re-throws; a failure of the install itself
     * re-installs the previous config. The first successful application
     * retains the base as the active base so expiry restores the pre-rule
     * state across consecutive versions.
     */
    private function applyRules(DynamicRules $rules): void
    {
        $previous = $this->installed;
        $base = $this->activeBaseSnapshot ?? $this->installed;
        $installAttempted = false;
        try {
            $this->applyIpRules($rules);
            $candidate = $this->buildCandidateConfig($base, $rules);
            $installAttempted = true;
            $this->installConfig($candidate);
        } catch (\Throwable $e) {
            if ($installAttempted) {
                try {
                    $this->installConfig($previous);
                } catch (\Throwable $restoreError) {
                    $this->log('error', 'Failed to restore the previous config: ' . $restoreError->getMessage());
                }
            }
            $this->log('error', 'Failed to apply dynamic rules: ' . $e->getMessage());
            throw $e;
        }
        if ($this->currentRules === null && $this->activeBaseSnapshot === null) {
            $this->activeBaseSnapshot = $base;
        }
        if ($rules->emergencyMode && $this->eventBus !== null) {
            $this->eventBus->sendHandlerEvent(
                EventTypes::EVENT_EMERGENCY_MODE,
                self::HANDLER_NAME,
                'system',
                'emergency_lockdown',
                '[EMERGENCY MODE] activated via dynamic rules',
                [
                    'whitelist_count' => count($rules->emergencyWhitelist),
                    'whitelist' => array_slice($rules->emergencyWhitelist, 0, 10),
                ]
            );
        }
        $this->persistLastKnownRules($rules);
    }

    /** _apply_ip_rules: ip_blacklist bans for ip_ban_duration, ip_whitelist unbans. */
    private function applyIpRules(DynamicRules $rules): void
    {
        if ($rules->ipBlacklist === [] && $rules->ipWhitelist === []) {
            return;
        }
        if ($this->banManager === null) {
            $this->log('warning', 'Dynamic rule: ip_blacklist and ip_whitelist are skipped: no ban manager is attached to the dynamic rule manager');

            return;
        }
        foreach ($rules->ipBlacklist as $ip) {
            try {
                if ($this->banManager->ban($ip, $rules->ipBanDuration, 'dynamic_rule')) {
                    $this->log('info', "Dynamic rule: Banned IP {$ip} for {$rules->ipBanDuration}s");
                }
            } catch (\Throwable $e) {
                $this->log('error', "Failed to ban IP {$ip}: {$e->getMessage()}");
            }
        }
        foreach ($rules->ipWhitelist as $ip) {
            try {
                $this->banManager->unban($ip);
                $this->log('info', "Dynamic rule: Whitelisted IP {$ip}");
            } catch (\Throwable $e) {
                $this->log('error', "Failed to whitelist IP {$ip}: {$e->getMessage()}");
            }
        }
    }

    /**
     * The config fields a rule changes (_apply_blocking_rules,
     * _apply_rate_limit_rules, _apply_feature_toggles and
     * _activate_emergency_mode, in that order), as with() values over the
     * base. Country rules are skipped with a warning when no resolver is
     * configured; unknown cloud providers and unvalidatable user-agent
     * patterns are warned and dropped, and the surviving lists REPLACE the
     * base values (an all-invalid list empties them, as in the reference);
     * suspicious patterns register through the engine's runtime pattern
     * registry (those already in the pool are not added again).
     *
     * @return array<string, mixed> the with() values
     */
    private function ruleFields(SecurityConfig $base, DynamicRules $rules): array
    {
        $fields = [];
        if ($rules->blockedCountries !== [] || $rules->whitelistCountries !== []) {
            if ($base->geoIpHandler === null && $base->geoIpDbPath === '') {
                $this->log('warning', 'Dynamic rule: country rules cannot take effect (blocked='
                    . self::pyList($rules->blockedCountries) . ', allowed=' . self::pyList($rules->whitelistCountries)
                    . '); no geo_ip_handler or geo_ip_db_path is configured to resolve IPs to countries');
            } else {
                if ($rules->blockedCountries !== []) {
                    $blocked = array_values(array_unique(array_map(strtoupper(...), $rules->blockedCountries)));
                    $fields['blocked_countries'] = $blocked;
                    $sorted = $blocked;
                    sort($sorted);
                    $this->log('info', 'Dynamic rule: Blocked countries ' . self::pyList($sorted));
                }
                if ($rules->whitelistCountries !== []) {
                    $allowed = array_values(array_unique(array_map(strtoupper(...), $rules->whitelistCountries)));
                    $fields['whitelist_countries'] = $allowed;
                    $sorted = $allowed;
                    sort($sorted);
                    $this->log('info', 'Dynamic rule: Whitelisted countries ' . self::pyList($sorted));
                }
            }
        }
        if ($rules->blockedCloudProviders !== []) {
            $valid = [];
            $invalid = [];
            foreach ($rules->blockedCloudProviders as $provider) {
                $bare = explode(':!', $provider, 2)[0];
                if (in_array($bare, CloudProviderRegistry::PROVIDERS, true)) {
                    $valid[] = $provider;
                } else {
                    $invalid[] = $provider;
                }
            }
            $fields['block_cloud_providers'] = $valid;
            if ($invalid !== []) {
                sort($invalid);
                $this->log('warning', 'Dynamic rule: ignored unknown cloud providers ' . self::pyList($invalid));
            }
            $this->log('info', 'Dynamic rule: Blocked cloud providers ' . self::pyList($valid));
        }
        if ($rules->blockedUserAgents !== []) {
            $valid = [];
            $rejected = [];
            foreach ($rules->blockedUserAgents as $pattern) {
                [$safe, $reason] = Prefilters::validatePatternSafety(
                    $pattern,
                    maxContentLength: self::MAX_USER_AGENT_MATCH_LENGTH,
                    validationCache: $this->validationCache
                );
                if ($safe) {
                    $valid[] = $pattern;
                } else {
                    $rejected[] = '(' . SusPatterns::sanitizeForReporting($pattern) . ', ' . $reason . ')';
                }
            }
            $fields['blocked_user_agents'] = $valid;
            if ($rejected !== []) {
                $this->log('warning', 'Dynamic rule: rejected blocked_user_agents patterns failing the ReDoS validator: [' . implode(', ', $rejected) . ']');
            }
            $this->log('info', 'Dynamic rule: Blocked user agents ' . self::pyList(array_map(SusPatterns::sanitizeForReporting(...), $valid)));
        }
        if ($rules->suspiciousPatterns !== []) {
            $this->applyPatternRules($rules->suspiciousPatterns);
        }
        if ($rules->globalRateLimit || $rules->endpointRateLimits !== []) {
            if ($rules->globalRateLimit) {
                $fields['rate_limit'] = $rules->globalRateLimit;
                if ($rules->globalRateWindow) {
                    $fields['rate_limit_window'] = $rules->globalRateWindow;
                }
                $this->log('info', "Dynamic rule: Global rate limit {$rules->globalRateLimit} per " . ($rules->globalRateWindow ?? 'null') . 's');
            }
            if ($rules->endpointRateLimits !== []) {
                // The rule wire format carries [requests, window] pairs; the
                // config surface takes {limit, window} maps. The rule's map
                // replaces the base map.
                $converted = [];
                foreach ($rules->endpointRateLimits as $endpoint => $pair) {
                    $converted[$endpoint] = ['limit' => $pair[0], 'window' => $pair[1]];
                }
                $fields['endpoint_rate_limits'] = $converted;
                $this->log('info', 'Dynamic rule: Applied endpoint-specific rate limits for '
                    . count($converted) . ' endpoints: ' . self::pyList(array_map(strval(...), array_keys($converted))));
            }
        }
        $toggles = [
            'enable_penetration_detection' => [$rules->enablePenetrationDetection, 'Penetration detection'],
            'enable_ip_banning' => [$rules->enableIpBanning, 'IP banning'],
            'enable_rate_limiting' => [$rules->enableRateLimiting, 'Rate limiting'],
            'enable_rate_limit_auto_ban' => [$rules->enableRateLimitAutoBan, 'Rate-limit auto-ban'],
            'auto_ban_threshold' => [$rules->autoBanThreshold, 'Auto-ban threshold'],
            'auto_ban_duration' => [$rules->autoBanDuration, 'Auto-ban duration'],
        ];
        foreach ($toggles as $field => [$value, $label]) {
            if ($value !== null) {
                $fields[$field] = $value;
                $this->log('info', "Dynamic rule: {$label} " . (is_bool($value) ? ($value ? 'True' : 'False') : (string) $value));
            }
        }
        if ($rules->emergencyMode) {
            $this->log('critical', '[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled');
            $original = $fields['auto_ban_threshold'] ?? $base->autoBanThreshold;
            $fields['emergency_mode'] = true;
            $fields['emergency_whitelist'] = $rules->emergencyWhitelist;
            $fields['auto_ban_threshold'] = max(1, intdiv($original, 2));
            $this->log('warning', "[EMERGENCY MODE] Reduced auto-ban threshold from {$original} to {$fields['auto_ban_threshold']}");
        }

        return $fields;
    }

    /**
     * _apply_pattern_rules: patterns already in the default pool are not
     * added again, every other pattern goes through the detection engine's
     * add_pattern gate (ReDoS-unsafe rows are rejected there, returning
     * false); the applied list is reported at info, the rejected at
     * warning. The registrations are runtime detection state, not config
     * fields: they stay installed after rule expiry, exactly like the
     * reference singleton pool.
     *
     * @param list<string> $patterns
     */
    private function applyPatternRules(array $patterns): void
    {
        if ($this->susPatterns === null) {
            $this->log('warning', 'suspicious_patterns from dynamic rules are skipped: no pattern registry is attached to the dynamic rule manager');

            return;
        }
        $known = array_flip($this->susPatterns->getDefaultPatterns());
        $pending = array_values(array_filter($patterns, static fn (string $p): bool => !isset($known[$p])));
        $added = [];
        $rejected = [];
        foreach ($pending as $pattern) {
            if ($this->susPatterns->addPattern($pattern)) {
                $added[] = $pattern;
            } else {
                $rejected[] = $pattern;
            }
        }
        if ($added !== []) {
            $this->log('info', 'Dynamic rule: Added suspicious patterns ' . implode(', ', $added));
        }
        if ($rejected !== []) {
            $this->log('warning', 'Dynamic rule: rejected patterns ' . implode(', ', $rejected));
        }
    }

    private function buildCandidateConfig(SecurityConfig $base, DynamicRules $rules): SecurityConfig
    {
        $fields = $this->ruleFields($base, $rules);
        $candidate = $fields === [] ? $base : $base->with($fields);
        // The pipeline rebuilds when the installed revision changes; with()
        // always lands on base+1, so lift each candidate past every
        // revision already installed.
        while ($candidate !== $base && $candidate->revision() <= $this->maxRevision) {
            $candidate = $candidate->with([]);
        }

        return $candidate;
    }

    private function installConfig(SecurityConfig $config): void
    {
        if ($this->applyConfig !== null) {
            ($this->applyConfig)($config);
        }
        $this->installed = $config;
        $this->maxRevision = max($this->maxRevision, $config->revision());
    }

    private function loadLastKnownRules(): ?DynamicRules
    {
        $redisPayload = $this->readRedisPayload();
        $filePayload = $this->readFilePayload();
        foreach ([$redisPayload, $filePayload] as $payload) {
            if ($payload === null) {
                continue;
            }
            try {
                $rules = DynamicRules::loadSnapshot($payload);
            } catch (\Throwable $e) {
                $this->log('error', 'Discarding unusable last-known dynamic rules payload: ' . $e->getMessage());

                continue;
            }
            if ($this->snapshotExpired($rules)) {
                $this->log('error', 'Discarding expired last-known dynamic rules '
                    . $rules->ruleId . ' v' . $rules->version . '; trying the next store');

                continue;
            }

            return $rules;
        }

        return null;
    }

    private function readRedisPayload(): ?string
    {
        if ($this->redisHandler === null) {
            return null;
        }
        try {
            $raw = $this->redisHandler->getKey(self::DYNAMIC_RULES_REDIS_NAMESPACE, self::LAST_KNOWN_RULES_KEY);
        } catch (\Throwable $e) {
            $this->log('error', 'Failed to read last-known dynamic rules from Redis: ' . $e->getMessage());

            return null;
        }
        if ($raw === null || $raw === '') {
            return null;
        }

        return $raw;
    }

    private function readFilePayload(): ?string
    {
        $path = $this->config->dynamicRulesCachePath;
        if ($path === null || !is_file($path)) {
            return null;
        }
        $payload = @file_get_contents($path);

        // An unreadable or empty file yields no payload (or an empty one,
        // which the strict snapshot parse discards with a log).
        return $payload === false ? null : $payload;
    }

    private function persistLastKnownRules(DynamicRules $rules): void
    {
        try {
            $payload = $rules->dumpSnapshot();
        } catch (\Throwable $e) {
            $this->log('error', 'Failed to build last-known dynamic rules snapshot: ' . $e->getMessage());

            return;
        }
        if ($this->redisHandler !== null) {
            try {
                $this->redisHandler->setKey(self::DYNAMIC_RULES_REDIS_NAMESPACE, self::LAST_KNOWN_RULES_KEY, $payload);
            } catch (\Throwable $e) {
                $this->log('error', 'Failed to persist dynamic rules to Redis: ' . $e->getMessage());
            }
        }
        $cachePath = $this->config->dynamicRulesCachePath;
        if ($cachePath === null) {
            return;
        }
        $tmpPath = $cachePath . '.tmp';
        try {
            if (@file_put_contents($tmpPath, $payload) === false || !@rename($tmpPath, $cachePath)) {
                @unlink($tmpPath);
                throw new \RuntimeException('atomic write failed');
            }
        } catch (\Throwable $e) {
            $this->log('error', 'Failed to persist dynamic rules to cache file ' . $cachePath . ': ' . $e->getMessage());
        }
    }

    private function snapshotExpired(DynamicRules $rules): bool
    {
        if ($rules->expiresAt === null) {
            return false;
        }

        return new \DateTimeImmutable('@' . ($this->clock)()) > $rules->expiresAt;
    }
}

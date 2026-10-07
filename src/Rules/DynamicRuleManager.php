<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Rules;

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
 * already-expired rejection, updated/applied events), the transactional
 * application (config snapshot before, restore on any exception - partial
 * application MUST NOT survive), the last-known persistence (Redis
 * `dynamic_rules:last_known`, no TTL, plus an optional atomic file copy)
 * and the hydration, and match_event.
 *
 * Application surface: the reference mutates a mutable config; the PHP
 * config is immutable, so the manager builds the candidate config with
 * SecurityConfig::with() (full validation runs there) and hands it to the
 * $applyConfig callable only after the candidate constructed cleanly -
 * when validation or application throws, the previous config stays
 * installed and the exception propagates (fail closed).
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

    private ?DynamicRules $currentRules = null;

    private float $lastUpdate = 0;

    private ?SecurityConfig $activeBaseSnapshot = null;

    private ?string $lastSkippedExpiredRule = null;

    private bool $hydratedLastKnownRules = false;

    /** @var \Closure(): int */
    private \Closure $clock;

    /**
     * @param object|null $agentHandler duck-typed getDynamicRules(): array|null
     * @param (\Closure(SecurityConfig): void)|null $applyConfig installs a
     *        validated config (the engine swaps it and rebuilds the
     *        pipeline); null records the rules without installing
     * @param SusPatterns|null $susPatterns the engine's detection engine:
     *        suspicious_patterns rules register here (the reference's
     *        _apply_pattern_rules over the singleton); null leaves the
     *        patterns unapplied with a warning
     * @param (\Closure(): int)|null $clock
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly ?object $agentHandler = null,
        private readonly ?RedisHandler $redisHandler = null,
        private readonly ?EventBus $eventBus = null,
        private readonly ?\Closure $applyConfig = null,
        private readonly ?\Closure $logger = null,
        ?\Closure $clock = null,
        private readonly ?SusPatterns $susPatterns = null
    ) {
        $this->clock = $clock ?? static fn (): int => time();
        // _apply_user_agent_rules builds its validator with the config's
        // disk-backed validation cache, so re-certifying user-agent
        // patterns across update passes reuses prior cost verdicts.
        $this->validationCache = $config->detectionPatternValidationCachePath !== null
            ? new ValidationCache($config->detectionPatternValidationCachePath)
            : null;
    }

    private ?ValidationCache $validationCache;

    public function currentRules(): ?DynamicRules
    {
        return $this->currentRules;
    }

    public function lastUpdate(): float
    {
        return $this->lastUpdate;
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
            $rules = $payload instanceof DynamicRules ? $payload : DynamicRules::fromArray($payload);

            if ($this->rejectIfAlreadyExpired($rules)) {
                return;
            }
            if (!$this->shouldUpdateRules($rules)) {
                return;
            }

            $this->sendRuleEvent(EventTypes::EVENT_DYNAMIC_RULE_UPDATED, $rules, 'rules_received');
            ($this->logger)('info', 'Applying dynamic rules: ' . $rules->ruleId . ' v' . $rules->version);
            $this->applyRules($rules);

            $this->currentRules = $rules;
            $this->lastUpdate = (float) ($this->clock)();

            $this->sendRuleEvent(EventTypes::EVENT_DYNAMIC_RULE_APPLIED, $rules, 'rules_updated');
        } catch (\Throwable $e) {
            ($this->logger)('error', 'Failed to update dynamic rules: ' . $e->getMessage());
        }
    }

    /**
     * Hydrates the last-known snapshot once before the update loop starts
     * (Redis first, then the cache file); expired or unparseable payloads
     * are skipped, and with no readable store the base config stays -
     * stale rules are never resurrected.
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
            ($this->logger)('info', 'Hydrated last-known dynamic rules ' . $rules->ruleId
                . ' v' . $rules->version . ' before the update loop started');
        } catch (\Throwable $e) {
            ($this->logger)('error', 'Failed to hydrate last-known dynamic rules: ' . $e->getMessage());
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
        ($this->logger)('info', 'Dynamic rule ' . $rules->ruleId . ' v' . $rules->version
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
            ($this->logger)('warning', 'Dynamic rule ' . $rules->ruleId . ' v' . $rules->version
                . ' already expired on receipt; ignoring');
        }

        return true;
    }

    /**
     * The transactional application (_apply_rules): snapshot the live
     * config, build the candidate (full validation), install, and on any
     * failure restore the snapshot and re-throw - partial application
     * never survives. The first successful rule's snapshot is retained as
     * the active base so expiry restores pre-rule state across rules.
     */
    private function applyRules(DynamicRules $rules): void
    {
        $snapshot = $this->config;
        try {
            $candidate = $this->buildCandidateConfig($snapshot, $rules);
            $this->installConfig($candidate);
        } catch (\Throwable $e) {
            try {
                $this->installConfig($snapshot);
            } catch (\Throwable $restoreError) {
                ($this->logger)('error', 'Failed to restore the base config: ' . $restoreError->getMessage());
            }
            ($this->logger)('error', 'Failed to apply dynamic rules: ' . $e->getMessage());
            throw $e;
        }
        if ($this->currentRules === null && $this->activeBaseSnapshot === null) {
            $this->activeBaseSnapshot = $snapshot;
        }
        $this->persistLastKnownRules($rules);
    }

    /**
     * The field application (_apply_rules order): ip rules, blocking
     * rules, rate limits, feature toggles, emergency mode. Unknown cloud
     * providers and unvalidatable user-agent patterns are warned and
     * dropped; suspicious patterns register through the engine's runtime
     * pattern registry (warned and skipped only when no registry is
     * attached).
     *
     * @return array<string, mixed> the with() values
     */
    private function ruleFields(DynamicRules $rules): array
    {
        $fields = [];
        if ($rules->ipBlacklist !== []) {
            $fields['blacklist'] = array_values(array_unique(array_merge($this->config->blacklist, $rules->ipBlacklist)));
        }
        if ($rules->ipWhitelist !== []) {
            $fields['whitelist'] = array_values(array_unique(array_merge($this->config->whitelist ?? [], $rules->ipWhitelist)));
        }
        if ($rules->blockedCountries !== []) {
            $fields['blocked_countries'] = $rules->blockedCountries;
        }
        if ($rules->whitelistCountries !== []) {
            $fields['whitelist_countries'] = $rules->whitelistCountries;
        }
        if ($rules->blockedCloudProviders !== []) {
            $selectors = [];
            foreach ($rules->blockedCloudProviders as $provider) {
                if (in_array($provider, $this->config->blockCloudProviders, true)) {
                    continue;
                }
                $selectors[] = $provider;
            }
            $fields['block_cloud_providers'] = array_values(array_merge($this->config->blockCloudProviders, $selectors));
        }
        if ($rules->blockedUserAgents !== []) {
            $validated = [];
            foreach ($rules->blockedUserAgents as $pattern) {
                [$safe, $reason] = Prefilters::validatePatternSafety($pattern, validationCache: $this->validationCache);
                if ($safe) {
                    $validated[] = $pattern;
                } else {
                    ($this->logger)('warning', "Rejected blocked_user_agents pattern '{$pattern}': {$reason}");
                }
            }
            if ($validated !== []) {
                $fields['blocked_user_agents'] = array_values(array_merge($this->config->blockedUserAgents, $validated));
            }
        }
        if ($rules->globalRateLimit !== null) {
            $fields['rate_limit'] = $rules->globalRateLimit;
        }
        if ($rules->globalRateWindow !== null) {
            $fields['rate_limit_window'] = $rules->globalRateWindow;
        }
        if ($rules->endpointRateLimits !== []) {
            // The rule wire format carries [requests, window] pairs; the
            // config surface takes {limit, window} maps.
            $converted = [];
            foreach ($rules->endpointRateLimits as $endpoint => $pair) {
                $converted[$endpoint] = ['limit' => $pair[0], 'window' => $pair[1]];
            }
            $fields['endpoint_rate_limits'] = array_merge($this->config->endpointRateLimits, $converted);
        }
        if ($rules->enablePenetrationDetection !== null) {
            $fields['enable_penetration_detection'] = $rules->enablePenetrationDetection;
        }
        if ($rules->enableIpBanning !== null) {
            $fields['enable_ip_banning'] = $rules->enableIpBanning;
        }
        if ($rules->enableRateLimiting !== null) {
            $fields['enable_rate_limiting'] = $rules->enableRateLimiting;
        }
        if ($rules->enableRateLimitAutoBan !== null) {
            $fields['enable_rate_limit_auto_ban'] = $rules->enableRateLimitAutoBan;
        }
        if ($rules->autoBanThreshold !== null) {
            $fields['auto_ban_threshold'] = $rules->autoBanThreshold;
        }
        if ($rules->autoBanDuration !== null) {
            $fields['auto_ban_duration'] = $rules->autoBanDuration;
        }
        if ($rules->emergencyMode) {
            $fields['emergency_mode'] = true;
            $fields['emergency_whitelist'] = $rules->emergencyWhitelist;
            // Emergency mode halves the auto-ban threshold.
            if (!$rules->emergencyWhitelist || $rules->autoBanThreshold !== null) {
                $fields['auto_ban_threshold'] = max(1, intdiv($rules->autoBanThreshold ?? $this->config->autoBanThreshold, 2));
            }
            ($this->logger)('critical', 'Emergency lockdown mode activated with '
                . count($rules->emergencyWhitelist) . ' whitelisted entries'
                . ($rules->emergencyWhitelist !== [] ? ': ' . implode(', ', array_slice($rules->emergencyWhitelist, 0, 10)) : ''));
        }
        if ($rules->suspiciousPatterns !== []) {
            // _apply_pattern_rules: every pattern goes through the
            // detection engine's add_pattern gate (ReDoS-unsafe rows are
            // rejected there, returning false); the applied list is
            // reported at info, the rejected at warning. The registrations
            // are runtime detection state, not config fields - they stay
            // installed after rule expiry, exactly like the reference
            // singleton pool.
            if ($this->susPatterns === null) {
                ($this->logger)('warning', 'suspicious_patterns from dynamic rules are skipped: no pattern registry is attached to the dynamic rule manager');
            } else {
                $added = [];
                $rejected = [];
                foreach ($rules->suspiciousPatterns as $pattern) {
                    if ($this->susPatterns->addPattern($pattern)) {
                        $added[] = $pattern;
                    } else {
                        $rejected[] = $pattern;
                    }
                }
                if ($added !== []) {
                    ($this->logger)('info', 'Dynamic rule: Added suspicious patterns ' . implode(', ', $added));
                }
                if ($rejected !== []) {
                    ($this->logger)('warning', 'Dynamic rule: rejected patterns ' . implode(', ', $rejected));
                }
            }
        }

        return $fields;
    }

    private function buildCandidateConfig(SecurityConfig $snapshot, DynamicRules $rules): SecurityConfig
    {
        $fields = $this->ruleFields($rules);

        return $fields === [] ? $snapshot : $snapshot->with($fields);
    }

    private function installConfig(SecurityConfig $config): void
    {
        if ($this->applyConfig !== null) {
            ($this->applyConfig)($config);
        }
    }

    private function sendRuleEvent(string $eventType, DynamicRules $rules, string $actionTaken): void
    {
        $this->eventBus?->sendMiddlewareEvent(
            $eventType,
            new class {
                public function state(): object
                {
                    return new class {
                        public ?string $clientIp = 'system';
                    };
                }

                public function urlPath(): string
                {
                    return '';
                }

                public function method(): string
                {
                    return 'SYSTEM';
                }

                public function headers(): object
                {
                    return new class {
                        public function get(string $name): ?string
                        {
                            return null;
                        }
                    };
                }
            },
            $actionTaken,
            "Dynamic rules {$rules->ruleId} v{$rules->version}",
            [
                'rule_id' => $rules->ruleId,
                'version' => $rules->version,
                'rule_type' => 'dynamic_rules',
            ]
        );
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
                ($this->logger)('error', 'Discarding unusable last-known dynamic rules payload: ' . $e->getMessage());

                continue;
            }
            if ($this->snapshotExpired($rules)) {
                ($this->logger)('error', 'Discarding expired last-known dynamic rules '
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
            ($this->logger)('error', 'Failed to read last-known dynamic rules from Redis: ' . $e->getMessage());

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
            ($this->logger)('error', 'Failed to build last-known dynamic rules snapshot: ' . $e->getMessage());

            return;
        }
        if ($this->redisHandler !== null) {
            try {
                $this->redisHandler->setKey(self::DYNAMIC_RULES_REDIS_NAMESPACE, self::LAST_KNOWN_RULES_KEY, $payload);
            } catch (\Throwable $e) {
                ($this->logger)('error', 'Failed to persist dynamic rules to Redis: ' . $e->getMessage());
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
            ($this->logger)('error', 'Failed to persist dynamic rules to cache file ' . $cachePath . ': ' . $e->getMessage());
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

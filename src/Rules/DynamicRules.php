<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Rules;

/**
 * Agent-synced dynamic rules, ported from the reference _dynamic_rules.py
 * (spec 12 "Dynamic rules"): rule_id, version, timestamp, expires_at,
 * ttl, the ip lists, country lists, rate-limit rules, cloud providers,
 * user-agent patterns, suspicious patterns, the nullable feature-toggle
 * overrides, and the emergency-mode pair.
 */
final class DynamicRules
{
    public const LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION = 1;

    /**
     * @param list<string> $ipBlacklist
     * @param list<string> $ipWhitelist
     * @param list<string> $blockedCountries
     * @param list<string> $whitelistCountries
     * @param array<string, array{0: int, 1: int}> $endpointRateLimits
     * @param list<string> $blockedCloudProviders
     * @param list<string> $blockedUserAgents
     * @param list<string> $suspiciousPatterns
     * @param list<string> $emergencyWhitelist
     */
    public function __construct(
        public readonly string $ruleId,
        public readonly int $version,
        public readonly \DateTimeImmutable $timestamp,
        public readonly ?\DateTimeImmutable $expiresAt = null,
        public readonly int $ttl = 300,
        public readonly array $ipBlacklist = [],
        public readonly array $ipWhitelist = [],
        public readonly int $ipBanDuration = 3600,
        public readonly array $blockedCountries = [],
        public readonly array $whitelistCountries = [],
        public readonly ?int $globalRateLimit = null,
        public readonly ?int $globalRateWindow = null,
        public readonly array $endpointRateLimits = [],
        public readonly array $blockedCloudProviders = [],
        public readonly array $blockedUserAgents = [],
        public readonly array $suspiciousPatterns = [],
        public readonly ?bool $enablePenetrationDetection = null,
        public readonly ?bool $enableIpBanning = null,
        public readonly ?bool $enableRateLimiting = null,
        public readonly ?int $autoBanThreshold = null,
        public readonly ?int $autoBanDuration = null,
        public readonly ?bool $enableRateLimitAutoBan = null,
        public readonly bool $emergencyMode = false,
        public readonly array $emergencyWhitelist = []
    ) {
    }

    /**
     * The strict agent-payload parse: known keys only, types coerced where
     * the reference's pydantic model coerces, everything else rejected.
     *
     * @param array<string, mixed> $payload
     */
    public static function fromArray(array $payload): self
    {
        foreach (['rule_id', 'version', 'timestamp'] as $required) {
            if (!array_key_exists($required, $payload)) {
                throw new \InvalidArgumentException("dynamic rules require '{$required}'");
            }
        }
        $timestamp = \DateTimeImmutable::createFromInterface(new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        $parsedTimestamp = strtotime((string) $payload['timestamp']);
        if ($parsedTimestamp === false) {
            throw new \InvalidArgumentException('dynamic rules timestamp is unparseable');
        }
        $timestamp = new \DateTimeImmutable('@' . $parsedTimestamp);
        $expiresAt = null;
        if (isset($payload['expires_at']) && $payload['expires_at'] !== null) {
            $parsedExpiry = strtotime((string) $payload['expires_at']);
            if ($parsedExpiry === false) {
                throw new \InvalidArgumentException('dynamic rules expires_at is unparseable');
            }
            $expiresAt = new \DateTimeImmutable('@' . $parsedExpiry);
        }
        $endpointRateLimits = [];
        foreach ($payload['endpoint_rate_limits'] ?? [] as $endpoint => $pair) {
            if (!is_array($pair) || count($pair) !== 2 || !isset($pair[0], $pair[1])) {
                throw new \InvalidArgumentException('endpoint_rate_limits entries are [requests, window] pairs');
            }
            $endpointRateLimits[(string) $endpoint] = [(int) $pair[0], (int) $pair[1]];
        }

        return new self(
            ruleId: (string) $payload['rule_id'],
            version: (int) $payload['version'],
            timestamp: $timestamp,
            expiresAt: $expiresAt,
            ttl: isset($payload['ttl']) ? (int) $payload['ttl'] : 300,
            ipBlacklist: self::stringList($payload['ip_blacklist'] ?? []),
            ipWhitelist: self::stringList($payload['ip_whitelist'] ?? []),
            ipBanDuration: isset($payload['ip_ban_duration']) ? (int) $payload['ip_ban_duration'] : 3600,
            blockedCountries: self::upperList($payload['blocked_countries'] ?? []),
            whitelistCountries: self::upperList($payload['whitelist_countries'] ?? []),
            globalRateLimit: isset($payload['global_rate_limit']) ? (int) $payload['global_rate_limit'] : null,
            globalRateWindow: isset($payload['global_rate_window']) ? (int) $payload['global_rate_window'] : null,
            endpointRateLimits: $endpointRateLimits,
            blockedCloudProviders: self::stringList($payload['blocked_cloud_providers'] ?? []),
            blockedUserAgents: self::stringList($payload['blocked_user_agents'] ?? []),
            suspiciousPatterns: self::stringList($payload['suspicious_patterns'] ?? []),
            enablePenetrationDetection: self::nullableBool($payload['enable_penetration_detection'] ?? null),
            enableIpBanning: self::nullableBool($payload['enable_ip_banning'] ?? null),
            enableRateLimiting: self::nullableBool($payload['enable_rate_limiting'] ?? null),
            autoBanThreshold: isset($payload['auto_ban_threshold']) ? (int) $payload['auto_ban_threshold'] : null,
            autoBanDuration: isset($payload['auto_ban_duration']) ? (int) $payload['auto_ban_duration'] : null,
            enableRateLimitAutoBan: self::nullableBool($payload['enable_rate_limit_auto_ban'] ?? null),
            emergencyMode: (bool) ($payload['emergency_mode'] ?? false),
            emergencyWhitelist: self::stringList($payload['emergency_whitelist'] ?? [])
        );
    }

    /**
     * The last-known snapshot dump (schema version 1): every mirrored
     * field, the strict shape loadSnapshot parses back.
     */
    public function dumpSnapshot(): string
    {
        $fields = [
            'rule_id' => $this->ruleId,
            'version' => $this->version,
            'timestamp' => $this->timestamp->format(\DateTimeInterface::ATOM),
            'expires_at' => $this->expiresAt?->format(\DateTimeInterface::ATOM),
            'ttl' => $this->ttl,
            'ip_blacklist' => $this->ipBlacklist,
            'ip_whitelist' => $this->ipWhitelist,
            'ip_ban_duration' => $this->ipBanDuration,
            'blocked_countries' => $this->blockedCountries,
            'whitelist_countries' => $this->whitelistCountries,
            'global_rate_limit' => $this->globalRateLimit,
            'global_rate_window' => $this->globalRateWindow,
            'endpoint_rate_limits' => $this->endpointRateLimits,
            'blocked_cloud_providers' => $this->blockedCloudProviders,
            'blocked_user_agents' => $this->blockedUserAgents,
            'suspicious_patterns' => $this->suspiciousPatterns,
            'enable_penetration_detection' => $this->enablePenetrationDetection,
            'enable_ip_banning' => $this->enableIpBanning,
            'enable_rate_limiting' => $this->enableRateLimiting,
            'auto_ban_threshold' => $this->autoBanThreshold,
            'auto_ban_duration' => $this->autoBanDuration,
            'enable_rate_limit_auto_ban' => $this->enableRateLimitAutoBan,
            'emergency_mode' => $this->emergencyMode,
            'emergency_whitelist' => $this->emergencyWhitelist,
        ];
        // Invalid UTF-8 payloads (and any other encoding failure) throw;
        // the manager's persistence catch logs and keeps the old snapshot.
        return json_encode(
            ['schema_version' => self::LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION, 'rules' => $fields],
            JSON_THROW_ON_ERROR
        );
    }

    /** The strict last-known snapshot parse: schema version pinned, unknown rule keys rejected. */
    public static function loadSnapshot(string $payload): self
    {
        $decoded = json_decode($payload, true);
        if (!is_array($decoded)
            || ($decoded['schema_version'] ?? null) !== self::LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION
            || !isset($decoded['rules'])
            || !is_array($decoded['rules'])) {
            throw new \InvalidArgumentException('unsupported or malformed last-known dynamic rules snapshot');
        }
        $known = [
            'rule_id', 'version', 'timestamp', 'expires_at', 'ttl', 'ip_blacklist', 'ip_whitelist',
            'ip_ban_duration', 'blocked_countries', 'whitelist_countries', 'global_rate_limit',
            'global_rate_window', 'endpoint_rate_limits', 'blocked_cloud_providers', 'blocked_user_agents',
            'suspicious_patterns', 'enable_penetration_detection', 'enable_ip_banning', 'enable_rate_limiting',
            'auto_ban_threshold', 'auto_ban_duration', 'enable_rate_limit_auto_ban', 'emergency_mode',
            'emergency_whitelist',
        ];
        foreach (array_keys($decoded['rules']) as $key) {
            if (!in_array($key, $known, true)) {
                throw new \InvalidArgumentException("unknown last-known dynamic rules field '{$key}'");
            }
        }

        return self::fromArray($decoded['rules']);
    }

    /** @return list<string> */
    private static function stringList(mixed $value): array
    {
        if (!is_array($value)) {
            throw new \InvalidArgumentException('dynamic rules list fields must be arrays');
        }
        $out = [];
        foreach ($value as $item) {
            if (!is_string($item) && !is_int($item)) {
                throw new \InvalidArgumentException('dynamic rules list entries must be strings');
            }
            $out[] = (string) $item;
        }

        return $out;
    }

    /** @return list<string> */
    private static function upperList(mixed $value): array
    {
        return array_map(strtoupper(...), self::stringList($value));
    }

    private static function nullableBool(mixed $value): ?bool
    {
        return $value === null ? null : (bool) $value;
    }
}

<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * The deterministic event-type threat score, ported from the reference
 * enricher.py (ThreatScorer + _THREAT_SCORE_MAP + _DEFAULT_THREAT_SCORE):
 * the score is a pure function of the event_type string, no state, no
 * network. The default for a type missing from the map is 20.
 */
final class ThreatScorer
{
    public const DEFAULT_THREAT_SCORE = 20;

    /** @var array<string, int> */
    private const THREAT_SCORE_MAP = [
        EventTypes::EVENT_PENETRATION_ATTEMPT => 90,
        EventTypes::EVENT_IP_BANNED => 70,
        EventTypes::EVENT_EMERGENCY_MODE => 60,
        EventTypes::EVENT_IP_BLOCKED => 50,
        EventTypes::EVENT_BEHAVIOR_VIOLATION => 50,
        EventTypes::EVENT_CLOUD_BLOCKED => 50,
        EventTypes::EVENT_COUNTRY_BLOCKED => 50,
        EventTypes::EVENT_DECORATOR_VIOLATION => 50,
        EventTypes::EVENT_AUTHENTICATION_FAILED => 50,
        EventTypes::EVENT_EMERGENCY_MODE_BLOCK => 50,
        EventTypes::EVENT_DYNAMIC_RULE_VIOLATION => 50,
        EventTypes::EVENT_PATTERN_DETECTED => 50,
        EventTypes::EVENT_SUSPICIOUS_REQUEST => 50,
        EventTypes::EVENT_DYNAMIC_RULE_APPLIED => 40,
        EventTypes::EVENT_CSP_VIOLATION => 40,
        EventTypes::EVENT_CONTENT_FILTERED => 40,
        EventTypes::EVENT_CUSTOM_REQUEST_CHECK => 40,
        EventTypes::EVENT_DECODING_ERROR => 40,
        EventTypes::EVENT_REDIS_ERROR => 40,
        EventTypes::EVENT_IP_BAN_FAILED => 40,
        EventTypes::EVENT_DETECTION_ENGINE_CALLBACK_ERROR => 40,
        EventTypes::EVENT_PATTERN_ANOMALY_TIMEOUT => 40,
        EventTypes::EVENT_PATTERN_ANOMALY_SLOW_EXECUTION => 40,
        EventTypes::EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY => 40,
        EventTypes::EVENT_ACCESS_DENIED => 30,
        EventTypes::EVENT_USER_AGENT_BLOCKED => 30,
        EventTypes::EVENT_SECURITY_BYPASS => 30,
        EventTypes::EVENT_RATE_LIMITED => 20,
        EventTypes::EVENT_GEO_LOOKUP_FAILED => 20,
        EventTypes::EVENT_REDIS_CONNECTION => 20,
        EventTypes::EVENT_ROUTE_UNRESOLVED => 20,
        EventTypes::EVENT_IP_UNBANNED => 10,
        EventTypes::EVENT_HTTPS_ENFORCED => 10,
        EventTypes::EVENT_DYNAMIC_RULE_UPDATED => 10,
        EventTypes::EVENT_PATH_EXCLUDED => 10,
        EventTypes::EVENT_PATTERN_ADDED => 10,
        EventTypes::EVENT_PATTERN_REMOVED => 10,
        EventTypes::EVENT_RATE_LIMIT_SCRIPT_RELOADED => 10,
        EventTypes::EVENT_SECURITY_HEADERS_APPLIED => 10,
    ];

    public static function scoreFor(string $eventType): int
    {
        return self::THREAT_SCORE_MAP[$eventType] ?? self::DEFAULT_THREAT_SCORE;
    }
}

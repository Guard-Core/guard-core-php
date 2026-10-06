<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Events;

/**
 * The security event type identifiers, ported verbatim from the reference
 * event_types.py (spec 12 "Event type constants"). The string identifiers
 * are the observable identity; the constant/string asymmetries are
 * normative (behavioral_violation, not behavior_violation;
 * emergency_mode_activated, not emergency_mode).
 */
final class EventTypes
{
    public const EVENT_PENETRATION_ATTEMPT = 'penetration_attempt';
    public const EVENT_IP_BLOCKED = 'ip_blocked';
    public const EVENT_IP_BANNED = 'ip_banned';
    public const EVENT_IP_BAN_FAILED = 'ip_ban_failed';
    public const EVENT_IP_UNBANNED = 'ip_unbanned';
    public const EVENT_CLOUD_BLOCKED = 'cloud_blocked';
    public const EVENT_HTTPS_ENFORCED = 'https_enforced';
    public const EVENT_DECORATOR_VIOLATION = 'decorator_violation';
    public const EVENT_BEHAVIOR_VIOLATION = 'behavioral_violation';
    public const EVENT_PATTERN_DETECTED = 'pattern_detected';
    public const EVENT_DYNAMIC_RULE_UPDATED = 'dynamic_rule_updated';
    public const EVENT_DYNAMIC_RULE_APPLIED = 'dynamic_rule_applied';
    public const EVENT_DYNAMIC_RULE_VIOLATION = 'dynamic_rule_violation';
    public const EVENT_EMERGENCY_MODE = 'emergency_mode_activated';

    public const EVENT_ACCESS_DENIED = 'access_denied';
    public const EVENT_AUTHENTICATION_FAILED = 'authentication_failed';
    public const EVENT_CONTENT_FILTERED = 'content_filtered';
    public const EVENT_COUNTRY_BLOCKED = 'country_blocked';
    public const EVENT_CSP_VIOLATION = 'csp_violation';
    public const EVENT_CUSTOM_REQUEST_CHECK = 'custom_request_check';
    public const EVENT_DECODING_ERROR = 'decoding_error';
    public const EVENT_EMERGENCY_MODE_BLOCK = 'emergency_mode_block';
    public const EVENT_GEO_LOOKUP_FAILED = 'geo_lookup_failed';
    public const EVENT_PATH_EXCLUDED = 'path_excluded';
    public const EVENT_PATTERN_ADDED = 'pattern_added';
    public const EVENT_PATTERN_REMOVED = 'pattern_removed';
    public const EVENT_RATE_LIMITED = 'rate_limited';
    public const EVENT_RATE_LIMIT_SCRIPT_RELOADED = 'rate_limit_script_reloaded';
    public const EVENT_REDIS_CONNECTION = 'redis_connection';
    public const EVENT_REDIS_ERROR = 'redis_error';
    public const EVENT_ROUTE_UNRESOLVED = 'route_unresolved';
    public const EVENT_SECURITY_BYPASS = 'security_bypass';
    public const EVENT_SECURITY_HEADERS_APPLIED = 'security_headers_applied';
    public const EVENT_USER_AGENT_BLOCKED = 'user_agent_blocked';
    public const EVENT_SUSPICIOUS_REQUEST = 'suspicious_request';
    public const EVENT_DETECTION_ENGINE_CALLBACK_ERROR = 'detection_engine_callback_error';
    public const EVENT_PATTERN_ANOMALY_TIMEOUT = 'pattern_anomaly_timeout';
    public const EVENT_PATTERN_ANOMALY_SLOW_EXECUTION = 'pattern_anomaly_slow_execution';
    public const EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY = 'pattern_anomaly_statistical_anomaly';

    /** @var list<string> every EVENT_* string, for validation surfaces. */
    public const EVENT_TYPE_VALUES = [
        self::EVENT_PENETRATION_ATTEMPT,
        self::EVENT_IP_BLOCKED,
        self::EVENT_IP_BANNED,
        self::EVENT_IP_BAN_FAILED,
        self::EVENT_IP_UNBANNED,
        self::EVENT_CLOUD_BLOCKED,
        self::EVENT_HTTPS_ENFORCED,
        self::EVENT_DECORATOR_VIOLATION,
        self::EVENT_BEHAVIOR_VIOLATION,
        self::EVENT_PATTERN_DETECTED,
        self::EVENT_DYNAMIC_RULE_UPDATED,
        self::EVENT_DYNAMIC_RULE_APPLIED,
        self::EVENT_DYNAMIC_RULE_VIOLATION,
        self::EVENT_EMERGENCY_MODE,
        self::EVENT_ACCESS_DENIED,
        self::EVENT_AUTHENTICATION_FAILED,
        self::EVENT_CONTENT_FILTERED,
        self::EVENT_COUNTRY_BLOCKED,
        self::EVENT_CSP_VIOLATION,
        self::EVENT_CUSTOM_REQUEST_CHECK,
        self::EVENT_DECODING_ERROR,
        self::EVENT_EMERGENCY_MODE_BLOCK,
        self::EVENT_GEO_LOOKUP_FAILED,
        self::EVENT_PATH_EXCLUDED,
        self::EVENT_PATTERN_ADDED,
        self::EVENT_PATTERN_REMOVED,
        self::EVENT_RATE_LIMITED,
        self::EVENT_RATE_LIMIT_SCRIPT_RELOADED,
        self::EVENT_REDIS_CONNECTION,
        self::EVENT_REDIS_ERROR,
        self::EVENT_ROUTE_UNRESOLVED,
        self::EVENT_SECURITY_BYPASS,
        self::EVENT_SECURITY_HEADERS_APPLIED,
        self::EVENT_USER_AGENT_BLOCKED,
        self::EVENT_SUSPICIOUS_REQUEST,
        self::EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
        self::EVENT_PATTERN_ANOMALY_TIMEOUT,
        self::EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
        self::EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
    ];

    // Enrichment metadata keys (event_types.py ENRICHMENT_KEY_*): the
    // guard.* family the EventEnricher stamps onto every event metadata bag
    // and every metric tags bag.

    public const ENRICHMENT_KEY_PROJECT_ID = 'guard.project_id';

    public const ENRICHMENT_KEY_SERVICE_NAME = 'guard.service.name';

    public const ENRICHMENT_KEY_DEPLOYMENT_ENV = 'guard.deployment.environment';

    public const ENRICHMENT_KEY_THREAT_SCORE = 'guard.threat_score';

    public const ENRICHMENT_KEY_RULE_ID = 'guard.rule.id';

    public const ENRICHMENT_KEY_RULE_VERSION = 'guard.rule.version';

    public const ENRICHMENT_KEY_BEHAVIOR_KEY = 'guard.behavior.correlation_key';

    public const ENRICHMENT_KEY_RECENT_EVENT_COUNT = 'guard.behavior.recent_event_count';

    // Metric type identifiers (event_types.py).

    public const METRIC_RESPONSE_TIME = 'response_time';
    public const METRIC_REQUEST_COUNT = 'request_count';
    public const METRIC_ERROR_RATE = 'error_rate';

    /** @var list<string> */
    public const METRIC_TYPE_VALUES = [
        self::METRIC_RESPONSE_TIME,
        self::METRIC_REQUEST_COUNT,
        self::METRIC_ERROR_RATE,
    ];
}

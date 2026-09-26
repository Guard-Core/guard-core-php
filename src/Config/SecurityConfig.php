<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Config;

use RenzoFranceschini\GuardCore\Cloud\CloudProviderRegistry;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\GeoIp\GeoIpManager;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\SecurityHeaders\SecurityHeadersPolicy;

final class SecurityConfig
{
    public const VALID_BYPASS_CHECKS = ['all', 'ip_ban', 'ip', 'clouds', 'rate_limit', 'penetration'];

    public const CLOUD_IP_REFRESH_INTERVAL_MIN = 60;

    public const CLOUD_IP_REFRESH_INTERVAL_MAX = 86400;

    public const CHECK_NAME_VALUES = [
        'route_config', 'emergency_mode', 'https_enforcement', 'request_logging',
        'request_size_content', 'required_headers', 'authentication', 'referrer',
        'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security',
        'cloud_provider', 'user_agent', 'rate_limit', 'suspicious_activity',
        'custom_request',
    ];

    public const DETECTION_CATEGORIES = [
        'xss', 'sqli', 'dir_traversal', 'path_traversal', 'cmd_injection',
        'file_inclusion', 'ldap', 'xml', 'ssrf', 'nosql', 'file_upload',
        'template', 'http_split', 'sensitive_file', 'cms_probing', 'recon',
        'proto_pollution', 'code_injection', 'deserialization',
    ];

    public const LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];

    public const DEFAULT_EXCLUDE_PATHS = [
        '/docs', '/redoc', '/openapi.json', '/openapi.yaml', '/favicon.ico', '/static',
    ];

    public readonly ?\Closure $customRequestCheck;

    private int $revision = 0;

    public readonly bool $enableRedis;

    public readonly string $redisUrl;

    public readonly string $redisPrefix;

    public readonly bool $redisFailOpen;

    public readonly bool $passiveMode;

    public readonly bool $failSecure;

    public readonly bool $routeResolutionStrict;

    /** @var list<string> */
    public readonly array $trustedProxies;

    public readonly int $trustedProxyDepth;

    public readonly bool $trustXForwardedProto;

    /** @var list<string>|null */
    public readonly ?array $whitelist;

    /** @var list<string> */
    public readonly array $blacklist;

    /** @var list<string> */
    public readonly array $exemptIps;

    public readonly bool $enableIpBanning;

    public readonly int $autoBanThreshold;

    public readonly int $autoBanDuration;

    /** @var array<string, array{threshold: int, duration: int}> */
    public readonly array $threatBanConfig;

    public readonly bool $enableRateLimitAutoBan;

    public readonly bool $enableRateLimiting;

    public readonly int $rateLimit;

    public readonly int $rateLimitWindow;

    /** @var array<string, array{limit: int, window: int}> */
    public readonly array $endpointRateLimits;

    public readonly bool $enablePenetrationDetection;

    /** @var array<string, true> */
    public readonly array $enabledDetectionCategories;

    public readonly float $detectionSemanticThreshold;

    public readonly int $detectionBinaryMinRunLength;

    /** @var array<string, true> */
    public readonly array $excludedDetectionParams;

    /** @var array<string, true> */
    public readonly array $excludedDetectionBodyFields;

    /** @var array<string, true> */
    public readonly array $excludedDetectionHeaders;

    /** @var list<string> */
    public readonly array $excludePaths;

    /** @var array<string, true> */
    public readonly array $mutedCheckLogs;

    /** @var array<string, true> */
    public readonly array $logSensitiveHeaders;

    /** @var array<string, true> */
    public readonly array $logSensitiveParams;

    /** @var array<string, true> */
    public readonly array $logSensitiveBodyFields;

    /** @var array<int, string> */
    public readonly array $customErrorResponses;

    /** @var list<string> */
    public readonly array $emergencyWhitelist;

    public readonly bool $emergencyMode;

    public readonly bool $enforceHttps;

    public readonly SecurityHeadersPolicy $securityHeaders;

    /** @var list<string> */
    public readonly array $blockedUserAgents;

    /** @var list<string> */
    public readonly array $blockCloudProviders;

    public readonly int $cloudIpRefreshInterval;

    /** @var (\Closure(object, string): mixed)|null */
    public readonly ?\Closure $authVerifier;

    public readonly bool $enableCors;

    /** @var list<string> */
    public readonly array $corsAllowOrigins;

    /** @var list<string> */
    public readonly array $corsAllowMethods;

    /** @var list<string> */
    public readonly array $corsAllowHeaders;

    public readonly bool $corsAllowCredentials;

    /** @var list<string> */
    public readonly array $corsExposeHeaders;

    public readonly int $corsMaxAge;

    /** @var list<string> */
    public readonly array $whitelistCountries;

    /** @var list<string> */
    public readonly array $blockedCountries;

    public readonly ?CountryResolver $geoIpHandler;

    public readonly string $geoIpDbPath;

    public readonly ?string $logSuspiciousLevel;

    public readonly ?string $logRequestLevel;

    /** @var (\Closure(object, array<string, mixed>): void)|null */
    public readonly ?\Closure $onBlock;

    /**
     * Supported-subset constructor. Any option belonging to a section-02
     * feature this port does not implement yet, when set to an enabling
     * value, throws UnsupportedFeatureError (fail closed).
     *
     * @param list<string>|null $whitelist
     * @param list<string> $blacklist
     * @param list<string> $exemptIps IPs/CIDRs that skip the rate-limit, user-agent and cloud-provider checks; never a deny path (the whitelist, blacklist, bans and detection still apply)
     * @param list<string> $trustedProxies
     * @param array<string, array{threshold: int, duration: int}> $threatBanConfig
     * @param array<string, array{limit: int, window: int}> $endpointRateLimits
     * @param list<string>|null $enabledDetectionCategories null = all categories
     * @param list<string> $excludedDetectionParams query parameter names excluded from penetration detection scanning
     * @param list<string> $excludedDetectionBodyFields body field names excluded from penetration detection scanning (JSON keys at any nesting depth, urlencoded and multipart field names)
     * @param list<string> $excludedDetectionHeaders header names merged into the excluded-header scan: excluded headers skip the ssrf category only when the header is address-carrying or its value parses as an address chain, every other category still scans them
     * @param list<string> $excludePaths
     * @param list<string> $mutedCheckLogs
     * @param list<string> $logSensitiveHeaders
     * @param list<string> $logSensitiveParams
     * @param list<string> $logSensitiveBodyFields
     * @param (\Closure(object, array<string, mixed>): void)|null $onBlock
     * @param list<string> $emergencyWhitelist
     * @param array<int, string> $customErrorResponses per-status-code body overrides
     * @param list<string> $blockedUserAgents regex patterns, subject truncated to 512 chars
     * @param list<string> $blockedCountries ISO country codes denied by the ip_security check; uppercased and deduplicated; ignored (with a warning) while $whitelistCountries is non-empty; requires a geo resolver (fail closed)
     * @param list<string> $whitelistCountries restrictive allowlist: only listed countries pass and an unresolved country is denied; uppercased and deduplicated; requires a geo resolver (fail closed)
     * @param string $geoIpDbPath path to a local MMDB database with top-level `country` records; builds the built-in GeoIpManager when no $geoIpHandler is injected
     * @param CountryResolver|null $geoIpHandler injected country resolver; replaces the built-in MMDB reader
     * @param list<string> $corsAllowOrigins exact origins; '*' allows every origin (incompatible with $corsAllowCredentials, fail-closed)
     * @param list<string> $corsAllowMethods uppercased at construction; an empty list falls back to ['GET'] at policy build
     * @param list<string> $corsAllowHeaders lowercased at construction; '*' echoes the requested headers verbatim
     * @param list<string> $corsExposeHeaders joined into Access-Control-Expose-Headers on responses
     * @param bool|null $enforceHttps unsupported when true (fail closed)
     * @param SecurityHeadersPolicy|array<string, mixed>|null $securityHeaders reference-shaped security_headers block (enabled, hsts, csp, frame_options, content_type_options, xss_protection, referrer_policy, permissions_policy, custom); invalid custom header names or values fail construction like the reference configure() raising
     * @param list<string> $blockedCountries unsupported when non-empty
     * @param list<string> $whitelistCountries unsupported when non-empty
     * @param list<string> $blockCloudProviders selectors "Provider" or "Provider:!region", unknown provider names rejected
     */
    public function __construct(
        ?bool $enableRedis = null,
        string $redisUrl = 'redis://localhost:6379',
        string $redisPrefix = 'guard_core:',
        ?bool $redisFailOpen = null,
        ?bool $passiveMode = null,
        ?bool $failSecure = null,
        ?bool $routeResolutionStrict = null,
        ?array $trustedProxies = null,
        ?int $trustedProxyDepth = null,
        ?bool $trustXForwardedProto = null,
        ?array $whitelist = null,
        ?array $blacklist = null,
        ?array $exemptIps = null,
        ?bool $enableIpBanning = null,
        ?int $autoBanThreshold = null,
        ?int $autoBanDuration = null,
        ?array $threatBanConfig = null,
        ?bool $enableRateLimitAutoBan = null,
        ?bool $enableRateLimiting = null,
        ?int $rateLimit = null,
        ?int $rateLimitWindow = null,
        ?array $endpointRateLimits = null,
        ?bool $enablePenetrationDetection = null,
        ?array $enabledDetectionCategories = null,
        ?float $detectionSemanticThreshold = null,
        ?int $detectionBinaryMinRunLength = null,
        ?array $excludedDetectionParams = null,
        ?array $excludedDetectionBodyFields = null,
        ?array $excludedDetectionHeaders = null,
        ?array $excludePaths = null,
        ?array $mutedCheckLogs = null,
        ?array $logSensitiveHeaders = null,
        ?array $logSensitiveParams = null,
        ?array $logSensitiveBodyFields = null,
        ?\Closure $onBlock = null,
        array $blockedCountries = [],
        array $whitelistCountries = [],
        string $geoIpDbPath = '',
        ?CountryResolver $geoIpHandler = null,
        array $blockCloudProviders = [],
        ?int $cloudIpRefreshInterval = null,
        ?bool $emergencyMode = null,
        ?array $emergencyWhitelist = null,
        ?bool $enforceHttps = null,
        SecurityHeadersPolicy|array|null $securityHeaders = null,
        ?array $customErrorResponses = null,
        ?array $blockedUserAgents = null,
        ?bool $enableCors = null,
        ?array $corsAllowOrigins = null,
        ?array $corsAllowMethods = null,
        ?array $corsAllowHeaders = null,
        ?bool $corsAllowCredentials = null,
        ?array $corsExposeHeaders = null,
        ?int $corsMaxAge = null,
        ?bool $enableAgent = null,
        ?bool $enableDynamicRules = null,
        ?\Closure $customRequestCheck = null,
        ?\Closure $authVerifier = null,
        ?string $logSuspiciousLevel = null,
        ?string $logRequestLevel = null
    ) {
        $this->enableRedis = $enableRedis ?? true;
        $this->redisUrl = $redisUrl;
        $this->redisPrefix = $redisPrefix;
        $this->redisFailOpen = $redisFailOpen ?? false;
        $this->passiveMode = $passiveMode ?? false;
        $this->failSecure = $failSecure ?? true;
        $this->routeResolutionStrict = $routeResolutionStrict ?? false;
        $this->trustedProxies = $this->validateIpCidrList($trustedProxies ?? [], 'trusted_proxies');
        $this->trustedProxyDepth = $trustedProxyDepth ?? 1;
        if ($this->trustedProxyDepth < 1) {
            throw new \InvalidArgumentException('trusted_proxy_depth must be >= 1');
        }
        $this->trustXForwardedProto = $trustXForwardedProto ?? false;
        $this->whitelist = $whitelist === null ? null : $this->validateIpCidrList($whitelist, 'whitelist');
        $this->blacklist = $this->validateIpCidrList($blacklist ?? [], 'blacklist');
        $this->exemptIps = $this->validateIpCidrList($exemptIps ?? [], 'exempt_ips');
        $this->enableIpBanning = $enableIpBanning ?? true;
        $this->autoBanThreshold = $autoBanThreshold ?? 10;
        if ($this->autoBanThreshold < 1) {
            throw new \InvalidArgumentException('auto_ban_threshold must be >= 1');
        }
        $this->autoBanDuration = $autoBanDuration ?? 3600;
        if ($this->autoBanDuration < 1) {
            throw new \InvalidArgumentException('auto_ban_duration must be >= 1');
        }
        $this->threatBanConfig = $this->validateThreatBanConfig($threatBanConfig ?? []);
        $this->enableRateLimitAutoBan = $enableRateLimitAutoBan ?? false;
        $this->enableRateLimiting = $enableRateLimiting ?? true;
        $this->rateLimit = $rateLimit ?? 10;
        $this->rateLimitWindow = $rateLimitWindow ?? 60;
        $this->endpointRateLimits = $this->validateEndpointRateLimits($endpointRateLimits ?? []);
        $this->enablePenetrationDetection = $enablePenetrationDetection ?? true;
        $this->enabledDetectionCategories = $this->validateDetectionCategories($enabledDetectionCategories);
        $this->detectionSemanticThreshold = $detectionSemanticThreshold ?? 0.7;
        if ($this->detectionSemanticThreshold < 0.0 || $this->detectionSemanticThreshold > 1.0) {
            throw new \InvalidArgumentException('detection_semantic_threshold must be within [0.0, 1.0]');
        }
        $this->detectionBinaryMinRunLength = $detectionBinaryMinRunLength ?? 16;
        if ($this->detectionBinaryMinRunLength < 4 || $this->detectionBinaryMinRunLength > 1024) {
            throw new \InvalidArgumentException('detection_binary_min_run_length must be within [4, 1024]');
        }
        $this->excludedDetectionParams = $this->validateExclusionSet($excludedDetectionParams, 'excluded_detection_params');
        $this->excludedDetectionBodyFields = $this->validateExclusionSet($excludedDetectionBodyFields, 'excluded_detection_body_fields');
        $this->excludedDetectionHeaders = $this->validateExclusionSet($excludedDetectionHeaders, 'excluded_detection_headers');
        $this->excludePaths = $this->validateExcludePaths($excludePaths ?? self::DEFAULT_EXCLUDE_PATHS);
        $this->mutedCheckLogs = $this->validateNameSet($mutedCheckLogs, self::CHECK_NAME_VALUES, 'muted_check_logs');
        $this->logSensitiveHeaders = $this->validateSensitiveSet($logSensitiveHeaders, 'log_sensitive_headers');
        $this->logSensitiveParams = $this->validateSensitiveSet($logSensitiveParams, 'log_sensitive_params');
        $this->logSensitiveBodyFields = $this->validateSensitiveSet($logSensitiveBodyFields, 'log_sensitive_body_fields');
        $this->onBlock = $onBlock;
        $this->customErrorResponses = $this->validateCustomErrorResponses($customErrorResponses ?? []);
        $this->emergencyWhitelist = $this->validateIpCidrList($emergencyWhitelist ?? [], 'emergency_whitelist');
        $this->emergencyMode = $emergencyMode ?? false;
        $this->enforceHttps = $enforceHttps ?? false;
        // Security headers surface, mirrored from the reference
        // security_headers dict field (_security_config_fields.py) and its
        // SecurityHeadersManager resolution. A policy instance passes
        // through; an array is normalized and validated fail-closed here
        // (the reference configure() raising out of _validate_header_name /
        // _validate_header_value); null builds the reference default block.
        $this->securityHeaders = $securityHeaders instanceof SecurityHeadersPolicy
            ? $securityHeaders
            : new SecurityHeadersPolicy($securityHeaders);
        $this->blockedUserAgents = $this->validateBlockedUserAgents($blockedUserAgents ?? []);
        $this->blockCloudProviders = $this->validateBlockCloudProviders($blockCloudProviders);
        $this->cloudIpRefreshInterval = max(
            self::CLOUD_IP_REFRESH_INTERVAL_MIN,
            min(self::CLOUD_IP_REFRESH_INTERVAL_MAX, $cloudIpRefreshInterval ?? 3600)
        );
        $this->authVerifier = $authVerifier;
        $this->logSuspiciousLevel = $this->validateLogLevel($logSuspiciousLevel, 'log_suspicious_level', 'WARNING');
        $this->logRequestLevel = $this->validateLogLevel($logRequestLevel, 'log_request_level', null);

        $this->enableCors = $enableCors ?? false;
        // CORS surface, mirrored from the reference cors_* SecurityConfig
        // fields (_security_config_fields.py): default origins/headers are
        // the wildcard, default methods cover the six common verbs, default
        // max_age is 600. Construction uppercases the methods and
        // lowercases the header names (CorsHandler._init_enabled) and
        // rejects the wildcard + credentials misconfiguration fail-closed
        // (the reference raises at handler construction; raising here only
        // moves the failure earlier).
        $this->corsAllowOrigins = $this->validateStringList($corsAllowOrigins ?? ['*'], 'cors_allow_origins');
        $this->corsAllowMethods = array_map(
            'strtoupper',
            $this->validateStringList(
                $corsAllowMethods ?? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
                'cors_allow_methods'
            )
        );
        $this->corsAllowHeaders = array_map(
            'strtolower',
            $this->validateStringList($corsAllowHeaders ?? ['*'], 'cors_allow_headers')
        );
        $this->corsAllowCredentials = $corsAllowCredentials ?? false;
        $this->corsExposeHeaders = $this->validateStringList($corsExposeHeaders ?? [], 'cors_expose_headers');
        $this->corsMaxAge = $corsMaxAge ?? 600;
        if (
            $this->enableCors
            && $this->corsAllowCredentials
            && in_array('*', $this->corsAllowOrigins, true)
        ) {
            throw new \InvalidArgumentException(
                "CORS misconfiguration: wildcard origin '*' is incompatible with cors_allow_credentials=True"
            );
        }

        if ($blockedCountries !== [] || $whitelistCountries !== []) {
            // Country rules with no resolver fail construction, mirroring
            // the reference `_resolve_geo_ip_handler` raising
            // "geo_ip_handler is required" (guard-core-go #23 carries the
            // same fail-closed default; a database path builds the
            // built-in GeoIpManager).
            $this->geoIpHandler = $geoIpHandler
                ?? ($geoIpDbPath !== '' ? new GeoIpManager($geoIpDbPath) : null);
            if ($this->geoIpHandler === null) {
                throw new \InvalidArgumentException(
                    'geo_ip_handler is required if blocked_countries or whitelist_countries is set'
                    . " (set geo_ip_db_path to an MMDB database or inject a geo_ip_handler)"
                );
            }
            if ($blockedCountries !== [] && $whitelistCountries !== []) {
                // The reference warns (UserWarning) instead of erroring:
                // the allowlist is restrictive and shadows the blocklist.
                // The PHP config has no warn channel, so the warning rides
                // the global error_log like guard-core-go's log.Printf.
                error_log(
                    'blocked_countries is ignored when whitelist_countries is non-empty:'
                    . ' a non-empty whitelist_countries is restrictive (only listed countries pass),'
                    . ' so blocked_countries has no effect. Use one or the other.'
                );
            }
            $this->whitelistCountries = $this->normalizeCountryList($whitelistCountries);
            $this->blockedCountries = $this->normalizeCountryList($blockedCountries);
        } else {
            $this->whitelistCountries = [];
            $this->blockedCountries = [];
            $this->geoIpHandler = null;
        }
        $this->geoIpDbPath = $geoIpDbPath;
        if ($enableAgent === true) {
            throw new UnsupportedFeatureError('guard agent telemetry');
        }
        if ($enableDynamicRules === true) {
            throw new UnsupportedFeatureError('dynamic rules');
        }
        $this->customRequestCheck = $customRequestCheck;
    }

    /**
     * Mirrors the reference coerce_country_set
     * (guard_core/_security_config_geo_validators.py): every entry is
     * uppercased and duplicates collapse (frozenset semantics, first-seen
     * order preserved). ISO codes are not format-validated, exactly like
     * the reference.
     *
     * @param list<string> $entries @return list<string>
     */
    private function normalizeCountryList(array $entries): array
    {
        $out = [];
        foreach ($entries as $entry) {
            if (!is_string($entry)) {
                $shown = get_debug_type($entry);
                throw new \InvalidArgumentException("countries: entries must be strings, got {$shown}");
            }
            $code = strtoupper($entry);
            if (!in_array($code, $out, true)) {
                $out[] = $code;
            }
        }

        return $out;
    }

    /** @param list<mixed> $entries @return list<string> */
    private function validateStringList(array $entries, string $field): array
    {
        foreach ($entries as $entry) {
            if (!is_string($entry)) {
                $shown = get_debug_type($entry);
                throw new \InvalidArgumentException("{$field}: entries must be strings, got {$shown}");
            }
        }

        return $entries;
    }

    private function validateLogLevel(?string $level, string $field, ?string $default): ?string
    {
        $level = $level ?? $default;
        if ($level !== null && !in_array($level, self::LOG_LEVELS, true)) {
            throw new \InvalidArgumentException("{$field}: unknown log level '{$level}'");
        }

        return $level;
    }

    /** @param array<int, string> $map @return array<int, string> */
    private function validateCustomErrorResponses(array $map): array
    {
        $out = [];
        foreach ($map as $status => $message) {
            if (!is_int($status) || !is_string($message)) {
                throw new \InvalidArgumentException('custom_error_responses: map of int status => string body');
            }
            $out[$status] = $message;
        }

        return $out;
    }

    /** @param list<string> $patterns @return list<string> */
    private function validateBlockedUserAgents(array $patterns): array
    {
        $out = [];
        foreach ($patterns as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                throw new \InvalidArgumentException('blocked_user_agents: patterns must be non-empty strings');
            }
            $out[] = $pattern;
        }

        return $out;
    }

    /** @param list<string> $selectors @return list<string> */
    private function validateBlockCloudProviders(array $selectors): array
    {
        $out = [];
        foreach ($selectors as $selector) {
            if (!is_string($selector)) {
                throw new \InvalidArgumentException('block_cloud_providers: selectors must be strings');
            }
            $marker = strpos($selector, ':!');
            $provider = $marker === false ? $selector : substr($selector, 0, $marker);
            if (!in_array($provider, CloudProviderRegistry::PROVIDERS, true)) {
                throw new \InvalidArgumentException(
                    "block_cloud_providers: unknown cloud provider '{$provider}'. Valid: "
                    . implode(', ', CloudProviderRegistry::PROVIDERS)
                    . " (a bare name blocks the whole provider; suffix ':!region' to carve out a region exception)"
                );
            }
            if (!in_array($selector, $out, true)) {
                $out[] = $selector;
            }
        }

        return $out;
    }

    public function revision(): int
    {
        return $this->revision;
    }

    public function cloudBlockingEnabled(): bool
    {
        return $this->blockCloudProviders !== [];
    }

    /**
     * Replaces one or more config values (immutable-copy style) and bumps
     * the revision counter, mirroring SecurityConfig.__setattr__ semantics:
     * pipeline staleness detection observes the new revision.
     *
     * @param array<string, mixed> $values
     */
    public function with(array $values): self
    {
        $known = $this->constructorArgs();
        $args = [];
        foreach ($values as $name => $value) {
            $arg = self::fieldNameToArg($name);
            if (!array_key_exists($arg, $known)) {
                throw new \InvalidArgumentException("unknown config field '{$name}'");
            }
            $args[$arg] = $value;
            unset($known[$arg]);
        }

        $copy = new self(...$known, ...$args);
        $copy->revision = $this->revision + 1;

        return $copy;
    }

    /** @return array<string, mixed> */
    private function constructorArgs(): array
    {
        return [
            'enableRedis' => $this->enableRedis,
            'redisUrl' => $this->redisUrl,
            'redisPrefix' => $this->redisPrefix,
            'redisFailOpen' => $this->redisFailOpen,
            'passiveMode' => $this->passiveMode,
            'failSecure' => $this->failSecure,
            'routeResolutionStrict' => $this->routeResolutionStrict,
            'trustedProxies' => $this->trustedProxies,
            'trustedProxyDepth' => $this->trustedProxyDepth,
            'trustXForwardedProto' => $this->trustXForwardedProto,
            'whitelist' => $this->whitelist,
            'blacklist' => $this->blacklist,
            'exemptIps' => $this->exemptIps,
            'enableIpBanning' => $this->enableIpBanning,
            'autoBanThreshold' => $this->autoBanThreshold,
            'autoBanDuration' => $this->autoBanDuration,
            'threatBanConfig' => $this->threatBanConfig,
            'enableRateLimitAutoBan' => $this->enableRateLimitAutoBan,
            'enableRateLimiting' => $this->enableRateLimiting,
            'rateLimit' => $this->rateLimit,
            'rateLimitWindow' => $this->rateLimitWindow,
            'endpointRateLimits' => $this->endpointRateLimits,
            'enablePenetrationDetection' => $this->enablePenetrationDetection,
            'enabledDetectionCategories' => array_keys($this->enabledDetectionCategories),
            'detectionSemanticThreshold' => $this->detectionSemanticThreshold,
            'detectionBinaryMinRunLength' => $this->detectionBinaryMinRunLength,
            'excludedDetectionParams' => array_keys($this->excludedDetectionParams),
            'excludedDetectionBodyFields' => array_keys($this->excludedDetectionBodyFields),
            'excludedDetectionHeaders' => array_keys($this->excludedDetectionHeaders),
            'excludePaths' => $this->excludePaths,
            'mutedCheckLogs' => array_keys($this->mutedCheckLogs),
            'logSensitiveHeaders' => array_keys($this->logSensitiveHeaders),
            'logSensitiveParams' => array_keys($this->logSensitiveParams),
            'logSensitiveBodyFields' => array_keys($this->logSensitiveBodyFields),
            'onBlock' => $this->onBlock,
            'customErrorResponses' => $this->customErrorResponses,
            'emergencyWhitelist' => $this->emergencyWhitelist,
            'emergencyMode' => $this->emergencyMode,
            'enforceHttps' => $this->enforceHttps,
            'securityHeaders' => $this->securityHeaders,
            'blockedUserAgents' => $this->blockedUserAgents,
            'enableCors' => $this->enableCors,
            'corsAllowOrigins' => $this->corsAllowOrigins,
            'corsAllowMethods' => $this->corsAllowMethods,
            'corsAllowHeaders' => $this->corsAllowHeaders,
            'corsAllowCredentials' => $this->corsAllowCredentials,
            'corsExposeHeaders' => $this->corsExposeHeaders,
            'corsMaxAge' => $this->corsMaxAge,
            'blockedCountries' => $this->blockedCountries,
            'whitelistCountries' => $this->whitelistCountries,
            'geoIpDbPath' => $this->geoIpDbPath,
            'geoIpHandler' => $this->geoIpHandler,
            'blockCloudProviders' => $this->blockCloudProviders,
            'cloudIpRefreshInterval' => $this->cloudIpRefreshInterval,
            'authVerifier' => $this->authVerifier,
            'logSuspiciousLevel' => $this->logSuspiciousLevel,
            'logRequestLevel' => $this->logRequestLevel,
            'customRequestCheck' => $this->customRequestCheck,
        ];
    }

    private static function fieldNameToArg(string $field): string
    {
        $parts = explode('_', $field);

        return $parts[0] . implode('', array_map(ucfirst(...), array_slice($parts, 1)));
    }

    /** @param list<string> $entries @return list<string> */
    private function validateIpCidrList(array $entries, string $field): array
    {
        $out = [];
        foreach ($entries as $entry) {
            if (!is_string($entry) || $entry === '') {
                throw new \InvalidArgumentException("{$field}: entries must be non-empty IP or CIDR strings");
            }
            if (str_contains($entry, '/')) {
                try {
                    $out[] = CanonicalIp::canonicalNetwork($entry);
                } catch (\InvalidArgumentException $e) {
                    throw new \InvalidArgumentException("{$field}: invalid IP/CIDR entry '{$entry}': {$e->getMessage()}");
                }
            } else {
                $parsed = CanonicalIp::parse($entry);
                if ($parsed === null) {
                    throw new \InvalidArgumentException("{$field}: invalid IP/CIDR entry '{$entry}'");
                }
                $out[] = $parsed;
            }
        }

        return $out;
    }

    /** @param array<string, mixed> $config @return array<string, array{threshold: int, duration: int}> */
    private function validateThreatBanConfig(array $config): array
    {
        $valid = [...self::DETECTION_CATEGORIES, 'rate_limit'];
        $out = [];
        foreach ($config as $category => $entry) {
            if (!in_array($category, $valid, true)) {
                throw new \InvalidArgumentException("threat_ban_config: unknown category '{$category}'");
            }
            if (!is_array($entry) || !isset($entry['threshold'], $entry['duration'])) {
                throw new \InvalidArgumentException("threat_ban_config: '{$category}' needs threshold and duration");
            }
            $threshold = $entry['threshold'];
            $duration = $entry['duration'];
            if (!is_int($threshold) || $threshold < 1 || !is_int($duration) || $duration < 1) {
                throw new \InvalidArgumentException("threat_ban_config: '{$category}' threshold/duration must be ints >= 1");
            }
            $out[$category] = ['threshold' => $threshold, 'duration' => $duration];
        }

        return $out;
    }

    /** @param array<string, mixed> $limits @return array<string, array{limit: int, window: int}> */
    private function validateEndpointRateLimits(array $limits): array
    {
        $out = [];
        foreach ($limits as $endpoint => $entry) {
            if (!is_string($endpoint) || !is_array($entry) || !isset($entry['limit'], $entry['window'])) {
                throw new \InvalidArgumentException('endpoint_rate_limits: map of endpoint => {limit, window}');
            }
            $limit = $entry['limit'];
            $window = $entry['window'];
            if (!is_int($limit) || !is_int($window)) {
                throw new \InvalidArgumentException("endpoint_rate_limits: '{$endpoint}' limit/window must be ints");
            }
            $out[$endpoint] = ['limit' => $limit, 'window' => $window];
        }

        return $out;
    }

    /** @param list<string>|null $categories @return array<string, true> */
    private function validateDetectionCategories(?array $categories): array
    {
        if ($categories === null) {
            return array_fill_keys(self::DETECTION_CATEGORIES, true);
        }
        $out = [];
        foreach ($categories as $category) {
            if (!is_string($category) || !in_array($category, self::DETECTION_CATEGORIES, true)) {
                $name = is_string($category) ? $category : get_debug_type($category);
                throw new \InvalidArgumentException("enabled_detection_categories: unknown category '{$name}'");
            }
            $out[$category] = true;
        }

        return $out;
    }

    /** @param list<string> $paths @return list<string> */
    private function validateExcludePaths(array $paths): array
    {
        $out = [];
        foreach ($paths as $path) {
            if (!is_string($path)) {
                throw new \InvalidArgumentException('exclude_paths: entries must be strings');
            }
            $normalized = self::normalizeUrlPath($path);
            if ($normalized === null) {
                throw new \InvalidArgumentException("exclude_paths: entry '{$path}' fails URL normalization");
            }
            if ($normalized === '/' && $path !== '/') {
                throw new \InvalidArgumentException("exclude_paths: entry '{$path}' normalizes to '/'");
            }
            if ($normalized === '/') {
                continue;
            }
            $out[] = $normalized;
        }

        return $out;
    }

    public static function normalizeUrlPath(string $path): ?string
    {
        $decoded = $path;
        for ($i = 0; $i < 4; $i++) {
            $raw = $decoded;
            $decoded = urldecode($raw);
            if ($decoded === $raw) {
                break;
            }
            if (!preg_match('//u', $decoded)) {
                return null;
            }
        }
        $decoded = str_replace('\\', '/', $decoded);
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $decoded) === 1) {
            return null;
        }
        $segments = [];
        foreach (explode('/', $decoded) as $segment) {
            if ($segment === '.' || $segment === '') {
                continue;
            }
            if ($segment === '..') {
                if ($segments === []) {
                    return null;
                }
                array_pop($segments);
                continue;
            }
            if (str_contains($segment, ';')) {
                $segment = explode(';', $segment, 2)[0];
                if ($segment === '') {
                    continue;
                }
            }
            $segments[] = $segment;
        }

        return '/' . implode('/', $segments);
    }

    /**
     * @param list<string>|null $names
     * @param list<string> $vocabulary
     * @return array<string, true>
     */
    private function validateNameSet(?array $names, array $vocabulary, string $field): array
    {
        $out = [];
        foreach ($names ?? [] as $name) {
            if (!is_string($name) || !in_array($name, $vocabulary, true)) {
                $shown = is_string($name) ? $name : get_debug_type($name);
                throw new \InvalidArgumentException("{$field}: unknown name '{$shown}'");
            }
            $out[strtolower($name)] = true;
        }

        return $out;
    }

    /** @param list<string>|null $names @return array<string, true> */
    private function validateSensitiveSet(?array $names, string $field): array
    {
        if (is_string($names)) {
            throw new \InvalidArgumentException("{$field}: bare string rejected, pass a list of names");
        }
        $out = [];
        foreach ($names ?? [] as $name) {
            if (!is_string($name)) {
                throw new \InvalidArgumentException("{$field}: items must be strings");
            }
            $out[strtolower($name)] = true;
        }

        return $out;
    }

    /**
     * Exclusion sets keep their entries verbatim (Python's _STR_SET_ADAPTER
     * stores them as given): scan sites lower the scanned name or key and
     * test membership against the untouched entries, exactly like the
     * reference's `key.lower() in excluded_params` membership tests.
     *
     * @param list<string>|null $names @return array<string, true>
     */
    private function validateExclusionSet(?array $names, string $field): array
    {
        if (is_string($names)) {
            throw new \InvalidArgumentException("{$field}: bare string rejected, pass a list of names");
        }
        $out = [];
        foreach ($names ?? [] as $name) {
            if (!is_string($name)) {
                throw new \InvalidArgumentException("{$field}: items must be strings");
            }
            $out[$name] = true;
        }

        return $out;
    }

}

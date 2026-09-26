<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Behavior\SuspiciousCountStore;
use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\Pipeline\Checks\AuthenticationCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\CloudIpRefreshCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\CloudProviderCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\CustomRequestCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\CustomValidatorsCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\EmergencyModeCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\HttpsEnforcementCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\IpSecurityCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RateLimitCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\ReferrerCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RequestLoggingCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RequestSizeContentCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RequiredHeadersCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RouteConfigCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\TimeWindowCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\UserAgentCheck;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class CheckFactory
{
    /** Slot order from spec 03 / factory.py DEFAULT_CHECK_CLASSES. */
    public const DEFAULT_CHECK_NAMES = [
        'route_config', 'emergency_mode', 'https_enforcement', 'request_logging',
        'request_size_content', 'required_headers', 'authentication', 'referrer',
        'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security',
        'cloud_provider', 'user_agent', 'rate_limit', 'suspicious_activity',
        'custom_request',
    ];

    /**
     * Container fields whose sizes participate in staleness detection
     * (factory.py WATCHED_CONTAINER_FIELDS, first-seen order).
     */
    public const WATCHED_CONTAINER_FIELDS = ['block_cloud_providers', 'blocked_user_agents', 'endpoint_rate_limits'];

    private readonly ?SusPatterns $susPatterns;

    private readonly CloudManager $cloudManager;

    private readonly ?CountryResolver $geoIpHandler;

    public function __construct(
        private readonly GuardResponseFactory $responseFactory,
        private readonly RouteResolver $routeResolver = new RouteResolver(),
        private readonly ?IpBanManager $ipBanManager = null,
        private readonly ?RateLimitHandler $rateLimitHandler = null,
        ?SusPatterns $susPatterns = null,
        ?CloudManager $cloudManager = null,
        ?CountryResolver $geoIpHandler = null,
        private readonly ?SuspiciousCountStore $suspiciousCountStore = null
    ) {
        $this->susPatterns = $susPatterns;
        $this->cloudManager = $cloudManager ?? new CloudManager();
        $this->geoIpHandler = $geoIpHandler;
    }
    /**
     * Spec 03 helpers.route_config_applies: when route_configs is null (no
     * decorator registered) every route predicate is satisfied.
     *
     * @param list<RouteConfig>|null $routeConfigs
     * @param \Closure(RouteConfig): bool $predicate
     */
    public static function routeConfigApplies(?array $routeConfigs, \Closure $predicate): bool
    {
        if ($routeConfigs === null) {
            return true;
        }
        foreach ($routeConfigs as $routeConfig) {
            if ($predicate($routeConfig)) {
                return true;
            }
        }

        return false;
    }

    /** @param list<RouteConfig>|null $routeConfigs @return list<SecurityCheck> */
    public function buildChecks(SecurityConfig $config, ?array $routeConfigs = null): array
    {
        $checks = [];
        foreach (self::DEFAULT_CHECK_NAMES as $name) {
            $check = $this->buildOne($name, $config);
            if ($check !== null && $check->appliesTo($config, $routeConfigs)) {
                $checks[] = $check;
            }
        }

        return $checks;
    }

    private function buildOne(string $name, SecurityConfig $config): ?SecurityCheck
    {
        return match ($name) {
            'route_config' => new RouteConfigCheck($config, $this->responseFactory, $this->routeResolver),
            'emergency_mode' => new EmergencyModeCheck($config, $this->responseFactory),
            'https_enforcement' => new HttpsEnforcementCheck($config, $this->responseFactory),
            'request_logging' => new RequestLoggingCheck($config, $this->responseFactory),
            'request_size_content' => new RequestSizeContentCheck($config, $this->responseFactory),
            'required_headers' => new RequiredHeadersCheck($config, $this->responseFactory),
            'authentication' => new AuthenticationCheck($config, $this->responseFactory),
            'referrer' => new ReferrerCheck($config, $this->responseFactory),
            'custom_validators' => new CustomValidatorsCheck($config, $this->responseFactory),
            'time_window' => new TimeWindowCheck($config, $this->responseFactory),
            'cloud_ip_refresh' => new CloudIpRefreshCheck($config, $this->responseFactory, $this->cloudManager, $this->routeResolver),
            'ip_security' => new IpSecurityCheck($config, $this->responseFactory, $this->ipBanManager, $this->routeResolver, $this->geoIpHandler),
            'cloud_provider' => new CloudProviderCheck($config, $this->responseFactory, $this->cloudManager, $this->routeResolver),
            'user_agent' => new UserAgentCheck($config, $this->responseFactory),
            'rate_limit' => new RateLimitCheck($config, $this->responseFactory, $this->rateLimitHandler, $this->routeResolver),
            'suspicious_activity' => new SuspiciousActivityCheck(
                $config,
                $this->responseFactory,
                $this->susPatterns ?? new SusPatterns($config->detectionSemanticThreshold),
                $this->ipBanManager,
                $this->routeResolver,
                $this->suspiciousCountStore
            ),
            'custom_request' => new CustomRequestCheck($config, $this->responseFactory),
            default => new DeferredCheck($name, $config, $this->responseFactory),
        };
    }
}

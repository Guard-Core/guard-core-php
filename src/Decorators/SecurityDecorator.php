<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Decorators;

use RenzoFranceschini\GuardCore\Behavior\BehaviorRule;
use RenzoFranceschini\GuardCore\Behavior\BehaviorRuleValidation;
use RenzoFranceschini\GuardCore\Behavior\BehaviorTracker;
use RenzoFranceschini\GuardCore\Cloud\CloudProviderRegistry;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\Redos\Prefilters;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

/**
 * The per-endpoint decorator family, the port of the reference
 * SecurityDecorator mixin composition (guard_core/decorators/__init__.py:
 * BaseSecurityDecorator + the access_control, rate_limiting, behavioral,
 * authentication, content_filtering and advanced mixins). The 25 config
 * methods each return a RouteDecoration chain that is applied with
 * decorate(), the PHP idiom of the reference's `@decorator def endpoint`
 * application; the applied chain ensures the endpoint's RouteConfig
 * (seeded with enable_penetration_detection like the reference
 * _ensure_route_config), mutates it, and stamps the route identity
 * (DecoratedEndpoint::$guardRouteId, the _guard_route_id equivalent).
 *
 * Method-for-method surface: require_ip, block_countries, allow_countries,
 * block_clouds, bypass, rate_limit, geo_rate_limit, usage_monitor,
 * return_monitor, behavior_analysis, suspicious_frequency, require_https,
 * require_auth, api_key_auth, require_authorization_header, require_headers,
 * block_user_agents, content_type_filter, max_request_size,
 * require_referrer, custom_validation, detection_exclusion, time_window,
 * suspicious_detection, honeypot_detection - plus the base infra
 * (config, route_config_revision, get_route_config,
 * initialize_behavior_tracking, initialize_agent and the five
 * send_*_event emitters) and the module-level
 * get_route_decorator_config helper as a static.
 *
 * Consumers resolve a decorated endpoint's config by route id
 * (getRouteDecoratorConfig / getRouteConfig) or hand the whole registry
 * (routeConfigs()) to an adapter's path-pattern route map, so decorated
 * endpoints flow through the identical pipeline checks.
 */
final class SecurityDecorator
{
    /** @var array<string, RouteConfig> route id => config */
    private array $routeConfigs = [];

    /**
     * Route id => endpoint identity of the endpoint the id was derived from.
     * A stamped route id is only reused when THIS instance assigned it to
     * THIS endpoint; otherwise a collision would select another route's
     * config (the reference _route_id_owner guard).
     *
     * @var array<string, string>
     */
    private array $routeIdOwner = [];

    /**
     * Endpoint identity => stamped route id (the _guard_route_id attribute
     * lookup of the reference reuse branch).
     *
     * @var array<string, string>
     */
    private array $endpointRouteIds = [];

    private RouteConfigRevision $revision;

    private BehaviorTracker $behaviorTracker;

    private ?object $agentHandler = null;

    private ?CountryResolver $geoIpHandler = null;

    public function __construct(private readonly SecurityConfig $config)
    {
        $this->revision = new RouteConfigRevision();
        $this->behaviorTracker = new BehaviorTracker($config, null, null);
    }

    public function config(): SecurityConfig
    {
        return $this->config;
    }

    /** The shared revision cell value (route_config_revision). */
    public function routeConfigRevision(): int
    {
        return $this->revision->value;
    }

    public function getRouteConfig(string $routeId): ?RouteConfig
    {
        return $this->routeConfigs[$routeId] ?? null;
    }

    /**
     * The whole registry, keyed by route id. This is the seam the
     * path-pattern adapters consume: the decorated configs ride the same
     * route map hand-built RouteConfigs use.
     *
     * @return array<string, RouteConfig>
     */
    public function routeConfigs(): array
    {
        return $this->routeConfigs;
    }

    public function behaviorTracker(): BehaviorTracker
    {
        return $this->behaviorTracker;
    }

    /**
     * initialize_behavior_tracking: wires Redis into the behavior tracker
     * (a null handler keeps the in-memory tracker, like the reference's
     * `if redis_handler:` guard).
     */
    public function initializeBehaviorTracking(?RedisHandler $redisHandler = null): void
    {
        if ($redisHandler === null) {
            return;
        }
        $this->behaviorTracker = new BehaviorTracker($this->config, $redisHandler, null);
    }

    /** The set_decorator_handler companion: wires the agent + geo handlers. */
    public function initializeAgent(object $agentHandler, ?CountryResolver $geoIpHandler = null): void
    {
        $this->agentHandler = $agentHandler;
        $this->geoIpHandler = $geoIpHandler;
    }

    // ------------------------------------------------------------------
    // AccessControlMixin (guard_core/decorators/access_control.py)
    // ------------------------------------------------------------------

    /**
     * @param list<string>|null $whitelist
     * @param list<string>|null $blacklist
     */
    public function requireIp(?array $whitelist = null, ?array $blacklist = null): RouteDecoration
    {
        return (new RouteDecoration($this))->requireIp($whitelist, $blacklist);
    }

    /** @param list<string> $countries */
    public function blockCountries(array $countries): RouteDecoration
    {
        return (new RouteDecoration($this))->blockCountries($countries);
    }

    /** @param list<string> $countries */
    public function allowCountries(array $countries): RouteDecoration
    {
        return (new RouteDecoration($this))->allowCountries($countries);
    }

    /**
     * @param list<string>|null $providers provider selectors ("AWS" or
     *     "AWS:!region"); null blocks every registered provider
     */
    public function blockClouds(?array $providers = null): RouteDecoration
    {
        return (new RouteDecoration($this))->blockClouds($providers);
    }

    /** @param list<string> $checks */
    public function bypass(array $checks): RouteDecoration
    {
        return (new RouteDecoration($this))->bypass($checks);
    }

    // ------------------------------------------------------------------
    // RateLimitingMixin (guard_core/decorators/rate_limiting.py)
    // ------------------------------------------------------------------

    public function rateLimit(int $requests, int $window = 60): RouteDecoration
    {
        return (new RouteDecoration($this))->rateLimit($requests, $window);
    }

    /**
     * @param array<string, array{limit: int, window: int}> $limits
     */
    public function geoRateLimit(array $limits): RouteDecoration
    {
        return (new RouteDecoration($this))->geoRateLimit($limits);
    }

    // ------------------------------------------------------------------
    // BehavioralMixin (guard_core/decorators/behavioral.py)
    // ------------------------------------------------------------------

    public function usageMonitor(int $maxCalls, int $window = 3600, string $action = 'ban'): RouteDecoration
    {
        return (new RouteDecoration($this))->usageMonitor($maxCalls, $window, $action);
    }

    public function returnMonitor(string $pattern, int $maxOccurrences, int $window = 86400, string $action = 'ban'): RouteDecoration
    {
        return (new RouteDecoration($this))->returnMonitor($pattern, $maxOccurrences, $window, $action);
    }

    /** @param list<BehaviorRule> $rules */
    public function behaviorAnalysis(array $rules): RouteDecoration
    {
        return (new RouteDecoration($this))->behaviorAnalysis($rules);
    }

    public function suspiciousFrequency(float $maxFrequency, int $window = 300, string $action = 'ban'): RouteDecoration
    {
        return (new RouteDecoration($this))->suspiciousFrequency($maxFrequency, $window, $action);
    }

    // ------------------------------------------------------------------
    // AuthenticationMixin (guard_core/decorators/authentication.py)
    // ------------------------------------------------------------------

    public function requireHttps(): RouteDecoration
    {
        return (new RouteDecoration($this))->requireHttps();
    }

    /**
     * @param (\Closure(object, string): mixed)|null $verifier
     */
    public function requireAuth(string $type = 'bearer', ?\Closure $verifier = null): RouteDecoration
    {
        return (new RouteDecoration($this))->requireAuth($type, $verifier);
    }

    /**
     * @param (\Closure(object, string): mixed)|null $verifier
     */
    public function apiKeyAuth(string $headerName = 'X-API-Key', ?\Closure $verifier = null): RouteDecoration
    {
        return (new RouteDecoration($this))->apiKeyAuth($headerName, $verifier);
    }

    public function requireAuthorizationHeader(string $scheme = 'bearer'): RouteDecoration
    {
        return (new RouteDecoration($this))->requireAuthorizationHeader($scheme);
    }

    /** @param array<string, string> $headers */
    public function requireHeaders(array $headers): RouteDecoration
    {
        return (new RouteDecoration($this))->requireHeaders($headers);
    }

    // ------------------------------------------------------------------
    // ContentFilteringMixin (guard_core/decorators/content_filtering.py)
    // ------------------------------------------------------------------

    /** @param list<string> $patterns */
    public function blockUserAgents(array $patterns): RouteDecoration
    {
        return (new RouteDecoration($this))->blockUserAgents($patterns);
    }

    /** @param list<string> $allowedTypes */
    public function contentTypeFilter(array $allowedTypes): RouteDecoration
    {
        return (new RouteDecoration($this))->contentTypeFilter($allowedTypes);
    }

    public function maxRequestSize(int $sizeBytes): RouteDecoration
    {
        return (new RouteDecoration($this))->maxRequestSize($sizeBytes);
    }

    /** @param list<string> $allowedDomains */
    public function requireReferrer(array $allowedDomains): RouteDecoration
    {
        return (new RouteDecoration($this))->requireReferrer($allowedDomains);
    }

    /**
     * @param \Closure(GuardRequest): (?GuardResponse|bool) $validator
     */
    public function customValidation(\Closure $validator): RouteDecoration
    {
        return (new RouteDecoration($this))->customValidation($validator);
    }

    /**
     * @param list<string>|null $headers
     * @param list<string>|null $params
     * @param list<string>|null $bodyFields
     * @param list<string>|null $categories
     */
    public function detectionExclusion(
        ?array $headers = null,
        ?array $params = null,
        ?array $bodyFields = null,
        ?array $categories = null,
        ?bool $scanBody = null
    ): RouteDecoration {
        return (new RouteDecoration($this))->detectionExclusion($headers, $params, $bodyFields, $categories, $scanBody);
    }

    // ------------------------------------------------------------------
    // AdvancedMixin (guard_core/decorators/advanced.py)
    // ------------------------------------------------------------------

    public function timeWindow(string $startTime, string $endTime, string $timezone = 'UTC'): RouteDecoration
    {
        return (new RouteDecoration($this))->timeWindow($startTime, $endTime, $timezone);
    }

    public function suspiciousDetection(bool $enabled = true): RouteDecoration
    {
        return (new RouteDecoration($this))->suspiciousDetection($enabled);
    }

    /** @param list<string> $trapFields */
    public function honeypotDetection(array $trapFields): RouteDecoration
    {
        return (new RouteDecoration($this))->honeypotDetection($trapFields);
    }

    // ------------------------------------------------------------------
    // application (base.py _ensure_route_config / _apply_route_config)
    // ------------------------------------------------------------------

    /**
     * Applies one decoration chain to an endpoint: resolves the route id
     * (_get_route_id), ensures the route's RouteConfig (created seeded with
     * enable_penetration_detection), applies every mutation in chain order,
     * and stamps the id on the returned endpoint shell.
     *
     * @param list<\Closure(RouteConfig): RouteConfig> $mutations
     */
    public function applyDecoration(array $mutations, mixed $endpoint): DecoratedEndpoint
    {
        $identity = self::endpointIdentity($endpoint);
        $routeId = $this->resolveRouteId($endpoint, $identity);
        if (!isset($this->routeConfigs[$routeId])) {
            $this->routeConfigs[$routeId] = new RouteConfig(
                enableSuspiciousDetection: $this->config->enablePenetrationDetection
            );
            $this->revision->bump();
        }
        $this->routeIdOwner[$routeId] ??= $identity;
        $this->endpointRouteIds[$identity] = $routeId;
        $config = $this->routeConfigs[$routeId];
        foreach ($mutations as $mutation) {
            $config = $mutation($config);
            $this->revision->bump();
        }
        $this->routeConfigs[$routeId] = $config;

        return new DecoratedEndpoint($endpoint, $routeId);
    }

    /**
     * The reference _get_route_id: the stamped id is reused only when this
     * instance assigned it to this endpoint (stacked decorations share one
     * config); otherwise the base id (the module.qualname equivalent) is
     * suffixed "#2", "#3", ... until free.
     *
     * @param list<\Closure(RouteConfig): RouteConfig> $mutations
     */
    private function resolveRouteId(mixed $endpoint, string $identity): string
    {
        $stamped = $this->endpointRouteIds[$identity] ?? null;
        if (
            $stamped !== null
            && isset($this->routeConfigs[$stamped])
            && ($this->routeIdOwner[$stamped] ?? null) === $identity
        ) {
            return $stamped;
        }
        $base = self::baseRouteId($endpoint);
        $routeId = $base;
        $suffix = 1;
        while (isset($this->routeConfigs[$routeId])) {
            $suffix++;
            $routeId = $base . '#' . $suffix;
        }

        return $routeId;
    }

    /** The endpoint identity key (the id(func) owner-chain equivalent). */
    private static function endpointIdentity(mixed $endpoint): string
    {
        if (is_string($endpoint)) {
            // Strings are route patterns: the pattern itself is the identity.
            return 'pattern:' . $endpoint;
        }
        if ($endpoint instanceof \Closure) {
            return 'closure#' . spl_object_id($endpoint);
        }
        if (is_array($endpoint) && array_is_list($endpoint) && count($endpoint) === 2) {
            [$class, $method] = $endpoint;
            $classPart = is_object($class) ? get_class($class) . '#' . spl_object_id($class) : (string) $class;

            return $classPart . '::' . $method;
        }
        if (is_object($endpoint)) {
            return get_class($endpoint) . '#' . spl_object_id($endpoint);
        }

        return 'endpoint:' . serialize($endpoint);
    }

    /** The base route id (the module.qualname equivalent). */
    private static function baseRouteId(mixed $endpoint): string
    {
        if (is_string($endpoint)) {
            return $endpoint;
        }
        if ($endpoint instanceof \Closure) {
            return 'closure#' . spl_object_id($endpoint);
        }
        if (is_array($endpoint) && array_is_list($endpoint) && count($endpoint) === 2) {
            [$class, $method] = $endpoint;

            return (is_object($class) ? get_class($class) : (string) $class) . '::' . $method;
        }
        if (is_object($endpoint)) {
            return get_class($endpoint);
        }

        return 'endpoint';
    }

    // ------------------------------------------------------------------
    // base infra events (guard_core/decorators/base.py)
    // ------------------------------------------------------------------

    /**
     * send_decorator_event: builds the middleware event bus over the wired
     * agent + geo handlers and emits one event with the decorator_type
     * metadata. A no handler wiring means no event (the reference's
     * `if not self.agent_handler: return` gate).
     *
     * @param array<string, mixed> $metadata
     */
    public function sendDecoratorEvent(
        string $eventType,
        object $request,
        string $actionTaken,
        string $reason,
        string $decoratorType,
        array $metadata = []
    ): void {
        if ($this->agentHandler === null) {
            return;
        }
        $geoIpHandler = $this->geoIpHandler;
        $eventBus = new EventBus(
            $this->agentHandler,
            $this->config,
            countryResolver: static fn (string $ip): ?string => $geoIpHandler?->getCountry($ip)
        );
        $eventBus->sendMiddlewareEvent(
            $eventType,
            $request,
            $actionTaken,
            $reason,
            ['decorator_type' => $decoratorType, ...$metadata]
        );
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function sendAccessDeniedEvent(object $request, string $reason, string $decoratorType, array $metadata = []): void
    {
        $this->sendDecoratorEvent(
            eventType: EventTypes::EVENT_ACCESS_DENIED,
            request: $request,
            actionTaken: 'blocked',
            reason: $reason,
            decoratorType: $decoratorType,
            metadata: $metadata
        );
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function sendAuthenticationFailedEvent(object $request, string $reason, string $authType, array $metadata = []): void
    {
        $this->sendDecoratorEvent(
            eventType: EventTypes::EVENT_AUTHENTICATION_FAILED,
            request: $request,
            actionTaken: 'blocked',
            reason: $reason,
            decoratorType: 'authentication',
            metadata: ['auth_type' => $authType, ...$metadata]
        );
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function sendRateLimitEvent(object $request, int $limit, int $window, array $metadata = []): void
    {
        $this->sendDecoratorEvent(
            eventType: EventTypes::EVENT_RATE_LIMITED,
            request: $request,
            actionTaken: 'blocked',
            reason: "Rate limit exceeded: {$limit} requests per {$window}s",
            decoratorType: 'rate_limiting',
            metadata: ['limit' => $limit, 'window' => $window, ...$metadata]
        );
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function sendDecoratorViolationEvent(object $request, string $violationType, string $reason, array $metadata = []): void
    {
        $this->sendDecoratorEvent(
            eventType: EventTypes::EVENT_DECORATOR_VIOLATION,
            request: $request,
            actionTaken: 'blocked',
            reason: $reason,
            decoratorType: $violationType,
            metadata: $metadata
        );
    }

    // ------------------------------------------------------------------
    // the module-level get_route_decorator_config helper
    // ------------------------------------------------------------------

    /**
     * get_route_decorator_config: the request's stamped route id resolved
     * through the decorator handler's registry (null without an id or for
     * an unknown one).
     */
    public static function getRouteDecoratorConfig(GuardRequest $request, SecurityDecorator $decoratorHandler): ?RouteConfig
    {
        $routeId = $request->state()->guardRouteId;
        if ($routeId === null || $routeId === '') {
            return null;
        }

        return $decoratorHandler->getRouteConfig($routeId);
    }

    // ------------------------------------------------------------------
    // shared validation + leniency helpers (mixin-level reference logic)
    // ------------------------------------------------------------------

    /**
     * The @block_clouds provider-selector resolution: null means every
     * registered provider; a selector is kept when its provider prefix
     * (the part before the ":!region" marker) is registered, and unknown
     * ones are reported with a decorator warning.
     *
     * @param list<string>|null $providers
     * @return list<string>
     */
    public static function resolveCloudProviderSelectors(?array $providers): array
    {
        if ($providers === null) {
            return CloudProviderRegistry::PROVIDERS;
        }
        $valid = [];
        foreach ($providers as $selector) {
            $marker = strpos($selector, ':!');
            $provider = $marker === false ? $selector : substr($selector, 0, $marker);
            if (in_array($provider, CloudProviderRegistry::PROVIDERS, true) && !in_array($selector, $valid, true)) {
                $valid[] = $selector;
            }
        }
        $invalid = array_diff($providers, $valid);
        if ($invalid !== []) {
            error_log('[guard_core.decorators] @block_clouds: ignored unknown cloud providers ' . self::describeList($invalid));
        }

        return $valid;
    }

    /**
     * The block_user_agents ReDoS gate: every pattern must pass the safety
     * validator or decoration is refused before any config is touched.
     *
     * @param list<string> $patterns
     */
    public static function assertUserAgentPatternsSafe(array $patterns): void
    {
        foreach ($patterns as $pattern) {
            [$safe, $reason] = Prefilters::validatePatternSafety($pattern);
            if (!$safe) {
                throw new \InvalidArgumentException(
                    'block_user_agents pattern rejected by ReDoS validator: '
                    . "'" . SusPatterns::sanitizeForReporting($pattern) . "' ({$reason})"
                );
            }
        }
    }

    /**
     * The return_monitor factory gate (_validate_return_pattern_body_scan):
     * a body-reading pattern is refused when the response body scan is off.
     */
    public static function assertReturnPatternScanSafe(string $pattern, SecurityConfig $config, string $fieldName): void
    {
        BehaviorRuleValidation::validateReturnPatternAgainstScanFlag($pattern, $config->behaviorScanResponseBody, $fieldName);
    }

    /**
     * The behavior_analysis factory gate: every return_pattern rule with a
     * body-reading pattern is refused when the response body scan is off.
     *
     * @param list<BehaviorRule> $rules
     */
    public static function assertBehaviorRulesScanSafe(array $rules, SecurityConfig $config, string $fieldName): void
    {
        BehaviorRuleValidation::validateRulesAgainstScanFlag($rules, $config->behaviorScanResponseBody, $fieldName);
    }

    /**
     * The @honeypot_detection validator: POST/PUT/PATCH bodies with a
     * filled trap field fail custom validation with a 403 "Forbidden"
     * response. Form bodies parse like parse_qs (first value per key),
     * JSON bodies like json.loads (unparsable bodies skip validation).
     * Note: the reference reads the body under the detection scan cap;
     * PHP requests arrive pre-buffered (GuardRequest::body()), so the
     * cap is inherent in the framework's read.
     *
     * @param list<string> $trapFields
     * @return \Closure(GuardRequest): ?GuardResponse
     */
    public static function honeypotValidator(array $trapFields): \Closure
    {
        return static function (GuardRequest $request) use ($trapFields): ?GuardResponse {
            if (!in_array($request->method(), ['POST', 'PUT', 'PATCH'], true)) {
                return null;
            }
            $body = $request->body();
            $contentType = $request->headers()->get('content-type') ?? '';
            if (str_contains($contentType, 'application/x-www-form-urlencoded')) {
                return self::honeypotFormViolation($body, $trapFields);
            }
            if (str_contains($contentType, 'application/json')) {
                return self::honeypotJsonViolation($body, $trapFields);
            }

            return null;
        };
    }

    /**
     * @param list<string> $trapFields
     */
    private static function honeypotFormViolation(string $body, array $trapFields): ?GuardResponse
    {
        $flat = [];
        foreach (explode('&', $body) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            $key = $eq === false ? $pair : substr($pair, 0, $eq);
            $value = $eq === false ? '' : substr($pair, $eq + 1);
            $key = urldecode($key);
            if (!array_key_exists($key, $flat)) {
                $flat[$key] = urldecode($value);
            }
        }

        return self::honeypotTrapHit($flat, $trapFields);
    }

    /**
     * @param list<string> $trapFields
     */
    private static function honeypotJsonViolation(string $body, array $trapFields): ?GuardResponse
    {
        $json = json_decode($body, true, 512);
        if (!is_array($json)) {
            // Unparsable JSON (json.JSONDecodeError / RecursionError family)
            // skips validation like the reference's guarded parse.
            return null;
        }

        return self::honeypotTrapHit($json, $trapFields);
    }

    /**
     * @param array<mixed> $data
     * @param list<string> $trapFields
     */
    private static function honeypotTrapHit(array $data, array $trapFields): ?GuardResponse
    {
        foreach ($trapFields as $field) {
            if (is_string($field) && array_key_exists($field, $data) && self::referenceTruthy($data[$field])) {
                return new GuardResponse(403, body: 'Forbidden');
            }
        }

        return null;
    }

    /**
     * Python truthiness for the trap-value check: "", 0, 0.0, false, null
     * and [] are falsy; everything else (including "0") is truthy.
     */
    private static function referenceTruthy(mixed $value): bool
    {
        return !in_array($value, [null, false, 0, 0.0, '', []], true);
    }

    /** @param list<string> $items */
    public static function describeList(array $items): string
    {
        $sorted = array_values(array_unique(array_map('strval', $items)));
        sort($sorted, SORT_STRING);

        return '[' . implode(', ', $sorted) . ']';
    }
}

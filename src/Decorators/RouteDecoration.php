<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Decorators;

use RenzoFranceschini\GuardCore\Behavior\BehaviorRule;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

/**
 * One fluent decoration chain, the port of the reference decorator closures
 * the mixin methods return (guard_core/decorators/*.py): the SecurityDecorator
 * config methods hand one of these out, further methods extend the chain, and
 * decorate() applies it to an endpoint - the `(func)` application step that
 * ensures the route's RouteConfig, mutates it, and stamps the route identity.
 *
 * Instances are immutable: chaining never mutates the handler or a shared
 * chain, so two factories built from one decorator never bleed into each
 * other (the reference's per-function route-id guarantee). Applying a chain
 * to an endpoint that was decorated before joins that endpoint's existing
 * RouteConfig, exactly like stacked reference decorators sharing one config.
 */
final class RouteDecoration
{
    /**
     * The RouteConfig-level config methods of the reference mixin family
     * (25 across access_control, rate_limiting, behavioral, authentication,
     * content_filtering and advanced). Each appends one mutator applied at
     * decorate() time against the route's current RouteConfig, in chain
     * order.
     *
     * @param list<\Closure(RouteConfig): RouteConfig> $mutations
     */
    public function __construct(
        private readonly SecurityDecorator $handler,
        private readonly array $mutations = []
    ) {
    }

    /**
     * Applies the chain to an endpoint (the reference decorator application).
     * The endpoint is a PHP callable (Closure, "Class::method" string,
     * [object, method] array) or a route pattern string ("METHOD /path" or
     * bare path, the adapter route key, which doubles as the route id).
     */
    public function decorate(mixed $endpoint): DecoratedEndpoint
    {
        return $this->handler->applyDecoration($this->mutations, $endpoint);
    }

    // ------------------------------------------------------------------
    // AccessControlMixin (guard_core/decorators/access_control.py)
    // ------------------------------------------------------------------

    /**
     * @param list<string>|null $whitelist
     * @param list<string>|null $blacklist
     */
    public function requireIp(?array $whitelist = null, ?array $blacklist = null): self
    {
        return $this->with(static function (RouteConfig $rc) use ($whitelist, $blacklist): RouteConfig {
            $values = [];
            if ($whitelist !== null && $whitelist !== []) {
                $values['ipWhitelist'] = $whitelist;
            }
            if ($blacklist !== null && $blacklist !== []) {
                $values['ipBlacklist'] = $blacklist;
            }

            return $values === [] ? $rc : $rc->with($values);
        });
    }

    /** @param list<string> $countries */
    public function blockCountries(array $countries): self
    {
        $upper = array_map(static fn (string $c): string => strtoupper($c), $countries);

        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with(['blockedCountries' => $upper]));
    }

    /** @param list<string> $countries */
    public function allowCountries(array $countries): self
    {
        $upper = array_map(static fn (string $c): string => strtoupper($c), $countries);

        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with(['whitelistCountries' => $upper]));
    }

    /**
     * @param list<string>|null $providers provider selectors ("AWS" or
     *     "AWS:!region"); null blocks every registered provider
     */
    public function blockClouds(?array $providers = null): self
    {
        $resolved = SecurityDecorator::resolveCloudProviderSelectors($providers);

        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with(['blockCloudProviders' => $resolved]));
    }

    /**
     * @param list<string> $checks check names to bypass on this route;
     *     unknown names are ignored with a warning (decorator-time leniency)
     */
    public function bypass(array $checks): self
    {
        return $this->with(static function (RouteConfig $rc) use ($checks): RouteConfig {
            $valid = array_values(array_intersect($checks, SecurityConfig::VALID_BYPASS_CHECKS));
            $merged = array_values(array_unique(array_merge($rc->bypassedChecks, $valid)));
            $invalid = array_diff($checks, $valid);
            if ($invalid !== []) {
                error_log('[guard_core.decorators] @bypass: ignored unknown checks ' . SecurityDecorator::describeList($invalid));
            }

            return $rc->with(['bypassedChecks' => $merged]);
        });
    }

    // ------------------------------------------------------------------
    // RateLimitingMixin (guard_core/decorators/rate_limiting.py)
    // ------------------------------------------------------------------

    public function rateLimit(int $requests, int $window = 60): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'rateLimit' => $requests,
            'rateLimitWindow' => $window,
        ]));
    }

    /**
     * @param array<string, array{limit: int, window: int}> $limits country
     *     code ("DE") or "*" fallback mapped to its limit/window tier
     */
    public function geoRateLimit(array $limits): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with(['geoRateLimits' => $limits]));
    }

    // ------------------------------------------------------------------
    // BehavioralMixin (guard_core/decorators/behavioral.py)
    // ------------------------------------------------------------------

    public function usageMonitor(int $maxCalls, int $window = 3600, string $action = 'ban'): self
    {
        $rule = new BehaviorRule(ruleType: 'usage', threshold: $maxCalls, window: $window, action: $action);

        return $this->appendBehaviorRules([$rule]);
    }

    public function returnMonitor(string $pattern, int $maxOccurrences, int $window = 86400, string $action = 'ban'): self
    {
        SecurityDecorator::assertReturnPatternScanSafe($pattern, $this->handler->config(), 'return_monitor');
        $rule = new BehaviorRule(
            ruleType: 'return_pattern',
            threshold: $maxOccurrences,
            window: $window,
            pattern: $pattern,
            action: $action
        );

        return $this->appendBehaviorRules([$rule]);
    }

    /** @param list<BehaviorRule> $rules */
    public function behaviorAnalysis(array $rules): self
    {
        SecurityDecorator::assertBehaviorRulesScanSafe($rules, $this->handler->config(), 'behavior_analysis');

        return $this->appendBehaviorRules($rules);
    }

    public function suspiciousFrequency(float $maxFrequency, int $window = 300, string $action = 'ban'): self
    {
        $rule = new BehaviorRule(
            ruleType: 'frequency',
            threshold: (int) ($maxFrequency * $window),
            window: $window,
            action: $action
        );

        return $this->appendBehaviorRules([$rule]);
    }

    // ------------------------------------------------------------------
    // AuthenticationMixin (guard_core/decorators/authentication.py)
    // ------------------------------------------------------------------

    public function requireHttps(): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with(['requireHttps' => true]));
    }

    /**
     * @param (\Closure(object, string): mixed)|null $verifier
     */
    public function requireAuth(string $type = 'bearer', ?\Closure $verifier = null): self
    {
        return $this->with(static function (RouteConfig $rc) use ($type, $verifier): RouteConfig {
            if ($rc->authorizationHeaderRequired !== null) {
                throw new \InvalidArgumentException(
                    'require_auth cannot be combined with require_authorization_header;'
                    . ' the latter is presence-only and mutually exclusive with'
                    . ' authenticated routes'
                );
            }

            return $rc->with(['authRequired' => $type, 'authVerifier' => $verifier]);
        });
    }

    /**
     * @param (\Closure(object, string): mixed)|null $verifier
     */
    public function apiKeyAuth(string $headerName = 'X-API-Key', ?\Closure $verifier = null): self
    {
        return $this->with(static function (RouteConfig $rc) use ($headerName, $verifier): RouteConfig {
            if ($rc->authorizationHeaderRequired !== null) {
                throw new \InvalidArgumentException(
                    'api_key_auth cannot be combined with require_authorization_header;'
                    . ' the latter is presence-only and mutually exclusive with'
                    . ' authenticated routes'
                );
            }

            return $rc->with([
                'apiKeyRequired' => true,
                'requiredHeaders' => [...$rc->requiredHeaders, $headerName => 'required'],
                'apiKeyHeader' => $headerName,
                'apiKeyVerifier' => $verifier,
            ]);
        });
    }

    public function requireAuthorizationHeader(string $scheme = 'bearer'): self
    {
        return $this->with(static function (RouteConfig $rc) use ($scheme): RouteConfig {
            if ($rc->authRequired !== null || $rc->apiKeyRequired) {
                throw new \InvalidArgumentException(
                    'require_authorization_header cannot be combined with'
                    . ' require_auth or api_key_auth; it is presence-only and'
                    . ' mutually exclusive with authenticated routes'
                );
            }

            return $rc->with(['authorizationHeaderRequired' => $scheme]);
        });
    }

    /** @param array<string, string> $headers */
    public function requireHeaders(array $headers): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'requiredHeaders' => [...$rc->requiredHeaders, ...$headers],
        ]));
    }

    // ------------------------------------------------------------------
    // ContentFilteringMixin (guard_core/decorators/content_filtering.py)
    // ------------------------------------------------------------------

    /**
     * @param list<string> $patterns every pattern must pass the ReDoS
     *     safety validator; a rejected pattern raises before decoration
     */
    public function blockUserAgents(array $patterns): self
    {
        SecurityDecorator::assertUserAgentPatternsSafe($patterns);

        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'blockedUserAgents' => [...$rc->blockedUserAgents, ...$patterns],
        ]));
    }

    /** @param list<string> $allowedTypes */
    public function contentTypeFilter(array $allowedTypes): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'allowedContentTypes' => $allowedTypes,
        ]));
    }

    public function maxRequestSize(int $sizeBytes): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with(['maxRequestSize' => $sizeBytes]));
    }

    /** @param list<string> $allowedDomains */
    public function requireReferrer(array $allowedDomains): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'requireReferrer' => $allowedDomains,
        ]));
    }

    /**
     * @param \Closure(GuardRequest): (?GuardResponse|bool) $validator
     */
    public function customValidation(\Closure $validator): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'customValidators' => [...$rc->customValidators, $validator],
        ]));
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
    ): self {
        return $this->with(static function (RouteConfig $rc) use ($headers, $params, $bodyFields, $categories, $scanBody): RouteConfig {
            $values = [];
            if ($headers !== null) {
                $values['excludedDetectionHeaders'] = $headers;
            }
            if ($params !== null) {
                $values['excludedDetectionParams'] = $params;
            }
            if ($bodyFields !== null) {
                $values['excludedDetectionBodyFields'] = $bodyFields;
            }
            if ($categories !== null) {
                $values['enabledDetectionCategories'] = $categories;
            }
            if ($scanBody !== null) {
                $values['detectionScanBody'] = $scanBody;
            }

            return $values === [] ? $rc : $rc->with($values);
        });
    }

    // ------------------------------------------------------------------
    // AdvancedMixin (guard_core/decorators/advanced.py)
    // ------------------------------------------------------------------

    public function timeWindow(string $startTime, string $endTime, string $timezone = 'UTC'): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'timeRestrictions' => ['start' => $startTime, 'end' => $endTime, 'timezone' => $timezone],
        ]));
    }

    public function suspiciousDetection(bool $enabled = true): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'enableSuspiciousDetection' => $enabled,
        ]));
    }

    /**
     * @param list<string> $trapFields request body fields that must stay
     *     empty; a filled trap field fails custom validation with 403
     */
    public function honeypotDetection(array $trapFields): self
    {
        $validator = SecurityDecorator::honeypotValidator($trapFields);

        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'customValidators' => [...$rc->customValidators, $validator],
        ]));
    }

    // ------------------------------------------------------------------
    // internals
    // ------------------------------------------------------------------

    /**
     * @param list<BehaviorRule> $rules
     */
    private function appendBehaviorRules(array $rules): self
    {
        return $this->with(static fn (RouteConfig $rc): RouteConfig => $rc->with([
            'behaviorRules' => [...$rc->behaviorRules, ...$rules],
        ]));
    }

    /** @param \Closure(RouteConfig): RouteConfig $mutation */
    private function with(\Closure $mutation): self
    {
        return new self($this->handler, [...$this->mutations, $mutation]);
    }
}

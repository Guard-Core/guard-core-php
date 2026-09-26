<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Routing;

use RenzoFranceschini\GuardCore\Behavior\BehaviorRule;
use RenzoFranceschini\GuardCore\Cloud\CloudProviderRegistry;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;

final class RouteConfig
{
    private int $revision = 0;

    /** @var list<string> */
    public readonly array $bypassedChecks;

    /** @var list<string> */
    public readonly array $blockCloudProviders;

    /** @var array<string, array{limit: int, window: int}> */
    public readonly array $geoRateLimits;

    /**
     * The route's behavior rules (the reference route_config.behavior_rules
     * list the behavioral decorators append to). Rule arrays are normalized
     * through BehaviorRule::fromArray; entries failing the reference's
     * BehaviorRuleConfig constraints are silently dropped (decorator-time
     * leniency, mirroring the other RouteConfig maps).
     *
     * @var list<BehaviorRule>
     */
    public readonly array $behaviorRules;

    /**
     * Per-route detection exclusion surface, mirrored from the reference
     * route_config fields and resolved with the _resolve_* helpers of
     * guard_core/_utils/detection_config.py. A null field means "inherit
     * the global config" for that surface; a non-null value replaces the
     * global one (the header exclusion set is the exception: it always
     * merges the hardcoded defaults with the global set and the route
     * set). Entries keep the same verbatim convention as the global
     * exclusion sets: scan sites lower the scanned name or key and test
     * membership against the untouched entries.
     */
    public readonly bool $enableSuspiciousDetection;

    /** @var list<string>|null */
    public readonly ?array $excludedDetectionHeaders;

    /** @var list<string>|null */
    public readonly ?array $excludedDetectionParams;

    /** @var list<string>|null */
    public readonly ?array $excludedDetectionBodyFields;

    /**
     * When non-null, replaces the global enabled category set for this
     * route (an empty list disables every category, like the reference's
     * empty frozenset). Entries are kept verbatim: an unknown category
     * simply never matches a threat category.
     *
     * @var list<string>|null
     */
    public readonly ?array $enabledDetectionCategories;

    /**
     * When non-null, overrides the reference detection_scan_body default
     * (true): a false skips the body surface while the URL path, query and
     * headers still scan.
     */
    public readonly ?bool $detectionScanBody;

    /**
     * @param list<string> $bypassedChecks invalid names are silently dropped
     *     (decorator-time leniency); valid names update the config
     * @param list<string> $blockedUserAgents
     * @param list<string> $blockCloudProviders selectors "Provider" or
     *     "Provider:!region"; unknown provider names are silently dropped
     *     (decorator-time leniency, mirroring @block_clouds)
     * @param array<string, array{limit: int, window: int}> $geoRateLimits
     *     country code ("DE") or the "*" fallback mapped to a limit/window
     *     tier (mirroring @geo_rate_limit); malformed entries are silently
     *     dropped (decorator-time leniency). WARNING: geo tiers only
     *     activate when a country resolver is configured on the rate limit
     *     handler (RateLimitHandler::setGeoResolver()); without one the geo
     *     tier is inert and the default limit applies
     * @param array<string, string> $requiredHeaders
     * @param list<string>|null $allowedContentTypes
     * @param array<string, string>|null $timeRestrictions start/end (HH:MM),
     *     optional timezone
     * @param list<string>|null $requireReferrer
     * @param (\Closure(object, string): mixed)|null $authVerifier
     * @param (\Closure(object, string): mixed)|null $apiKeyVerifier
     * @param list<\Closure> $customValidators
     */
    public function __construct(
        array $bypassedChecks = [],
        array $behaviorRules = [],
        bool $enableSuspiciousDetection = true,
        ?array $excludedDetectionHeaders = null,
        ?array $excludedDetectionParams = null,
        ?array $excludedDetectionBodyFields = null,
        ?array $enabledDetectionCategories = null,
        ?bool $detectionScanBody = null,
        public readonly ?int $rateLimit = null,
        public readonly ?int $rateLimitWindow = null,
        array $geoRateLimits = [],
        public readonly bool $requireHttps = false,
        public readonly ?string $authRequired = null,
        public readonly array $blockedUserAgents = [],
        array $blockCloudProviders = [],
        public readonly array $requiredHeaders = [],
        public readonly ?int $maxRequestSize = null,
        public readonly ?array $allowedContentTypes = null,
        public readonly ?array $timeRestrictions = null,
        public readonly ?array $requireReferrer = null,
        public readonly bool $apiKeyRequired = false,
        public readonly ?\Closure $authVerifier = null,
        public readonly ?\Closure $apiKeyVerifier = null,
        public readonly ?string $apiKeyHeader = null,
        public readonly ?string $authorizationHeaderRequired = null,
        public readonly array $customValidators = []
    ) {
        $this->bypassedChecks = array_values(array_filter(
            $bypassedChecks,
            fn (string $name): bool => in_array($name, SecurityConfig::VALID_BYPASS_CHECKS, true)
        ));
        $this->blockCloudProviders = self::validateBlockCloudProviders($blockCloudProviders);
        $this->geoRateLimits = self::validateGeoRateLimits($geoRateLimits);
        $rules = [];
        foreach ($behaviorRules as $rule) {
            try {
                $rules[] = $rule instanceof BehaviorRule ? $rule : BehaviorRule::fromArray($rule);
            } catch (\InvalidArgumentException) {
                continue;
            }
        }
        $this->behaviorRules = $rules;
        $this->enableSuspiciousDetection = $enableSuspiciousDetection;
        $this->excludedDetectionHeaders = self::stringListOrNull($excludedDetectionHeaders);
        $this->excludedDetectionParams = self::stringListOrNull($excludedDetectionParams);
        $this->excludedDetectionBodyFields = self::stringListOrNull($excludedDetectionBodyFields);
        $this->enabledDetectionCategories = self::stringListOrNull($enabledDetectionCategories);
        $this->detectionScanBody = $detectionScanBody;
    }

    /**
     * Non-string entries are silently dropped (decorator-time leniency,
     * mirroring the other RouteConfig lists).
     *
     * @return list<string>|null
     */
    private static function stringListOrNull(?array $entries): ?array
    {
        if ($entries === null) {
            return null;
        }
        $out = [];
        foreach ($entries as $entry) {
            if (is_string($entry)) {
                $out[] = $entry;
            }
        }

        return $out;
    }

    /**
     * Country codes (or the "*" fallback) to {limit, window} tiers. Entries
     * that are not a string key holding an int limit/window pair are
     * silently dropped (decorator-time leniency, mirroring the other
     * RouteConfig maps). Keys are matched verbatim against the resolver's
     * country string; there is no case normalization (parity with the
     * Python and Go engines).
     *
     * @param array<string, mixed> $geoRateLimits
     * @return array<string, array{limit: int, window: int}>
     */
    private static function validateGeoRateLimits(array $geoRateLimits): array
    {
        $out = [];
        foreach ($geoRateLimits as $country => $entry) {
            if (!is_string($country) || !is_array($entry) || !isset($entry['limit'], $entry['window'])) {
                continue;
            }
            $limit = $entry['limit'];
            $window = $entry['window'];
            if (!is_int($limit) || !is_int($window) || $limit < 1 || $window < 1) {
                continue;
            }
            $out[$country] = ['limit' => $limit, 'window' => $window];
        }

        return $out;
    }

    /** @param list<string> $selectors @return list<string> */
    private static function validateBlockCloudProviders(array $selectors): array
    {
        $out = [];
        foreach ($selectors as $selector) {
            if (!is_string($selector)) {
                continue;
            }
            $marker = strpos($selector, ':!');
            $provider = $marker === false ? $selector : substr($selector, 0, $marker);
            if (!in_array($provider, CloudProviderRegistry::PROVIDERS, true)) {
                continue;
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

    /** @param array<string, mixed> $values */
    public function with(array $values): self
    {
        $known = [
            'bypassedChecks' => $this->bypassedChecks,
            'behaviorRules' => $this->behaviorRules,
            'enableSuspiciousDetection' => $this->enableSuspiciousDetection,
            'excludedDetectionHeaders' => $this->excludedDetectionHeaders,
            'excludedDetectionParams' => $this->excludedDetectionParams,
            'excludedDetectionBodyFields' => $this->excludedDetectionBodyFields,
            'enabledDetectionCategories' => $this->enabledDetectionCategories,
            'detectionScanBody' => $this->detectionScanBody,
            'rateLimit' => $this->rateLimit,
            'rateLimitWindow' => $this->rateLimitWindow,
            'geoRateLimits' => $this->geoRateLimits,
            'requireHttps' => $this->requireHttps,
            'authRequired' => $this->authRequired,
            'blockedUserAgents' => $this->blockedUserAgents,
            'blockCloudProviders' => $this->blockCloudProviders,
            'requiredHeaders' => $this->requiredHeaders,
            'maxRequestSize' => $this->maxRequestSize,
            'allowedContentTypes' => $this->allowedContentTypes,
            'timeRestrictions' => $this->timeRestrictions,
            'requireReferrer' => $this->requireReferrer,
            'apiKeyRequired' => $this->apiKeyRequired,
            'authVerifier' => $this->authVerifier,
            'apiKeyVerifier' => $this->apiKeyVerifier,
            'apiKeyHeader' => $this->apiKeyHeader,
            'authorizationHeaderRequired' => $this->authorizationHeaderRequired,
            'customValidators' => $this->customValidators,
        ];
        foreach ($values as $name => $value) {
            if (!array_key_exists($name, $known)) {
                throw new \InvalidArgumentException("unknown route config field '{$name}'");
            }
            $known[$name] = $value;
        }

        $copy = new self(...$known);
        $copy->revision = $this->revision + 1;

        return $copy;
    }
}

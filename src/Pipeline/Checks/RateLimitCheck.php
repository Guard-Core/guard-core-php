<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class RateLimitCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly ?RateLimitHandler $rateLimitHandler,
        private readonly RouteResolver $routeResolver
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'rate_limit';
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return true;
    }

    public function containerFields(): array
    {
        return ['endpoint_rate_limits'];
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return $config->enableRateLimiting
            || $config->endpointRateLimits !== []
            || ($routeConfigs !== null && CheckFactory::routeConfigApplies(
                $routeConfigs,
                fn (RouteConfig $rc): bool => $rc->rateLimit !== null || $rc->geoRateLimits !== []
            ));
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $clientIp = $request->state()->clientIp;
        if ($clientIp === null || $request->state()->isWhitelisted || $request->state()->isExempt) {
            return null;
        }

        $routeConfig = $request->state()->routeConfig;
        $bypassed = $this->routeResolver->shouldBypassCheck('rate_limit', $routeConfig);
        if ($bypassed && $routeConfig !== null) {
            return null;
        }

        if ($this->rateLimitHandler === null) {
            return null;
        }

        // Geo tiers ride along only when the route carries a non-empty map
        // (empty keeps the geo branch fully inert, resolver untouched).
        // The handler resolves the country itself: geo tiers activate only
        // when a resolver is configured on it (setGeoResolver), otherwise
        // the default limit applies.
        $geoRateLimits = $routeConfig?->geoRateLimits;

        $outcome = $this->rateLimitHandler->checkRateLimit(
            new RateLimitRequest(
                urlPath: $request->urlPath(),
                whitelisted: false,
                bypassRateLimit: $bypassed,
                geoRateLimits: $geoRateLimits !== null && $geoRateLimits !== [] ? $geoRateLimits : null,
                routeRateLimit: $routeConfig?->rateLimit,
                routeRateLimitWindow: $routeConfig?->rateLimitWindow
            ),
            $clientIp
        );

        if ($outcome === null) {
            return null;
        }

        // The hook reason mirrors the reference ratelimit_handler log
        // format: the tripped tier's request count and window, with an
        // empty trigger_info.
        $reason = "Rate limit exceeded for IP: {$clientIp} ({$outcome->count} requests in {$outcome->window}s window)";
        $this->stashBlock($request, $reason, '');
        if ($this->isPassiveMode()) {
            $this->firePassiveBlockHook($request, $reason, '');

            return null;
        }

        $response = $this->responseFactory->createResponse(
            $outcome::MESSAGE,
            $outcome::STATUS
        );
        foreach ($outcome->errorResponse()['headers'] as $name => $value) {
            $response->headers()->set($name, $value);
        }

        return $response;
    }
}

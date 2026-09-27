<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\ClientIpResolver;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class RouteConfigCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly RouteResolver $routeResolver
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'route_config';
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return true;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $resolved = $this->routeResolver->getRouteConfig($request);
        $state = $request->state();
        if ($resolved !== null || $state->routeConfig === null) {
            $state->routeConfig = $resolved;
        }
        $state->clientIp = ClientIpResolver::extract($request, $this->config);

        if ($this->config->routeResolutionStrict && $state->guardRouteUnresolved === true) {
            $reason = 'Route resolution failed; per-route decorator config could not be applied';
            $this->stashBlock($request, $reason, '');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(500, 'Route resolution failed');
            }
            $this->firePassiveBlockHook($request, $reason, '');
        }

        return null;
    }
}

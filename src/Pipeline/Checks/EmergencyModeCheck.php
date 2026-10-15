<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\ClientIpResolver;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;

final class EmergencyModeCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'emergency_mode';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return $config->emergencyMode;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        if (!$this->config->emergencyMode) {
            return null;
        }

        $clientIp = $request->state()->clientIp;
        if ($clientIp === null || $clientIp === '') {
            $clientIp = ClientIpResolver::extract($request, $this->config, $this->logger);
        }

        $isWhitelisted = CanonicalIp::ipInList($clientIp, $this->config->emergencyWhitelist);

        if (!$isWhitelisted) {
            $reason = "[EMERGENCY MODE] Access denied for IP {$clientIp}";
            $this->stashBlock($request, $reason, '');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(503, 'Service temporarily unavailable');
            }
            $this->firePassiveBlockHook($request, $reason, '');

            return null;
        }

        return null;
    }
}

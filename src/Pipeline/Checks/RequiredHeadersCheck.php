<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

final class RequiredHeadersCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'required_headers';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return CheckFactory::routeConfigApplies($routeConfigs, fn (RouteConfig $rc): bool => $rc->requiredHeaders !== []);
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $routeConfig = $request->state()->routeConfig;
        if ($routeConfig === null || $routeConfig->requiredHeaders === []) {
            return null;
        }

        foreach ($routeConfig->requiredHeaders as $header => $expected) {
            $actual = $request->headers()->get($header);
            if ($actual === null || $actual === '') {
                return $this->reportViolation(
                    $request,
                    $header,
                    "Missing required header: {$header}",
                    'missing_header'
                );
            }
            if ($expected !== 'required' && $actual !== $expected) {
                return $this->reportViolation(
                    $request,
                    $header,
                    "Header '{$header}' does not match the required value",
                    'mismatched_header'
                );
            }
        }

        return null;
    }

    private function reportViolation(GuardRequest $request, string $header, string $reason, string $headerField): ?GuardResponse
    {
        $this->stashBlock($request, $reason, '');
        if (!$this->isPassiveMode()) {
            return $this->createErrorResponse(400, $reason);
        }
        $this->firePassiveBlockHook($request, $reason, '');

        return null;
    }
}

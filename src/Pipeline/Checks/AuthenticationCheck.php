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

final class AuthenticationCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'authentication';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return CheckFactory::routeConfigApplies(
            $routeConfigs,
            fn (RouteConfig $rc): bool => $rc->authRequired !== null
                || $rc->apiKeyRequired
                || $rc->authorizationHeaderRequired !== null
        );
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $routeConfig = $request->state()->routeConfig;
        if ($routeConfig === null) {
            return null;
        }

        $presenceScheme = $routeConfig->authorizationHeaderRequired;
        if ($presenceScheme !== null) {
            $authHeader = $request->headers()->get('authorization') ?? '';
            [$credential, $reason] = self::extractCredential($authHeader, $presenceScheme);
            if ($credential === null) {
                return $this->handleFailure($request, $routeConfig, $reason, true);
            }

            return null;
        }

        if ($routeConfig->authRequired === null && !$routeConfig->apiKeyRequired) {
            return null;
        }

        if ($routeConfig->authRequired !== null) {
            $verifier = $routeConfig->authVerifier ?? $this->config->authVerifier;
            $authHeader = $request->headers()->get('authorization') ?? '';
            [$credential, $reason] = self::extractCredential($authHeader, $routeConfig->authRequired);
            if ($credential === null) {
                return $this->handleFailure($request, $routeConfig, $reason);
            }
        } else {
            $verifier = $routeConfig->apiKeyVerifier ?? $this->config->authVerifier;
            $headerName = $routeConfig->apiKeyHeader;
            $credential = $headerName !== null ? ($request->headers()->get($headerName) ?? '') : '';
            if ($credential === '') {
                return $this->handleFailure($request, $routeConfig, 'Missing API key');
            }
        }

        if ($verifier === null) {
            return $this->handleFailure($request, $routeConfig, 'No auth verifier configured');
        }

        try {
            $result = ($verifier)($request, $credential);
        } catch (\Throwable) {
            return $this->handleFailure($request, $routeConfig, 'Authentication error');
        }
        if (!$result) {
            return $this->handleFailure($request, $routeConfig, 'Authentication failed');
        }

        $request->state()->authPrincipal = $result;

        return null;
    }

    /** @return array{0: string|null, 1: string} */
    private static function extractCredential(string $authHeader, string $authType): array
    {
        if ($authType === 'bearer') {
            if (!str_starts_with($authHeader, 'Bearer ')) {
                return [null, 'Missing or invalid Bearer token'];
            }

            return [substr($authHeader, 7), ''];
        }
        if ($authType === 'basic') {
            if (!str_starts_with($authHeader, 'Basic ')) {
                return [null, 'Missing or invalid Basic authentication'];
            }

            return [substr($authHeader, 6), ''];
        }
        if ($authHeader === '') {
            return [null, "Missing {$authType} authentication"];
        }

        return [$authHeader, ''];
    }

    private function handleFailure(GuardRequest $request, RouteConfig $routeConfig, string $reason, bool $headerPresence = false): ?GuardResponse
    {
        $this->stashBlock($request, "Authentication failure: {$reason}", '');
        if (!$this->isPassiveMode()) {
            return $this->createErrorResponse(401, 'Authentication required');
        }
        $this->firePassiveBlockHook($request, "Authentication failure: {$reason}", '');

        return null;
    }
}

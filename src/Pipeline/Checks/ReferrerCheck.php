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

final class ReferrerCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'referrer';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return CheckFactory::routeConfigApplies($routeConfigs, fn (RouteConfig $rc): bool => $rc->requireReferrer !== null && $rc->requireReferrer !== []);
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $routeConfig = $request->state()->routeConfig;
        if ($routeConfig === null || $routeConfig->requireReferrer === null || $routeConfig->requireReferrer === []) {
            return null;
        }

        $referrer = $request->headers()->get('referer') ?? '';

        if ($referrer === '') {
            $reason = 'Missing referrer header';
            $this->stashBlock($request, $reason, '');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(403, 'Referrer required');
            }
            $this->firePassiveBlockHook($request, $reason, '');

            return null;
        }

        if (!self::isReferrerDomainAllowed($referrer, $routeConfig->requireReferrer)) {
            $reason = "Invalid referrer: {$referrer}";
            $this->stashBlock($request, $reason, '');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(403, 'Invalid referrer');
            }
            $this->firePassiveBlockHook($request, $reason, '');

            return null;
        }

        return null;
    }

    /** @param list<string> $allowedDomains */
    private static function isReferrerDomainAllowed(string $referrer, array $allowedDomains): bool
    {
        $referrerDomain = strtolower(parse_url($referrer, PHP_URL_HOST) ?? '');
        if ($referrerDomain === '') {
            return false;
        }

        foreach ($allowedDomains as $entry) {
            $normalized = self::normalizeAllowedDomain($entry);
            if ($referrerDomain === $normalized
                || str_ends_with($referrerDomain, '.' . $normalized)
            ) {
                return true;
            }
        }

        return false;
    }

    private static function normalizeAllowedDomain(string $entry): string
    {
        if (str_contains($entry, '://')) {
            $host = strtolower(parse_url($entry, PHP_URL_HOST) ?? '');
            $port = parse_url($entry, PHP_URL_PORT);

            return $port !== null ? "{$host}:{$port}" : $host;
        }
        $normalized = strtolower($entry);
        $slash = strpos($normalized, '/');

        return $slash === false ? $normalized : substr($normalized, 0, $slash);
    }
}

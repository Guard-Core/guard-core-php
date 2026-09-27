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
use RenzoFranceschini\GuardCore\Support\Rx;

final class UserAgentCheck extends SecurityCheck
{
    private const MAX_MATCH_LENGTH = 512;

    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'user_agent';
    }

    public function containerFields(): array
    {
        return ['blocked_user_agents'];
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        if ($config->blockedUserAgents !== []) {
            return true;
        }

        return CheckFactory::routeConfigApplies($routeConfigs, fn (RouteConfig $rc): bool => $rc->blockedUserAgents !== []);
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        if ($request->state()->isWhitelisted || $request->state()->isExempt) {
            return null;
        }

        $routeConfig = $request->state()->routeConfig;
        $userAgent = $request->headers()->get('user-agent') ?? '';

        $routeMatch = $routeConfig !== null
            && $routeConfig->blockedUserAgents !== []
            && self::matchesAnyPattern($userAgent, $routeConfig->blockedUserAgents);

        if ($routeMatch || self::matchesAnyPattern($userAgent, $this->config->blockedUserAgents)) {
            $reason = "Blocked user agent: {$userAgent}";
            $this->stashBlock($request, $reason, '');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(403, 'User-Agent not allowed');
            }
            $this->firePassiveBlockHook($request, $reason, '');
        }

        return null;
    }

    /** @param list<string> $patterns */
    private static function matchesAnyPattern(string $userAgent, array $patterns): bool
    {
        if ($patterns === []) {
            return false;
        }
        $subject = substr($userAgent, 0, self::MAX_MATCH_LENGTH);
        foreach ($patterns as $pattern) {
            $ok = @preg_match(Rx::pattern($pattern, false), $subject) === 1;
            if ($ok) {
                return true;
            }
        }

        return false;
    }
}

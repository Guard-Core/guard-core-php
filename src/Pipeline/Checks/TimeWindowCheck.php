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

final class TimeWindowCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'time_window';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return CheckFactory::routeConfigApplies($routeConfigs, fn (RouteConfig $rc): bool => $rc->timeRestrictions !== null && $rc->timeRestrictions !== []);
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $routeConfig = $request->state()->routeConfig;
        if ($routeConfig === null || $routeConfig->timeRestrictions === null || $routeConfig->timeRestrictions === []) {
            return null;
        }

        if (!self::isWithinWindow($routeConfig->timeRestrictions)) {
            $reason = 'Access outside allowed time window';
            $this->stashBlock($request, $reason, '');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(403, 'Access not allowed at this time');
            }
            $this->firePassiveBlockHook($request, $reason, '');
        }

        return null;
    }

    /** @param array<string, string> $restrictions */
    private static function isWithinWindow(array $restrictions): bool
    {
        try {
            $start = $restrictions['start'] ?? throw new \InvalidArgumentException('missing start');
            $end = $restrictions['end'] ?? throw new \InvalidArgumentException('missing end');
            $tzName = $restrictions['timezone'] ?? 'UTC';
            try {
                $tz = new \DateTimeZone($tzName);
            } catch (\Throwable) {
                $tz = new \DateTimeZone('UTC');
            }
            $now = (new \DateTimeImmutable('now', $tz))->format('H:i');

            if ($start > $end) {
                return $now >= $start || $now <= $end;
            }

            return $start <= $now && $now <= $end;
        } catch (\Throwable) {
            return true;
        }
    }
}

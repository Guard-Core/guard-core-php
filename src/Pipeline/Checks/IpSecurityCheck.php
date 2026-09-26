<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

final class IpSecurityCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory,
        private readonly ?IpBanManager $ipBanManager,
        private readonly RouteResolver $routeResolver,
        private readonly ?CountryResolver $geoIpHandler = null
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'ip_security';
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return true;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $clientIp = $request->state()->clientIp;
        if ($clientIp === null) {
            return null;
        }

        $routeConfig = $request->state()->routeConfig;

        if (!$this->routeResolver->shouldBypassCheck('ip_ban', $routeConfig)
            && $this->ipBanManager !== null
            && $this->ipBanManager->isIpBanned($clientIp)
        ) {
            $this->stashBlock($request, "Banned IP attempted access: {$clientIp}", 'banned');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(403, 'IP address banned');
            }

            return null;
        }

        if ($this->routeResolver->shouldBypassCheck('ip', $routeConfig)) {
            return null;
        }

        $whitelist = $this->config->whitelist;
        $whitelistActive = $whitelist !== null && $whitelist !== [];
        $request->state()->isWhitelisted = false;
        $request->state()->isExempt = false;
        $skipCountries = false;

        foreach ($this->config->blacklist as $entry) {
            if (self::matches($entry, $clientIp)) {
                $this->stashBlock($request, "IP blacklisted: {$clientIp}", 'global');
                if (!$this->isPassiveMode()) {
                    return $this->createErrorResponse(403, 'Forbidden');
                }

                return null;
            }
        }

        if ($whitelistActive) {
            $allowed = false;
            foreach ($whitelist as $entry) {
                if (self::matches($entry, $clientIp)) {
                    $allowed = true;
                    break;
                }
            }
            if (!$allowed) {
                $this->stashBlock($request, "IP not in whitelist: {$clientIp}", 'global');
                if (!$this->isPassiveMode()) {
                    return $this->createErrorResponse(403, 'Forbidden');
                }

                return null;
            }
            $request->state()->isWhitelisted = true;
            // A global whitelist match skips the country stage (the
            // reference sets skip_countries from the whitelist
            // membership), so a whitelisted IP is never country blocked.
            // The exempt resolution below still runs, like the reference
            // whitelist branch resolving the exempt flag too.
            $skipCountries = true;
        }

        // Country stage, mirroring _resolve_country_verdict plus
        // _check_blocked_countries_detail (guard_core/_utils/access_control.py):
        // it runs after the global IP lists and before the exempt flag is
        // resolved, loopback IPs are exempt, an unresolved country fails
        // closed only when the allowlist is restrictive (the blocklist
        // mode cannot confirm a country and lets the request pass), and
        // the allowlist takes precedence over the blocklist. The deny
        // reasons match the reference block reasons.
        if (!$this->hasCountryRules() || $skipCountries) {
            // fall through to exempt resolution below
        } elseif (CanonicalIp::isLoopback($clientIp)) {
            // loopback exempt from the global country stage
        } else {
            $country = $this->geoIpHandler?->getCountry($clientIp);
            $allowed = $this->config->whitelistCountries;
            $blocked = $this->config->blockedCountries;
            if ($country === null || $country === '') {
                if ($allowed !== []) {
                    return $this->denyCountry(
                        $request,
                        "IP {$clientIp} not in global allowlist/blocklist"
                    );
                }
            } elseif ($allowed !== []) {
                if (!in_array($country, $allowed, true)) {
                    return $this->denyCountry($request, "IP from blocked country: {$country}");
                }
            } elseif (in_array($country, $blocked, true)) {
                return $this->denyCountry($request, "IP from blocked country: {$country}");
            }
        }

        // Exempt resolution mirrors the reference's _resolve_is_exempt: it
        // runs only after every deny check above passed (the reference's
        // is_allowed, reached by falling through), so it never adds or
        // removes a deny path. An exempt match sets the skip flag the
        // rate-limit, user-agent and cloud-provider checks honor; the
        // whitelist deny path above is untouched, so an exempt IP does not
        // pass a restrictive whitelist, and penetration detection ignores
        // the flag entirely.
        if ($this->config->exemptIps !== []) {
            foreach ($this->config->exemptIps as $entry) {
                if (self::matches($entry, $clientIp)) {
                    $request->state()->isExempt = true;
                    break;
                }
            }
        }

        return null;
    }

    private function hasCountryRules(): bool
    {
        if ($this->config->blockedCountries === [] && $this->config->whitelistCountries === []) {
            return false;
        }

        return $this->geoIpHandler !== null;
    }

    private function denyCountry(GuardRequest $request, string $reason): ?GuardResponse
    {
        $this->stashBlock($request, $reason, 'country_restriction');
        if (!$this->isPassiveMode()) {
            return $this->createErrorResponse(403, 'Forbidden');
        }

        return null;
    }

    private static function matches(string $entry, string $ip): bool
    {
        if (str_contains($entry, '/')) {
            $addr = CanonicalIp::parse($ip);

            return $addr !== null && CanonicalIp::networkContains($entry, $addr);
        }

        return CanonicalIp::parse($ip) === $entry;
    }
}

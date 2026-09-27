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
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
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
            $reason = "Banned IP attempted access: {$clientIp}";
            $this->stashBlock($request, $reason, '');
            if (!$this->isPassiveMode()) {
                return $this->createErrorResponse(403, 'IP address banned');
            }
            $this->firePassiveBlockHook($request, $reason, '');

            return null;
        }

        if ($this->routeResolver->shouldBypassCheck('ip', $routeConfig)) {
            return null;
        }

        $routeOverridesIpLists = false;
        $skipCountries = false;

        // The route IP/country stage (check_route_ip_access,
        // guard_core/core/checks/helpers.py): the route blacklist denies
        // first, a configured route whitelist takes over the route verdict
        // (a miss denies, a match passes the route stage), and the route
        // country verdict denies its match or a miss under a restrictive
        // allowlist. The global lists are still enforced afterwards, so a
        // route whitelist match never relaxes them; it only clears the
        // identity flags, and a route allow_countries match clears the
        // global country stage (the reference _route_country_whitelist_matched).
        if ($routeConfig !== null) {
            $routeResponse = $this->checkRouteIpAccess($request, $clientIp, $routeConfig);
            if ($routeResponse !== null) {
                return $routeResponse;
            }
            $routeOverridesIpLists = $routeConfig->ipWhitelist !== [];
            $routeAllowed = $this->routeCountryVerdict($clientIp, $routeConfig);
            if ($routeAllowed === true) {
                $skipCountries = true;
            }
        }

        $whitelist = $this->config->whitelist;
        $whitelistActive = $whitelist !== null && $whitelist !== [];

        foreach ($this->config->blacklist as $entry) {
            if (self::matches($entry, $clientIp)) {
                return $this->deny($request, $clientIp, self::GENERIC_LIST_BLOCK_REASON);
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
                return $this->deny($request, $clientIp, self::GENERIC_LIST_BLOCK_REASON);
            }
            $request->state()->isWhitelisted = !$routeOverridesIpLists;
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
                    return $this->deny($request, $clientIp, self::GENERIC_LIST_BLOCK_REASON);
                }
            } elseif ($allowed !== []) {
                if (!in_array($country, $allowed, true)) {
                    return $this->deny($request, $clientIp, "IP from blocked country: {$country}");
                }
            } elseif (in_array($country, $blocked, true)) {
                return $this->deny($request, $clientIp, "IP from blocked country: {$country}");
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
        if (!$routeOverridesIpLists && $this->config->exemptIps !== []) {
            foreach ($this->config->exemptIps as $entry) {
                if (self::matches($entry, $clientIp)) {
                    $request->state()->isExempt = true;
                    break;
                }
            }
        }

        return null;
    }

    private const GENERIC_LIST_BLOCK_REASON = 'IP %s not in global allowlist/blocklist';

    /**
     * check_route_ip_access: the route blacklist denies first, then a
     * configured route whitelist takes over the route verdict, then the
     * route country verdict (a blocked-country match denies, a restrictive
     * allowlist denies a miss). The deny reason and payload shapes mirror
     * the reference ip_security check.
     */
    private function checkRouteIpAccess(GuardRequest $request, string $clientIp, RouteConfig $routeConfig): ?GuardResponse
    {
        $ipBlocked = false;
        if ($routeConfig->ipBlacklist !== [] && $this->ipInList($clientIp, $routeConfig->ipBlacklist)) {
            $ipBlocked = true;
        } elseif ($routeConfig->ipWhitelist !== [] && !$this->ipInList($clientIp, $routeConfig->ipWhitelist)) {
            $ipBlocked = true;
        }

        if (!$ipBlocked) {
            $verdict = $this->routeCountryVerdict($clientIp, $routeConfig);
            if ($verdict === false) {
                $ipBlocked = true;
            }
        }

        if (!$ipBlocked) {
            return null;
        }

        $reason = "IP not allowed by route config: {$clientIp}";
        $this->stashBlock($request, $reason, '');
        if (!$this->isPassiveMode()) {
            return $this->createErrorResponse(403, 'Forbidden');
        }
        $this->firePassiveBlockHook($request, $reason, '');

        return null;
    }

    /**
     * check_country_access verdict for the route lists: true when allowed,
     * false when denied (a blocked-country match, or any miss under a
     * restrictive route allowlist, including an unresolved country), null
     * when the route carries no country rules.
     */
    private function routeCountryVerdict(string $clientIp, RouteConfig $routeConfig): ?bool
    {
        if ($routeConfig->blockedCountries === [] && $routeConfig->whitelistCountries === []) {
            return null;
        }
        $country = $this->geoIpHandler?->getCountry($clientIp);
        if ($routeConfig->whitelistCountries !== []) {
            if ($country === null || $country === '') {
                return false;
            }

            return in_array($country, $routeConfig->whitelistCountries, true);
        }

        return !($country !== null && $country !== '' && in_array($country, $routeConfig->blockedCountries, true));
    }

    /** @param list<string> $entries */
    private function ipInList(string $ip, array $entries): bool
    {
        foreach ($entries as $entry) {
            if (self::matches($entry, $ip)) {
                return true;
            }
        }

        return false;
    }

    private function hasCountryRules(): bool
    {
        if ($this->config->blockedCountries === [] && $this->config->whitelistCountries === []) {
            return false;
        }

        return $this->geoIpHandler !== null;
    }

    /**
     * The reference _check_global_ip_restrictions block path: the hook
     * reason composes "IP not allowed: {ip} - {access reason}" over the
     * generic list block string with an empty trigger_info, and the
     * passive mode still fires the hook with a null status.
     */
    private function deny(GuardRequest $request, string $clientIp, string $accessReason): ?GuardResponse
    {
        $accessReason = str_replace('%s', $clientIp, $accessReason);
        $reason = "IP not allowed: {$clientIp} - {$accessReason}";
        $this->stashBlock($request, $reason, '');
        if (!$this->isPassiveMode()) {
            return $this->createErrorResponse(403, 'Forbidden');
        }
        $this->firePassiveBlockHook($request, $reason, '');

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

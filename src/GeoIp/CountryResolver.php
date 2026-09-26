<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\GeoIp;

/**
 * Mirrors the lookup half of the reference GeoIPHandler protocol
 * (guard_core/protocols/geo_ip_protocol.py): getCountry returns the ISO
 * country code for the ip, or null when the IP can not be resolved. Like
 * the reference get_country it must be cheap, run inline per request, and
 * report a miss instead of raising.
 */
interface CountryResolver
{
    public function getCountry(string $ip): ?string;
}

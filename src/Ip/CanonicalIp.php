<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Ip;

final class CanonicalIp
{
    public static function stripBrackets(string $value): string
    {
        if (str_starts_with($value, '[') && str_ends_with($value, ']')) {
            return substr($value, 1, -1);
        }

        return $value;
    }

    /**
     * The reference _canonicalize_ip: brackets stripped, an IPv4-mapped
     * IPv6 address without a zone becomes IPv4, a zoned address keeps its
     * zone, anything unparseable is returned unchanged.
     */
    public static function canonicalize(string $value): string
    {
        return self::referenceText(self::stripBrackets($value)) ?? $value;
    }

    /**
     * The reference _canonical_ip_text over ip_address(): null when the
     * value is not an address (Python ipaddress acceptance: an IPv6 zone id
     * is accepted, brackets, ports and an IPv4 zone are not).
     */
    public static function referenceText(string $value): ?string
    {
        $raw = self::parseRaw($value);
        if ($raw === null) {
            return null;
        }
        if (strlen($raw['bytes']) === 16 && $raw['scope'] === null && self::isV4Mapped($raw['bytes'])) {
            return inet_ntop(substr($raw['bytes'], 12, 4));
        }

        return self::renderRaw($raw);
    }

    /** The reference str(ip_address(value)) (no IPv4-mapped collapse): null when invalid. */
    public static function strOf(string $value): ?string
    {
        $raw = self::parseRaw($value);

        return $raw === null ? null : self::renderRaw($raw);
    }

    /**
     * Packed address bytes of ip_address(value), zone dropped, no
     * IPv4-mapped collapse (an IPv6 address stays a 16-byte value).
     */
    public static function packedRaw(string $value): ?string
    {
        $raw = self::parseRaw($value);

        return $raw === null ? null : $raw['bytes'];
    }

    /**
     * ip_network(value, strict=False): the packed network address and the
     * prefix length, null when invalid (the reference ValueError).
     *
     * @return array{0: string, 1: int}|null
     */
    public static function parseNetwork(string $value): ?array
    {
        $slash = strrpos($value, '/');
        if ($slash === false) {
            return null;
        }
        $prefix = substr($value, $slash + 1);
        $addr = substr($value, 0, $slash);
        if ($prefix === '' || !ctype_digit($prefix) || str_contains($addr, '%')) {
            return null;
        }
        $bytes = self::packedRaw($addr);
        if ($bytes === null || (int) $prefix > strlen($bytes) * 8) {
            return null;
        }

        return [$bytes, (int) $prefix];
    }

    /** Whether packed $ip lies in the packed network (the address families must match). */
    public static function bytesInNetwork(string $ip, string $network, int $prefixLen): bool
    {
        if (strlen($ip) !== strlen($network)) {
            return false;
        }
        $bytes = intdiv($prefixLen, 8);
        if (substr($ip, 0, $bytes) !== substr($network, 0, $bytes)) {
            return false;
        }
        $rem = $prefixLen % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rem)) & 0xff;

        return (ord($ip[$bytes]) & $mask) === (ord($network[$bytes]) & $mask);
    }

    /**
     * The reference _ip_in_list (_utils/access_control.py): a bare entry
     * matches when its canonical form equals the canonical client address,
     * a CIDR entry by network membership (a zone id never defeats it). A
     * malformed CIDR entry matches nothing.
     *
     * @param list<string> $entries
     */
    public static function ipInList(string $ip, array $entries): bool
    {
        $canonical = self::canonicalize($ip);
        $packed = self::packedRaw($canonical);
        foreach ($entries as $entry) {
            if (str_contains($entry, '/')) {
                $network = self::parseNetwork($entry);
                if ($network !== null && $packed !== null && self::bytesInNetwork($packed, $network[0], $network[1])) {
                    return true;
                }
            } elseif ($canonical === self::canonicalize($entry)) {
                return true;
            }
        }

        return false;
    }

    public static function parse(string $value): ?string
    {
        return self::canonicalText(self::stripBrackets($value));
    }

    public static function canonicalNetwork(string $cidr): string
    {
        $slash = strrpos($cidr, '/');
        if ($slash === false) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}': missing prefix length");
        }
        $addrPart = substr($cidr, 0, $slash);
        $prefixLen = filter_var(substr($cidr, $slash + 1), FILTER_VALIDATE_INT);
        $addr = self::strOf(self::stripBrackets($addrPart));
        if ($addr === null || str_contains($addr, '%') || $prefixLen === false) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}'");
        }
        $bytes = @inet_pton($addr);
        if ($bytes === false) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}'");
        }
        $totalBits = strlen($bytes) * 8;
        if ($prefixLen < 0 || $prefixLen > $totalBits) {
            throw new \InvalidArgumentException("Invalid CIDR network '{$cidr}': prefix length out of range");
        }
        $masked = self::clearHostBits($bytes, $prefixLen);

        return self::renderRaw(['bytes' => $masked, 'scope' => null]) . '/' . $prefixLen;
    }

    public static function networkContains(string $network, string $ip): bool
    {
        $slash = strrpos($network, '/');
        if ($slash === false) {
            return false;
        }
        $prefixLen = (int) substr($network, $slash + 1);
        $netBytes = @inet_pton(substr($network, 0, $slash));
        $ipBytes = @inet_pton($ip);
        if ($netBytes === false || $ipBytes === false || strlen($netBytes) !== strlen($ipBytes)) {
            return false;
        }

        return substr(self::clearHostBits($ipBytes, $prefixLen), 0, (int) ceil($prefixLen / 8))
            === substr(self::clearHostBits($netBytes, $prefixLen), 0, (int) ceil($prefixLen / 8));
    }

    public static function isLoopback(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return str_starts_with($ip, '127.');
        }
        $bytes = @inet_pton($ip);
        if ($bytes === false || strlen($bytes) !== 16) {
            return false;
        }

        return $bytes === inet_pton('::1') || self::isV4Mapped($bytes)
            && str_starts_with(inet_ntop(substr($bytes, 12, 4)), '127.');
    }

    /** @return array{bytes: string, scope: ?string}|null */
    private static function parseRaw(string $value): ?array
    {
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $bytes = @inet_pton($value);

            return $bytes === false ? null : ['bytes' => $bytes, 'scope' => null];
        }
        $addr = $value;
        $scope = null;
        $pct = strpos($value, '%');
        if ($pct !== false) {
            $addr = substr($value, 0, $pct);
            $scope = substr($value, $pct + 1);
            if ($scope === '' || str_contains($scope, '%') || str_contains($scope, '/')) {
                return null;
            }
        }
        if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return null;
        }
        $bytes = @inet_pton($addr);
        if ($bytes === false || strlen($bytes) !== 16) {
            return null;
        }

        return ['bytes' => $bytes, 'scope' => $scope];
    }

    /** @param array{bytes: string, scope: ?string} $raw */
    private static function renderRaw(array $raw): string
    {
        if (strlen($raw['bytes']) === 4) {
            return inet_ntop($raw['bytes']);
        }
        $text = self::isV4Mapped($raw['bytes'])
            ? '::ffff:' . inet_ntop(substr($raw['bytes'], 12, 4))
            : self::bytesToText($raw['bytes']);

        return $raw['scope'] === null ? $text : $text . '%' . $raw['scope'];
    }

    private static function canonicalText(string $value, bool $allowV4MappedCollapse = true): ?string
    {
        if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $value;
        }
        if (!filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return null;
        }
        $bytes = @inet_pton($value);
        if ($bytes === false || strlen($bytes) !== 16) {
            return null;
        }
        if ($allowV4MappedCollapse && self::isV4Mapped($bytes)) {
            return inet_ntop(substr($bytes, 12, 4));
        }

        return self::bytesToText($bytes);
    }

    private static function isV4Mapped(string $bytes16): bool
    {
        return substr($bytes16, 0, 10) === str_repeat("\x00", 10)
            && substr($bytes16, 10, 2) === "\xff\xff";
    }

    public static function maskBytes(string $bytes, int $prefixLen): string
    {
        return self::clearHostBits($bytes, $prefixLen);
    }

    private static function clearHostBits(string $bytes, int $prefixLen): string
    {
        $out = $bytes;
        $fullBytes = intdiv($prefixLen, 8);
        $remBits = $prefixLen % 8;
        for ($i = $fullBytes + ($remBits > 0 ? 1 : 0); $i < strlen($bytes); $i++) {
            $out[$i] = "\x00";
        }
        if ($remBits > 0) {
            $mask = (0xff << (8 - $remBits)) & 0xff;
            $out[$fullBytes] = chr(ord($out[$fullBytes]) & $mask);
        }

        return $out;
    }

    private static function bytesToText(string $bytes): string
    {
        $groups = array_values(unpack('n8', $bytes));
        $hex = array_map(dechex(...), $groups);
        $bestStart = -1;
        $bestLen = 0;
        $curStart = -1;
        $curLen = 0;
        foreach ($groups as $i => $g) {
            if ($g === 0) {
                if ($curStart === -1) {
                    $curStart = $i;
                    $curLen = 1;
                } else {
                    $curLen++;
                }
                if ($curLen > $bestLen) {
                    $bestStart = $curStart;
                    $bestLen = $curLen;
                }
            } else {
                $curStart = -1;
                $curLen = 0;
            }
        }
        if ($bestLen < 2) {
            return implode(':', $hex);
        }
        $left = implode(':', array_slice($hex, 0, $bestStart));
        $right = implode(':', array_slice($hex, $bestStart + $bestLen));

        return $left . '::' . $right;
    }
}

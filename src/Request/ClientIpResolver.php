<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\HeaderExclusions;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Logging\LogSanitizer;
use RenzoFranceschini\GuardCore\Logging\RequestLogger;
use RenzoFranceschini\GuardCore\Logging\SimpleRequestLogger;

/**
 * Client identity resolution, the port of the reference
 * guard_core/_utils/ip_extraction.py (extract_client_ip): the connecting
 * address is canonicalized (an IPv4-mapped IPv6 address becomes IPv4), the
 * X-Forwarded-For chain is honored only from a trusted connecting peer
 * (compared as raw text or by CIDR membership), entries are counted from
 * the right at trusted_proxy_depth, and a chain from an untrusted peer is
 * reported as a spoof attempt and ignored.
 */
final class ClientIpResolver
{
    public const UNKNOWN_CLIENT_IDENTITY = 'unknown';

    /** @var array<string, bool> the once-per-process warning gates */
    private static array $warned = [];

    /** Clears the once-per-process warning gates (the reference module flags). */
    public static function resetWarnings(): void
    {
        self::$warned = [];
    }

    public static function extract(
        GuardRequest $request,
        SecurityConfig $config,
        ?RequestLogger $logger = null,
        ?EventBus $eventBus = null
    ): string {
        $cached = $request->state()->clientIp;
        if ($cached !== null && $cached !== '') {
            return $cached;
        }
        $logger ??= new SimpleRequestLogger();
        $forwardedFor = $request->headers()->get('x-forwarded-for');

        $connectingIp = $request->clientHost();
        if ($connectingIp === null || $connectingIp === '') {
            return in_array('unix', $config->trustedProxies, true)
                ? self::resolveForwardedChain(
                    self::UNKNOWN_CLIENT_IDENTITY,
                    $forwardedFor,
                    $config->trustedProxyDepth,
                    $config->trustedProxies,
                    $logger
                )
                : self::UNKNOWN_CLIENT_IDENTITY;
        }

        $canonical = CanonicalIp::canonicalize($connectingIp);

        if ($config->trustedProxies === []) {
            self::warnPreempted($connectingIp, $forwardedFor, $logger);

            return $canonical;
        }

        if (!self::isTrustedProxy($connectingIp, $config->trustedProxies)) {
            return self::handleUntrustedProxy($request, $connectingIp, $canonical, $forwardedFor, $logger, $eventBus);
        }

        return self::resolveForwardedChain(
            $canonical,
            $forwardedFor,
            $config->trustedProxyDepth,
            $config->trustedProxies,
            $logger
        );
    }

    /**
     * The reference _is_trusted_proxy: the raw connecting address against
     * each entry, bare entries by text equality and CIDR entries by
     * membership (an IPv4-mapped IPv6 peer is not a member of an IPv4
     * network). An unparseable peer, or a malformed CIDR entry reached
     * before a match, is never trusted (the reference ValueError arm).
     *
     * @param list<string> $trustedProxies
     */
    public static function isTrustedProxy(string $connectingIp, array $trustedProxies): bool
    {
        $packed = CanonicalIp::packedRaw($connectingIp);
        if ($packed === null) {
            return false;
        }
        foreach ($trustedProxies as $proxy) {
            if (!str_contains($proxy, '/')) {
                if ($connectingIp === $proxy) {
                    return true;
                }
                continue;
            }
            $network = CanonicalIp::parseNetwork($proxy);
            if ($network === null) {
                return false;
            }
            if (CanonicalIp::bytesInNetwork($packed, $network[0], $network[1])) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $trustedProxies
     */
    public static function resolveForwardedChain(
        string $connectingIp,
        ?string $forwardedFor,
        int $proxyDepth,
        array $trustedProxies,
        ?RequestLogger $logger = null
    ): string {
        if ($forwardedFor === null || $forwardedFor === '') {
            return $connectingIp;
        }
        $logger ??= new SimpleRequestLogger();

        $ips = self::forwardedIps($forwardedFor);
        $chainLength = count($ips);
        if ($chainLength < $proxyDepth) {
            self::warnChainTooShort($forwardedFor, $chainLength, $logger);

            return $connectingIp;
        }

        if ($trustedProxies !== []) {
            $unlisted = 0;
            foreach (array_slice($ips, max(0, $chainLength - $proxyDepth + 1)) as $entry) {
                if (!self::isTrustedProxy(CanonicalIp::canonicalize($entry), $trustedProxies)) {
                    $unlisted++;
                }
            }
            if ($unlisted > 0) {
                self::warnDepthOvercounts($unlisted, $forwardedFor, $logger);

                return self::resolveRightToLeft($ips, $trustedProxies) ?? $connectingIp;
            }
        }

        $client = self::extractFromForwardedHeader($ips, $proxyDepth);
        if ($client !== null && $client !== '') {
            if (self::isTrustedProxy($client, $trustedProxies)) {
                self::warnSelectedTrusted($client, $logger);
            }

            return $client;
        }

        return $connectingIp;
    }

    /** @return list<string> */
    private static function forwardedIps(string $forwardedFor): array
    {
        return array_map(
            static fn (string $entry): string => HeaderExclusions::stripForwardedEntryPort(trim($entry)),
            explode(',', $forwardedFor)
        );
    }

    /** @param list<string> $ips */
    private static function extractFromForwardedHeader(array $ips, int $proxyDepth): ?string
    {
        // The caller already proved count($ips) >= $proxyDepth and the config
        // guarantees trusted_proxy_depth >= 1.
        $candidate = $ips[count($ips) - $proxyDepth];
        $text = CanonicalIp::referenceText($candidate);
        if ($text === null || self::hasMetachar($candidate)) {
            return null;
        }

        return $text;
    }

    /**
     * The rightmost entry that is not a trusted proxy is the client; null
     * when every entry is trusted or the first untrusted one is malformed.
     *
     * @param list<string> $ips
     * @param list<string> $trustedProxies
     */
    private static function resolveRightToLeft(array $ips, array $trustedProxies): ?string
    {
        foreach (array_reverse($ips) as $entry) {
            if (self::isTrustedProxy(CanonicalIp::canonicalize($entry), $trustedProxies)) {
                continue;
            }
            $text = CanonicalIp::referenceText($entry);
            if ($text === null || self::hasMetachar($entry)) {
                return null;
            }

            return $text;
        }

        return null;
    }

    private static function hasMetachar(string $candidate): bool
    {
        return strpbrk($candidate, '*?[]\\') !== false;
    }

    private static function isPrivateOrLoopback(string $ip): bool
    {
        $packed = CanonicalIp::packedRaw($ip);
        if ($packed === null) {
            return false;
        }
        $privateRanges = strlen($packed) === 4
            ? ['0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/29', '192.0.0.170/31', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '240.0.0.0/4', '255.255.255.255/32']
            : ['::1/128', '::/128', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64', '2001::/23', '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10'];
        foreach ($privateRanges as $range) {
            $network = CanonicalIp::parseNetwork($range);
            if ($network !== null && CanonicalIp::bytesInNetwork($packed, $network[0], $network[1])) {
                return true;
            }
        }

        return false;
    }

    private static function displayChain(string $value): string
    {
        $displayed = [];
        foreach (explode(',', $value) as $part) {
            $candidate = HeaderExclusions::stripForwardedEntryPort(trim($part));
            $displayed[] = CanonicalIp::referenceText($candidate) !== null ? $part : '[REDACTED]';
        }

        return implode(',', $displayed);
    }

    private static function handleUntrustedProxy(
        GuardRequest $request,
        string $connectingIp,
        string $canonicalConnectingIp,
        ?string $forwardedFor,
        RequestLogger $logger,
        ?EventBus $eventBus
    ): string {
        if ($forwardedFor !== null && $forwardedFor !== '') {
            self::warnPreempted($connectingIp, $forwardedFor, $logger);
            $display = self::displayChain($forwardedFor);
            $logger->log(
                self::isPrivateOrLoopback($connectingIp) ? 'debug' : 'warning',
                'Potential IP spoof attempt: X-Forwarded-For header (' . LogSanitizer::sanitize($display)
                . ') received from untrusted IP ' . LogSanitizer::sanitize($connectingIp)
            );
            $eventBus?->sendRequestHandlerEvent(
                EventTypes::EVENT_SUSPICIOUS_REQUEST,
                'ip_extraction',
                $canonicalConnectingIp,
                $request,
                'spoofing_detected',
                'Potential IP spoof attempt: X-Forwarded-For header ' . $display
            );
        }

        return $canonicalConnectingIp;
    }

    private static function once(string $flag): bool
    {
        if (isset(self::$warned[$flag])) {
            return false;
        }
        self::$warned[$flag] = true;

        return true;
    }

    private static function warnPreempted(string $connectingIp, ?string $forwardedFor, RequestLogger $logger): void
    {
        if (isset(self::$warned['preempted']) || $forwardedFor === null || $forwardedFor === '') {
            return;
        }
        $entries = array_map('trim', explode(',', $forwardedFor));
        if (!in_array($connectingIp, $entries, true)) {
            return;
        }
        self::$warned['preempted'] = true;
        $logger->log('warning', sprintf(
            'The connecting IP (%s) already appears inside its own X-Forwarded-For chain: the '
            . 'application server resolved the client from that header before guard-core ran. '
            . 'While it is, the address guard-core sees is whatever the client claimed, so a '
            . 'rotating X-Forwarded-For defeats rate limiting and IP banning. Declare the proxy '
            . 'via trusted_proxies / trusted_proxy_depth so guard-core resolves the real client '
            . 'itself. This warning is logged once.',
            LogSanitizer::sanitize($connectingIp)
        ));
    }

    private static function warnChainTooShort(string $forwardedFor, int $chainLength, RequestLogger $logger): void
    {
        if (!self::once('too_short')) {
            return;
        }
        $logger->log('warning', sprintf(
            'The X-Forwarded-For chain has only %d entries, fewer than the configured '
            . 'trusted_proxy_depth; chain was %s; falling back to the connecting peer as the '
            . 'client. This warning is logged once.',
            $chainLength,
            LogSanitizer::sanitize(self::displayChain($forwardedFor))
        ));
    }

    private static function warnSelectedTrusted(string $entry, RequestLogger $logger): void
    {
        if (!self::once('selected_trusted')) {
            return;
        }
        $logger->log('warning', sprintf(
            'trusted_proxy_depth selected %s from the X-Forwarded-For chain, but that address is '
            . 'itself listed in trusted_proxies; the chain likely has more proxy hops than '
            . 'trusted_proxy_depth accounts for. This warning is logged once.',
            LogSanitizer::sanitize($entry)
        ));
    }

    private static function warnDepthOvercounts(int $unlisted, string $forwardedFor, RequestLogger $logger): void
    {
        if (!self::once('overcounts')) {
            return;
        }
        $logger->log('warning', sprintf(
            'trusted_proxy_depth selected an entry from the X-Forwarded-For chain with %d '
            . 'entry/entries to its right that are not listed in trusted_proxies; chain was %s; '
            . 'the declared depth over-counts the real proxy hops. Set trusted_proxy_depth to the '
            . 'number of proxies that append to X-Forwarded-For. This warning is logged once.',
            $unlisted,
            LogSanitizer::sanitize(self::displayChain($forwardedFor))
        ));
    }
}

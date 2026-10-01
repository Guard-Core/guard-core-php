<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\GeoIp;

use RenzoFranceschini\GuardCore\Cloud\HttpClient;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;

/**
 * The IPInfo geo database lifecycle, ported from the reference
 * ipinfo_handler.py IPInfoManager (spec 10 "Country filtering"):
 *
 * - the free `country_asn.mmdb` download from
 *   https://ipinfo.io/data/free/country_asn.mmdb with the
 *   `Authorization: Bearer {token}` header (empty token is a constructor
 *   error), up to 3 attempts with exponential backoff starting at 1 s;
 * - atomic writes (tmp file + rename) and a corrupted-database removal;
 * - freshness by the file's mtime against maxAge (default 86400 s); a
 *   download failure keeps the existing reader and emits geo_lookup_failed
 *   with action database_download_failed;
 * - Redis sharing: on download the database bytes are cached at the
 *   `ipinfo:database` key with TTL maxAge; initialization with Redis
 *   prefers the cached copy over a download;
 * - getCountry is synchronous, never raises: an unavailable reader warns
 *   and returns null; a lookup failure emits geo_lookup_failed (action
 *   lookup_failed) and returns null;
 * - checkCountryAccess with the reference verdict and the country_blocked
 *   events (rule_type country_blacklist / country_whitelist).
 *
 * The reference sends its events to the agent handler; this port hands
 * them to the injectable $eventSink (the adapter or the event bus
 * subscribes). The $sleep and $clock injection points exist for tests; the
 * defaults are a real sleep and time().
 */
final class IpInfoManager implements CountryResolver
{
    public const DOWNLOAD_URL = 'https://ipinfo.io/data/free/country_asn.mmdb';

    public int $downloadRetries = 3;

    private ?MmdbReader $reader = null;

    private bool $initializationAttempted = false;

    private ?\DateTimeImmutable $lastRefreshed = null;

    /** @var \Closure(float): void */
    private \Closure $sleep;

    /** @var \Closure(): int */
    private \Closure $clock;

    /**
     * @param callable(SecurityEvent): void|null $eventSink
     * @param (\Closure(float): void)|null $sleep
     * @param (\Closure(): int)|null $clock
     */
    public function __construct(
        private readonly string $token,
        private readonly string $dbPath = 'data/ipinfo/country_asn.mmdb',
        private readonly int $maxAge = 86400,
        private readonly ?HttpClient $httpClient = null,
        private readonly ?RedisHandler $redisHandler = null,
        private readonly mixed $eventSink = null,
        ?\Closure $sleep = null,
        ?\Closure $clock = null
    ) {
        if ($token === '') {
            throw new \InvalidArgumentException('IPInfo token is required!');
        }
        $this->sleep = $sleep ?? static function (float $seconds): void { usleep((int) ($seconds * 1000000)); };
        $this->clock = $clock ?? static fn (): int => time();
    }

    public function dbPath(): string
    {
        return $this->dbPath;
    }

    public function isInitialized(): bool
    {
        return $this->reader !== null;
    }

    public function lastRefreshed(): ?\DateTimeImmutable
    {
        return $this->lastRefreshed;
    }

    /** @return array{ready: bool, last_refreshed: \DateTimeImmutable|null, entries: int|null} */
    public function getStatus(): array
    {
        return [
            'ready' => $this->isInitialized(),
            'last_refreshed' => $this->lastRefreshed,
            'entries' => $this->reader?->nodeCount(),
        ];
    }

    public function initialize(): void
    {
        try {
            $directory = dirname($this->dbPath);
            if ($directory !== '' && $directory !== '.' && !is_dir($directory)) {
                @mkdir($directory, 0777, true);
            }

            if ($this->redisHandler !== null) {
                try {
                    $cachedDb = $this->redisHandler->getKey('ipinfo', 'database');
                } catch (\Throwable $e) {
                    error_log('[guard_core] Cached GeoIP database unavailable: ' . $e->getMessage());
                    $cachedDb = null;
                }
                if ($cachedDb !== null && $cachedDb !== '') {
                    $this->writeDatabaseAtomically($cachedDb);
                    $this->applyReader($this->openDatabaseOrNone());

                    return;
                }
            }

            try {
                if (!is_file($this->dbPath) || $this->isDbOutdated()) {
                    $this->downloadDatabase();
                }
            } catch (\Throwable $e) {
                error_log('[guard_core] IPInfo database download failed, keeping existing reader: ' . self::describeDownloadError($e));
                $this->sendGeoEvent(
                    EventTypes::EVENT_GEO_LOOKUP_FAILED,
                    'system',
                    'database_download_failed',
                    'Failed to download IPInfo database: ' . self::describeDownloadError($e)
                );

                return;
            }

            if (is_file($this->dbPath)) {
                $this->applyReader($this->openDatabaseOrNone());
            }
        } finally {
            $this->initializationAttempted = true;
        }
    }

    public function refresh(): void
    {
        try {
            $this->downloadDatabase();
        } catch (\Throwable $e) {
            error_log('[guard_core] IPInfo refresh failed: ' . self::describeDownloadError($e));
            $this->initializationAttempted = true;

            return;
        } finally {
            $this->initializationAttempted = true;
        }

        // A successful download always left the file on disk; opening it
        // may still fail (garbage bytes), which keeps the existing reader.
        $reader = $this->openDatabaseOrNone();
        if ($reader === null) {
            return;
        }
        $this->reader = $reader;
        $this->lastRefreshed = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function getCountry(string $ip): ?string
    {
        $reader = $this->reader;
        if ($reader === null) {
            if ($this->initializationAttempted) {
                error_log('[guard_core] Geo-IP reader unavailable after a failed initialization attempt; returning null for '
                    . $ip . '. Check the IPInfo token and network reachability, then call refresh() to retry.');
            } else {
                error_log('[guard_core] Geo-IP reader uninitialized; returning null for ' . $ip);
            }

            return null;
        }

        try {
            $record = $reader->lookup($ip);
        } catch (\Throwable $e) {
            $this->sendGeoEvent(
                EventTypes::EVENT_GEO_LOOKUP_FAILED,
                $ip,
                'lookup_failed',
                'Geographic lookup failed: ' . $e::class
            );

            return null;
        }
        if ($record === null) {
            return null;
        }
        $country = $record['country'] ?? null;
        if (!is_string($country) || $country === '') {
            return null;
        }

        return $country;
    }

    /**
     * The reference verdict: no country blocks only under an allowlist; a
     * non-empty allowlist shadows the blocklist entirely. Both block arms
     * emit country_blocked with their rule_type.
     *
     * @param list<string> $blockedCountries
     * @param list<string>|null $whitelistCountries
     * @return array{0: bool, 1: string|null} [allowed, country]
     */
    public function checkCountryAccess(string $ip, array $blockedCountries, ?array $whitelistCountries = null): array
    {
        $country = $this->getCountry($ip);

        if ($country === null) {
            if ($whitelistCountries !== null && $whitelistCountries !== []) {
                return [false, null];
            }

            return [true, null];
        }

        if ($whitelistCountries !== null && $whitelistCountries !== [] && !in_array($country, $whitelistCountries, true)) {
            $this->sendGeoEvent(
                EventTypes::EVENT_COUNTRY_BLOCKED,
                $ip,
                'request_blocked',
                "Country {$country} not in allowed list",
                country: $country,
                ruleType: 'country_whitelist'
            );

            return [false, $country];
        }

        if (in_array($country, $blockedCountries, true)) {
            $this->sendGeoEvent(
                EventTypes::EVENT_COUNTRY_BLOCKED,
                $ip,
                'request_blocked',
                "Country {$country} is blocked",
                country: $country,
                ruleType: 'country_blacklist'
            );

            return [false, $country];
        }

        return [true, $country];
    }

    /**
     * Freshness by the file's mtime against maxAge; a missing (or
     * unreadable) file is always outdated.
     */
    public function isDbOutdated(): bool
    {
        clearstatcache(true, $this->dbPath);
        $mtime = is_file($this->dbPath) ? filemtime($this->dbPath) : false;

        return $mtime === false || ($this->clock)() - $mtime > $this->maxAge;
    }

    private function downloadDatabase(): void
    {
        $client = $this->httpClient ?? throw new \LogicException('IpInfoManager requires an HTTP client for downloads');
        $retries = $this->downloadRetries;
        $backoff = 1;
        for ($attempt = 0; $attempt < $retries; $attempt++) {
            try {
                $response = $client->get(self::DOWNLOAD_URL, [
                    'timeout' => 10.0,
                    'headers' => ['Authorization' => 'Bearer ' . $this->token],
                ]);
                $response->isSuccess() || throw new CloudDownloadException('HTTP ' . $response->status);
                $this->writeDatabaseAtomically($response->body);

                if ($this->redisHandler !== null) {
                    try {
                        $this->redisHandler->setKey('ipinfo', 'database', $response->body, $this->maxAge);
                    } catch (\Throwable $e) {
                        error_log('[guard_core] Failed to cache GeoIP database in Redis: ' . $e->getMessage());
                    }
                }

                return;
            } catch (\Throwable $e) {
                if ($attempt === $retries - 1) {
                    throw $e;
                }
                ($this->sleep)($backoff);
                $backoff *= 2;
            }
        }
    }

    private function openDatabaseOrNone(): ?MmdbReader
    {
        try {
            return new MmdbReader($this->dbPath);
        } catch (MmdbError $e) {
            if (is_file($this->dbPath) && @unlink($this->dbPath)) {
                error_log('[guard_core] IPInfo database at ' . $this->dbPath . ' is corrupted, removing: ' . $e->getMessage());
            } else {
                error_log('[guard_core] IPInfo database at ' . $this->dbPath . ' is unavailable: ' . $e->getMessage());
            }

            return null;
        }
    }

    private function applyReader(?MmdbReader $reader): void
    {
        if ($reader !== null) {
            $this->reader = $reader;
            $this->lastRefreshed = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        }
    }

    private function writeDatabaseAtomically(string $content): void
    {
        $tmpPath = $this->dbPath . '.tmp';
        if (@file_put_contents($tmpPath, $content) === false) {
            @unlink($tmpPath);
            throw new \RuntimeException('failed to write the IPInfo database');
        }
        if (!@rename($tmpPath, $this->dbPath)) {
            @unlink($tmpPath);
            throw new \RuntimeException('failed to replace the IPInfo database');
        }
        clearstatcache(true, $this->dbPath);
    }

    private function sendGeoEvent(
        string $eventType,
        string $ipAddress,
        string $actionTaken,
        string $reason,
        ?string $country = null,
        ?string $ruleType = null
    ): void {
        if ($this->eventSink === null) {
            return;
        }
        $metadata = [];
        if ($country !== null) {
            $metadata['country'] = $country;
        }
        if ($ruleType !== null) {
            $metadata['rule_type'] = $ruleType;
        }
        $event = new SecurityEvent(
            timestamp: new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            eventType: $eventType,
            ipAddress: $ipAddress,
            actionTaken: $actionTaken,
            reason: $reason,
            ruleType: $ruleType,
            handlerName: 'ipinfo',
            metadata: $metadata
        );
        try {
            ($this->eventSink)($event);
        } catch (\Throwable $e) {
            error_log('[guard_core] Failed to send geo event to agent: ' . $e->getMessage());
        }
    }

    private static function describeDownloadError(\Throwable $e): string
    {
        $message = $e->getMessage();

        return str_starts_with($message, 'HTTP ')
            ? $e::class . ' (' . $message . ')'
            : $e::class;
    }
}

final class CloudDownloadException extends \RuntimeException
{
}

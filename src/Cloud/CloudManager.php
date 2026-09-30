<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Logging\SimpleRequestLogger;
use RenzoFranceschini\GuardCore\Logging\RequestLogger;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Redis\RedisLock;

final class CloudManager
{
    public const EMPTY_RANGES_WARNING_COOLDOWN = 300.0;

    /**
     * The Redis-lock namespace for cross-request single-flight (the
     * in-flight flag is per-request in FPM; workers that share the
     * RedisCloudIpStore coordinate through this lock so one cache-miss
     * thundering herd produces one network fetch per provider).
     */
    public const REFRESH_LOCK_NAMESPACE = 'cloud_refresh_lock';
    public const REFRESH_LOCK_TTL_MS = 15000;

    /** @var array<string, array<string, bool>> provider => canonical network => true */
    public array $ipRanges;

    /** @var array<string, array<string, string>> provider => network => region */
    public array $networkRegions;

    /** @var array<string, int|null> provider => last successful fetch (unix seconds) */
    public array $lastUpdated;

    public int $lastCloudIpRefresh = 0;

    private ?RedisHandler $redisHandler = null;

    private ?CloudIpStore $store;

    private bool $refreshInFlight = false;

    /** @var array<string, float> */
    private array $emptyRangesWarnedAt = [];

    private readonly \Closure $clock;

    public function __construct(
        private readonly ?HttpClient $httpClient = null,
        ?CloudIpStore $store = null,
        private readonly RequestLogger $logger = new SimpleRequestLogger(),
        ?\Closure $clock = null
    ) {
        $this->store = $store ?? new InMemoryCloudIpStore();
        $this->ipRanges = array_fill_keys(CloudProviderRegistry::PROVIDERS, []);
        $this->networkRegions = array_fill_keys(CloudProviderRegistry::PROVIDERS, []);
        $this->lastUpdated = array_fill_keys(CloudProviderRegistry::PROVIDERS, null);
        $this->clock = $clock ?? static fn (): float => microtime(true);
    }

    public function setStore(?CloudIpStore $store): void
    {
        $this->store = $store;
    }

    public function redisHandler(): ?RedisHandler
    {
        return $this->redisHandler;
    }

    public function initializeRedis(RedisHandler $redisHandler, array $providers = CloudProviderRegistry::PROVIDERS, int $ttl = 3600): void
    {
        $this->redisHandler = $redisHandler;
        if ($this->store === null || $this->store instanceof InMemoryCloudIpStore) {
            $this->store = new RedisCloudIpStore($redisHandler);
        }
        $this->refreshAsync($providers, $ttl);
    }

    /**
     * Single-flight: while a refresh is in flight further calls are no-ops
     * returning false.
     *
     * @param list<string> $providers
     * @param (\Closure(): void)|null $refresh
     */
    public function scheduleRefresh(array $providers = CloudProviderRegistry::PROVIDERS, int $ttl = 3600, ?\Closure $refresh = null): bool
    {
        if ($this->refreshInFlight) {
            return false;
        }
        $this->refreshInFlight = true;
        try {
            if ($refresh === null) {
                $this->refreshAsync($providers, $ttl);
            } else {
                $refresh();
            }
        } catch (\Throwable $e) {
            $this->logger->log('error', 'Background cloud IP refresh failed: ' . $e->getMessage());
        } finally {
            $this->refreshInFlight = false;
        }

        return true;
    }

    /** @param list<string> $providers */
    public function refresh(array $providers = CloudProviderRegistry::PROVIDERS): void
    {
        if ($this->store === null) {
            $this->refreshProviders($providers);

            return;
        }
        throw new \LogicException('Use refreshAsync() when a store is attached');
    }

    /** @param list<string> $providers */
    public function refreshAsync(array $providers = CloudProviderRegistry::PROVIDERS, int $ttl = 3600): void
    {
        if ($this->store === null) {
            $this->refreshProvidersViaRedisHandler($providers, $ttl);

            return;
        }

        $lock = $this->redisHandler !== null && $this->redisHandler->isEnabled() && $this->store instanceof RedisCloudIpStore
            ? new RedisLock($this->redisHandler)
            : null;
        foreach (CloudProviderRegistry::bareProviderNames($providers) as $provider) {
            $lockToken = null;
            try {
                $cached = $this->store->get($provider);
                if ($cached !== null) {
                    [$networks, $regions] = CloudProviderRegistry::decodeCached($cached);
                    $this->ipRanges[$provider] = $networks;
                    $this->networkRegions[$provider] = $regions;
                    continue;
                }

                // Cross-request single-flight: when another worker already
                // holds the provider's fetch lock, re-read the cache once
                // (the worker may have finished meanwhile) and skip the
                // network fetch otherwise - the ranges land in the shared
                // store for the next request. A Redis outage degrades to
                // the per-request guard (RedisLock is fail-open).
                if ($lock !== null) {
                    $lockToken = bin2hex(random_bytes(8));
                    if (!$lock->acquire(self::REFRESH_LOCK_NAMESPACE, $provider, $lockToken, self::REFRESH_LOCK_TTL_MS)) {
                        $lockToken = null;
                        $cached = $this->store->get($provider);
                        if ($cached !== null) {
                            [$networks, $regions] = CloudProviderRegistry::decodeCached($cached);
                            $this->ipRanges[$provider] = $networks;
                            $this->networkRegions[$provider] = $regions;
                        }

                        continue;
                    }
                }

                [$ranges, $regions] = CloudFetchers::fetchProviderRanges($provider, $this->requireClient());
                if ($ranges !== []) {
                    $this->store->set($provider, CloudProviderRegistry::encodeCached($ranges, $regions), $ttl);
                    $this->install($provider, $ranges, $regions);
                }
            } catch (\Throwable $e) {
                // The constructor pre-seeds every provider's range map, so a
                // failed refresh leaves the (empty) entry in place.
                $this->logger->log('error', 'Failed to refresh ' . $provider . ' IP ranges: ' . $e->getMessage());
            } finally {
                if ($lock !== null && $lockToken !== null) {
                    $lock->release(self::REFRESH_LOCK_NAMESPACE, $provider, $lockToken);
                }
            }
        }
    }

    /** @param list<string> $providers */
    private function refreshProviders(array $providers): void
    {
        foreach (CloudProviderRegistry::bareProviderNames($providers) as $provider) {
            try {
                [$ranges, $regions] = CloudFetchers::fetchProviderRanges($provider, $this->requireClient());
                if ($ranges !== []) {
                    $this->install($provider, $ranges, $regions);
                }
            } catch (\Throwable $e) {
                $this->logger->log('error', 'Failed to fetch ' . $provider . ' IP ranges: ' . $e->getMessage());
                $this->ipRanges[$provider] = [];
                $this->networkRegions[$provider] = [];
            }
        }
    }

    /** @param list<string> $providers */
    private function refreshProvidersViaRedisHandler(array $providers, int $ttl = 3600): void
    {
        $redis = $this->redisHandler;
        if ($redis === null) {
            $this->refreshProviders($providers);

            return;
        }

        foreach (CloudProviderRegistry::bareProviderNames($providers) as $provider) {
            try {
                $cached = $redis->getKey('cloud_ranges_v2', $provider);
                if ($cached !== null && $cached !== '') {
                    [$networks, $regions] = CloudProviderRegistry::decodeCached(explode(',', $cached));
                    $this->ipRanges[$provider] = $networks;
                    $this->networkRegions[$provider] = $regions;
                    continue;
                }

                [$ranges, $regions] = CloudFetchers::fetchProviderRanges($provider, $this->requireClient());
                if ($ranges !== []) {
                    $entries = CloudProviderRegistry::encodeCached($ranges, $regions);
                    sort($entries);
                    $redis->setKey('cloud_ranges_v2', $provider, implode(',', $entries), $ttl);
                    $this->install($provider, $ranges, $regions);
                }
            } catch (\Throwable $e) {
                $this->logger->log('error', 'Failed to refresh ' . $provider . ' IP ranges: ' . $e->getMessage());
                if (!array_key_exists($provider, $this->ipRanges)) {
                    $this->ipRanges[$provider] = [];
                    $this->networkRegions[$provider] = [];
                }
            }
        }
    }

    /** @param array<string, bool> $ranges @param array<string, string> $regions */
    private function install(string $provider, array $ranges, array $regions): void
    {
        $old = $this->ipRanges[$provider] ?? [];
        if ($old != $ranges) {
            $this->logger->log(
                'info',
                'Cloud IP range update for ' . $provider
                    . ': +' . count(array_diff_key($ranges, $old))
                    . ' added, -' . count(array_diff_key($old, $ranges)) . ' removed'
            );
        }
        $this->ipRanges[$provider] = $ranges;
        $this->networkRegions[$provider] = $regions;
        $this->lastUpdated[$provider] = time();
    }

    private function requireClient(): HttpClient
    {
        $client = $this->httpClient ?? throw new \LogicException('CloudManager requires an HTTP client for fetching');

        return $client;
    }

    private function warnEmptyRanges(string $provider): void
    {
        $now = ($this->clock)();
        $warnedAt = $this->emptyRangesWarnedAt[$provider] ?? null;
        if ($warnedAt !== null && $now - $warnedAt < self::EMPTY_RANGES_WARNING_COOLDOWN) {
            return;
        }
        $this->emptyRangesWarnedAt[$provider] = $now;
        $this->logger->log(
            'warning',
            'Cloud IP ranges for ' . $provider
                . ' are not populated yet; is_cloud_ip is returning not-blocked for every '
                . $provider . ' IP until the initial fetch completes.'
        );
    }

    /**
     * Spec 10 matching: unparseable IP -> not blocked; empty range set ->
     * fail-open with a 300 s warning cooldown; carve-out subtraction is
     * per-network via the network's registered region.
     *
     * @param list<string> $selectors
     */
    public function isCloudIp(string $ip, array $selectors = CloudProviderRegistry::PROVIDERS): bool
    {
        $ipCanonical = CanonicalIp::parse(CanonicalIp::stripBrackets($ip));
        if ($ipCanonical === null) {
            $this->logger->log('error', 'Invalid IP address: ' . $ip);

            return false;
        }
        [$blocked, $carveouts] = CloudProviderRegistry::parseCloudSelectors($selectors);
        foreach ($blocked as $provider) {
            if (!array_key_exists($provider, $this->ipRanges)) {
                continue;
            }
            $ranges = $this->ipRanges[$provider];
            if ($ranges === []) {
                $this->warnEmptyRanges($provider);
            }
            $allowedRegions = $carveouts[$provider] ?? null;
            $providerRegions = $this->networkRegions[$provider] ?? [];
            foreach (array_keys($ranges) as $network) {
                if (!CanonicalIp::networkContains($network, $ipCanonical)) {
                    continue;
                }
                if ($allowedRegions !== null && in_array($providerRegions[$network] ?? null, $allowedRegions, true)) {
                    continue;
                }

                return true;
            }
        }

        return false;
    }

    /** @return array<string, array<string, mixed>> */
    public function getStatus(): array
    {
        $status = [];
        foreach (CloudProviderRegistry::PROVIDERS as $provider) {
            $status[$provider] = [
                'ready' => ($this->ipRanges[$provider] ?? []) !== [],
                'last_refreshed' => $this->lastUpdated[$provider] ?? null,
                'entries' => count($this->ipRanges[$provider] ?? []),
            ];
        }

        return $status;
    }

    /**
     * @param list<string> $providers
     * @return array{0: string, 1: string}|null
     */
    public function getCloudProviderDetails(string $ip, array $providers = CloudProviderRegistry::PROVIDERS): ?array
    {
        $ipCanonical = CanonicalIp::parse(CanonicalIp::stripBrackets($ip));
        if ($ipCanonical === null) {
            $this->logger->log('error', 'Invalid IP address: ' . $ip);

            return null;
        }
        foreach (CloudProviderRegistry::bareProviderNames($providers) as $provider) {
            if (!array_key_exists($provider, $this->ipRanges)) {
                continue;
            }
            foreach (array_keys($this->ipRanges[$provider]) as $network) {
                if (CanonicalIp::networkContains($network, $ipCanonical)) {
                    return [$provider, $network];
                }
            }
        }

        return null;
    }
}

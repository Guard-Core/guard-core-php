<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cloud;

use RenzoFranceschini\GuardCore\Redis\RedisHandler;

class RedisCloudIpStore implements CloudIpStore
{
    public function __construct(
        private readonly RedisHandler $redis,
        private readonly string $keyPrefix = 'cloud_ip_v2'
    ) {
    }

    public function get(string $provider): ?array
    {
        $raw = $this->redis->getKey($this->keyPrefix, $provider);
        if ($raw === null) {
            return null;
        }
        $decoded = json_decode($raw, true);
        if (!is_array($decoded) || array_is_list($decoded) === false) {
            return null;
        }
        $ranges = [];
        foreach ($decoded as $item) {
            if (!is_string($item)) {
                return null;
            }
            $ranges[] = $item;
        }

        return $ranges;
    }

    public function set(string $provider, array $ranges, ?int $ttl = null): void
    {
        $values = array_values($ranges);
        sort($values);
        $quoted = [];
        foreach ($values as $entry) {
            $chunk = json_encode($entry, JSON_UNESCAPED_SLASHES);
            if ($chunk === false) {
                throw new \RuntimeException('cloud_ip_v2 payload encoding failed');
            }
            $quoted[] = $chunk;
        }
        $payload = '[' . implode(', ', $quoted) . ']';
        $this->redis->setKey($this->keyPrefix, $provider, $payload, $ttl);
    }

    public function clear(): void
    {
        $keys = $this->redis->keys($this->keyPrefix . ':*');
        $base = $this->redis->prefix() . $this->keyPrefix . ':';
        foreach ($keys as $key) {
            $provider = str_starts_with($key, $base) ? substr($key, strlen($base)) : '';
            if ($provider !== '') {
                $this->redis->delete($this->keyPrefix, $provider);
            }
        }
    }
}

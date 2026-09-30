<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Redis;

/**
 * A Redis-backed mutual-exclusion lock for cross-request single-flight
 * (specs/impl/php.md runtime model): classic FPM workers share nothing, so
 * the reference's in-process refresh guard degenerates to per-request;
 * workers that attach Redis coordinate through this lock instead
 * (SET NX PX + token-checked release).
 *
 * Fail-open by design: when Redis is disabled the lock behaves as
 * uncontended (shared-nothing workers cannot contend anyway), and when a
 * Redis operation throws the acquire reports success so a Redis outage
 * degrades to the per-request guard instead of blocking refreshes.
 */
final class RedisLock
{
    public function __construct(private readonly RedisHandler $redis)
    {
    }

    public function acquire(string $namespace, string $key, string $token, int $ttlMs): bool
    {
        if (!$this->redis->isEnabled()) {
            return true;
        }
        try {
            $reply = $this->redis->connection()->command(
                'SET',
                $this->redis->fullKey($namespace, $key),
                $token,
                'NX',
                'PX',
                (string) $ttlMs
            );
        } catch (\Throwable) {
            return true;
        }

        return $reply === 'OK';
    }

    public function release(string $namespace, string $key, string $token): void
    {
        if (!$this->redis->isEnabled()) {
            return;
        }
        try {
            $full = $this->redis->fullKey($namespace, $key);
            if ($this->redis->connection()->get($full) === $token) {
                $this->redis->connection()->del($full);
            }
        } catch (\Throwable) {
            // A lost release expires via the lock TTL.
        }
    }
}

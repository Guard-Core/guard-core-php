<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Redis;

class RedisHandler
{
    private RespConnection $connection;
    private bool $initialized = false;

    /**
     * Transient-error retries (redis_retries, default 1): the number of
     * re-attempts after a connect/write/read/timeout failure, each after
     * a capped backoff pause (the reference Retry(ExponentialBackoff(),
     * retries) pacing). 0 disables retries.
     */
    private int $retries;

    public function __construct(
        private bool $enableRedis = true,
        private string $prefix = 'guard_core:',
        private string $host = '127.0.0.1',
        private int $port = 6379,
        private float $connectTimeout = 2.0,
        private float $timeout = 2.0,
        ?RespConnection $connection = null,
        ?int $retries = null,
        ?int $healthCheckInterval = 30,
        ?int $maxConnections = null
    ) {
        $this->connection = $connection ?? new RespConnection(
            $host,
            $port,
            $connectTimeout,
            $timeout,
            $healthCheckInterval,
            $maxConnections
        );
        $this->retries = $retries ?? 1;
    }

    public static function fromEnv(): self
    {
        return new self(
            enableRedis: getenv('ENABLE_REDIS') !== '0',
            prefix: getenv('REDIS_PREFIX') ?: 'guard_core:',
            host: getenv('REDIS_HOST') ?: '127.0.0.1',
            port: (int) (getenv('REDIS_PORT') ?: 6379)
        );
    }

    /**
     * The redis_retries backoff pacing before attempt n (1-based, the
     * first retry being n=1): min(n * 200, 2000) milliseconds, the same
     * capped exponential-ish shape the sibling ports use for the
     * reference's ExponentialBackoff.
     */
    public static function retryDelayMs(int $attempt): int
    {
        return min($attempt * 200, 2000);
    }

    public function prefix(): string
    {
        return $this->prefix;
    }

    public function isEnabled(): bool
    {
        return $this->enableRedis;
    }

    public function initialize(): void
    {
        if (!$this->enableRedis) {
            return;
        }
        $this->safeOperation(function (): void {
            $this->connection->ping();
        });
        $this->initialized = true;
    }

    public function isInitialized(): bool
    {
        return $this->initialized;
    }

    public function fullKey(string $namespace, string $key): string
    {
        return $this->prefix . $namespace . ':' . $key;
    }

    public function connection(): RespConnection
    {
        return $this->connection;
    }

    public function getKey(string $namespace, string $key): ?string
    {
        if (!$this->enableRedis) {
            return null;
        }

        return $this->safeOperation(function (string $ns, string $k): ?string {
            return $this->connection->get($this->prefix . $ns . ':' . $k);
        }, $namespace, $key);
    }

    public function setKey(string $namespace, string $key, string $value, ?int $ttl = null): bool
    {
        if (!$this->enableRedis) {
            return false;
        }

        return $this->safeOperation(function (string $ns, string $k, string $v, ?int $t): bool {
            $full = $this->prefix . $ns . ':' . $k;
            if ($t) {
                return $this->connection->set($full, $v, ex: $t);
            }

            return $this->connection->set($full, $v);
        }, $namespace, $key, $value, $ttl);
    }

    public function exists(string $namespace, string $key): ?bool
    {
        if (!$this->enableRedis) {
            return null;
        }

        return $this->safeOperation(function (string $ns, string $k): bool {
            return $this->connection->exists($this->prefix . $ns . ':' . $k);
        }, $namespace, $key);
    }

    public function delete(string $namespace, string $key): int
    {
        if (!$this->enableRedis) {
            return 0;
        }

        return $this->safeOperation(function (string $ns, string $k): int {
            return $this->connection->del($this->prefix . $ns . ':' . $k);
        }, $namespace, $key);
    }

    /** @return list<string> */
    public function keys(string $pattern): array
    {
        if (!$this->enableRedis) {
            return [];
        }

        return $this->safeOperation(function (string $p): array {
            return $this->connection->keys($this->prefix . $p);
        }, $pattern);
    }

    public function deletePattern(string $pattern): int
    {
        if (!$this->enableRedis) {
            return 0;
        }

        return $this->safeOperation(function (string $p): int {
            $keys = $this->connection->keys($this->prefix . $p);
            if ($keys === []) {
                return 0;
            }

            return $this->connection->del(...$keys);
        }, $pattern);
    }

    public function incr(string $namespace, string $key, ?int $ttl = null): int
    {
        if (!$this->enableRedis) {
            return 0;
        }

        return $this->safeOperation(function (string $ns, string $k, ?int $t): int {
            $full = $this->prefix . $ns . ':' . $k;
            $pipe = $this->connection->pipeline();
            $pipe->incr($full);
            if ($t) {
                $pipe->expire($full, $t);
            }
            $result = $pipe->execute();

            return (int) ($result[0] ?? 0);
        }, $namespace, $key, $ttl);
    }

    public function recordSlidingWindowHit(
        string $namespace,
        string $key,
        float $timestamp,
        float $windowStart,
        int $ttl
    ): int {
        if (!$this->enableRedis) {
            return 0;
        }

        return $this->safeOperation(function (string $ns, string $k, float $ts, float $ws, int $t): int {
            $full = $this->prefix . $ns . ':' . $k;
            $member = bin2hex(random_bytes(16));
            $pipe = $this->connection->pipeline();
            $pipe->zAdd($full, $ts, $member);
            $pipe->zRemRangeByScore($full, '-inf', '(' . $ws);
            $pipe->zCard($full);
            $pipe->expire($full, $t);
            $result = $pipe->execute();

            return isset($result[2]) ? (int) $result[2] : 0;
        }, $namespace, $key, $timestamp, $windowStart, $ttl);
    }

    /**
     * safe_operation with the redis_retries backoff: a transient failure
     * (connect/write/read/timeout, never a server-side error reply) is
     * re-attempted up to $this->retries times after the capped pause; the
     * failed socket is dropped first so the retry reconnects fresh.
     *
     * @param callable $fn
     */
    private function safeOperation(callable $fn, mixed ...$args): mixed
    {
        $attempt = 0;
        while (true) {
            try {
                return $fn(...$args);
            } catch (GuardRedisException $e) {
                $attempt++;
                if (!$e->transient || $attempt > $this->retries) {
                    throw $e;
                }
                $this->connection->close();
                usleep(self::retryDelayMs($attempt) * 1000);
            } catch (\Throwable $e) {
                throw new GuardRedisException('Redis operation failed: ' . $e->getMessage(), 503, $e);
            }
        }
    }
}

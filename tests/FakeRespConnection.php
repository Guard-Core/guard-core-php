<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RespConnection;

final class FakeRespConnection extends RespConnection
{
    /** @var array<string, array{value: string, px: float|null}> */
    public array $store = [];
    public bool $failWrites = false;
    public array $log = [];
    /** @var list<mixed> */
    private array $replies = [];

    public function __construct()
    {
        parent::__construct();
    }

    public function seed(string $key, string $value, ?int $px = null): void
    {
        $this->store[$key] = ['value' => $value, 'px' => $px !== null ? microtime(true) * 1000 + $px : null];
    }

    public function writeCommands(array $commands): void
    {
        if ($this->failWrites) {
            throw new GuardRedisException('Redis write failed: simulated failure');
        }
        $i = 0;
        $n = count($commands);
        while ($i < $n) {
            $args = array_map('strval', $commands[$i]);
            if (strtoupper($args[0]) === 'MULTI') {
                $i++;
                $queued = [];
                while ($i < $n && strtoupper(implode(' ', $commands[$i])) !== 'EXEC') {
                    $queued[] = $commands[$i];
                    $i++;
                }
                $i++;
                $this->replies[] = 'OK';
                foreach ($queued as $_) {
                    $this->replies[] = 'QUEUED';
                }
                $results = [];
                foreach ($queued as $q) {
                    $results[] = $this->evalCommand(array_map('strval', $q));
                }
                $this->replies[] = $results;
                continue;
            }
            $this->replies[] = $this->evalCommand($args);
            $i++;
        }
    }

    public function readReplies(int $count): array
    {
        if (count($this->replies) < $count) {
            throw new GuardRedisException('fake redis: not enough replies');
        }
        $out = array_splice($this->replies, 0, $count);

        return $out;
    }

    private function expireIfNeeded(string $key): void
    {
        if (isset($this->store[$key]) && $this->store[$key]['px'] !== null && $this->store[$key]['px'] <= microtime(true) * 1000) {
            unset($this->store[$key]);
        }
    }

    /** @param list<string> $args */
    private function evalCommand(array $args): mixed
    {
        $cmd = strtoupper(array_shift($args));
        $this->log[] = $cmd;
        switch ($cmd) {
            case 'PING':
                return 'PONG';
            case 'GET':
                $key = $args[0];
                $this->expireIfNeeded($key);

                return $this->store[$key]['value'] ?? null;
            case 'SET':
                $key = $args[0];
                $value = $args[1];
                $nx = false;
                $px = null;
                for ($i = 2, $n = count($args); $i < $n; $i++) {
                    if (strtoupper($args[$i]) === 'NX') {
                        $nx = true;
                    } elseif (strtoupper($args[$i]) === 'EX') {
                        $px = microtime(true) * 1000 + ((int) $args[$i + 1]) * 1000;
                        $i++;
                    } elseif (strtoupper($args[$i]) === 'PX') {
                        $px = microtime(true) * 1000 + (int) $args[$i + 1];
                        $i++;
                    }
                }
                $this->expireIfNeeded($key);
                if ($nx && isset($this->store[$key])) {
                    return null;
                }
                $this->store[$key] = ['value' => $value, 'px' => $px];

                return 'OK';
            case 'DEL':
                $count = 0;
                foreach ($args as $key) {
                    $this->expireIfNeeded($key);
                    if (isset($this->store[$key])) {
                        unset($this->store[$key]);
                        $count++;
                    }
                }

                return $count;
            case 'EXISTS':
                $key = $args[0];
                $this->expireIfNeeded($key);

                return isset($this->store[$key]) ? 1 : 0;
            case 'PTTL':
                $key = $args[0];
                $this->expireIfNeeded($key);
                if (!isset($this->store[$key])) {
                    return -2;
                }

                return $this->store[$key]['px'] === null
                    ? -1
                    : max(1, (int) round($this->store[$key]['px'] - microtime(true) * 1000));
            case 'EXPIRETIME':
                $key = $args[0];
                $this->expireIfNeeded($key);
                if (!isset($this->store[$key])) {
                    return -2;
                }

                return $this->store[$key]['px'] === null
                    ? -1
                    : (int) ceil($this->store[$key]['px'] / 1000);
            case 'EXPIRE':
                $key = $args[0];
                $this->expireIfNeeded($key);
                if (!isset($this->store[$key])) {
                    return 0;
                }
                $this->store[$key]['px'] = microtime(true) * 1000 + ((int) $args[1]) * 1000;

                return 1;
            case 'INCR':
                $key = $args[0];
                $this->expireIfNeeded($key);
                $current = (int) ($this->store[$key]['value'] ?? '0');
                $this->store[$key] = ['value' => (string) ($current + 1), 'px' => $this->store[$key]['px'] ?? null];

                return $current + 1;
            case 'KEYS':
                return $this->matchKeys($args[0]);
            case 'SCAN':
                $match = '0';
                for ($j = 0; $j < count($args) - 1; $j++) {
                    if (strtoupper($args[$j]) === 'MATCH') {
                        $match = $args[$j + 1];
                    }
                }

                return ['0', $this->matchKeys($match)];
            case 'ZADD':
                $key = $args[0];
                $score = $args[1];
                $member = $args[2];
                $this->expireIfNeeded($key);
                $z = $this->zset($key);
                $z[$member] = (float) $score;
                $this->storeZset($key, $z);

                return 1;
            case 'ZCARD':
                return count($this->zset($args[0]));
            case 'ZREMRANGEBYSCORE':
                $key = $args[0];
                $z = $this->zset($key);
                $kept = [];
                $removed = 0;
                foreach ($z as $member => $score) {
                    if ($this->scoreInRange($score, $args[1], $args[2])) {
                        $removed++;
                    } else {
                        $kept[$member] = $score;
                    }
                }
                $this->storeZset($key, $kept);

                return $removed;
            case 'ZRANGEBYSCORE':
                $z = $this->zset($args[0]);
                $out = [];
                foreach ($z as $member => $score) {
                    if ($this->scoreInRange($score, $args[1], $args[2])) {
                        $out[] = $member;
                    }
                }

                return $out;
            case 'SCRIPT':
                return sha1($args[1]);
            case 'EVALSHA':
                return 1;
            default:
                throw new GuardRedisException("fake redis: unsupported command {$cmd}");
        }
    }

    private function matchKeys(string $pattern): array
    {
        $keys = [];
        foreach (array_keys($this->store) as $key) {
            $this->expireIfNeeded($key);
            if (isset($this->store[$key]) && $this->globMatch($pattern, $key)) {
                $keys[] = $key;
            }
        }
        sort($keys);

        return $keys;
    }

    private function globMatch(string $pattern, string $subject): bool
    {
        return (bool) preg_match('/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/', $subject);
    }

    /** @return array<string, float> */
    private function zset(string $key): array
    {
        $this->expireIfNeeded($key);
        if (!isset($this->store[$key])) {
            return [];
        }

        return json_decode($this->store[$key]['value'], true, 512, JSON_THROW_ON_ERROR);
    }

    /** @param array<string, float> $z */
    private function storeZset(string $key, array $z): void
    {
        $this->store[$key] = [
            'value' => json_encode($z, JSON_THROW_ON_ERROR),
            'px' => $this->store[$key]['px'] ?? null,
        ];
    }

    private function scoreInRange(float $score, string $min, string $max): bool
    {
        $minOk = $min === '-inf'
            ? true
            : (str_starts_with($min, '(') ? $score > (float) substr($min, 1) : $score >= (float) $min);
        $maxOk = $max === '+inf'
            ? true
            : (str_starts_with($max, '(') ? $score < (float) substr($max, 1) : $score <= (float) $max);

        return $minOk && $maxOk;
    }
}

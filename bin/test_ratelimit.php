<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitOutcome;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitRequest;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Redis\RespConnection;

require __DIR__ . '/../vendor/autoload.php';

final class RateLimitFakeConnection extends RespConnection
{
    /** @var array<string, array<string, float>> */
    public array $zsets = [];

    /** @var array<string, float> */
    public array $ttls = [];

    /** @var array<string, string> */
    public array $scripts = [];

    public float $now = 1000.0;

    public bool $fail = false;

    public int $evalShaCalls = 0;

    public int $multiCalls = 0;

    /** @var list<list<string>> */
    public array $log = [];

    /** @var list<mixed> */
    private array $replies = [];

    public function flushScripts(): void
    {
        $this->scripts = [];
    }

    public function writeCommands(array $commands): void
    {
        if ($this->fail) {
            throw new GuardRedisException('Redis write failed: simulated failure');
        }
        $i = 0;
        $n = count($commands);
        while ($i < $n) {
            $args = array_map('strval', $commands[$i]);
            $this->log[] = $args;
            if (strtoupper($args[0]) === 'MULTI') {
                $i++;
                $this->multiCalls++;
                $queued = [];
                while ($i < $n && strtoupper(implode(' ', $commands[$i])) !== 'EXEC') {
                    $queued[] = $commands[$i];
                    $i++;
                }
                $i++;
                $this->replies[] = 'OK';
                foreach ($queued as $q) {
                    $this->log[] = $q;
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

        return array_splice($this->replies, 0, $count);
    }

    private function expireIfNeeded(string $key): void
    {
        if (isset($this->ttls[$key]) && $this->ttls[$key] <= $this->now) {
            unset($this->zsets[$key], $this->ttls[$key]);
        }
    }

    /** @param list<string> $args */
    private function evalCommand(array $args): mixed
    {
        $cmd = strtoupper(array_shift($args));
        switch ($cmd) {
            case 'PING':
                return 'PONG';
            case 'SCRIPT':
                $sha = sha1($args[1]);
                $this->scripts[$sha] = $args[1];

                return $sha;
            case 'EVALSHA':
                $this->evalShaCalls++;
                $sha = $args[0];
                if (!isset($this->scripts[$sha])) {
                    throw new GuardRedisException('Redis error reply: NOSCRIPT no matching script. Please use EVAL.');
                }
                $key = $args[2];
                $now = (float) $args[3];
                $window = (int) $args[4];
                $this->expireIfNeeded($key);
                $z = $this->zsets[$key] ?? [];
                $z[(string) $now] = $now;
                $windowStart = $now - $window;
                foreach ($z as $member => $score) {
                    if ($score <= $windowStart) {
                        unset($z[$member]);
                    }
                }
                $count = count($z);
                $this->zsets[$key] = $z;
                $this->ttls[$key] = $this->now + $window * 2;

                return $count;
            case 'ZADD':
                $key = $args[0];
                $this->expireIfNeeded($key);
                $z = $this->zsets[$key] ?? [];
                $member = $args[2];
                $z[$member] = (float) $args[1];
                $this->zsets[$key] = $z;

                return 1;
            case 'ZCARD':
                $this->expireIfNeeded($args[0]);

                return count($this->zsets[$args[0]] ?? []);
            case 'ZREMRANGEBYSCORE':
                $key = $args[0];
                $this->expireIfNeeded($key);
                $z = $this->zsets[$key] ?? [];
                $min = (float) $args[1];
                $max = (float) $args[2];
                $removed = 0;
                foreach ($z as $member => $score) {
                    if ($score >= $min && $score <= $max) {
                        unset($z[$member]);
                        $removed++;
                    }
                }
                $this->zsets[$key] = $z;

                return $removed;
            case 'ZRANGEBYSCORE':
                $this->expireIfNeeded($args[0]);
                $z = $this->zsets[$args[0]] ?? [];
                $min = (float) $args[1];
                $max = (float) $args[2];
                $out = [];
                foreach ($z as $member => $score) {
                    if ($score >= $min && $score <= $max) {
                        $out[] = (string) $member;
                    }
                }
                sort($out);

                return $out;
            case 'EXPIRE':
                $key = $args[0];
                $this->expireIfNeeded($key);
                if (!isset($this->zsets[$key])) {
                    return 0;
                }
                $this->ttls[$key] = $this->now + (int) $args[1];

                return 1;
            case 'PTTL':
                $this->expireIfNeeded($args[0]);
                if (!isset($this->zsets[$args[0]])) {
                    return -2;
                }

                return (int) round(($this->ttls[$args[0]] - $this->now) * 1000);
            case 'DEL':
                $count = 0;
                foreach ($args as $key) {
                    if (isset($this->zsets[$key])) {
                        unset($this->zsets[$key], $this->ttls[$key]);
                        $count++;
                    }
                }

                return $count;
            case 'KEYS':
                $out = [];
                foreach (array_keys($this->zsets) as $key) {
                    if ($this->globMatch($args[0], $key)) {
                        $out[] = $key;
                    }
                }
                sort($out);

                return $out;
            default:
                throw new GuardRedisException("fake redis: unsupported command {$cmd}");
        }
    }

    private function globMatch(string $pattern, string $subject): bool
    {
        return (bool) preg_match('/^' . str_replace('\*', '.*', preg_quote($pattern, '/')) . '$/', $subject);
    }
}

final class T
{
    public int $passed = 0;
    public int $failed = 0;
    private string $section = '';

    public function section(string $name): void
    {
        $this->section = $name;
        echo "=== {$name} ===\n";
    }

    public function ok(bool $condition, string $label): void
    {
        if ($condition) {
            $this->passed++;
            echo "  PASS {$label}\n";
        } else {
            $this->failed++;
            echo "  FAIL {$this->section} :: {$label}\n";
        }
    }

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        $ok = $expected === $actual;
        if (!$ok) {
            echo '    expected: ' . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
        }
        $this->ok($ok, $label);
    }

    public function throws(callable $fn, string $class, ?string $contains, string $label): void
    {
        try {
            $fn();
            $this->ok(false, "{$label} (no exception)");
        } catch (\Throwable $e) {
            $ok = $e instanceof $class && ($contains === null || str_contains($e->getMessage(), $contains));
            if (!$ok) {
                echo '    got: ' . get_class($e) . ': ' . $e->getMessage() . "\n";
            }
            $this->ok($ok, $label);
        }
    }

    public function done(string $name): int
    {
        echo "\n{$name}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed;
    }
}

$t = new T();
$integration = in_array('--integration', $argv, true);

/**
 * @param (\Closure(string): string)|null $geo
 */
function makeHandler(
    RateLimitConfig $config,
    ?float $now,
    ?RateLimitFakeConnection &$fake = null,
    ?RedisHandler &$redis = null,
    ?\Closure $geo = null,
    ?IpBanManager &$bans = null,
    bool $advance = false
): RateLimitHandler {
    $fake = new RateLimitFakeConnection();
    if ($now !== null) {
        $fake->now = $now;
        $GLOBALS['CLOCK'] = $now;
    }
    $GLOBALS['FAKE'] = $fake;
    $GLOBALS['ADVANCE'] = $advance;
    $redis = new RedisHandler(true, 'guard_core:', connection: $fake);
    $GLOBALS['WARNLIST'] = new ArrayObject([]);
    $GLOBALS['RELOADCTR'] = new ArrayObject(['n' => 0]);
    if ($now === null) {
        $GLOBALS['CLOCK'] = microtime(true);
    }
    $clock = static fn (): float => $GLOBALS['ADVANCE'] || $now === null
        ? ($GLOBALS['CLOCK'] += 0.001)
        : $GLOBALS['CLOCK'];
    $handler = new RateLimitHandler(
        $config,
        $clock,
        static function (string $msg): void {
            $GLOBALS['WARNLIST'][] = $msg;
        },
        static function (): void {
            $GLOBALS['RELOADCTR']['n']++;
        },
        $geo
    );
    $handler->initializeRedis($redis);
    $bans = new IpBanManager();
    $handler->initializeIpBan($bans);

    return $handler;
}

function warnings(): array
{
    return $GLOBALS['WARNLIST']->getArrayCopy();
}

function reloadEvents(): int
{
    return $GLOBALS['RELOADCTR']['n'];
}

function setClock(float $t): void
{
    $GLOBALS['CLOCK'] = $t;
    $GLOBALS['FAKE']->now = $t;
}

function makeIntegrationHandler(RateLimitConfig $config, RedisHandler $redis, ?\Closure $geo = null): RateLimitHandler
{
    $GLOBALS['WARNLIST'] = new ArrayObject([]);
    $GLOBALS['RELOADCTR'] = new ArrayObject(['n' => 0]);
    $handler = new RateLimitHandler(
        $config,
        static fn (): float => ($GLOBALS['CLOCK'] += 0.001),
        static function (string $msg): void {
            $GLOBALS['WARNLIST'][] = $msg;
        },
        static function (): void {
            $GLOBALS['RELOADCTR']['n']++;
        },
        $geo
    );
    $handler->initializeRedis($redis);
    $handler->initializeIpBan(new IpBanManager());

    return $handler;
}

if (!$integration) {
    $nb = null;
    $bans = null;
    $t->section('config defaults');
    $cfg = new RateLimitConfig();
    $t->same(true, $cfg->enableRateLimiting, 'enable_rate_limiting default true');
    $t->same(10, $cfg->rateLimit, 'rate_limit default 10');
    $t->same(60, $cfg->rateLimitWindow, 'rate_limit_window default 60');
    $t->same([], $cfg->endpointRateLimits, 'endpoint_rate_limits default empty');
    $t->same(false, $cfg->enableRateLimitAutoBan, 'enable_rate_limit_auto_ban default false');
    $t->same(10, $cfg->autoBanThreshold, 'auto_ban_threshold default 10');
    $t->same(3600, $cfg->autoBanDuration, 'auto_ban_duration default 3600');
    $t->same(false, $cfg->redisFailOpen, 'redis_fail_open default false');

    $t->section('in-memory window math and counter asymmetry');
    $h = makeHandler(new RateLimitConfig(rateLimit: 2, rateLimitWindow: 60), 100.0, $f);
    $req = new RateLimitRequest();
    $t->same(null, $h->checkRateLimit($req, '1.2.3.4'), 'hit 1 allowed');
    $t->same(null, $h->checkRateLimit($req, '1.2.3.4'), 'hit 2 allowed');
    $blocked = $h->checkRateLimit($req, '1.2.3.4');
    $t->same(true, $blocked instanceof RateLimitOutcome, 'hit 3 blocked');
    $t->same(3, $blocked->count, 'in-memory blocked count reported +1 (pre-append compare)');
    $t->same('60', $blocked->retryAfter(), 'retry-after = effective window');
    $t->same(429, $blocked->errorResponse()['status'], 'status 429');
    $t->same('Too many requests', $blocked->errorResponse()['message'], 'message Too many requests');
    $t->same(['Retry-After' => '60'], $blocked->errorResponse()['headers'], 'retry-after header');
    $t->same(true, $blocked->inMemory, 'in-memory flag');
    $t->same('global', $blocked->tier, 'global tier name');

    $t->section('in-memory window eviction boundaries');
    $hA = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60), 1.0, $f);
    $hA->checkRateLimit(new RateLimitRequest(), '2.2.2.1');
    setClock(60.0);
    $res = $hA->checkRateLimit(new RateLimitRequest(), '2.2.2.1');
    $t->same(true, $res !== null && $res->count === 2, 't=1 hit still alive at t=60 (window_start=0, 1>0) -> blocks');
    $hB = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60), 1.0, $f);
    $hB->checkRateLimit(new RateLimitRequest(), '2.2.2.2');
    setClock(61.0);
    $t->same(null, $hB->checkRateLimit(new RateLimitRequest(), '2.2.2.2'), 't=1 hit evicted at t=61 (window_start=1, inclusive <=)');
    $t->same(1, $hB->pipelineBucketCount(), 'one bucket for global tier');

    $h = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60), 0.0, $f);
    $h->checkRateLimit(new RateLimitRequest(), '3.3.3.3');
    $t->same(true, $h->checkRateLimit(new RateLimitRequest(), '3.3.3.3') !== null, 'limit 1 second hit blocked');
    setClock(60.0);
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '3.3.3.3'), 'hit at t=0 evicted exactly at t=60 (inclusive)');

    $t->section('tier composition, shared buckets, short-circuit');
    $h = makeHandler(new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60, enableRedis: true), 1000.0, $f, $r, null, $nb, true);
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(urlPath: '/login'), '4.4.4.4'), 'global tier allowed');
    $hE = makeHandler(new RateLimitConfig(
        rateLimit: 100,
        rateLimitWindow: 60,
        enableRedis: true,
        endpointRateLimits: ['/login' => ['limit' => 1, 'window' => 60]]
    ), 1000.0, $f, $r, null, $nb, true);
    $t->same(null, $hE->checkRateLimit(new RateLimitRequest(urlPath: '/login'), '4.4.4.5'), 'endpoint tier hit 1 allowed');
    $res = $hE->checkRateLimit(new RateLimitRequest(urlPath: '/login'), '4.4.4.5');
    $t->same(true, $res !== null && $res->tier === 'endpoint', 'endpoint tier block');
    $t->same('60', $res->retryAfter(), 'endpoint block retry-after uses effective window');
    $t->same(null, $hE->checkRateLimit(new RateLimitRequest(urlPath: '/other'), '4.4.4.5'), 'non-endpoint path uses global tier');
    $t->same(2, count($f->zsets), 'hashed endpoint key + global key');
    $hashed = 'guard_core:rate_limit:rate:4.4.4.5:' . hash('sha256', '/login');
    $t->same(2, count($f->zsets[$hashed] ?? []), 'endpoint tier hit 1 + blocked hit 2 in hashed key');
    $t->same(2, count($f->zsets['guard_core:rate_limit:rate:4.4.4.5'] ?? []), 'global key: global hit from call1 + /other call');

    $h = makeHandler(new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60, enableRedis: true), 1000.0, $f, $r, static fn (string $ip): string => 'US', $nb, true);
    $req = new RateLimitRequest(
        urlPath: '/api',
        routeRateLimit: 50,
        routeRateLimitWindow: 30,
        geoRateLimits: ['US' => ['limit' => 40, 'window' => 120], '*' => ['limit' => 20, 'window' => 240]]
    );
    $t->same(null, $h->checkRateLimit($req, '5.5.5.5'), '4-tier request allowed');
    $hashedKey = 'guard_core:rate_limit:rate:5.5.5.5:' . hash('sha256', '/api');
    $t->same(2, count($f->zsets[$hashedKey] ?? []), 'route+geo share one hashed bucket (2 hits, no endpoint tier)');
    $t->same('guard_core:rate_limit:rate:5.5.5.5', array_values(array_diff(array_keys($f->zsets), [$hashedKey]))[0] ?? null, 'global key byte-exact');
    $t->same(1, count($f->zsets['guard_core:rate_limit:rate:5.5.5.5'] ?? []), 'global tier adds 1 hit');
    $ttlExp = $f->ttls[$hashedKey] ?? 0;
    $t->same(true, $ttlExp > 1000.0, 'TTL set on every hit');

    $h = makeHandler(new RateLimitConfig(
        rateLimit: 100,
        rateLimitWindow: 60,
        enableRedis: true,
        endpointRateLimits: ['/x' => ['limit' => 1, 'window' => 60]]
    ), 1000.0, $f, $r, null, $nb, true);
    $reqX = new RateLimitRequest(urlPath: '/x', routeRateLimit: 100, geoRateLimits: ['*' => ['limit' => 100, 'window' => 100]]);
    $h->checkRateLimit($reqX, '6.6.6.6');
    $res = $h->checkRateLimit($reqX, '6.6.6.6');
    $t->same(true, $res !== null && $res->tier === 'endpoint', 'first block short-circuits at endpoint tier');
    $t->same(3, count($f->zsets['guard_core:rate_limit:rate:6.6.6.6:' . hash('sha256', '/x')] ?? []), 'no hits after short-circuit (geo inert without resolver: 2 from request 1 + blocked hit)');

    $t->section('geo tier resolution');
    $hDe = makeHandler(new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60), 1000.0, $f, $r, static fn (string $ip): string => 'DE', $nb, true);
    $reqGeo = new RateLimitRequest(urlPath: '/g', geoRateLimits: ['US' => ['limit' => 1, 'window' => 60], '*' => ['limit' => 5, 'window' => 60]]);
    $hDe->checkRateLimit($reqGeo, '7.7.7.7');
    $t->same(null, $hDe->checkRateLimit($reqGeo, '7.7.7.7'), 'non-matching country falls back to * entry');
    $hUs = makeHandler(new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60), 1000.0, $f, $r, static fn (string $ip): string => 'US', $nb, true);
    $hUs->checkRateLimit($reqGeo, '8.8.8.8');
    $res = $hUs->checkRateLimit($reqGeo, '8.8.8.8');
    $t->same(true, $res !== null && $res->tier === 'geo', 'matching country enforced at geo tier');
    $hNone = makeHandler(new RateLimitConfig(rateLimit: 3, rateLimitWindow: 60), 1000.0, $f, $r, null, $nb, true);
    $reqNoGeo = new RateLimitRequest(urlPath: '/n', geoRateLimits: ['*' => ['limit' => 1, 'window' => 60]]);
    $t->same(null, $hNone->checkRateLimit($reqNoGeo, '7.7.7.9'), 'no resolver: hit 1 allowed despite * geo limit 1');
    $t->same(null, $hNone->checkRateLimit($reqNoGeo, '7.7.7.9'), 'no resolver: hit 2 allowed (geo tier inert)');
    $t->same(null, $hNone->checkRateLimit($reqNoGeo, '7.7.7.9'), 'no resolver: hit 3 allowed (default limit governs)');
    $res = $hNone->checkRateLimit($reqNoGeo, '7.7.7.9');
    $t->same(true, $res !== null && $res->tier === 'global', 'no resolver: crossing happens at the global tier (default limit 3) on hit 4');

    $t->section('gates');
    $h = makeHandler(new RateLimitConfig(enableRateLimiting: false, rateLimit: 1, rateLimitWindow: 60), 0.0, $f);
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '9.9.9.9'), 'enable_rate_limiting=false allows pipeline');
    $t->same(true, $h->checkRateLimitByIp('9.9.9.9'), 'enable_rate_limiting=false allows primitive');
    $t->throws(static fn (): bool => $h->checkRateLimitByIp('bogus'), InvalidArgumentException::class, 'invalid ip', 'validation precedes enable_rate_limiting early return');
    $t->same(0, count($f->zsets), 'no keys written when disabled');
    $h = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60), 0.0, $f);
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(whitelisted: true), '10.0.0.1'), 'whitelisted skips all tiers');
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(bypassRateLimit: true), '10.0.0.2'), 'rate_limit bypass skips all tiers');
    $t->same(0, count($f->zsets), 'no keys written for whitelisted/bypass');

    $t->section('primitive validation and contract');
    $h = makeHandler(new RateLimitConfig(rateLimit: 2, rateLimitWindow: 60), 0.0, $f);
    $t->throws(static fn (): bool => $h->checkRateLimitByIp('not-an-ip'), InvalidArgumentException::class, 'invalid ip', 'invalid ip throws');
    $t->throws(static fn (): bool => $h->checkRateLimitByIp('1.1.1.1', 'ws:x'), InvalidArgumentException::class, 'must not contain', 'endpoint_path with colon throws');
    $t->same(0, count($f->zsets), 'validation runs before side effects');
    $h = makeHandler(new RateLimitConfig(rateLimit: 2, rateLimitWindow: 60), 0.0, $f);
    $t->same(true, $h->checkRateLimitByIp('11.1.1.1'), 'primitive hit 1');
    $t->same(true, $h->checkRateLimitByIp('11.1.1.1'), 'primitive hit 2');
    $t->same(false, $h->checkRateLimitByIp('11.1.1.1'), 'primitive hit 3 blocked');
    $t->same(1, $h->primitiveBucketCount(), 'primitive has its own in-memory store');
    $h->checkRateLimit(new RateLimitRequest(), '11.1.1.1');
    $t->same(1, $h->pipelineBucketCount(), 'pipeline store never shares primitive counts');
    $h = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60), 0.0, $f);
    $t->same(true, $h->checkRateLimitByIp('12.1.1.1', 'ws'), 'endpoint_path isolates primitive budget');

    $t->section('MULTI fallback over fake wire');
    $h = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60, enableRedis: true), 500.0, $f, $r, null, $nb, true);
    $h->checkRateLimitByIp('13.1.1.1');
    $hasMulti = false;
    foreach ($f->log as $cmd) {
        if (strtoupper($cmd[0]) === 'MULTI') {
            $hasMulti = true;
        }
    }
    $t->same(true, $hasMulti, 'primitive always uses MULTI/EXEC pipeline fallback');
    $zaddMember = null;
    $zremMax = null;
    foreach ($f->log as $cmd) {
        if (strtoupper($cmd[0]) === 'ZADD') {
            $zaddMember = $cmd[3];
        }
        if (strtoupper($cmd[0]) === 'ZREMRANGEBYSCORE') {
            $zremMax = $cmd[3];
        }
    }
    $t->same('500.001', $zaddMember, 'zset member is the float timestamp string');
    $t->same('440.001', $zremMax, 'ZREMRANGEBYSCORE max = now - window (inclusive)');
    $t->same(1, $f->multiCalls, 'one MULTI per redis hit');
    $t->same(false, $h->checkRateLimitByIp('13.1.1.1'), 'count read from position 3 blocks at limit');

    $t->section('EVALSHA and NOSCRIPT reload');
    $h = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60, enableRedis: true), 0.0, $f, $r, null, $nb, true);
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '14.1.1.1'), 'initial EVALSHA works');
    $sha = $h->scriptSha();
    $t->same(true, is_string($sha) && strlen($sha) === 40, 'script loaded at init');
    $before = $f->evalShaCalls;
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '14.1.1.2'), 'manager path allowed');
    $t->same(true, $f->evalShaCalls > $before, 'manager path uses EVALSHA');
    $f->flushScripts();
    $t->same(true, $h->checkRateLimit(new RateLimitRequest(), '14.1.1.2') !== null, 'blocked after NOSCRIPT reload cycle');
    $t->same(1, reloadEvents(), 'rate_limit_script_reloaded event fired once');
    $t->same(true, is_string($h->scriptSha()) && $h->scriptSha() === $sha, 'sha re-cached deterministically');

    $t->section('redis fail modes');
    $h = makeHandler(new RateLimitConfig(rateLimit: 2, rateLimitWindow: 60, enableRedis: true, redisFailOpen: true), 0.0, $f, $r, null, $nb, true);
    $f->fail = true;
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '15.1.1.1'), 'fail-open falls back to in-memory');
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '15.1.1.1'), 'fail-open counts in-memory');
    $t->same(true, $h->checkRateLimit(new RateLimitRequest(), '15.1.1.1') !== null, 'fail-open blocks via in-memory');
    $t->same(1, count(warnings()), 'fail-open warns once');
    $t->same(true, str_contains(warnings()[0] ?? '', 'workers x rate_limit'), 'fail-open warning text');
    $f->fail = false;
    $h->checkRateLimit(new RateLimitRequest(), '15.1.1.9');
    $t->same(1, count(warnings()), 'warn exactly once per process');

    $h = makeHandler(new RateLimitConfig(rateLimit: 2, rateLimitWindow: 60, enableRedis: true, redisFailOpen: false), 0.0, $f);
    $f->fail = true;
    $t->throws(static fn () => $h->checkRateLimit(new RateLimitRequest(), '16.1.1.1'), GuardRedisException::class, 'Redis rate limiting unavailable', 'fail-secure raises 503');
    $t->throws(static fn (): bool => $h->checkRateLimitByIp('16.1.1.2'), GuardRedisException::class, 'Redis rate limiting unavailable', 'primitive propagates fail-secure');

    $t->section('LRU cap 10000');
    $h = makeHandler(new RateLimitConfig(rateLimit: 1000000, rateLimitWindow: 60), 0.0, $f);
    for ($i = 0; $i < 10005; $i++) {
        $h->checkRateLimitByIp(sprintf('10.%d.%d.7', intdiv($i, 250), $i % 250));
    }
    $t->same(RateLimitHandler::MAX_TRACKED_RATE_LIMIT_KEYS, $h->primitiveBucketCount(), 'primitive store capped at 10000');

    $t->section('autoban feed (primitive)');
    $h = makeHandler(new RateLimitConfig(
        rateLimit: 1,
        rateLimitWindow: 60,
        enableRateLimitAutoBan: true,
        enableIpBanning: true
    ), 0.0, $f, $r, null, $bans);
    for ($i = 0; $i < 10; $i++) {
        $h->checkRateLimitByIp('21.1.1.1');
    }
    $t->same(false, $bans->isIpBanned('21.1.1.1'), '9 violations below flat threshold 10');
    $h->checkRateLimitByIp('21.1.1.1');
    $t->same(true, $bans->isIpBanned('21.1.1.1'), '10th violation triggers flat autoban');
    $t->same(10, $h->primitiveAutobanCount('21.1.1.1'), 'counter incremented per violation');
    $ref = new ReflectionProperty(IpBanManager::class, 'bannedIps');
    $ref->setAccessible(true);
    $expiry = $ref->getValue($bans)['21.1.1.1'] ?? null;
    $t->same(true, $expiry !== null && ($expiry - microtime(true)) >= 3599.0 && ($expiry - microtime(true)) <= 3601.0, 'flat autoban duration 3600');
    $before = $h->primitiveAutobanCount('21.1.1.1');
    $h->checkRateLimitByIp('21.1.1.1');
    $h->checkRateLimitByIp('21.1.1.1');
    $t->same($before, $h->primitiveAutobanCount('21.1.1.1'), 'already-banned short-circuit: no counter growth');

    $h = makeHandler(new RateLimitConfig(
        rateLimit: 1,
        rateLimitWindow: 60,
        enableRateLimitAutoBan: true,
        enableIpBanning: true,
        threatBanConfig: ['rate_limit' => ['threshold' => 3, 'duration' => 120]]
    ), 0.0, $f, $r, null, $bans);
    $h->checkRateLimitByIp('22.1.1.1');
    for ($i = 0; $i < 2; $i++) {
        $h->checkRateLimitByIp('22.1.1.1');
    }
    $t->same(false, $bans->isIpBanned('22.1.1.1'), 'threat threshold 3 not reached at 2');
    $h->checkRateLimitByIp('22.1.1.1');
    $t->same(true, $bans->isIpBanned('22.1.1.1'), 'threat_ban_config rate_limit fires at 3');
    $expiry = $ref->getValue($bans)['22.1.1.1'] ?? null;
    $t->same(true, $expiry !== null && ($expiry - microtime(true)) >= 119.0 && ($expiry - microtime(true)) <= 121.0, 'threat ban duration 120');

    $h = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60, enableRateLimitAutoBan: true, enableIpBanning: true, passiveMode: true), 0.0, $f);
    $h->checkRateLimitByIp('23.1.1.1');
    $h->checkRateLimitByIp('23.1.1.1');
    $t->same(0, $h->primitiveAutobanCount('23.1.1.1'), 'passive mode suppresses autoban counting');

    $h = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60, enableRateLimitAutoBan: true), 0.0, $f);
    $h->checkRateLimitByIp('24.1.1.1');
    $h->checkRateLimitByIp('24.1.1.1');
    $t->same(0, $h->primitiveAutobanCount('24.1.1.1'), 'no counting without enable_ip_banning');

    $t->section('autoban feed (pipeline) and store separation');
    $h = makeHandler(new RateLimitConfig(
        rateLimit: 1,
        rateLimitWindow: 60,
        enableRateLimitAutoBan: true,
        enableIpBanning: true
    ), 0.0, $f, $r, null, $bans);
    $req = new RateLimitRequest();
    $h->checkRateLimit($req, '25.1.1.1');
    for ($i = 0; $i < 9; $i++) {
        $h->checkRateLimit($req, '25.1.1.1');
    }
    $t->same(false, $bans->isIpBanned('25.1.1.1'), 'pipeline 9 violations below threshold');
    $h->checkRateLimit($req, '25.1.1.1');
    $t->same(true, $bans->isIpBanned('25.1.1.1'), 'pipeline 10th violation bans');
    $t->same(10, $h->pipelineSuspiciousCount('25.1.1.1'), 'pipeline suspicious count store');
    $t->same(0, $h->primitiveAutobanCount('25.1.1.1'), 'pipeline and primitive autoban counts independent');

    echo "\n";
}

$t->section('handler lifecycle: script load failure and reset');

$brokenFake = new RateLimitFakeConnection();
$brokenFake->fail = true;
$brokenRedis = new RedisHandler(true, 'guard_core:', connection: $brokenFake);
$brokenHandler = new RateLimitHandler(new RateLimitConfig(rateLimit: 5, rateLimitWindow: 60, enableRedis: true), null, static function (string $m): void {
});
$brokenHandler->initializeRedis($brokenRedis);
$t->same(true, $brokenHandler->scriptSha() === null || is_string($brokenHandler->scriptSha()), 'a script load failure leaves the handler usable');
$brokenHandler->reset();
$t->same(true, $brokenHandler->scriptSha() === null, 'reset clears the script sha');

$lifecycleHandler = makeHandler(new RateLimitConfig(rateLimit: 5, rateLimitWindow: 60, enableRedis: true), 0.0, $f, $r, null, $nb, true);
$lifecycleHandler->checkRateLimit(new RateLimitRequest(), '21.1.1.1');
$lifecycleHandler->reset();
$t->same(null, $lifecycleHandler->scriptSha(), 'reset clears the cached sha with redis attached');
$noRedisHandler = makeHandler(new RateLimitConfig(rateLimit: 5, rateLimitWindow: 60), 0.0, $f);
$noRedisHandler->reset();
$t->same(true, true, 'reset without redis is a no-op');

$t->section('autoban counter lru eviction');
$lruBans = new IpBanManager([], null);
$lruHandler = makeHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60, enableRateLimitAutoBan: true, enableIpBanning: true, autoBanThreshold: 1000000), 0.0, $f, $r, null, $lruBans, true);
for ($i = 0; $i < 10002; $i++) {
    $ip = sprintf('10.9.%d.%d', intdiv($i, 250), $i % 250);
    $lruHandler->checkRateLimitByIp($ip);
    $lruHandler->checkRateLimitByIp($ip);
}
$t->same(RateLimitHandler::MAX_TRACKED_RATE_LIMIT_KEYS, $lruHandler->primitiveBucketCount(), 'the autoban feed runs through the same cap');


if ($integration) {
    $host = getenv('REDIS_HOST') ?: '127.0.0.1';
    $redis = RedisHandler::fromEnv();
    $conn = $redis->connection();
    try {
        $GLOBALS['CLOCK'] = microtime(true);
    $conn->command('FLUSHDB');
    } catch (Throwable $e) {
        echo "SKIP: cannot reach redis at {$host}: {$e->getMessage()}\n";
        exit(2);
    }

    $t->section('integration: Lua script over the wire');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(new RateLimitConfig(rateLimit: 2, rateLimitWindow: 60, enableRedis: true), $redis);
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '30.1.1.1'), 'lua hit 1 allowed');
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '30.1.1.1'), 'lua hit 2 allowed');
    $res = $h->checkRateLimit(new RateLimitRequest(), '30.1.1.1');
    $t->same(true, $res !== null && $res->count === 3, 'lua 3rd hit blocked, count includes current');
    $t->same('60', $res->retryAfter(), 'retry-after 60');
    $key = 'guard_core:rate_limit:rate:30.1.1.1';
    $t->same(3, (int) $conn->command('ZCARD', $key), 'zset has 3 members');
    $pttl = (int) $conn->command('PTTL', $key);
    $t->same(true, $pttl > 59000 && $pttl <= 120000, 'TTL 2x window refreshed on hit');
    $t->same(true, $res->inMemory === false, 'block served by redis');

    $t->section('integration: inclusive eviction boundary');
    $conn->command('DEL', 'guard_core:rate_limit:rate:31.1.1.1');
    $nowF = microtime(true);
    $conn->command('ZADD', 'guard_core:rate_limit:rate:31.1.1.1', (string) ($nowF - 60), (string) ($nowF - 60));
    $t->same(true, $h->checkRateLimitByIp('31.1.1.1'), 'member at exactly now-60 evicted inclusively (limit 2)');

    $t->section('integration: primitive MULTI fallback + multi-key');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(new RateLimitConfig(rateLimit: 2, rateLimitWindow: 60, enableRedis: true), $redis);
    $t->same(true, $h->checkRateLimitByIp('32.1.1.1'), 'primitive redis hit 1');
    $t->same(true, $h->checkRateLimitByIp('32.1.1.1'), 'primitive redis hit 2');
    $t->same(false, $h->checkRateLimitByIp('32.1.1.1'), 'primitive redis hit 3 blocked');
    $t->same(true, $h->checkRateLimitByIp('32.1.1.1', 'ws'), 'endpoint_path isolates budget');
    $t->same(true, $h->checkRateLimitByIp('32.1.1.2'), 'different ip isolated');
    $t->same(3, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:32.1.1.1'), 'global bucket has 3 hits');
    $t->same(1, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:32.1.1.1:' . hash('sha256', 'ws')), 'hashed bucket separate');
    $t->same(1, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:32.1.1.2'), 'other ip bucket');

    $t->section('integration: shared buckets, up to 4 hits');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60, enableRedis: true), $redis, static fn (string $ip): string => 'US');
    $req = new RateLimitRequest(
        urlPath: '/api',
        routeRateLimit: 100,
        routeRateLimitWindow: 30,
        geoRateLimits: ['*' => ['limit' => 100, 'window' => 120]]
    );
    $t->same(null, $h->checkRateLimit($req, '33.1.1.1'), '4-tier redis request allowed');
    $t->same(2, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:33.1.1.1:' . hash('sha256', '/api')), 'route+geo share one bucket (no endpoint tier)');
    $t->same(1, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:33.1.1.1'), 'global bucket 1 hit');

    $t->section('integration: geo tier inert without a resolver');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(new RateLimitConfig(rateLimit: 100, rateLimitWindow: 60, enableRedis: true), $redis);
    $t->same(null, $h->checkRateLimit($req, '33.1.1.2'), 'geo map without resolver: request allowed');
    $t->same(1, (int) $conn->command('ZCARD', 'guard_core:rate_limit:rate:33.1.1.2:' . hash('sha256', '/api')), 'only the route tier hits the hashed bucket (geo skipped, no resolver)');

    $t->section('integration: NOSCRIPT recovery');
    $conn->command('FLUSHDB');
    $h = makeIntegrationHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60, enableRedis: true), $redis);
    $t->same(null, $h->checkRateLimit(new RateLimitRequest(), '34.1.1.1'), 'initial EVALSHA works');
    $t->same(true, is_string($h->scriptSha()) && strlen((string) $h->scriptSha()) === 40, 'sha cached');
    $conn->command('SCRIPT', 'FLUSH');
    $t->same(true, $h->checkRateLimit(new RateLimitRequest(), '34.1.1.1') !== null, 'NOSCRIPT recovered, still blocking at limit');
    $t->same(1, reloadEvents(), 'reload event fired over the wire');
    $t->same(true, is_string($h->scriptSha()) && strlen((string) $h->scriptSha()) === 40, 'new sha cached');

    $t->section('integration: reset deletes shared keys');
    $h = makeIntegrationHandler(new RateLimitConfig(rateLimit: 1, rateLimitWindow: 60, enableRedis: true), $redis);
    $h->checkRateLimitByIp('35.1.1.1');
    $t->same(1, (int) $conn->command('EXISTS', 'guard_core:rate_limit:rate:35.1.1.1'), 'key exists before reset');
    $h->reset();
    $t->same(0, (int) $conn->command('EXISTS', 'guard_core:rate_limit:rate:35.1.1.1'), 'reset deleted shared keys');

    echo "\n";
}

exit($t->done($integration ? 'RATELIMIT INTEGRATION' : 'RATELIMIT UNIT'));

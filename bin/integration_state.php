<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Redis\RespConnection;
use RenzoFranceschini\GuardCore\Redis\RespPipeline;

return function (TestRunner $t): int {
    $host = getenv('REDIS_HOST') ?: '127.0.0.1';
    $port = (int) (getenv('REDIS_PORT') ?: 6379);
    $prefix = 'guard_core_test:' . bin2hex(random_bytes(3)) . ':';
    $conn = new RespConnection($host, $port, 2.0, 2.0);

    $t->section("Integration against real Redis ({$host}:{$port})");

    $t->ok($conn->command('PING') === 'PONG', 'PING');
    $conn->set('k:test', 'hello-world');
    $t->same('hello-world', $conn->get('k:test'), 'SET/GET string round-trip');
    $conn->set('k:ex', 'v', ex: 120);
    $pttl = $conn->pttl('k:ex');
    $t->ok($pttl > 0 && $pttl <= 120000, "SET EX -> PTTL in ms range ({$pttl})");
    $conn->set('k:px', 'v', px: 250);
    $t->ok($conn->pttl('k:px') > 0 && $conn->pttl('k:px') <= 250, 'SET PX');
    $t->same(-1, $conn->pttl('k:test'), 'persist key PTTL -1');
    $t->same(null, $conn->get('k:missing'), 'GET miss is null');
    $t->ok($conn->exists('k:test'), 'EXISTS hit');
    $t->ok(!$conn->exists('k:nope'), 'EXISTS miss');
    $t->ok($conn->expire('k:test', 999), 'EXPIRE');
    $t->ok($conn->pttl('k:test') > 900000, 'EXPIRE applied');
    $t->ok($conn->expireTime('k:test') > time() + 900, 'EXPIRETIME');
    $t->same(1, $conn->incr('k:counter'), 'INCR');
    $t->same('1', $conn->get('k:counter'), 'counter is a string value');
    $conn->del('k:test', 'k:ex', 'k:px', 'k:counter', 'k:m', 'k:mc');
    $t->ok($conn->keys('k:*') === [], 'DEL + KEYS');

    $conn->zAdd('k:zset', 1.5, 'a');
    $conn->zAdd('k:zset', 9.5, 'b');
    $t->same(2, $conn->zCard('k:zset'), 'ZADD/ZCARD');
    $t->same(1, $conn->zRemRangeByScore('k:zset', '-inf', '(5'), 'ZREMRANGEBYSCORE exclusive bound');
    $t->same(['b'], $conn->zRangeByScore('k:zset', '-inf', '+inf'), 'ZRANGEBYSCORE after removal');
    $conn->del('k:zset');

    $sha = $conn->scriptLoad('return redis.call("EXISTS", KEYS[1])');
    $t->ok(strlen($sha) === 40, 'SCRIPT LOAD returns sha1');
    $t->same(0, $conn->evalSha($sha, 1, 'k:evaluated'), 'EVALSHA');

    $conn->del('k:m', 'k:mc');
    $pipe = (new RespPipeline($conn))->multi();
    $pipe->set('k:m', 'mv')->incr('k:mc')->get('k:m');
    $t->same(['OK', 1, 'mv'], $pipe->execute(), 'MULTI/EXEC over real socket');
    $conn->del('k:m', 'k:mc');

    $scanConn = new RespConnection($host, $port, 2.0, 2.0);
    $scanConn->set('k:s1', '1');
    $scanConn->set('k:s2', '1');
    $cursor = '0';
    $keys = [];
    do {
        [$cursor, $batch] = $scanConn->scan($cursor, 'k:s*');
        foreach ($batch as $scanned) {
            $keys[] = $scanned;
        }
    } while ($cursor !== '0');
    $t->same('0', $cursor, 'SCAN terminates with cursor 0');
    $t->ok(in_array('k:s1', $keys, true) && in_array('k:s2', $keys, true), 'SCAN MATCH returns keys');
    $scanConn->del('k:s1', 'k:s2');

    $t->section('Integration: namespaced helpers byte-exact keys');
    $handler = new RedisHandler(true, $prefix, $host, $port);
    $handler->initialize();
    $handler->setKey('banned_ips', '203.0.113.50', '1735689600.123456', 300);
    $raw = $conn->get($prefix . 'banned_ips:203.0.113.50');
    $t->same('1735689600.123456', $raw, '{prefix}banned_ips:{ip} value byte-exact');
    $t->ok($conn->pttl($prefix . 'banned_ips:203.0.113.50') > 0, 'ban TTL in seconds -> ms PTTL');
    $t->same('1735689600.123456', $handler->getKey('banned_ips', '203.0.113.50'), 'namespaced get');

    $t->section('Integration: ban lifecycle end-to-end');
    $mgr = new IpBanManager([], null, null);
    $t->ok($mgr->initializeRedis($handler), 'migration clean on empty namespace');
    $t->ok($mgr->ban('198.51.100.77', 120, 'integration'), 'ban writes through');
    $stored = $conn->get($prefix . 'banned_ips:198.51.100.77');
    $t->ok(preg_match('/^\d+\.\d+$/', strval($stored)) === 1, 'stored expiry is a decimal float string');
    $t->ok((float) strval($stored) > microtime(true) + 100, 'stored expiry is now+duration');
    $t->ok($mgr->isIpBanned('198.51.100.77'), 'is_ip_banned via redis');
    $fresh = new IpBanManager([], null, null);
    $fresh->initializeRedis($handler);
    $t->ok($fresh->isIpBanned('198.51.100.77'), 'fresh manager sees redis ban (cross-worker)');
    $t->ok(!$fresh->ban('127.0.0.1', 60), 'self-DoS refusal against real redis');
    $fresh->unban('198.51.100.77');
    $t->ok($conn->get($prefix . 'banned_ips:198.51.100.77') === null, 'unban deleted redis key');

    $t->section('Integration: legacy migration end-to-end');
    $conn->set($prefix . 'banned_ips:[2001:db8:99::1]', '888', ex: 60);
    $mgrMig = new IpBanManager([], null, null);
    $t->ok($mgrMig->initializeRedis($handler), 'migration succeeds');
    $t->ok($conn->get($prefix . 'banned_ips:2001:db8:99::1') === '888', 'canonical key created with legacy value');
    $t->ok($conn->get($prefix . 'banned_ips:[2001:db8:99::1]') === null, 'legacy key deleted');
    $t->ok($conn->pttl($prefix . 'banned_ips:2001:db8:99::1') > 50000, 'legacy ms TTL preserved (PTTL discipline)');

    $keys = $conn->keys($prefix . '*');
    if ($keys !== []) {
        $conn->del(...$keys);
    }
    $conn->close();

    return $t->summary();
};

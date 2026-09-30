<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\BanEventSink;
use RenzoFranceschini\GuardCore\Cloud\RedisCloudIpStore;
use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RespConnection;
use RenzoFranceschini\GuardCore\Redis\RespPipeline;


require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/FakeRespConnection.php';

final class AbortingExecConnection extends RespConnection
{
    public function writeCommands(array $commands): void
    {
        $this->replies = ['OK'];
        foreach ($commands as $index => $_) {
            if ($index === 0) {
                continue;
            }
            $this->replies[] = $index === 1 ? 'ERR nope' : 'QUEUED';
        }
        $this->replies[] = 'NOT-AN-ARRAY';
    }

    public function readReplies(int $count): array
    {
        $out = array_slice($this->replies, 0, $count);
        $this->replies = array_slice($this->replies, $count);

        return $out;
    }
}

final class TestRunner
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
        $this->ok($expected === $actual, "{$label} (" . var_export($actual, true) . ")");
    }

    public function throws(callable $fn, string $class, string $label): void
    {
        try {
            $fn();
            $this->ok(false, "{$label} (no exception thrown)");
        } catch (\Throwable $e) {
            $this->ok($e instanceof $class, "{$label} (threw " . get_class($e) . ': ' . $e->getMessage() . ')');
        }
    }

    public function summary(): int
    {
        echo "\nPassed: {$this->passed}, Failed: {$this->failed}\n";
        echo ($this->failed === 0 ? 'GREEN' : 'RED') . "\n";

        return $this->failed === 0 ? 0 : 1;
    }
}

final class RecordingEventSink implements BanEventSink
{
    public array $bans = [];
    public array $unbans = [];

    public function sendBanEvent(string $ip, int $duration, string $reason): void
    {
        $this->bans[] = ['ip' => $ip, 'duration' => $duration, 'reason' => $reason];
    }

    public function sendUnbanEvent(string $ip): void
    {
        $this->unbans[] = $ip;
    }
}

$t = new TestRunner();

$t->section('CanonicalIp');
$t->same('1.2.3.4', CanonicalIp::stripBrackets('[1.2.3.4]'), 'stripBrackets');
$t->same('1.2.3.4', CanonicalIp::canonicalize('[1.2.3.4]'), 'bracketed IPv4 canonicalized');
$t->same('2001:db8::1', CanonicalIp::canonicalize('[2001:0DB8:0000:0000:0000:0000:0000:0001]'), 'bracketed full IPv6 compressed + lowercased');
$t->same('192.168.1.1', CanonicalIp::canonicalize('::ffff:192.168.1.1'), 'IPv4-mapped collapsed');
$t->same('10.0.0.1', CanonicalIp::canonicalize('[::ffff:10.0.0.1]'), 'bracketed IPv4-mapped collapsed');
$t->same('::ffff:102:304%eth0', CanonicalIp::canonicalize('::ffff:1.2.3.4%eth0'), 'scoped IPv4-mapped stays IPv6-rendered with scope');
$t->same('fe80::1%eth0', CanonicalIp::canonicalize('fe80::1%eth0'), 'scope id preserved');
$t->same('::', CanonicalIp::canonicalize('0:0:0:0:0:0:0:0'), 'all-zero compressed');
$t->same('2001:0:0:1::1', CanonicalIp::canonicalize('2001:0:0:1:0:0:0:1'), 'longest zero run wins, leftmost on tie');
$t->same('::1', CanonicalIp::canonicalize('0:0:0:0:0:0:0:1'), 'loopback compressed');
$t->same('1.2.3.4', CanonicalIp::canonicalize('1.2.3.4'), 'IPv4 passthrough');
$t->same('not-an-ip', CanonicalIp::canonicalize('not-an-ip'), 'parse failure passthrough');
$t->same('[not-an-ip]', CanonicalIp::canonicalize('[not-an-ip]'), 'parse failure passthrough keeps brackets');
$t->same('unknown', CanonicalIp::canonicalize('unknown'), 'identity string passthrough');
$t->throws(fn () => CanonicalIp::canonicalNetwork('10.0.0.0'), \InvalidArgumentException::class, 'canonicalNetwork requires prefix');
$t->same('10.0.0.0/24', CanonicalIp::canonicalNetwork('10.0.0.9/24'), 'host bits cleared v4');
$t->same('2001:db8:dead::/48', CanonicalIp::canonicalNetwork('2001:db8:dead:beef::1/48'), 'host bits cleared v6');
$t->ok(CanonicalIp::networkContains('10.0.0.0/24', '10.0.0.199'), 'networkContains hit');
$t->ok(!CanonicalIp::networkContains('10.0.0.0/24', '10.0.1.1'), 'networkContains miss');
$t->ok(CanonicalIp::networkContains('2001:db8::/32', '2001:db8:aaaa::1'), 'networkContains v6 hit');

$t->section('Ban expiry float-string format');
$t->same('1735689600.123456', IpBanManager::formatExpiry(1735689600.123456), 'six-digit microsecond fraction');
$t->same('1735689600.0', IpBanManager::formatExpiry(1735689600.0), 'integral value keeps .0 like Python repr');
$t->ok(preg_match('/^\d+\.\d+$/', IpBanManager::formatExpiry(microtime(true) + 600)) === 1, 'realistic expiry is a decimal float string');
$t->same(1735689600.123456, (float) IpBanManager::formatExpiry(1735689600.123456), 'round-trips as float');

$t->section('Redis key grammar (spec 08) via namespaced helpers');
$fake = new FakeRespConnection();
$h = new RedisHandler(true, 'guard_core:', connection: $fake);
$t->ok($h->setKey('banned_ips', '1.2.3.4', '1735689600.5', 600), 'setKey with ttl');
$t->same('1735689600.5', $fake->store['guard_core:banned_ips:1.2.3.4']['value'], 'full key is {prefix}banned_ips:{ip} byte-exact');
$t->ok($fake->store['guard_core:banned_ips:1.2.3.4']['px'] !== null, 'ttl stored');
$t->same('1735689600.5', $h->getKey('banned_ips', '1.2.3.4'), 'getKey round-trip');
$t->same(null, $h->getKey('banned_ips', 'nope'), 'miss returns null, never throws');
$t->same('gp:banned_networks:10.0.0.0/24', (new RedisHandler(true, 'gp:', connection: $fake))->fullKey('banned_networks', '10.0.0.0/24'), 'network key grammar');
$t->ok($h->setKey('patterns', 'custom', 'p1,p2'), 'setKey without ttl persists');
$t->ok($fake->store['guard_core:patterns:custom']['px'] === null, 'ttl=null persists');
$t->ok($h->setKey('x', 'y', 'v', 0), 'setKey ttl=0 accepted');
$t->ok($fake->store['guard_core:x:y']['px'] === null, 'ttl=0 treated as persist (spec 08 discrepancy 3)');
$t->same(1, $h->delete('banned_ips', '1.2.3.4'), 'delete count');
$t->same(null, $h->getKey('banned_ips', '1.2.3.4'), 'delete removes key');
$fake->seed('guard_core:banned_ips:2.2.2.2', '1');
$fake->seed('guard_core:banned_ips:3.3.3.3', '1');
$fake->seed('guard_core:other:x', '1');
$t->same(['guard_core:banned_ips:2.2.2.2', 'guard_core:banned_ips:3.3.3.3'], $h->keys('banned_ips:*'), 'keys() prefixes pattern');
$t->same(2, $h->deletePattern('banned_ips:*'), 'deletePattern removes matches');
$t->same(['guard_core:patterns:custom', 'guard_core:x:y', 'guard_core:other:x'], array_keys($fake->store), 'deletePattern leaves others');
$t->same(null, (new RedisHandler(false, connection: $fake))->getKey('a', 'b'), 'disabled redis returns null');
$t->same(1, $h->incr('rate_limit:rate', '1.2.3.4', 60), 'incr pipeline');
$px = $fake->store['guard_core:rate_limit:rate:1.2.3.4']['px'];
$t->ok($px !== null, 'incr applies EXPIRE');
$t->same(2, $h->incr('rate_limit:rate', '1.2.3.4'), 'incr second hit');

$t->section('MULTI-EXEC pipeline over fake');
$pipe = $h->connection()->pipeline()->multi();
$pipe->set('guard_core:mk', 'mv')->get('guard_core:mk')->incr('guard_core:mc');
$res = $pipe->execute();
$t->same(['OK', 'mv', 1], $res, 'MULTI/EXEC replies');

$t->section('Ban lifecycle with in-memory Redis');
$sink = new RecordingEventSink();
$warnings = [];
$mgr = new IpBanManager([], function (string $m) use (&$warnings) { $warnings[] = $m; }, $sink);
$mgr->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $fake));
$t->ok($mgr->ban('203.0.113.9', 600, 'unit_test'), 'ban returns true');
$t->same([['ip' => '203.0.113.9', 'duration' => 600, 'reason' => 'unit_test']], $sink->bans, 'ip_banned event shape');
$banKey = 'guard_core:banned_ips:203.0.113.9';
$t->ok(isset($fake->store[$banKey]), 'redis ban key exists');
$t->ok((float) $fake->store[$banKey]['value'] > microtime(true) + 590, 'stored expiry is float-string now+duration');
$t->ok($fake->store[$banKey]['px'] - microtime(true) * 1000 <= 600 * 1000, 'redis TTL equals duration');
$t->ok($mgr->isIpBanned('203.0.113.9'), 'is_ip_banned true (local exact)');
$t->ok($mgr->isIpBanned('[203.0.113.9]'), 'canonical input matches');
$t->ok(!$mgr->isIpBanned('203.0.113.10'), 'unbanned ip false');
$fake->seed('guard_core:banned_ips:198.51.100.7', (string) (microtime(true) + 900), 900000);
$mgr2 = new IpBanManager([], null, $sink);
$mgr2->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $fake));
$t->ok($mgr2->isIpBanned('198.51.100.7'), 'redis exact repopulates local cache');
$fake->seed('guard_core:banned_ips:198.51.100.8', (string) (microtime(true) - 5), 1000);
$t->ok(!$mgr2->isIpBanned('198.51.100.8'), 'stale redis entry is not banned');
$t->ok(!isset($fake->store['guard_core:banned_ips:198.51.100.8']), 'early delete on stale redis entry (normative)');
$t->throws(fn () => $mgr->ban('1.2.3.4', 0), \InvalidArgumentException::class, 'duration 0 rejected');
$t->throws(fn () => $mgr->ban('1.2.3.4', -5), \InvalidArgumentException::class, 'negative duration rejected');
$t->ok(!$mgr->ban('127.0.0.1', 600), 'loopback ban refused');
$t->ok(!isset($fake->store['guard_core:banned_ips:127.0.0.1']), 'refused ban writes nothing');
$t->ok(!$mgr->ban('::1', 600), 'IPv6 loopback ban refused');
$t->ok(!$mgr->ban('127.4.5.6', 600), 'inside 127.0.0.0/8 refused');
$proxyMgr = new IpBanManager(['10.10.0.0/16', 'not-a-network'], null, $sink);
$proxyMgr->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $fake));
$t->ok(!$proxyMgr->ban('10.10.3.4', 600), 'trusted-proxy IP ban refused');
$t->ok(!$proxyMgr->ban('10.10.77.0/24', 600), 'trusted-proxy CIDR ban refused');
$t->ok($proxyMgr->ban('10.11.0.1', 600), 'outside trusted proxy allowed');
$t->ok(count(array_filter($warnings, fn ($w) => str_contains($w, 'self-DoS'))) >= 2, 'refusals warned');
$t->ok($mgr->unban('203.0.113.9') === null, 'unban runs');
$t->ok(!$mgr->isIpBanned('203.0.113.9'), 'unbanned locally');
$t->ok(!isset($fake->store[$banKey]), 'unban deletes redis key');
$t->same(['203.0.113.9'], $sink->unbans, 'ip_unbanned event');

$t->section('CIDR bans and local clamp');
$localOnly = new IpBanManager([], null, $sink);
$t->ok($localOnly->ban('10.77.1.2/8', 600), 'CIDR ban without redis');
$t->ok($localOnly->isIpBanned('10.200.3.4'), 'CIDR covers addresses');
$t->ok(!$localOnly->isIpBanned('192.168.5.5'), 'CIDR does not cover other ranges');
$t->throws(fn () => $localOnly->ban('not-a-cidr/40', 600), \InvalidArgumentException::class, 'invalid CIDR rejected');
$clamps = [];
$clamped = new IpBanManager([], function (string $m) use (&$clamps) { $clamps[] = $m; }, $sink);
$t->ok($clamped->ban('5.5.5.5', 7200), 'over-cap local ban succeeds');
$t->ok(count(array_filter($clamps, fn ($m) => str_contains($m, 'shortened from 7200s to 3600s'))) === 1, 'clamp warning text');
$last = array_values(array_slice($sink->bans, -1))[0];
$t->same(3600, $last['duration'], 'event duration clamped to LOCAL_CACHE_TTL_CAP_SECONDS');
$t->ok($clamped->isIpBanned('5.5.5.5'), 'clamped ban enforced');

$t->section('Redis-failure fallback clamp');
$failing = new FakeRespConnection();
$failing->failWrites = true;
$fMgr = new IpBanManager([], null, $sink);
$fMgr->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $failing));
$t->ok($fMgr->ban('6.6.6.6', 7200), 'ban survives redis failure');
$t->ok($fMgr->isIpBanned('6.6.6.6'), 'local-only ban enforced');
$fdur = array_values(array_slice($sink->bans, -1))[0]['duration'];
$t->same(3600, $fdur, 'redis-failure ban clamped to 3600');
$fCidr = new IpBanManager([], null, $sink);
$fCidr->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $failing));
$t->ok($fCidr->ban('172.20.0.0/16', 7200), 'CIDR ban survives redis failure');
$t->ok($fCidr->isIpBanned('172.20.9.9'), 'CIDR local-only ban enforced');
$t->throws(function () use ($failing): void {
    (new RedisHandler(true, 'guard_core:', connection: $failing))->getKey('a', 'b');
}, GuardRedisException::class, 'operation failure throws GuardRedisException (503)');
$t->same(503, (function () use ($failing) {
    try {
        (new RedisHandler(true, 'guard_core:', connection: $failing))->setKey('a', 'b', 'v');
    } catch (GuardRedisException $e) {
        return $e->getCode();
    }

    return 0;
})(), '503 semantics on setKey failure');

$t->section('Legacy ban-key migration (spec 08 migration algorithm)');
$mk = new FakeRespConnection();
$mk->seed('guard_core:banned_ips:[2001:db8::1]', '999', 5000);
$mk->seed('guard_core:banned_ips:203.0.113.1', '123', 5000);
$mk->seed('guard_core:banned_ips:[10.9.9.9]', '555');
$mk->seed('guard_core:banned_ips:[10.1.1.1]', '444', 5000);
$mk->seed('guard_core:banned_ips:10.1.1.1', '444', 2000);
$mMgr = new IpBanManager([], null, $sink);
$ok = $mMgr->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $mk));
$t->ok($ok, 'migration reports success');
$t->ok(!isset($mk->store['guard_core:banned_ips:[2001:db8::1]']) && isset($mk->store['guard_core:banned_ips:203.0.113.1']), 'legacy key deleted, canonical-key untouched (skip)');
$t->ok(isset($mk->store['guard_core:banned_ips:2001:db8::1']), 'canonical key written from legacy');
$t->ok($mk->store['guard_core:banned_ips:2001:db8::1']['value'] === '999', 'canonical key keeps value');
$t->ok($mk->store['guard_core:banned_ips:2001:db8::1']['px'] - microtime(true) * 1000 <= 5000, 'canonical key keeps longer TTL via SET PX');
$t->ok(!isset($mk->store['guard_core:banned_ips:[10.9.9.9]']) && !isset($mk->store['guard_core:banned_ips:10.9.9.9']), 'persistent legacy key (pttl<=0) deleted, never SET');
$mMgr2 = new IpBanManager([], null, $sink);
$mk2 = new FakeRespConnection();
$mk2->seed('guard_core:banned_ips:[10.1.1.1]', '444', 5000);
$mMgr2->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $mk2));
$t->ok(!isset($mk2->store['guard_core:banned_ips:[10.1.1.1]']) && isset($mk2->store['guard_core:banned_ips:10.1.1.1']), 'keep-longer comparison: canonical TTL raised');
$t->ok($mk2->store['guard_core:banned_ips:10.1.1.1']['px'] - microtime(true) * 1000 > 4000, 'canonical now has the longer expiry');
$mMgr3 = new IpBanManager([], null, $sink);
$mk3 = new FakeRespConnection();
$mk3->seed('guard_core:banned_ips:[10.1.1.1]', '444', -100);
$mMgr3->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $mk3));
$t->ok(!isset($mk3->store['guard_core:banned_ips:[10.1.1.1]']), 'expired legacy key deleted');

$t->section('reset()');
$rFake = new FakeRespConnection();
$rMgr = new IpBanManager([], null, $sink);
$rMgr->initializeRedis(new RedisHandler(true, 'guard_core:', connection: $rFake));
$rMgr->ban('7.7.7.7', 600);
$rMgr->ban('10.0.0.0/8', 600);
$rMgr->reset();
$t->ok(!$rMgr->isIpBanned('7.7.7.7'), 'reset clears local exact');
$t->ok(!$rMgr->isIpBanned('10.4.4.4'), 'reset clears local networks');
$rIps = array_filter(array_keys($rFake->store), fn ($k) => str_contains($k, 'banned_ips:'));
$t->ok($rIps === [], 'reset deletes redis ban keys (networks keys are per-process per spec)');

$t->section('Disabled redis state semantics');
$dMgr = new IpBanManager([], null, $sink);
$dMgr->initializeRedis(null);
$t->ok($dMgr->ban('8.8.8.8', 7200), 'ban without redis');
$t->ok($dMgr->isIpBanned('8.8.8.8'), 'local-only enforcement');
$ddur = array_values(array_slice($sink->bans, -1))[0]['duration'];
$t->same(3600, $ddur, 'no-handler ban clamped to 3600 (spec 09)');

$t->section('ban expiry: local entries age out');
$eMgr = new IpBanManager([], null, $sink);
$eMgr->ban('9.9.9.1', 1);
$eMgr->ban('11.0.0.0/8', 1);
$t->ok($eMgr->isIpBanned('9.9.9.1'), 'fresh short ban enforced');
$t->ok($eMgr->isIpBanned('11.1.2.3'), 'fresh short cidr enforced');
usleep(1150000);
$t->ok(!$eMgr->isIpBanned('9.9.9.1'), 'an expired exact ban is unset and false');
$t->ok(!$eMgr->isIpBanned('11.1.2.3'), 'an expired network entry drops out of the cache');
$t->ok(!$eMgr->isIpBanned('totally-not-an-ip'), 'an unparseable ip is never banned');

$t->section('ban input validation');
$t->throws(fn () => (new IpBanManager([], null, $sink))->ban('999.999.999.999', 600), \InvalidArgumentException::class, 'an invalid exact ip is rejected');
$t->throws(fn () => (new IpBanManager([], null, $sink))->ban('1.2.3.4/33', 600), \InvalidArgumentException::class, 'a v4 cidr with an out of range prefix is rejected');

$t->section('ban refusal geometry: prefix zero, partial bits, families');
$privateWarnings = [];
$pMgr = new IpBanManager([], function (string $m) use (&$privateWarnings) { $privateWarnings[] = $m; }, $sink);
// /0 target: the hi() bound collapses to all-ones; refused as loopback.
$t->ok(!$pMgr->ban('8.8.8.8/0', 600), 'a zero prefix target overlaps everything and is refused');
// /9 target: the partial-byte bound keeps the remaining high bits.
$t->ok((new IpBanManager(['10.64.0.0/9'], null, $sink))->ban('10.90.0.1/32', 600) === false, 'a partial prefix overlap with a trusted proxy is refused');
// mixed families never overlap and are allowed.
$v6Mgr = new IpBanManager(['2001:db8::/32'], null, $sink);
$t->ok($v6Mgr->ban('8.8.8.8', 600), 'a v4 target does not overlap a v6 trusted proxy');
$t->ok($v6Mgr->ban('2001:db9::1', 600), 'a v6 target outside the proxy prefix is allowed');

$t->section('private range warnings');
$t->ok($pMgr->ban('fe80::/10', 600), 'a link local range ban succeeds with a warning');
$t->ok($pMgr->ban('fd00::/8', 600), 'a unique local range ban succeeds with a warning');
$t->ok($pMgr->ban('::ffff:10.0.0.5', 600), 'a v4 mapped private address ban succeeds with a warning');
$t->ok(count(array_filter($privateWarnings, fn ($w) => str_contains($w, 'private IP range'))) === 3, 'each private range ban warned once');

$t->section('local cache overflow eviction');
$oMgr = new IpBanManager([], null, null);
for ($i = 0; $i <= 10001; $i++) {
    $oMgr->ban(sprintf('9.%d.%d.%d', intdiv($i, 65536), intdiv($i, 256) % 256, $i % 256), 600);
}
$t->ok(!$oMgr->isIpBanned('9.0.0.0'), 'the first banned ip was evicted');
$t->ok($oMgr->isIpBanned('9.0.39.17'), 'the newest banned ip survives');

$t->section('redis handler: disabled and enabled surfaces');

$disabledHandler = new RedisHandler(false, 'guard_core_test:');
$disabledHandler->initialize();
$t->ok(!$disabledHandler->isInitialized(), 'a disabled handler never initializes');
$t->same(false, $disabledHandler->setKey('ns', 'k', 'v'), 'setKey on a disabled handler is false');
$t->same(null, $disabledHandler->exists('ns', 'k'), 'exists on a disabled handler is null');
$t->same(0, $disabledHandler->delete('ns', 'k'), 'delete on a disabled handler is zero');
$t->same([], $disabledHandler->keys('ns:*'), 'keys on a disabled handler is empty');
$t->same(0, $disabledHandler->deletePattern('ns:*'), 'deletePattern on a disabled handler is zero');
$t->same(0, $disabledHandler->incr('ns', 'k'), 'incr on a disabled handler is zero');
$t->same(0, $disabledHandler->recordSlidingWindowHit('ns', 'k', microtime(true), microtime(true) - 60, 60), 'sliding window on a disabled handler is zero');
$t->same(null, $disabledHandler->getKey('ns', 'k'), 'getKey on a disabled handler is null');

$fakeRedis = new FakeRespConnection();
$enabledHandler = new RedisHandler(true, 'guard_core_test:', connection: $fakeRedis);
$enabledHandler->initialize();
$t->ok($enabledHandler->isInitialized(), 'an enabled handler initializes');
$t->same(true, $enabledHandler->setKey('ns', 'k', 'v'), 'setKey round-trips');
$t->same(true, $enabledHandler->exists('ns', 'k'), 'exists reports the stored key');
$t->same(false, $enabledHandler->exists('ns', 'missing'), 'exists reports misses');
$t->same(1, $enabledHandler->delete('ns', 'k'), 'delete removes the key');
$t->same(true, $enabledHandler->setKey('ns', 'gone', 'v'), 'seed a key for the pattern delete');
$t->same(1, $enabledHandler->deletePattern('ns:gone*'), 'deletePattern removes matching keys');
$t->same(0, $enabledHandler->deletePattern('ns:nothing*'), 'deletePattern with no matches is zero');
$t->same(1, $enabledHandler->incr('ns', 'counter'), 'incr starts at one');
$t->same(2, $enabledHandler->incr('ns', 'counter'), 'incr accumulates');
$t->ok($enabledHandler->recordSlidingWindowHit('ns', 'win', microtime(true), microtime(true) - 60, 60) >= 1, 'a sliding window hit records');

$t->section('redis cloud ip store: decode, encode, clear');

$cloudFake = new FakeRespConnection();
$cloudStore = new RenzoFranceschini\GuardCore\Cloud\RedisCloudIpStore(new RedisHandler(true, 'guard_core_probe:', connection: $cloudFake));
$cloudFake->seed('guard_core_probe:cloud_ip_v2:AWS', 'not-json');
$t->same(null, $cloudStore->get('AWS'), 'a malformed payload decodes as null');
$cloudFake->seed('guard_core_probe:cloud_ip_v2:AWS', '{"a":1}');
$t->same(null, $cloudStore->get('AWS'), 'a map payload decodes as null');
$cloudFake->seed('guard_core_probe:cloud_ip_v2:AWS', '[1,2]');
$t->same(null, $cloudStore->get('AWS'), 'a list of numbers decodes as null');
$cloudFake->seed('guard_core_probe:cloud_ip_v2:AWS', '["10.0.0.0/8"]');
$t->same(['10.0.0.0/8'], $cloudStore->get('AWS'), 'a list of strings decodes as ranges');
$cloudStore->set('GCP', ['10.1.0.0/16', '10.0.0.0/8']);
$t->same('["10.0.0.0/8", "10.1.0.0/16"]', $cloudFake->store['guard_core_probe:cloud_ip_v2:GCP']['value'] ?? null, 'set sorts and encodes the ranges');
$t->throws(static fn () => $cloudStore->set('X', [NAN]), RuntimeException::class, 'an unencodable range raises');
$cloudStore->set('AZ', ['10.4.0.0/16']);
$cloudStore->clear();
$t->same(false, isset($cloudFake->store['guard_core_probe:cloud_ip_v2:GCP']), 'clear removes stored providers');
$t->same(false, isset($cloudFake->store['guard_core_probe:cloud_ip_v2:AZ']), 'clear removes every stored provider');

$memoryStore = new RenzoFranceschini\GuardCore\Cloud\InMemoryCloudIpStore();
$memoryStore->set('AWS', ['10.0.0.0/8']);
$memoryStore->clear();
$t->same(null, $memoryStore->get('AWS'), 'the in memory store clears too');

$t->section('resp pipeline: exec, ttl variants, and delete');

$pipeFake = new FakeRespConnection();
$respPipe = $pipeFake->pipeline();
$t->same([], $respPipe->execute(), 'an empty pipeline executes to an empty list');
$respPipe->set('k', 'v', ex: 60);
$respPipe->set('k2', 'v2', px: 500);
$respPipe->del('k', 'k2');
$t->same(['OK', 'OK', 2], $respPipe->execute(), 'set with ex, px and a multi key del execute');

$t->section('resp pipeline: aborted exec');

$abortFake = new AbortingExecConnection();
$abortPipe = $abortFake->pipeline()->multi();
$abortPipe->set('a', 'b');
$abortPipe->set('c', 'd');
$t->throws(static fn () => $abortPipe->execute(), GuardRedisException::class, 'a non array exec reply aborts the pipeline');

$t->section('resp connection: scripted stream error paths');

/**
 * Starts tests/resp_scripted_server.php in the given mode and returns
 * [proc, port]; the caller must proc_close in a finally.
 */
function startRespServer(string $mode): array
{
    $command = [PHP_BINARY, __DIR__ . '/../tests/resp_scripted_server.php', $mode];
    $proc = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('failed to start the scripted resp server');
    }
    $portLine = fgets($pipes[1], 32);
    if ($portLine === false) {
        proc_terminate($proc);
        throw new RuntimeException('the scripted resp server printed no port');
    }

    return [$proc, $pipes, (int) trim($portLine)];
}

function withRespServer(string $mode, callable $fn): void
{
    [$proc, $pipes, $port] = startRespServer($mode);
    try {
        $fn(new RespConnection('127.0.0.1', $port, 2.0, 2.0));
    } finally {
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        proc_terminate($proc);
        proc_close($proc);
    }
}

function respExpect(string $mode, callable $fn, string $label): void
{
    global $t;
    try {
        withRespServer($mode, $fn);
        $t->ok(true, $label);
    } catch (GuardRedisException $e) {
        $t->ok(str_contains($e->getMessage(), 'Redis'), "{$label} ({$e->getMessage()})");
    }
}

// A non-array reply to KEYS and ZRANGEBYSCORE yields an empty list.
respExpect('int_reply', static function (RespConnection $conn): void {
    global $t;
    $conn->ping();
    $t->same([], $conn->keys('nomatch:*'), 'a non array keys reply yields an empty list');
    $t->same([], $conn->zRangeByScore('z', '0', '10'), 'a non array zrange reply yields an empty list');
}, 'int replies keep the connection usable');
respExpect('null_array', static function (RespConnection $conn): void {
    global $t;
    $t->same([], $conn->keys('*'), 'a null array keys reply yields an empty list');
    $t->same([], $conn->zRangeByScore('z', '0', '10'), 'a null array zrange reply yields an empty list');
}, 'null array replies yield empty lists');

// A redis -ERR reply surfaces as GuardRedisException.
respExpect('error', static function (RespConnection $conn): void {
    $conn->ping();
}, 'an error reply throws with the redis prefix');

// A null bulk decodes to PHP null.
respExpect('null_bulk', static function (RespConnection $conn): void {
    global $t;
    $t->same(null, $conn->get('missing'), 'a null bulk reply decodes to null');
}, 'null bulk replies decode');

// An unknown reply type byte is a protocol error.
respExpect('garbage', static function (RespConnection $conn): void {
    $conn->ping();
}, 'an unknown reply type throws a protocol error');

// A server that closes without replying produces the empty-reply error.
respExpect('close_now', static function (RespConnection $conn): void {
    $conn->ping();
}, 'a closed socket produces the empty reply error');

// A truncated bulk payload dies in the byte reader.
respExpect('half_bulk', static function (RespConnection $conn): void {
    $conn->get('k');
}, 'a truncated bulk reply fails the byte read');

// A server that never answers trips the socket timeout in the line reader.
$t0 = microtime(true);
try {
    withRespServer('hang', static function (RespConnection $conn): void {
        $conn->ping();
    });
    $t->ok(false, 'a silent server throws the timeout error');
} catch (GuardRedisException $e) {
    $t->ok(str_contains($e->getMessage(), 'timeout'), 'a silent server trips the socket timeout (' . $e->getMessage() . ')');
}
$t->ok(microtime(true) - $t0 < 4, 'the timeout fires at the client budget, not the server one');

// A peer that disappears mid-write fails the write loop.
try {
    withRespServer('rst', static function (RespConnection $conn): void {
        $conn->zAdd('bigz', 1.0, str_repeat('x', 4 * 1024 * 1024));
    });
    $t->same('no-exception', 'GuardRedisException', 'a failed write throws');
} catch (GuardRedisException $e) {
    $t->ok(str_contains($e->getMessage(), 'Redis write failed'), 'a dead peer fails the write loop (' . $e->getMessage() . ')');
}

$exit = $t->summary();

$integration = in_array('--integration', $argv, true);
if ($integration) {
    $exit = max($exit, (require __DIR__ . '/integration_state.php')($t));
}

exit($exit);

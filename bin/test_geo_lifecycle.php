<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Cloud\HttpClient;
use RenzoFranceschini\GuardCore\Cloud\HttpResponse;
use RenzoFranceschini\GuardCore\Cloud\InMemoryCloudIpStore;
use RenzoFranceschini\GuardCore\Cloud\RedisCloudIpStore;
use RenzoFranceschini\GuardCore\GeoIp\IpInfoManager;
use RenzoFranceschini\GuardCore\GeoIp\MmdbReader;
use RenzoFranceschini\GuardCore\Logging\SimpleRequestLogger;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Redis\RedisLock;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/FakeRespConnection.php';
require __DIR__ . '/../tests/MmdbFixture.php';

// Spec 10 "Country filtering": the IPInfo database lifecycle ported from
// the reference ipinfo_handler.py - the token download (3 attempts,
// exponential backoff from 1 s), atomic writes, mtime freshness, the
// Redis-cached database copy (ipinfo:database), the never-raising
// get_country, the check_country_access verdicts with their country_blocked
// events, and the geo_lookup_failed events. Plus the cross-request refresh
// lock (specs/impl/php.md runtime model): the Redis-backed single-flight
// the shared-nothing FPM workers use around cache-missing provider
// fetches. All network and Redis surfaces are scripted stubs.

final class GeoT
{
    public int $passed = 0;

    public int $failed = 0;

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
            echo '  expected: ' . var_export($expected, true) . "\n";
            echo '  actual:   ' . var_export($actual, true) . "\n";
        }
    }

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }

    public function finish(string $label): int
    {
        echo "\n{$label}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed === 0 ? 0 : 1;
    }
}

/**
 * @param list<HttpResponse|Throwable> $responses scripted in order; the
 *        last one repeats
 */
final class LifecycleStubClient implements HttpClient
{
    public int $calls = 0;

    /** @var list<string> */
    public array $urls = [];

    /** @var list<array<string, string>> */
    public array $headers = [];

    /** @var list<HttpResponse|Throwable> */
    private array $responses;

    /** @param list<HttpResponse|Throwable> $responses */
    public function __construct(array $responses)
    {
        $this->responses = $responses;
    }

    public function get(string $url, array $options = []): HttpResponse
    {
        $this->calls++;
        $this->urls[] = $url;
        $this->headers[] = $options['headers'] ?? [];
        $response = $this->responses[min($this->calls, count($this->responses)) - 1];
        if ($response instanceof Throwable) {
            throw $response;
        }

        return $response;
    }
}

final class LifecycleEventSink
{
    /** @var list<array<string, mixed>> */
    public array $events = [];

    public function __invoke(object $event): void
    {
        $this->events[] = [
            'event_type' => $event->eventType,
            'ip_address' => $event->ipAddress,
            'action_taken' => $event->actionTaken,
            'reason' => $event->reason,
            'country' => $event->metadata['country'] ?? null,
            'rule_type' => $event->metadata['rule_type'] ?? null,
            'handler_name' => $event->handlerName,
        ];
    }
}

const GEO_MMDB = ['192.0.2.0/24' => 'US', '198.51.100.0/24' => 'BR'];

/** buildTestMmdb writes a file and returns its path; the download stubs need the bytes. */
function geoMmdbBytes(array $entries = GEO_MMDB): string
{
    return (string) file_get_contents(buildTestMmdb($entries));
}
const GEO_US_IP = '192.0.2.7';
const GEO_BR_IP = '198.51.100.5';

$t = new GeoT();

// ---------------------------------------------------------------------
// 1. Token and download lifecycle
// ---------------------------------------------------------------------

$t->section('token validation');
$threw = false;
try {
    new IpInfoManager('');
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'an empty token is a constructor error');

$t->section('download and install');
$mmdb = geoMmdbBytes();
$client = new LifecycleStubClient([new HttpResponse(200, $mmdb)]);
$path = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path);
$manager = new IpInfoManager(
    token: 'test-token',
    dbPath: $path,
    httpClient: $client,
    clock: static fn (): int => 1700000000
);
$manager->initialize();
$t->same(1, $client->calls, 'one download for a missing database');
$t->same(IpInfoManager::DOWNLOAD_URL, $client->urls[0], 'download url');
$t->truthy(str_starts_with($client->headers[0]['Authorization'] ?? '', 'Bearer test-token'), 'bearer token header');
$t->truthy(is_file($path), 'database written');
$t->truthy(!is_file($path . '.tmp'), 'atomic write left no tmp file');
$t->same('US', $manager->getCountry(GEO_US_IP), 'downloaded database resolves');
$t->truthy($manager->isInitialized(), 'manager initialized');
$status = $manager->getStatus();
$t->truthy($status['ready'] && ($status['entries'] ?? 0) > 0, 'status ready with entries');

$t->section('fresh database is not re-downloaded');
$client2 = new LifecycleStubClient([]);
$manager2 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path,
    httpClient: $client2,
    clock: static fn (): int => 1700000000
);
$manager2->initialize();
$t->same(0, $client2->calls, 'fresh mtime skips the download');
$t->same('US', $manager2->getCountry(GEO_US_IP), 'existing reader still resolves');

$t->section('outdated database is re-downloaded');
$outdated = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
file_put_contents($outdated, buildTestMmdb(GEO_MMDB));
@touch($outdated, 1700000000 - 86400 - 10);
$client3 = new LifecycleStubClient([new HttpResponse(200, geoMmdbBytes(['10.0.0.0/8' => 'DE']))]);
$manager3 = new IpInfoManager(
    token: 'test-token',
    dbPath: $outdated,
    httpClient: $client3,
    clock: static fn (): int => 1700000000
);
$manager3->initialize();
$t->same(1, $client3->calls, 'an mtime older than max_age re-downloads');
$t->same(null, $manager3->getCountry(GEO_US_IP), 'old mapping replaced');

$t->section('retries with exponential backoff');
$client4 = new LifecycleStubClient([
    new HttpResponse(500, 'nope'),
    new HttpResponse(503, 'nope'),
    new HttpResponse(200, $mmdb),
]);
$path4 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path4);
$sleeps = [];
$manager4 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path4,
    httpClient: $client4,
    sleep: static function (float $seconds) use (&$sleeps): void {
        $sleeps[] = $seconds;
    },
    clock: static fn (): int => 1700000000
);
$manager4->initialize();
$t->same(3, $client4->calls, 'two failed attempts then success');
$t->same([1.0, 2.0], $sleeps, 'exponential backoff starting at 1s');
$t->same('US', $manager4->getCountry(GEO_US_IP), 'retry succeeded');

$t->section('download failure keeps nothing and emits geo_lookup_failed');
$client5 = new LifecycleStubClient([
    new HttpResponse(500, 'nope'),
    new HttpResponse(500, 'nope'),
    new HttpResponse(500, 'nope'),
]);
$path5 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path5);
$sink5 = new LifecycleEventSink();
$manager5 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path5,
    httpClient: $client5,
    eventSink: $sink5,
    sleep: static function (float $seconds): void {
    },
    clock: static fn (): int => 1700000000
);
$manager5->initialize();
$t->same(3, $client5->calls, 'all three attempts exhausted');
$t->same(1, count($sink5->events), 'one failure event');
$event = $sink5->events[0];
$t->same('geo_lookup_failed', $event['event_type'], 'failure event type');
$t->same('system', $event['ip_address'], 'failure event from system');
$t->same('database_download_failed', $event['action_taken'], 'failure event action');
$t->same('ipinfo', $event['handler_name'], 'failure event handler');
$t->same(null, $manager5->getCountry(GEO_BR_IP), 'no reader after the failed download');

$t->section('corrupted database is removed');
$path6 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
file_put_contents($path6, 'this is not an mmdb');
$manager6 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path6,
    httpClient: new LifecycleStubClient([]),
    clock: static fn (): int => 1700000000
);
$manager6->initialize();
$t->truthy(!is_file($path6), 'corrupted database removed');
$t->same(null, $manager6->getCountry(GEO_US_IP), 'unavailable reader returns null');

$t->section('refresh');
$client7 = new LifecycleStubClient([
    new HttpResponse(200, geoMmdbBytes()),
    new HttpResponse(200, geoMmdbBytes(['10.0.0.0/8' => 'DE'])),
]);
$path7 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path7);
$manager7 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path7,
    httpClient: $client7,
    clock: static fn (): int => 1700000000
);
$manager7->initialize();
$t->same('US', $manager7->getCountry(GEO_US_IP), 'initial mapping');
$manager7->refresh();
$t->same(2, $client7->calls, 'refresh downloads');
$t->same(null, $manager7->getCountry(GEO_US_IP), 'refresh swapped the reader');

$t->section('refresh failure keeps the existing reader');
$client8 = new LifecycleStubClient([
    new HttpResponse(200, geoMmdbBytes()),
    new HttpResponse(500, 'nope'),
    new HttpResponse(500, 'nope'),
    new HttpResponse(500, 'nope'),
]);
$path8 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path8);
$manager8 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path8,
    httpClient: $client8,
    sleep: static function (float $seconds): void {
    },
    clock: static fn (): int => 1700000000
);
$manager8->initialize();
$manager8->refresh();
$t->same(4, $client8->calls, 'refresh retried to exhaustion');
$t->same('US', $manager8->getCountry(GEO_US_IP), 'existing reader kept');

// ---------------------------------------------------------------------
// 2. Redis-cached database copy
// ---------------------------------------------------------------------

$t->section('redis cache preferred over download');
$fake = new FakeRespConnection();
$redis = new RedisHandler(true, 'guard_core_geo:', connection: $fake);
$fake->seed('guard_core_geo:ipinfo:database', geoMmdbBytes());
$client9 = new LifecycleStubClient([]);
$path9 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path9);
$manager9 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path9,
    httpClient: $client9,
    redisHandler: $redis,
    clock: static fn (): int => 1700000000
);
$manager9->initialize();
$t->same(0, $client9->calls, 'cached copy skips the download');
$t->same('US', $manager9->getCountry(GEO_US_IP), 'cached copy installed');

$t->section('download caches the bytes in redis');
$fake2 = new FakeRespConnection();
$redis2 = new RedisHandler(true, 'guard_core_geo:', connection: $fake2);
$client10 = new LifecycleStubClient([new HttpResponse(200, $mmdb)]);
$path10 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path10);
$manager10 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path10,
    httpClient: $client10,
    redisHandler: $redis2,
    clock: static fn (): int => 1700000000
);
$manager10->initialize();
$cached = $redis2->getKey('ipinfo', 'database');
$t->same($mmdb, $cached, 'ipinfo:database carries the database bytes');

$t->section('redis errors do not break initialization');
$client11 = new LifecycleStubClient([new HttpResponse(200, $mmdb)]);
$fakeBroken = new FakeRespConnection();
$fakeBroken->failWrites = true;
$broken = new RedisHandler(true, 'guard_core_geo:', connection: $fakeBroken);
$path11 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path11);
$manager11 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path11,
    httpClient: $client11,
    redisHandler: $broken,
    clock: static fn (): int => 1700000000
);
$manager11->initialize();
$t->same('US', $manager11->getCountry(GEO_US_IP), 'download still installed with redis down');

// ---------------------------------------------------------------------
// 3. Country verdicts and events
// ---------------------------------------------------------------------

$t->section('check_country_access verdicts');
$sink = new LifecycleEventSink();
$manager12 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path,
    httpClient: new LifecycleStubClient([]),
    eventSink: $sink,
    clock: static fn (): int => 1700000000
);
$manager12->initialize();
[$allowed, $country] = $manager12->checkCountryAccess(GEO_US_IP, ['BR']);
$t->same([true, 'US'], [$allowed, $country], 'non-listed country allowed under a blocklist');
[$allowed, $country] = $manager12->checkCountryAccess(GEO_BR_IP, ['BR']);
$t->same([false, 'BR'], [$allowed, $country], 'blocked country denied');
[$allowed, $country] = $manager12->checkCountryAccess(GEO_US_IP, [], ['US']);
$t->same([true, 'US'], [$allowed, $country], 'whitelisted country allowed');
[$allowed, $country] = $manager12->checkCountryAccess(GEO_BR_IP, ['BR'], ['US']);
$t->same([false, 'BR'], [$allowed, $country], 'allowlist shadows the blocklist');
$allowlistMiss = null;
foreach ($sink->events as $e) {
    if ($e['rule_type'] === 'country_whitelist') {
        $allowlistMiss = $e;
    }
}
$t->truthy($allowlistMiss !== null, 'allowlist miss recorded');
$t->same('country_blocked', $allowlistMiss['event_type'], 'allowlist miss event type');
$t->same('request_blocked', $allowlistMiss['action_taken'], 'allowlist miss action');
$t->same('Country BR not in allowed list', $allowlistMiss['reason'], 'allowlist miss reason');
[$allowed, $country] = $manager12->checkCountryAccess('203.0.113.99', ['BR'], ['US']);
$t->same([false, null], [$allowed, $country], 'unresolved country blocks under an allowlist');
[$allowed, $country] = $manager12->checkCountryAccess('203.0.113.99', ['BR']);
$t->same([true, null], [$allowed, $country], 'unresolved country allows under a blocklist');
$blacklistHit = null;
foreach ($sink->events as $e) {
    if ($e['rule_type'] === 'country_blacklist') {
        $blacklistHit = $e;
    }
}
$t->truthy($blacklistHit !== null, 'blacklist hit recorded');
$t->same('Country BR is blocked', $blacklistHit['reason'], 'blacklist reason');
$t->same(GEO_BR_IP, $blacklistHit['ip_address'], 'blacklist event ip');
$t->same('country_blocked', $blacklistHit['event_type'], 'blacklist event type');

// ---------------------------------------------------------------------
// 4. Cross-request refresh lock
// ---------------------------------------------------------------------

$t->section('redis lock basics');
$fake3 = new FakeRespConnection();
$lockRedis = new RedisHandler(true, 'guard_core_lock:', connection: $fake3);
$lock = new RedisLock($lockRedis);
$t->truthy($lock->acquire('ns', 'k', 'token-a', 5000), 'first acquire succeeds');
$t->truthy(!$lock->acquire('ns', 'k', 'token-b', 5000), 'second acquire contends');
$t->truthy($lock->acquire('ns', 'other', 'token-b', 5000), 'a different key is independent');
$lock->release('ns', 'k', 'wrong-token');
$t->truthy(!$lock->acquire('ns', 'k', 'token-b', 5000), 'a wrong-token release does not free the lock');
$lock->release('ns', 'k', 'token-a');
$t->truthy($lock->acquire('ns', 'k', 'token-b', 5000), 'the owner release frees the lock');
$disabledRedis = new RedisHandler(false, 'guard_core_lock:', connection: $fake3);
$disabledLock = new RedisLock($disabledRedis);
$t->truthy($disabledLock->acquire('ns', 'k', 't', 5000), 'a disabled redis lock is uncontended');

$t->section('cloud refresh single-flight across workers');
$fetches = [];
$stub = new class implements HttpClient {
    public int $calls = 0;

    public function get(string $url, array $options = []): HttpResponse
    {
        $this->calls++;

        return new HttpResponse(200, (string) json_encode([
            'prefixes' => [
                ['ip_prefix' => '203.0.113.0/24', 'region' => 'us-east-1', 'service' => 'AMAZON'],
            ],
        ]));
    }
};
$fake4 = new FakeRespConnection();
$cloudRedis = new RedisHandler(true, 'guard_core_cloud:', connection: $fake4);
$cloudManager = new CloudManager($stub, new RedisCloudIpStore($cloudRedis), new SimpleRequestLogger());
$cloudManager->initializeRedis($cloudRedis, ['AWS'], 3600);
$t->same(1, $stub->calls, 'first worker fetches on the cache miss');
$t->truthy($cloudManager->isCloudIp('203.0.113.5', ['AWS']), 'ranges installed');
$cloudManager2 = new CloudManager($stub, new RedisCloudIpStore($cloudRedis), new SimpleRequestLogger());
$cloudManager2->initializeRedis($cloudRedis, ['AWS'], 3600);
$t->same(1, $stub->calls, 'second worker hits the shared cache');

$t->section('a contended lock skips the fetch');
$fake5 = new FakeRespConnection();
$cloudRedis5 = new RedisHandler(true, 'guard_core_cloud2:', connection: $fake5);
$store5 = new RedisCloudIpStore($cloudRedis5);
$stub5 = new class implements HttpClient {
    public int $calls = 0;

    public function get(string $url, array $options = []): HttpResponse
    {
        $this->calls++;

        return new HttpResponse(200, (string) json_encode([
            'prefixes' => [
                ['ip_prefix' => '203.0.113.0/24', 'region' => 'us-east-1', 'service' => 'AMAZON'],
            ],
        ]));
    }
};
$cloudManager5 = new CloudManager($stub5, $store5, new SimpleRequestLogger());
$cloudManager5->initializeRedis($cloudRedis5, ['AWS'], 3600);
$t->same(1, $stub5->calls, 'first manager fetched');
// Simulate a second worker starting while the first still holds the lock:
// seed the lock key as a foreign owner, then clear the shared cache so the
// worker faces a cache miss.
$store5->clear();
// A foreign worker holds the provider's fetch lock.
$foreignLock = new RedisLock($cloudRedis5);
$foreignLock->acquire(CloudManager::REFRESH_LOCK_NAMESPACE, 'AWS', 'foreign-worker', CloudManager::REFRESH_LOCK_TTL_MS);
$cloudManager6 = new CloudManager($stub5, $store5, new SimpleRequestLogger());
$cloudManager6->initializeRedis($cloudRedis5, ['AWS'], 3600);
$t->same(1, $stub5->calls, 'the lock holder wins; the other worker skipped the fetch');
$cloudManager6->refreshAsync(['AWS'], 3600);
$t->same(1, $stub5->calls, 'the skip held on the refresh path too');
$foreignLock->release(CloudManager::REFRESH_LOCK_NAMESPACE, 'AWS', 'foreign-worker');
$cloudManager6->refreshAsync(['AWS'], 3600);
$t->same(2, $stub5->calls, 'once the lock frees, the worker fetches');


// ---------------------------------------------------------------------
// 5. Remaining lifecycle arms
// ---------------------------------------------------------------------

$t->section('accessors and uninitialized reads');
$t->truthy(str_ends_with($manager->dbPath(), '.mmdb'), 'dbPath accessor');
$t->truthy($manager->lastRefreshed() instanceof DateTimeImmutable, 'lastRefreshed set after initialize');
$uninitialized = new IpInfoManager(
    token: 'test-token',
    dbPath: (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb',
    httpClient: new LifecycleStubClient([]),
    clock: static fn (): int => 1700000000
);
$t->same(null, $uninitialized->getCountry(GEO_US_IP), 'uninitialized reader returns null with the init warning');

$t->section('freshness query');
$fresh = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
$clockManager = new IpInfoManager(
    token: 'test-token',
    dbPath: $fresh,
    httpClient: new LifecycleStubClient([]),
    clock: static fn (): int => 1700000000
);
$t->truthy($clockManager->isDbOutdated(), 'a missing file is outdated');
file_put_contents($fresh, 'x');
@touch($fresh, 1700000000);
$t->truthy(!$clockManager->isDbOutdated(), 'a fresh file is not outdated');
@touch($fresh, 1700000000 - 90000);
$t->truthy($clockManager->isDbOutdated(), 'an old file is outdated');

$t->section('nested directory creation');
$nested = sys_get_temp_dir() . '/geoip-nested-' . bin2hex(random_bytes(4)) . '/db/country.mmdb';
$nestedManager = new IpInfoManager(
    token: 'test-token',
    dbPath: $nested,
    httpClient: new LifecycleStubClient([new HttpResponse(200, geoMmdbBytes())]),
    clock: static fn (): int => 1700000000
);
$nestedManager->initialize();
$t->truthy(is_file($nested), 'the database directory is created');

$t->section('lookup failure emits geo_lookup_failed');
$lookupSink = new LifecycleEventSink();
$lookupManager = new IpInfoManager(
    token: 'test-token',
    dbPath: (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb',
    httpClient: new LifecycleStubClient([]),
    eventSink: $lookupSink,
    clock: static fn (): int => 1700000000
);
$corruptBytes = file_get_contents(buildTestMmdb(GEO_MMDB));
$marker = strpos($corruptBytes, "\xAB\xCD\xEFMaxMind.com");
file_put_contents($lookupManager->dbPath(), str_repeat("\x07", (int) $marker) . substr($corruptBytes, (int) $marker));
$openMethod = new ReflectionMethod($lookupManager, 'openDatabaseOrNone');
$openMethod->setAccessible(true);
$badReader = $openMethod->invoke($lookupManager);
$t->truthy($badReader instanceof MmdbReader, 'a corrupted-tree database still opens');
$lookupManager->initialize();
$t->same(null, $lookupManager->getCountry(GEO_US_IP), 'lookup exception returns null');
$lookupFailed = null;
foreach ($lookupSink->events as $e) {
    if ($e['action_taken'] === 'lookup_failed') {
        $lookupFailed = $e;
    }
}
$t->truthy($lookupFailed !== null, 'lookup failure event recorded');
$t->same('geo_lookup_failed', $lookupFailed['event_type'], 'lookup failure event type');
$t->same(GEO_US_IP, $lookupFailed['ip_address'], 'lookup failure carries the ip');

$t->section('empty country records resolve as misses');
$emptyCountry = new IpInfoManager(
    token: 'test-token',
    dbPath: buildTestMmdb(['10.9.9.0/24' => '']),
    httpClient: new LifecycleStubClient([]),
    clock: static fn (): int => 1700000000
);
$emptyCountry->initialize();
$t->same(null, $emptyCountry->getCountry('10.9.9.1'), 'a record with an empty country is a miss');
$t->same(null, $emptyCountry->getCountry('10.8.8.1'), 'an unlisted ip is a miss');

$t->section('unwritable database targets');
$writeFailure = new IpInfoManager(
    token: 'test-token',
    dbPath: '/dev/null/impossible/country.mmdb',
    httpClient: new LifecycleStubClient([new HttpResponse(200, geoMmdbBytes())]),
    clock: static fn (): int => 1700000000
);
$writeMethod = new ReflectionMethod($writeFailure, 'writeDatabaseAtomically');
$writeMethod->setAccessible(true);
$writeThrew = false;
try {
    $writeMethod->invoke($writeFailure, 'bytes');
} catch (RuntimeException $e) {
    $writeThrew = str_contains($e->getMessage(), 'failed to write');
}
$t->truthy($writeThrew, 'an unwritable target rejects the write');
// The tmp file lands beside the target, so the write succeeds and the
// rename onto an existing directory is what fails.
$dirTarget = sys_get_temp_dir() . '/geoip-rename-' . bin2hex(random_bytes(4));
@mkdir($dirTarget);
$renameManager = new IpInfoManager(
    token: 'test-token',
    dbPath: $dirTarget,
    httpClient: new LifecycleStubClient([]),
    clock: static fn (): int => 1700000000
);
$renameMethod = new ReflectionMethod($renameManager, 'writeDatabaseAtomically');
$renameMethod->setAccessible(true);
$renameThrew = false;
try {
    $renameMethod->invoke($renameManager, 'bytes');
} catch (RuntimeException $e) {
    $renameThrew = str_contains($e->getMessage(), 'failed to replace');
}
$t->truthy($renameThrew, 'a failed rename cleans up and rejects');
@rmdir($dirTarget);

$t->section('unremovable corrupted database');
$dirPath = sys_get_temp_dir() . '/geoip-dir-' . bin2hex(random_bytes(4));
@mkdir($dirPath);
$dirManager = new IpInfoManager(
    token: 'test-token',
    dbPath: $dirPath,
    httpClient: new LifecycleStubClient([]),
    clock: static fn (): int => 1700000000
);
$dirOpen = new ReflectionMethod($dirManager, 'openDatabaseOrNone');
$dirOpen->setAccessible(true);
$t->same(null, $dirOpen->invoke($dirManager), 'an unopenable database path returns none');
@rmdir($dirPath);

$t->section('a throwing event sink is swallowed');
$throwingSinkCount = [0];
$manager13 = new IpInfoManager(
    token: 'test-token',
    dbPath: (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb',
    httpClient: new LifecycleStubClient([
        new HttpResponse(500, 'no'),
        new HttpResponse(500, 'no'),
        new HttpResponse(500, 'no'),
    ]),
    eventSink: static function (object $event) use (&$throwingSinkCount): void {
        $throwingSinkCount[0]++;
        throw new RuntimeException('sink down');
    },
    sleep: static function (float $seconds): void {
    },
    clock: static fn (): int => 1700000000
);
$manager13->initialize();
$t->same(1, $throwingSinkCount[0], 'the failure event reached the sink exactly once');

$t->section('refresh with garbage bytes keeps the reader');
$client14 = new LifecycleStubClient([
    new HttpResponse(200, geoMmdbBytes()),
    new HttpResponse(200, 'this is not an mmdb'),
]);
$path14 = (string) tempnam(sys_get_temp_dir(), 'geoip') . '.mmdb';
@unlink($path14);
$manager14 = new IpInfoManager(
    token: 'test-token',
    dbPath: $path14,
    httpClient: $client14,
    clock: static fn (): int => 1700000000
);
$manager14->initialize();
$t->same('US', $manager14->getCountry(GEO_US_IP), 'initial good database');
$manager14->refresh();
$t->same('US', $manager14->getCountry(GEO_US_IP), 'a garbage refresh keeps the existing reader');

$t->section('contended lock with a filled cache');
$stub15 = new class implements HttpClient {
    public int $calls = 0;

    public function get(string $url, array $options = []): HttpResponse
    {
        $this->calls++;

        return new HttpResponse(200, (string) json_encode([
            'prefixes' => [
                ['ip_prefix' => '203.0.113.0/24', 'region' => 'us-east-1', 'service' => 'AMAZON'],
            ],
        ]));
    }
};
$fake6 = new FakeRespConnection();
$cloudRedis6 = new RedisHandler(true, 'guard_core_cloud3:', connection: $fake6);
$store6 = new RedisCloudIpStore($cloudRedis6);
$store6->set('AWS', ['203.0.113.0/24|us-east-1'], 3600);
$foreign = new RedisLock($cloudRedis6);
$foreign->acquire(CloudManager::REFRESH_LOCK_NAMESPACE, 'AWS', 'foreign-worker', CloudManager::REFRESH_LOCK_TTL_MS);
$contended = new CloudManager($stub15, $store6, new SimpleRequestLogger());
$contended->initializeRedis($cloudRedis6, ['AWS'], 3600);
$t->same(0, $stub15->calls, 'no fetch under the foreign lock');
$t->truthy($contended->isCloudIp('203.0.113.5', ['AWS']), 'the cache re-read installed the ranges');

$t->section('redis lock failure arms');
$fake7 = new FakeRespConnection();
$fake7->failWrites = true;
$failingRedis = new RedisHandler(true, 'guard_core_lock2:', connection: $fake7);
$failingLock = new RedisLock($failingRedis);
$t->truthy($failingLock->acquire('ns', 'k', 't', 5000), 'a failing redis degrades to uncontended');
$failingLock->release('ns', 'k', 't');
$t->truthy(true, 'a failing release does not throw');
$disabledLock2 = new RedisLock(new RedisHandler(false, 'guard_core_lock2:', connection: $fake7));
$disabledLock2->release('ns', 'k', 't');
$t->truthy(true, 'a disabled release does not throw');


$t->section('contention re-read installs a filled cache');
$fake8 = new FakeRespConnection();
$cloudRedis8 = new RedisHandler(true, 'guard_core_cloud4:', connection: $fake8);
$stub17 = new class implements HttpClient {
    public int $calls = 0;

    public function get(string $url, array $options = []): HttpResponse
    {
        $this->calls++;

        return new HttpResponse(200, '{}');
    }
};
$flaky = new class ($cloudRedis8) extends RedisCloudIpStore {
    public int $gets = 0;

    /** @var list<string> */
    public array $sets = [];

    public function get(string $provider): ?array
    {
        $this->gets++;

        return $this->gets === 1 ? null : ['203.0.113.0/24|us-east-1'];
    }

    public function set(string $provider, array $ranges, ?int $ttl = null): void
    {
        $this->sets[] = $provider;
    }
};
$foreign8 = new RedisLock($cloudRedis8);
$foreign8->acquire(CloudManager::REFRESH_LOCK_NAMESPACE, 'AWS', 'foreign-worker', CloudManager::REFRESH_LOCK_TTL_MS);
$contended8 = new CloudManager($stub17, $flaky, new SimpleRequestLogger());
$contended8->initializeRedis($cloudRedis8, ['AWS'], 3600);
$t->same(0, $stub17->calls, 'no fetch while the foreign worker holds the lock');
$t->truthy($contended8->isCloudIp('203.0.113.5', ['AWS']), 'the re-read installed the ranges the other worker wrote');
$t->same([], $flaky->sets, 'the contended worker wrote nothing');

$t->section('store failures keep the provider entry');
$fake9 = new FakeRespConnection();
$fake9->failWrites = true;
$failingManager = new CloudManager(
    new LifecycleStubClient([new HttpResponse(200, '{}')]),
    new RedisCloudIpStore(new RedisHandler(true, 'guard_core_cloud5:', connection: $fake9)),
    new SimpleRequestLogger()
);
$failingManager->initializeRedis(new RedisHandler(true, 'guard_core_cloud5:', connection: $fake9), ['AWS'], 3600);
$t->same(false, $failingManager->isCloudIp('203.0.113.5', ['AWS']), 'a failing store leaves the provider unblocked');
$t->same(false, $failingManager->getStatus()['AWS']['ready'], 'the provider entry exists but is not ready');

$t->section('verdicts without an event sink stay silent');
$noSink = new IpInfoManager(
    token: 'test-token',
    dbPath: $path,
    httpClient: new LifecycleStubClient([]),
    clock: static fn (): int => 1700000000
);
$noSink->initialize();
[$allowed] = $noSink->checkCountryAccess(GEO_BR_IP, ['BR']);
$t->same(false, $allowed, 'the block verdict holds without a sink');

exit($t->finish('GEO LIFECYCLE'));

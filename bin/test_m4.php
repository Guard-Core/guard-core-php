<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Cloud\CloudHttpException;
use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Cloud\CloudIpStore;
use RenzoFranceschini\GuardCore\Cloud\CloudProviderRegistry;
use RenzoFranceschini\GuardCore\Cloud\HttpClient;
use RenzoFranceschini\GuardCore\Cloud\HttpResponse;
use RenzoFranceschini\GuardCore\Cloud\InMemoryCloudIpStore;
use RenzoFranceschini\GuardCore\Cloud\RedisCloudIpStore;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Config\UnsupportedFeatureError;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/FakeRespConnection.php';

final class T
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

    public function throws(string $class, callable $fn, string $label): void
    {
        try {
            $fn();
            $this->failed++;
            echo "FAIL - {$label}\n  expected {$class} but nothing was thrown\n";
        } catch (\Throwable $e) {
            $this->same($class, $e::class, $label);
        }
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

final class M4StubClient implements HttpClient
{
    public int $calls = 0;

    /** @var array<string, int> */
    public array $callsByUrl = [];

    /** @var array<string, string> */
    private array $bodies;

    /** @var list<string> */
    private array $throwOn;

    /**
     * @param array<string, string> $bodies
     * @param list<string> $throwOn substrings of urls that fail with a transport error
     */
    public function __construct(array $bodies = [], array $throwOn = [])
    {
        $this->bodies = $bodies;
        $this->throwOn = $throwOn;
    }

    public function get(string $url, array $options = []): HttpResponse
    {
        $this->calls++;
        $this->callsByUrl[$url] = ($this->callsByUrl[$url] ?? 0) + 1;
        foreach ($this->throwOn as $needle) {
            if (str_contains($url, $needle)) {
                throw new CloudHttpException('stub transport failure for ' . $url);
            }
        }

        return new HttpResponse(200, $this->bodies[$url] ?? '{}');
    }
}

final class M4RecordingLogger implements RenzoFranceschini\GuardCore\Logging\RequestLogger
{
    /** @var list<string> */
    public array $lines = [];

    public function log(string $level, string $message, array $context = []): void
    {
        $this->lines[] = $level . ': ' . $message;
    }

    public function countContaining(string $needle): int
    {
        return count(array_filter($this->lines, fn (string $line): bool => str_contains($line, $needle)));
    }
}

final class M4CountingStore implements CloudIpStore
{
    public int $gets = 0;
    public int $sets = 0;

    private InMemoryCloudIpStore $inner;

    public function __construct()
    {
        $this->inner = new InMemoryCloudIpStore();
    }

    public function get(string $provider): ?array
    {
        $this->gets++;

        return $this->inner->get($provider);
    }

    /** @param list<string> $ranges */
    public function set(string $provider, array $ranges, ?int $ttl = null): void
    {
        $this->sets++;
        $this->inner->set($provider, $ranges, $ttl);
    }

    public function clear(): void
    {
        $this->inner->clear();
    }
}

$t = new T();

function m4Request(string $path = '/', string $ip = '9.9.9.9', array $headers = [], string $scheme = 'http'): SimpleGuardRequest
{
    $request = new SimpleGuardRequest(urlPath: $path, urlScheme: $scheme, headers: $headers);
    $request->state()->clientIp = $ip;

    return $request;
}

function m4AwsBody(): string
{
    return (string) json_encode([
        'prefixes' => [
            ['ip_prefix' => '10.1.0.0/16', 'region' => 'us-east-1', 'service' => 'AMAZON'],
            ['ip_prefix' => '10.2.0.0/16', 'region' => 'us-west-2', 'service' => 'AMAZON'],
            ['ip_prefix' => '10.3.0.0/16', 'service' => 'AMAZON'],
            ['ip_prefix' => '192.168.1.0/24', 'region' => 'eu-west-1', 'service' => 'EC2'],
        ],
    ]);
}

function m4GcpBody(): string
{
    return (string) json_encode([
        'prefixes' => [
            ['ipv4Prefix' => '172.16.0.0/12', 'scope' => 'us-central1'],
            ['ipv6Prefix' => '2001:db8::/32', 'scope' => 'us-central1'],
        ],
    ]);
}

function m4StubBodies(): array
{
    return [
        'https://ip-ranges.amazonaws.com/ip-ranges.json' => m4AwsBody(),
        'https://www.gstatic.com/ipranges/cloud.json' => m4GcpBody(),
    ];
}

/** @param array<string, RouteConfig>|null $routeConfigs */
function m4Pipeline(SecurityConfig $config, ?array $routeConfigs = null, ?CloudManager $cloudManager = null): SecurityCheckPipeline
{
    $builder = new CheckFactory(
        new GuardResponseFactory(),
        new RouteResolver($routeConfigs ?? []),
        null,
        null,
        null,
        $cloudManager
    );

    return new SecurityCheckPipeline($builder->buildChecks($config, $routeConfigs), $config);
}

$t->section('config: cloud_ip_refresh_interval');
$t->same(3600, (new SecurityConfig())->cloudIpRefreshInterval, 'default 3600');
$t->same(60, (new SecurityConfig(cloudIpRefreshInterval: 0))->cloudIpRefreshInterval, '0 clamps to 60');
$t->same(60, (new SecurityConfig(cloudIpRefreshInterval: 59))->cloudIpRefreshInterval, '59 clamps to 60');
$t->same(86400, (new SecurityConfig(cloudIpRefreshInterval: 86401))->cloudIpRefreshInterval, '86401 clamps to 86400');
$t->same(86400, (new SecurityConfig(cloudIpRefreshInterval: 86400))->cloudIpRefreshInterval, '86400 stays');
$t->same(120, (new SecurityConfig(cloudIpRefreshInterval: 120))->cloudIpRefreshInterval, 'in-range value stays');
$t->same(60, (new SecurityConfig())->with(['cloud_ip_refresh_interval' => 59])->cloudIpRefreshInterval, 'with() clamps too');

$t->section('config: block_cloud_providers un-gated');
$t->same([], (new SecurityConfig())->blockCloudProviders, 'default empty');
$t->same(['AWS', 'GCP:!us-central1'], (new SecurityConfig(blockCloudProviders: ['AWS', 'GCP:!us-central1']))->blockCloudProviders, 'selectors accepted verbatim');
$t->same(['AWS'], (new SecurityConfig(blockCloudProviders: ['AWS', 'AWS']))->blockCloudProviders, 'duplicates collapse');
$t->same(['AWS'], (new SecurityConfig())->with(['block_cloud_providers' => ['AWS']])->blockCloudProviders, 'with() accepts block_cloud_providers');
$t->throws(\InvalidArgumentException::class, fn () => new SecurityConfig(blockCloudProviders: ['AWSX']), 'unknown provider name rejected');
$t->throws(\InvalidArgumentException::class, fn () => new SecurityConfig(blockCloudProviders: ['aws']), 'provider names case-sensitive');
$t->throws(\InvalidArgumentException::class, fn () => new SecurityConfig(blockCloudProviders: ['Foo:!region']), 'carve-out on unknown provider rejected');
$t->throws(UnsupportedFeatureError::class, fn () => new SecurityConfig(blockedCountries: ['CN']), 'geo country blocking still fail-closed');
$t->throws(UnsupportedFeatureError::class, fn () => new SecurityConfig(enableDynamicRules: true), 'dynamic rules still fail-closed');
$t->same(true, (new SecurityConfig(blockCloudProviders: ['AWS']))->cloudBlockingEnabled(), 'cloudBlockingEnabled true with providers');
$t->same(false, (new SecurityConfig())->cloudBlockingEnabled(), 'cloudBlockingEnabled false without providers');

$t->section('route_config: block_cloud_providers leniency');
$t->same(['AWS'], (new RouteConfig(blockCloudProviders: ['AWS', 'nope', 'AWS']))->blockCloudProviders, 'invalid names dropped, duplicates collapse');
$t->same(['GCP:!us-central1'], (new RouteConfig(blockCloudProviders: ['GCP:!us-central1']))->blockCloudProviders, 'carve-out selector kept');
$t->same([], (new RouteConfig())->blockCloudProviders, 'default empty');

$t->section('registry: selector parsing');
$t->same([['AWS'], []], CloudProviderRegistry::parseCloudSelectors(['AWS']), 'bare selector is a plain block');
$t->same([['GCP'], ['GCP' => ['us-central1']]], CloudProviderRegistry::parseCloudSelectors(['GCP:!us-central1']), 'carve-out parsed');
$t->same([['Azure'], []], CloudProviderRegistry::parseCloudSelectors(['Azure:!']), 'trailing bare ! is a plain block, no carve-out');
$t->same([['AWS'], []], CloudProviderRegistry::parseCloudSelectors(['AWS:!']), 'empty region registers nothing');
$t->same([['GCP'], ['GCP' => ['a', 'b']]], CloudProviderRegistry::parseCloudSelectors(['GCP:!a', 'GCP:!b']), 'multiple carve-outs union');
$t->same([['AWS'], ['AWS' => ['x']]], CloudProviderRegistry::parseCloudSelectors(['AWS', 'AWS:!x']), 'blocked deduped, carve-out kept');
$t->same([['GCP', 'AWS'], []], CloudProviderRegistry::parseCloudSelectors(['GCP', 'AWS']), 'order preserved');
$t->same(['GCP', 'AWS'], CloudProviderRegistry::bareProviderNames(['GCP:!us-central1', 'AWS']), 'bare names split at first :!');

$t->section('registry: cached entry encode/decode');
$t->same(['10.0.0.0/8|us-east-1'], CloudProviderRegistry::encodeCached(['10.0.0.0/8' => true], ['10.0.0.0/8' => 'us-east-1']), 'region joined with |');
$t->same(['10.0.0.0/8'], CloudProviderRegistry::encodeCached(['10.0.0.0/8' => true], []), 'no region keeps bare network');
$decoded = CloudProviderRegistry::decodeCached(['10.0.0.0/8|us-east-1', '10.2.0.0/16']);
$t->same(['10.0.0.0/8' => true, '10.2.0.0/16' => true], $decoded[0], 'decode splits networks');
$t->same(['10.0.0.0/8' => 'us-east-1'], $decoded[1], 'decode keeps regions');
$canonical = CloudProviderRegistry::decodeCached(['10.1.2.3/8']);
$t->same(['10.0.0.0/8' => true], $canonical[0], 'decode canonicalizes prefix');
$t->throws(\InvalidArgumentException::class, fn () => CloudProviderRegistry::decodeCached(['not-a-cidr']), 'corrupt cache entry throws');

$t->section('cloud manager: fetch and matching');
$client = new M4StubClient(m4StubBodies());
$manager = new CloudManager($client);
$manager->refreshAsync(['AWS']);
$t->same(1, $client->calls, 'one fetch per provider');
$t->same(3, count($manager->ipRanges['AWS']), 'AMAZON service prefixes installed, others skipped');
$t->same('us-east-1', $manager->networkRegions['AWS']['10.1.0.0/16'], 'region map installed');
$t->same(false, $manager->lastUpdated['AWS'] === null, 'last_updated stamped on non-empty fetch');
$t->same(true, $manager->isCloudIp('10.1.2.3', ['AWS']), 'matching network blocks');
$t->same(false, $manager->isCloudIp('192.168.1.5', ['AWS']), 'non-AMAZON service range not registered');
$t->same(false, $manager->isCloudIp('10.2.2.3', ['AWS:!us-west-2']), 'carve-out region allowed');
$t->same(true, $manager->isCloudIp('10.2.2.3', ['AWS']), 'same ip blocked without carve-out');
$t->same(true, $manager->isCloudIp('10.3.0.5', ['AWS:!us-west-2']), 'range without region never carved out');
$t->same(false, $manager->isCloudIp('not-an-ip', ['AWS']), 'unparseable ip not blocked');
$t->same(false, $manager->isCloudIp('10.1.2.3', ['NoSuchProvider']), 'provider absent from registry skipped');
$client->calls = 0;
$gcpManager = new CloudManager($client);
$gcpManager->refreshAsync(['GCP']);
$t->same(true, $gcpManager->isCloudIp('172.16.5.5', ['GCP']), 'ipv4Prefix parsed');
$t->same(['GCP', '2001:db8::/32'], $gcpManager->getCloudProviderDetails('2001:db8::1', ['GCP']), 'ipv6Prefix details render canonical network');
$t->same(['AWS', '10.1.0.0/16'], $manager->getCloudProviderDetails('10.1.2.3', ['AWS']), 'details are provider and str(network)');
$t->same(null, $manager->getCloudProviderDetails('8.8.8.8', ['AWS']), 'no match returns null');
$counting = new M4CountingStore();
$hotManager = new CloudManager(new M4StubClient(m4StubBodies()), $counting);
$hotManager->refreshAsync(['AWS']);
$counting->gets = 0;
$t->same(true, $hotManager->isCloudIp('10.1.2.3', ['AWS']), 'hot path match');
$t->same(false, $hotManager->isCloudIp('8.8.8.8', ['AWS']), 'hot path miss');
$t->same(0, $counting->gets, 'is_cloud_ip reads only the in-memory layer');

$t->section('cloud manager: empty ranges and 300s warning cooldown');
$now = 1000.0;
$coolLogger = new M4RecordingLogger();
$coolManager = new CloudManager(null, null, $coolLogger, static function () use (&$now): float {
    return $now;
});
$t->same(false, $coolManager->isCloudIp('10.1.2.3', ['AWS']), 'unpopulated provider blocks nothing (fail open)');
$t->same(1, $coolLogger->countContaining('not populated yet'), 'empty ranges warning logged once');
$t->same(false, $coolManager->isCloudIp('10.1.2.3', ['AWS']), 'second call still not blocked');
$t->same(1, $coolLogger->countContaining('not populated yet'), 'warning suppressed within 300s cooldown');
$now += 301;
$t->same(false, $coolManager->isCloudIp('10.1.2.3', ['AWS']), 'after cooldown still fail open');
$t->same(2, $coolLogger->countContaining('not populated yet'), 'warning re-emitted after 300s cooldown');
$failingClient = new M4StubClient([], ['amazonaws']);
$failManager = new CloudManager($failingClient);
$failManager->refreshAsync(['AWS']);
$t->same([], $failManager->ipRanges['AWS'], 'failed fetch leaves empty in-memory entry');
$t->same(null, $failManager->lastUpdated['AWS'], 'failed fetch does not stamp last_updated');
$emptyClient = new M4StubClient(['https://ip-ranges.amazonaws.com/ip-ranges.json' => (string) json_encode(['prefixes' => []])]);
$emptyStore = new M4CountingStore();
$emptyManager = new CloudManager($emptyClient, $emptyStore);
$emptyManager->refreshAsync(['AWS']);
$t->same(0, $emptyStore->sets, 'empty fetch result is not cached');
$t->same(null, $emptyManager->lastUpdated['AWS'], 'empty fetch does not update last_updated');

$t->section('store: null vs empty distinction');
$now = 1000.0;
$memStore = new InMemoryCloudIpStore(static function () use (&$now): float {
    return $now;
});
$t->same(null, $memStore->get('AWS'), 'miss returns None (refresh eligible)');
$memStore->set('AWS', [], 3600);
$t->same([], $memStore->get('AWS'), 'empty set is a hit (known, no ranges)');
$memStore->set('AWS', ['10.0.0.0/8'], 100);
$now += 101;
$t->same(null, $memStore->get('AWS'), 'ttl expiry returns to None');
$knownEmptyClient = new M4StubClient(m4StubBodies());
$knownEmptyStore = new InMemoryCloudIpStore();
$knownEmptyStore->set('AWS', [], null);
$knownEmptyManager = new CloudManager($knownEmptyClient, $knownEmptyStore);
$knownEmptyManager->refreshAsync(['AWS']);
$t->same(0, $knownEmptyClient->calls, 'cached empty entry is a hit: no network fetch');
$t->same([], $knownEmptyManager->ipRanges['AWS'], 'known-empty installed in memory');
$missManager = new CloudManager(new M4StubClient(m4StubBodies()), new InMemoryCloudIpStore());
$missManager->refreshAsync(['AWS']);
$t->same(3, count($missManager->ipRanges['AWS']), 'store miss goes to network fetch');

$t->section('manager: single-flight refresh');
$inFlightManager = new CloudManager(new M4StubClient(m4StubBodies()));
$innerResult = null;
$outer = $inFlightManager->scheduleRefresh(['AWS'], 3600, static function () use (&$innerResult, $inFlightManager): void {
    $innerResult = $inFlightManager->scheduleRefresh(['AWS'], 3600);
});
$t->same(false, $innerResult, 'call while refresh in flight is a no-op returning false');
$t->same(true, $outer, 'outer call scheduled');
$t->same(true, $inFlightManager->scheduleRefresh(['AWS'], 3600), 'in-flight cleared after refresh completes');
$throwingManager = new CloudManager(new M4StubClient(m4StubBodies()));
$throwResult = $throwingManager->scheduleRefresh(['AWS'], 3600, static function (): void {
    throw new RuntimeException('refresh blew up');
});
$t->same(true, $throwResult, 'refresh failure does not propagate, scheduling reported');

$t->section('cloud_ip_refresh check: stamp advance and rollback');
$ttlNow = 1000.0;
$ttlStore = new InMemoryCloudIpStore(static function () use (&$ttlNow): float {
    return $ttlNow;
});
$ttlClient = new M4StubClient(m4StubBodies());
$ttlManager = new CloudManager($ttlClient, $ttlStore);
$ttlConfig = new SecurityConfig(blockCloudProviders: ['AWS'], cloudIpRefreshInterval: 120);
$refreshCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudIpRefreshCheck($ttlConfig, new GuardResponseFactory(), $ttlManager, new RouteResolver());
$before = time();
$t->same(null, $refreshCheck->check(m4Request()), 'refresh check never blocks');
$t->same(true, $ttlManager->lastCloudIpRefresh >= $before, 'due stamp advanced to int(time())');
$t->same(1, $ttlClient->calls, 'due stamp scheduled refresh (network fetch ran)');
$ttlNow += 121;
$t->same(null, $ttlStore->get('AWS'), 'refresh ttl equals cloud_ip_refresh_interval');
$withinManager = new CloudManager(new M4StubClient(m4StubBodies()));
$stampBefore = time() - 10;
$withinManager->lastCloudIpRefresh = $stampBefore;
$withinConfig = new SecurityConfig(blockCloudProviders: ['AWS'], cloudIpRefreshInterval: 3600);
$withinCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudIpRefreshCheck($withinConfig, new GuardResponseFactory(), $withinManager, new RouteResolver());
$t->same(null, $withinCheck->check(m4Request()), 'within interval: no refresh');
$t->same($stampBefore, $withinManager->lastCloudIpRefresh, 'within interval: stamp untouched');
$dueManager = new CloudManager(new M4StubClient(m4StubBodies()));
$dueStamp = time() - 4000;
$dueManager->lastCloudIpRefresh = $dueStamp;
$dueCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudIpRefreshCheck($withinConfig, new GuardResponseFactory(), $dueManager, new RouteResolver());
$t->same(null, $dueCheck->check(m4Request()), 'past interval: never blocks');
$t->same(true, $dueManager->lastCloudIpRefresh > $dueStamp, 'past interval: stamp advanced');
$rollManager = new CloudManager(new M4StubClient(m4StubBodies()));
$rollManager->lastCloudIpRefresh = 12345;
$flip = \Closure::bind(static function (CloudManager $cm, bool $inFlight): void {
    $cm->refreshInFlight = $inFlight;
}, null, CloudManager::class);
$flip($rollManager, true);
$rollCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudIpRefreshCheck($withinConfig, new GuardResponseFactory(), $rollManager, new RouteResolver());
$t->same(null, $rollCheck->check(m4Request()), 'single-flight busy: check still allows');
$t->same(12345, $rollManager->lastCloudIpRefresh, 'scheduling failure rolls the stamp back');
$flip($rollManager, false);
$globalEmptyCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudIpRefreshCheck(new SecurityConfig(), new GuardResponseFactory(), new CloudManager(new M4StubClient()), new RouteResolver());
$t->same(null, $globalEmptyCheck->check(m4Request()), 'no providers: refresh check is a no-op');
$routeRefreshConfig = new SecurityConfig(cloudIpRefreshInterval: 3600);
$routeOnlyManager = new CloudManager($routeClient = new M4StubClient(m4StubBodies()));
$routeRefreshCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudIpRefreshCheck($routeRefreshConfig, new GuardResponseFactory(), $routeOnlyManager, new RouteResolver());
$routeRefreshReq = m4Request();
$routeRefreshReq->state()->routeConfig = new RouteConfig(blockCloudProviders: ['GCP']);
$t->same(null, $routeRefreshCheck->check($routeRefreshReq), 'route-only providers: no-op verdict');
$t->same(0, $routeClient->callsByUrl['https://ip-ranges.amazonaws.com/ip-ranges.json'] ?? 0, 'route providers drive the fetch set: AWS untouched');
$t->same(1, $routeClient->callsByUrl['https://www.gstatic.com/ipranges/cloud.json'] ?? 0, 'route providers drive the fetch set: GCP fetched');

$t->section('cloud_provider check: direct skips');
$populatedManager = new CloudManager(new M4StubClient(m4StubBodies()));
$populatedManager->refreshAsync(['AWS', 'GCP']);
$cloudConfig = new SecurityConfig(blockCloudProviders: ['AWS']);
$cloudCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudProviderCheck($cloudConfig, new GuardResponseFactory(), $populatedManager, new RouteResolver());
$freshRequest = new SimpleGuardRequest();
$t->same(null, $cloudCheck->check($freshRequest), 'no client ip: skip');
$whitelistedRequest = m4Request(ip: '10.1.2.3');
$whitelistedRequest->state()->isWhitelisted = true;
$t->same(null, $cloudCheck->check($whitelistedRequest), 'whitelisted request: skip');
$bypassRequest = m4Request(ip: '10.1.2.3');
$bypassRequest->state()->routeConfig = new RouteConfig(bypassedChecks: ['clouds']);
$t->same(null, $cloudCheck->check($bypassRequest), 'clouds bypass: skip');
$allBypassRequest = m4Request(ip: '10.1.2.3');
$allBypassRequest->state()->routeConfig = new RouteConfig(bypassedChecks: ['all']);
$t->same(null, $cloudCheck->check($allBypassRequest), 'all bypass: skip');
$t->same(null, (new RenzoFranceschini\GuardCore\Pipeline\Checks\CloudProviderCheck(new SecurityConfig(), new GuardResponseFactory(), $populatedManager, new RouteResolver()))->check(m4Request(ip: '10.1.2.3')), 'no providers to check: skip');
$t->same(null, $cloudCheck->check(m4Request(ip: '8.8.8.8')), 'not a cloud ip: allow');

$t->section('pipeline: cloud_provider verdicts');
$blockPipeline = m4Pipeline(new SecurityConfig(blockCloudProviders: ['AWS']), [], $populatedManager);
$blocked = $blockPipeline->execute(m4Request(ip: '10.1.2.3'));
$t->same(403, $blocked?->statusCode(), 'cloud ip blocked with 403');
$t->same('Cloud provider IP not allowed', $blocked?->body(), '403 default message');
$customPipeline = m4Pipeline(new SecurityConfig(blockCloudProviders: ['AWS'], customErrorResponses: [403 => 'no clouds here']), [], $populatedManager);
$t->same('no clouds here', $customPipeline->execute(m4Request(ip: '10.1.2.3'))?->body(), 'custom_error_responses override 403 body');
$t->same(null, $blockPipeline->execute(m4Request(ip: '8.8.8.8')), 'non-cloud ip allowed');
$hookPayloads = [];
$hook = static function ($request, array $payload) use (&$hookPayloads): void {
    $hookPayloads[] = $payload;
};
$activeHookPipeline = m4Pipeline(new SecurityConfig(blockCloudProviders: ['AWS'], onBlock: $hook), [], $populatedManager);
$hookPayloads = [];
$t->same(403, $activeHookPipeline->execute(m4Request(ip: '10.1.2.3'))?->statusCode(), 'active block fires hook path');
$t->same(1, count($hookPayloads), 'on_block fired exactly once');
$t->same('cloud_provider', $hookPayloads[0]['check_name'] ?? null, 'check_name in payload');
$t->same('Blocked cloud provider IP: 10.1.2.3', $hookPayloads[0]['reason'] ?? null, 'reason from suspicious log');
$t->same('', $hookPayloads[0]['trigger_info'] ?? null, 'trigger_info empty');
$t->same(false, $hookPayloads[0]['passive_mode'] ?? null, 'passive_mode false on short-circuit');
$t->same(403, $hookPayloads[0]['status_code'] ?? null, 'status_code 403 on short-circuit');
$passiveHookPipeline = m4Pipeline(new SecurityConfig(blockCloudProviders: ['AWS'], passiveMode: true, onBlock: $hook), [], $populatedManager);
$hookPayloads = [];
$t->same(null, $passiveHookPipeline->execute(m4Request(ip: '10.1.2.3')), 'passive mode never blocks');
$t->same(1, count($hookPayloads), 'passive mode fires on_block inline');
$t->same(true, $hookPayloads[0]['passive_mode'] ?? null, 'passive_mode true in payload');
$t->same(null, $hookPayloads[0]['status_code'] ?? null, 'passive payload has no status code');
$whitelistPipeline = m4Pipeline(new SecurityConfig(blockCloudProviders: ['AWS'], whitelist: ['10.1.2.3']), [], $populatedManager);
$t->same(null, $whitelistPipeline->execute(m4Request(ip: '10.1.2.3')), 'whitelisted request skips cloud_provider');
$routeBypassPipeline = m4Pipeline(new SecurityConfig(blockCloudProviders: ['AWS']), [], $populatedManager);
$bypassViaRoute = m4Request(ip: '10.1.2.3');
$bypassViaRoute->state()->routeConfig = new RouteConfig(bypassedChecks: ['clouds']);
$t->same(null, $routeBypassPipeline->execute($bypassViaRoute), 'clouds bypass through pipeline');

$t->section('pipeline: route-level provider lists');
$routeOnlyConfigs = ['gcp' => new RouteConfig(blockCloudProviders: ['GCP'])];
$routePipeline = m4Pipeline(new SecurityConfig(), $routeOnlyConfigs, $populatedManager);
$routeRequest = m4Request(ip: '172.16.5.5');
$routeRequest->state()->guardRouteId = 'gcp';
$t->same(403, $routePipeline->execute($routeRequest)?->statusCode(), 'route-only cloud blocking enforces on its route');
$plainRequest = m4Request(ip: '172.16.5.5');
$t->same(null, $routePipeline->execute($plainRequest), 'no route: global empty allows');
$overridePipeline = m4Pipeline(new SecurityConfig(blockCloudProviders: ['AWS']), ['gcponly' => new RouteConfig(blockCloudProviders: ['GCP'])], $populatedManager);
$overrideRequest = m4Request(ip: '10.1.2.3');
$overrideRequest->state()->guardRouteId = 'gcponly';
$t->same(null, $overridePipeline->execute($overrideRequest), 'route list overrides global: AWS ip allowed on GCP-only route');
$overrideBlockRequest = m4Request(ip: '172.16.5.5');
$overrideBlockRequest->state()->guardRouteId = 'gcponly';
$t->same(403, $overridePipeline->execute($overrideBlockRequest)?->statusCode(), 'route list overrides global: GCP ip blocked on route');

$t->section('factory: cloud gating and slot order');
$builder = new CheckFactory(new GuardResponseFactory(), new RouteResolver(), null, null, null, new CloudManager(new M4StubClient()));
$namesWithClouds = array_map(fn ($c) => $c->checkName(), $builder->buildChecks(new SecurityConfig(blockCloudProviders: ['AWS']), []));
$t->same(['route_config', 'cloud_ip_refresh', 'ip_security', 'cloud_provider', 'rate_limit', 'suspicious_activity'], $namesWithClouds, 'cloud pair at slots 11 and 13, refresh precedes blocking');
$namesWithout = array_map(fn ($c) => $c->checkName(), $builder->buildChecks(new SecurityConfig(), []));
$t->same(false, in_array('cloud_ip_refresh', $namesWithout, true), 'no global clouds and empty routes: refresh check absent');
$t->same(false, in_array('cloud_provider', $namesWithout, true), 'no global clouds and empty routes: block check absent');
$routeGatedNames = array_map(fn ($c) => $c->checkName(), $builder->buildChecks(new SecurityConfig(), array_values($routeOnlyConfigs)));
$t->same(true, in_array('cloud_ip_refresh', $routeGatedNames, true), 'route-only clouds: refresh check constructed');
$t->same(true, in_array('cloud_provider', $routeGatedNames, true), 'route-only clouds: block check constructed');
$nullRoutesNames = array_map(fn ($c) => $c->checkName(), $builder->buildChecks(new SecurityConfig()));
$t->same(true, in_array('cloud_ip_refresh', $nullRoutesNames, true), 'no decorator registered: route predicate vacuously satisfied (refresh)');
$t->same(true, in_array('cloud_provider', $nullRoutesNames, true), 'no decorator registered: route predicate vacuously satisfied (block)');

$t->section('pipeline: staleness on block_cloud_providers');
$smallConfig = new SecurityConfig(blockCloudProviders: ['AWS']);
$largeConfig = new SecurityConfig(blockCloudProviders: ['AWS', 'GCP']);
$sameSizeConfig = new SecurityConfig(blockCloudProviders: ['AWS', 'GCP']);
$configRef = static function () use (&$smallConfig): SecurityConfig {
    return $smallConfig;
};
$staleBuilder = new CheckFactory(new GuardResponseFactory(), new RouteResolver(), null, null, null, new CloudManager(new M4StubClient(m4StubBodies())));
$rebuilds = 0;
$stalePipeline = new SecurityCheckPipeline(
    $staleBuilder->buildChecks($smallConfig, []),
    $smallConfig,
    [],
    rebuildChecks: static function () use ($staleBuilder, $configRef, &$rebuilds): array {
        $rebuilds++;

        return $staleBuilder->buildChecks($configRef(), []);
    },
    configProvider: $configRef
);
$stalePipeline->execute(m4Request());
$t->same(0, $rebuilds, 'same revision and signature: no rebuild');
$smallConfig = $largeConfig;
$stalePipeline->execute(m4Request());
$t->same(1, $rebuilds, 'container signature change rebuilds even at equal revision');
$smallConfig = $sameSizeConfig;
$stalePipeline->execute(m4Request());
$t->same(1, $rebuilds, 'same size and revision: no rebuild');

$t->section('redis store: cloud_ip_v2 grammar over RESP');
$fake = new FakeRespConnection();
$fakeRedis = new RedisHandler(true, 'guard_core_m4u:', connection: $fake);
$fakeStore = new RedisCloudIpStore($fakeRedis);
$entries = CloudProviderRegistry::encodeCached(
    ['10.1.0.0/16' => true, '10.2.0.0/16' => true],
    ['10.1.0.0/16' => 'us-east-1']
);
$fakeStore->set('AWS', $entries, 3600);
$t->same('["10.1.0.0/16|us-east-1", "10.2.0.0/16"]', $fake->store['guard_core_m4u:cloud_ip_v2:AWS']['value'], 'payload is a sorted JSON list with python json.dumps ", " separators under {prefix}cloud_ip_v2:{provider}');
$t->same(['10.1.0.0/16|us-east-1', '10.2.0.0/16'], $fakeStore->get('AWS'), 'decode round-trips');
$fakeStore->set('GCP', ['10.3.0.0/16', '10.4.0.0/16'], 3600);
$t->same('["10.3.0.0/16", "10.4.0.0/16"]', $fake->store['guard_core_m4u:cloud_ip_v2:GCP']['value'], 'payload byte-matches python json.dumps list format (interop regression)');
$t->same(null, $fakeStore->get('MISSING'), 'redis miss returns null');
$fake->seed('guard_core_m4u:cloud_ip_v2:BAD', '{not-json');
$t->same(null, $fakeStore->get('BAD'), 'malformed payload treated as miss');
$fake->seed('guard_core_m4u:cloud_ip_v2:SCALAR', '"just-a-string"');
$t->same(null, $fakeStore->get('SCALAR'), 'non-list payload treated as miss');
$redisFromFake = new CloudManager(null, $fakeStore);
$redisFromFake->refreshAsync(['AWS']);
$t->same(2, count($redisFromFake->ipRanges['AWS']), 'cache hit installs ranges without network');
$t->same('us-east-1', $redisFromFake->networkRegions['AWS']['10.1.0.0/16'], 'regions survive redis round-trip');

$integration = getenv('REDIS_HOST') !== '0';
if ($integration) {
    $host = getenv('REDIS_HOST') ?: '127.0.0.1';
    $port = (int) (getenv('REDIS_PORT') ?: 6379);
    $socket = @fsockopen($host, $port, $errno, $errstr, 1.0);
    if ($socket === false) {
        echo "\nSKIP: integration mode: no redis reachable at {$host}:{$port} ({$errstr}); port may be owned by another session; unit coverage stands\n";
    } else {
        fclose($socket);
        runM4Integration($t);
    }
} else {
    echo "\nNOTE: integration mode off (set REDIS_HOST to run cloud store end-to-end)\n";
}

function runM4Integration(T $t): void
{
    putenv('REDIS_PREFIX=guard_core_m4:');
    $redis = RedisHandler::fromEnv();
    $redis->initialize();
    $conn = $redis->connection();
    m4DeleteOwnKeys($redis, $conn);

    $t->section('integration: redis cache hit path and cross-instance sharing');
    $store = new RedisCloudIpStore($redis);
    $clientA = new M4StubClient(m4StubBodies());
    $managerA = new CloudManager($clientA, $store);
    $managerA->refreshAsync(['AWS']);
    $t->same(1, $clientA->calls, 'manager A fetched from network and cached in redis');
    $t->same(true, $managerA->isCloudIp('10.1.2.3', ['AWS']), 'manager A matches from fetched ranges');

    $clientB = new M4StubClient();
    $managerB = new CloudManager($clientB, $store);
    $managerB->refreshAsync(['AWS']);
    $t->same(0, $clientB->calls, 'manager B cache hit: no network fetch');
    $t->same(true, $managerB->isCloudIp('10.1.2.3', ['AWS']), 'manager B hydrated from redis cache');
    $t->same(false, $managerB->isCloudIp('10.2.2.3', ['AWS:!us-west-2']), 'carve-out survives redis round-trip');
    $t->same(['AWS', '10.1.0.0/16'], $managerB->getCloudProviderDetails('10.1.2.3', ['AWS']), 'details from cached ranges');

    $store->set('GCP', [], 3600);
    $clientC = new M4StubClient();
    $managerC = new CloudManager($clientC, $store);
    $managerC->refreshAsync(['GCP']);
    $t->same(0, $clientC->calls, 'cached empty value is a hit, not a miss');
    $t->same([], $managerC->ipRanges['GCP'], 'null-vs-empty distinction preserved through redis');

    $t->section('integration: cloud block through pipeline over redis cache');
    $config = new SecurityConfig(blockCloudProviders: ['AWS']);
    $builder = new CheckFactory(new GuardResponseFactory(), new RouteResolver(), null, null, null, $managerB);
    $pipeline = new SecurityCheckPipeline($builder->buildChecks($config), $config);
    $t->same(403, $pipeline->execute(m4Request(ip: '10.1.2.3'))?->statusCode(), 'cloud block end-to-end via redis cache');
    $t->same('Cloud provider IP not allowed', $pipeline->execute(m4Request(ip: '10.1.2.3'))?->body(), '403 message end-to-end');
    $t->same(null, $pipeline->execute(m4Request(ip: '8.8.8.8')), 'non-cloud ip allowed end-to-end');

    m4DeleteOwnKeys($redis, $conn);
}

function m4DeleteOwnKeys(RedisHandler $redis, object $conn): void
{
    foreach ($redis->keys('*') as $key) {
        if (str_starts_with((string) $key, 'guard_core_m4:')) {
            $conn->del($key);
        }
    }
}

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);

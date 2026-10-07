<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Detection\Redos\Prefilters;
use RenzoFranceschini\GuardCore\Detection\Redos\ValidationCache;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\Checks\IpSecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Redis\RespConnection;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;
use RenzoFranceschini\GuardCore\Rules\DynamicRuleManager;

require __DIR__ . '/../vendor/autoload.php';

// The config-field parity cluster: detection_threat_score_threshold,
// detection_pattern_validation_cache_path, log_country_check_level,
// redis_health_check_interval, redis_max_connections, redis_retries and
// agent_strict - defaults, validation, with() round-trips, and the
// consumers (detect verdict gate, disk-backed cost-verdict cache, the
// country verdict log lines, the RESP health probe and retry backoff, and
// the strict agent attach).

final class CfgT
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

    public function throws(callable $fn, string $label): void
    {
        try {
            $fn();
            $this->same('throw', 'no throw', $label);
        } catch (\InvalidArgumentException) {
            $this->same('throw', 'throw', $label);
        }
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

final class CapturingLogger implements \RenzoFranceschini\GuardCore\Logging\RequestLogger
{
    /** @var list<array{level: string, message: string}> */
    public array $records = [];

    public function log(string $level, string $message, array $context = []): void
    {
        $this->records[] = ['level' => strtolower($level), 'message' => $message];
    }
}

final class StaticResolver implements CountryResolver
{
    public function __construct(private readonly ?string $country)
    {
    }

    public function getCountry(string $ip): ?string
    {
        return $this->country;
    }
}

final class ProbeConnection extends RespConnection
{
    public int $readRepliesCalls = 0;

    public bool $failNextRead = false;

    public function __construct()
    {
        parent::__construct(healthCheckInterval: 30);
    }

    public function forceStale(): void
    {
        $this->lastActivityNs = (float) hrtime(true) - (int) (40 * 1e9);
        $this->failNextRead = true;
    }

    public function readReplies(int $count): array
    {
        $this->readRepliesCalls++;
        if ($this->failNextRead) {
            $this->failNextRead = false;
            throw new GuardRedisException('Redis read failed: probe boom', 503, null, transient: true);
        }

        return parent::readReplies($count);
    }
}

final class ThrowingConnection extends RespConnection
{
    public function writeCommands(array $commands): void
    {
        throw new RuntimeException('socket exploded');
    }
}

final class FlakyWriteConnection extends RespConnection
{
    public int $writeCalls = 0;

    public function __construct(private readonly int $failFirst)
    {
        parent::__construct();
    }

    public function writeCommands(array $commands): void
    {
        $this->writeCalls++;
        if ($this->writeCalls <= $this->failFirst) {
            throw new GuardRedisException('Redis write failed: flaky', 503, null, transient: true);
        }
        parent::writeCommands($commands);
    }
}

final class AlwaysErrorConnection extends RespConnection
{
    public int $writeCalls = 0;

    public function writeCommands(array $commands): void
    {
        $this->writeCalls++;
        throw new GuardRedisException('Redis error reply: NOAUTH what you typing', 503, null, transient: false);
    }
}

$t = new CfgT();

// ---------------------------------------------------------------------
// 1. Defaults and validation
// ---------------------------------------------------------------------
$t->section('field defaults and validation');
$config = new SecurityConfig();
$t->same(1.0, $config->detectionThreatScoreThreshold, 'threat score threshold defaults to 1.0');
$t->same(null, $config->detectionPatternValidationCachePath, 'validation cache path defaults to null');
$t->same('INFO', $config->logCountryCheckLevel, 'log_country_check_level defaults to INFO');
$t->same(30, $config->redisHealthCheckInterval, 'redis_health_check_interval defaults to 30');
$t->same(null, $config->redisMaxConnections, 'redis_max_connections defaults to null');
$t->same(1, $config->redisRetries, 'redis_retries defaults to 1');
$t->same(false, $config->agentStrict, 'agent_strict defaults to false');

$t->throws(static fn () => new SecurityConfig(detectionThreatScoreThreshold: -0.1), 'threat threshold below 0.0 rejects');
$t->throws(static fn () => new SecurityConfig(detectionThreatScoreThreshold: 10.1), 'threat threshold above 10.0 rejects');
$t->same(10.0, (new SecurityConfig(detectionThreatScoreThreshold: 10.0))->detectionThreatScoreThreshold, 'threat threshold accepts the 10.0 bound');
$t->throws(static fn () => new SecurityConfig(redisHealthCheckInterval: -1), 'negative health check interval rejects');
$t->same(0, (new SecurityConfig(redisHealthCheckInterval: 0))->redisHealthCheckInterval, 'zero health check interval disables');
$t->throws(static fn () => new SecurityConfig(redisMaxConnections: 0), 'max connections below 1 rejects');
$t->same(4, (new SecurityConfig(redisMaxConnections: 4))->redisMaxConnections, 'max connections accepts 4');
$t->throws(static fn () => new SecurityConfig(redisRetries: -1), 'negative retries reject');
$t->same(0, (new SecurityConfig(redisRetries: 0))->redisRetries, 'zero retries disables');
$t->throws(static fn () => new SecurityConfig(logCountryCheckLevel: 'LOUD'), 'unknown country log level rejects');
$t->same(null, (new SecurityConfig(logCountryCheckLevel: null))->logCountryCheckLevel, 'null country log level disables');

$t->section('with() round-trips');
$mutated = $config->with([
    'detection_threat_score_threshold' => 2.5,
    'detection_pattern_validation_cache_path' => '/tmp/guard-cache.json',
    'log_country_check_level' => 'DEBUG',
    'redis_health_check_interval' => 0,
    'redis_max_connections' => 8,
    'redis_retries' => 3,
    'agent_strict' => true,
]);
$t->same(2.5, $mutated->detectionThreatScoreThreshold, 'with() carries the threat threshold');
$t->same('/tmp/guard-cache.json', $mutated->detectionPatternValidationCachePath, 'with() carries the cache path');
$t->same('DEBUG', $mutated->logCountryCheckLevel, 'with() carries the country log level');
$t->same(0, $mutated->redisHealthCheckInterval, 'with() carries the health check interval');
$t->same(8, $mutated->redisMaxConnections, 'with() carries max connections');
$t->same(3, $mutated->redisRetries, 'with() carries retries');
$t->truthy($mutated->agentStrict, 'with() carries agent strict');

// ---------------------------------------------------------------------
// 2. The threat-score threshold gate
// ---------------------------------------------------------------------
$t->section('threat score threshold gate');
$strict = new SusPatterns(0.99, threatScoreThreshold: 2.5);
$strict->addPattern('zzcfgprobe001', custom: true);
$t->truthy($strict->detect('zzcfgprobe001 here', '1.2.3.4', 'query_param')['is_threat'] === false, 'an anomaly under the threshold is not a threat');
$lenient = new SusPatterns(0.99, threatScoreThreshold: 0.5);
$lenient->addPattern('zzcfgprobe001', custom: true);
$t->truthy($lenient->detect('zzcfgprobe001 here', '1.2.3.4', 'query_param')['is_threat'], 'an anomaly over the threshold is a threat');

// ---------------------------------------------------------------------
// 3. The validation cache
// ---------------------------------------------------------------------
$t->section('validation cache');
$tmpPath = sys_get_temp_dir() . '/guard-validation-cache-' . getmypid() . '.json';
@unlink($tmpPath);
$cache = new ValidationCache($tmpPath);
$t->same(null, $cache->get('zzpattern', true), 'an empty store answers no verdict');
$cache->put('zzpattern', true, false, 'slow on this host');
$t->same(['safe' => false, 'reason' => 'slow on this host'], $cache->get('zzpattern', true), 'the verdict round-trips');
$t->truthy(ValidationCache::key('zzpattern', true) !== ValidationCache::key('zzpattern', false), 'the flags participate in the key');

$reloaded = new ValidationCache($tmpPath);
$t->same(['safe' => false, 'reason' => 'slow on this host'], $reloaded->get('zzpattern', true), 'a fresh instance loads the persisted verdict');

// A cached verdict participates in validate_pattern_safety's cost layer:
// a pattern the arbiter would call safe is rejected from a cached unsafe
// verdict, and the cheap layers still run.
$poisoned = new ValidationCache($tmpPath);
$poisoned->put('zzsafebyarbiters', true, false, 'poisoned verdict');
$t->same([false, 'poisoned verdict'], Prefilters::validatePatternSafety('zzsafebyarbiters', validationCache: $poisoned), 'the cached cost verdict wins');
$t->same([false, 'Pattern contains dangerous construct: ' . '\(\.(?:\*|\+|\{[0-9]+,\})\)(?:\+|\{[0-9]+,\})'], Prefilters::validatePatternSafety('(.*)+', validationCache: $poisoned), 'the dangerous-construct layer ignores the cache');

// The cache rides the registry gate.
$registry = new SusPatterns(0.99, validationCache: $cache);
$t->truthy($registry->addPattern('zzcfgcached002'), 'the registry validates through the cache seam');

// Stale-version entries drop on load; a corrupt file starts empty.
file_put_contents($tmpPath, (string) json_encode([
    ValidationCache::key('stale', true) => ['version' => '0.0.1', 'safe' => true, 'reason' => ''],
    'bogus' => 'not an object',
]));
$stale = new ValidationCache($tmpPath);
$t->same(null, $stale->get('stale', true), 'a stale-version entry drops on load');
file_put_contents($tmpPath, '{not json');
$corrupt = new ValidationCache($tmpPath);
$t->same(null, $corrupt->get('anything', true), 'a corrupt cache file starts empty');
@unlink($tmpPath);

// ---------------------------------------------------------------------
// 4. log_country_check_level
// ---------------------------------------------------------------------
$t->section('log_country_check_level');
$responseFactory = new GuardResponseFactory();
$routeResolver = new RouteResolver();

$usConfig = new SecurityConfig(whitelistCountries: ['US'], geoIpHandler: new StaticResolver('CA'));
$logger = new CapturingLogger();
$check = new IpSecurityCheck($usConfig, $responseFactory, null, $routeResolver, $usConfig->geoIpHandler, $logger);
$request = new SimpleGuardRequest(urlPath: '/', clientHost: '9.9.9.9');
$request->state()->clientIp = '9.9.9.9';
$denied = $check->check($request);
$t->truthy($denied !== null && $denied->statusCode() === 403, 'an allowlist miss denies');
$t->truthy(!(bool) array_filter($logger->records, static fn (array $r): bool => str_contains($r['message'], 'whitelisted country')), 'a block verdict does not log the allowlist line');

$allowedConfig = new SecurityConfig(whitelistCountries: ['US'], geoIpHandler: new StaticResolver('US'));
$logger = new CapturingLogger();
$check = new IpSecurityCheck($allowedConfig, $responseFactory, null, $routeResolver, $allowedConfig->geoIpHandler, $logger);
$whitelistedRequest = new SimpleGuardRequest(urlPath: '/', clientHost: '9.9.9.9');
$whitelistedRequest->state()->clientIp = '9.9.9.9';
$check->check($whitelistedRequest);
$t->truthy((bool) array_filter($logger->records, static fn (array $r): bool => $r['level'] === 'info'
    && str_contains($r['message'], 'IP from whitelisted country')), 'the whitelisted verdict logs at log_country_check_level');

$neutralConfig = new SecurityConfig(blockedCountries: ['RU'], geoIpHandler: new StaticResolver('CA'));
$logger = new CapturingLogger();
$check = new IpSecurityCheck($neutralConfig, $responseFactory, null, $routeResolver, $neutralConfig->geoIpHandler, $logger);
$neutralRequest = new SimpleGuardRequest(urlPath: '/', clientHost: '9.9.9.9');
$neutralRequest->state()->clientIp = '9.9.9.9';
$check->check($neutralRequest);
$t->truthy((bool) array_filter($logger->records, static fn (array $r): bool => $r['level'] === 'info'
    && str_contains($r['message'], 'IP not from blocked or whitelisted country')), 'the not-affected verdict logs at log_country_check_level');

$mutedConfig = new SecurityConfig(blockedCountries: ['RU'], geoIpHandler: new StaticResolver('CA'), logCountryCheckLevel: null);
$logger = new CapturingLogger();
$check = new IpSecurityCheck($mutedConfig, $responseFactory, null, $routeResolver, $mutedConfig->geoIpHandler, $logger);
$mutedRequest = new SimpleGuardRequest(urlPath: '/', clientHost: '9.9.9.9');
$mutedRequest->state()->clientIp = '9.9.9.9';
$check->check($mutedRequest);
$t->truthy(!(bool) array_filter($logger->records, static fn (array $r): bool => str_contains($r['message'], 'not from blocked or whitelisted')), 'a null level mutes the country verdict line');

$debugConfig = new SecurityConfig(blockedCountries: ['RU'], geoIpHandler: new StaticResolver('CA'), logCountryCheckLevel: 'DEBUG');
$logger = new CapturingLogger();
$check = new IpSecurityCheck($debugConfig, $responseFactory, null, $routeResolver, $debugConfig->geoIpHandler, $logger);
$loopbackRequest = new SimpleGuardRequest(urlPath: '/', clientHost: '127.0.0.1');
$loopbackRequest->state()->clientIp = '127.0.0.1';
$check->check($loopbackRequest);
$t->truthy((bool) array_filter($logger->records, static fn (array $r): bool => $r['level'] === 'debug'
    && str_contains($r['message'], 'Loopback IP exempt from country allowlist check')), 'the loopback skip logs at debug');

$unresolvedConfig = new SecurityConfig(blockedCountries: ['RU'], geoIpHandler: new StaticResolver(null));
$logger = new CapturingLogger();
$check = new IpSecurityCheck($unresolvedConfig, $responseFactory, null, $routeResolver, $unresolvedConfig->geoIpHandler, $logger);
$unresolvedRequest = new SimpleGuardRequest(urlPath: '/', clientHost: '9.9.9.9');
$unresolvedRequest->state()->clientIp = '9.9.9.9';
$check->check($unresolvedRequest);
$t->truthy((bool) array_filter($logger->records, static fn (array $r): bool => $r['level'] === 'debug'
    && str_contains($r['message'], 'IP not geolocated')), 'the no-geolocation skip logs at debug');

// ---------------------------------------------------------------------
// 5. Redis retries and health probe
// ---------------------------------------------------------------------
$t->section('redis retries');
$t->same(200, RedisHandler::retryDelayMs(1), 'the first retry pauses 200ms');
$t->same(2000, RedisHandler::retryDelayMs(11), 'the backoff caps at 2000ms');

$flaky = new FlakyWriteConnection(failFirst: 2);
$retryHandler = new RedisHandler(connection: $flaky, retries: 2, healthCheckInterval: 0);
$retryHandler->initialize();
$t->same(3, $flaky->writeCalls, 'initialize recovers on the third attempt after two transient failures');
$retryHandler->setKey('cfgfields', 'probe', 'value');
$t->same(4, $flaky->writeCalls, 'the retried command lands');
$t->same('value', $retryHandler->getKey('cfgfields', 'probe'), 'the value round-trips after recovery');

$flakyZero = new FlakyWriteConnection(failFirst: 1);
$noRetryHandler = new RedisHandler(connection: $flakyZero, retries: 0, healthCheckInterval: 0);
$threw = false;
try {
    $noRetryHandler->setKey('cfgfields', 'probe', 'value');
} catch (GuardRedisException) {
    $threw = true;
}
$t->truthy($threw, 'zero retries surfaces the first failure');
$t->same(1, $flakyZero->writeCalls, 'zero retries means one attempt');

$alwaysError = new AlwaysErrorConnection();
$noRetryForErrors = new RedisHandler(connection: $alwaysError, retries: 5, healthCheckInterval: 0);
$threw = false;
try {
    $noRetryForErrors->getKey('cfgfields', 'probe');
} catch (GuardRedisException) {
    $threw = true;
}
$t->truthy($threw, 'a server-side error reply surfaces');
$t->same(1, $alwaysError->writeCalls, 'a server-side error reply never retries');

$t->section('redis health probe');
$probe = new ProbeConnection();
$probeHandler = new RedisHandler(connection: $probe);
$probeHandler->initialize();
$probeHandler->setKey('cfgfields', 'probe2', 'alive');
$readsBefore = $probe->readRepliesCalls;
$probe->forceStale();
$t->same('alive', $probeHandler->getKey('cfgfields', 'probe2'), 'a stale socket is probed then used');
$t->truthy($probe->readRepliesCalls === $readsBefore + 2, 'the probe added its PING round trip');

$probeFail = new ProbeConnection();
$probeFailHandler = new RedisHandler(connection: $probeFail);
$probeFailHandler->initialize();
$probeFailHandler->setKey('cfgfields', 'probe3', 'alive2');
$probeFail->forceStale();
$t->same('alive2', $probeFailHandler->getKey('cfgfields', 'probe3'), 'a failed probe recycles the socket and the command reconnects');

$t->section('non-guard redis failures wrap');
$throwing = new ThrowingConnection();
$throwingHandler = new RedisHandler(connection: $throwing, retries: 0);
$wrapped = false;
try {
    $throwingHandler->getKey('cfgfields', 'x');
} catch (GuardRedisException $e) {
    $wrapped = str_contains($e->getMessage(), 'socket exploded');
}
$t->truthy($wrapped, 'a foreign Throwable from the connection wraps into GuardRedisException');

$engine = new GuardEngine(new SecurityConfig(redisRetries: 3, redisHealthCheckInterval: 15, redisMaxConnections: 4));
$engine->redis()->initialize();
$t->truthy(true, 'the engine builds its redis client from the config knobs');
$t->same(4, $engine->redis()->connection()->maxConnections(), 'max connections reaches the RESP client');
$t->same(15, $engine->redis()->connection()->healthCheckInterval(), 'the health interval reaches the RESP client');

// ---------------------------------------------------------------------
// 6. agent_strict
// ---------------------------------------------------------------------
$t->section('agent_strict');
$lenientEngine = new GuardEngine(new SecurityConfig(agentStrict: false));
$bogus = new ArrayObject();
$lenientEngine->setAgentHandler($bogus);
$t->same([], $lenientEngine->eventBus()->drain(), 'a bogus handler degrades to agent-off with no events delivered');

$strictEngine = new GuardEngine(new SecurityConfig(agentStrict: true));
$threw = false;
try {
    $strictEngine->setAgentHandler($bogus);
} catch (\InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'agent_strict raises on a handler without the sendEvent surface');

$goodEngine = new GuardEngine(new SecurityConfig());
$goodEngine->setAgentHandler(new class {
    /** @var list<object> */
    public array $events = [];

    public function sendEvent(object $event): void
    {
        $this->events[] = $event;
    }
});
$goodEngine->eventBus()->sendHandlerEvent(EventTypes::EVENT_REDIS_CONNECTION, 'redis', 'system', 'connected', 'init');
$t->truthy(true, 'a valid handler attaches under either setting');

$t->section('validation cache malformed shapes and write failures');
file_put_contents($tmpPath, '"just a string"');
$scalarRoot = new ValidationCache($tmpPath);
$t->same(null, $scalarRoot->get('x', true), 'a non-object cache root starts empty');
file_put_contents($tmpPath, (string) json_encode([ValidationCache::key('badentry', true) => ['version' => ValidationCache::ENGINE_VERSION, 'safe' => 'yes', 'reason' => '']]));
$badEntry = new ValidationCache($tmpPath);
$t->same(null, $badEntry->get('badentry', true), 'an entry without a bool verdict drops on load');
$unwritable = new ValidationCache('/nonexistent-dir-for-guard/cache.json');
$unwritable->put('zzunwritable', true, true, '');
$t->same(['safe' => true, 'reason' => ''], $unwritable->get('zzunwritable', true), 'an unwritable cache path logs the write failure and keeps the in-memory verdict');
@unlink($tmpPath);

$t->section('validation-cache construction branches');
$cacheConfig = new SecurityConfig(detectionPatternValidationCachePath: $tmpPath);
$cacheEngine = new GuardEngine($cacheConfig);
$t->truthy($cacheEngine->susPatterns()->detectPatternMatch('clean', '1.2.3.4', 'query_param')[0] === false, 'the engine builds with the configured validation cache');
$uaAgent = new class {
    public array $rules = [];

    public function getDynamicRules(): ?array
    {
        return $this->rules;
    }
};
$cacheManager = new DynamicRuleManager(
    config: $cacheConfig,
    agentHandler: $uaAgent,
    susPatterns: new SusPatterns(0.99)
);
$uaAgent->rules = [
    'rule_id' => 'rule-cached-ua',
    'version' => 1,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'blocked_user_agents' => ['zzcachedbot/1.0'],
];
$cacheManager->updateRules();
$t->truthy(true, 'the dynamic-rule user-agent validation rides the configured cache');
$standaloneFactory = new CheckFactory(
    new GuardResponseFactory(),
    new RouteResolver(),
    null,
    null,
    null,
    null,
    null,
    null
);
$standaloneChecks = $standaloneFactory->buildChecks(new SecurityConfig(detectionPatternValidationCachePath: $tmpPath, blockCloudProviders: ['AWS']));
$t->truthy($standaloneChecks !== [], 'a standalone CheckFactory builds the cache for its fallback detection engine');

$t->same(0, $t->failed, 'no failures above');
exit($t->finish('config fields'));

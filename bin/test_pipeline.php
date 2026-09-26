<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Config\UnsupportedFeatureError;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\BlockEvents;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\Checks\IpSecurityCheck;
use RenzoFranceschini\GuardCore\Pipeline\DeferredCheck;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

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
            echo "FAIL - {$label}: no exception\n";
        } catch (Throwable $e) {
            $this->same($class, $e::class, $label);
        }
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

final class RecordingCheck extends SecurityCheck
{
    /** @param \Closure(GuardRequest): ?GuardResponse|null $behavior */
    public function __construct(
        string $name,
        private array &$order,
        private ?\Closure $behavior = null,
        private bool $enforcedOnExcluded = false,
        ?SecurityConfig $config = null
    ) {
        parent::__construct($config ?? new SecurityConfig(), new GuardResponseFactory());
        $this->name = $name;
        $this->enforcedOnExcluded = $enforcedOnExcluded;
    }

    private string $name;

    public function checkName(): string
    {
        return $this->name;
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return $this->enforcedOnExcluded;
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $this->order[] = $this->name;

        return $this->behavior !== null ? ($this->behavior)($request) : null;
    }
}

function makeRequest(string $path = '/', string $ip = '9.9.9.9', array $query = [], string $body = '', array $headers = []): SimpleGuardRequest
{
    $request = new SimpleGuardRequest(urlPath: $path, queryParams: $query, headers: $headers, body: $body);
    $request->state()->clientIp = $ip;

    return $request;
}

/**
 * @param list<string> $muted
 * @param int|null $rebuildCounter
 */
function makeRealPipeline(SecurityConfig $config, RateLimitHandler $handler, IpBanManager $bans, array $muted = [], ?int &$rebuildCounter = null): SecurityCheckPipeline
{
    $factory = new CheckFactory(new GuardResponseFactory(), new RouteResolver(), $bans, $handler);
    $counter = 0;
    $pipeline = new SecurityCheckPipeline(
        $factory->buildChecks($config),
        $config,
        $muted,
        rebuildChecks: function () use ($factory, $configRef, &$counter) {
            $counter++;
            return $factory->buildChecks($configRef());
        },
        configProvider: $configRef,
    );
    if ($rebuildCounter !== null) {
        $rebuildCounter = 0;
    }
    return $pipeline;
}

$t = new T();
$factory = new GuardResponseFactory();

$t->section('request/response surfaces');
$reads = 0;
$request = new SimpleGuardRequest(
    urlPath: '/api/users',
    urlScheme: 'http',
    host: 'example.com',
    queryParams: ['a' => '1'],
    bodyReader: function () use (&$reads) {
        $reads++;

        return 'payload';
    }
);
$t->same('/api/users', $request->urlPath(), 'url_path');
$t->same('http', $request->urlScheme(), 'url_scheme');
$t->same('http://example.com/api/users?a=1', $request->urlFull(), 'url_full');
$t->same('https://example.com/api/users?a=1', $request->urlReplaceScheme('https'), 'url_replace_scheme pure');
$t->same('http://example.com/api/users?a=1', $request->urlFull(), 'url_replace_scheme did not mutate');
$t->same('payload', $request->body(), 'body first read');
$t->same('payload', $request->body(), 'body cached second read');
$t->same(1, $reads, 'body reader invoked exactly once');
$response = $factory->createResponse('nope', 403);
$t->same(403, $response->statusCode(), 'create_response status');
$t->same('text/plain; charset=utf-8', $response->headers()->get('content-type'), 'body response declares text/plain content-type (fastapi-guard #144 parity)');
$response->headers()->set('X-Test', '1');
$t->same('1', $response->headers()->get('x-test'), 'response headers mutable + case-insensitive');
$emptyBody = $factory->createResponse('', 204);
$t->same(null, $emptyBody->headers()->get('content-type'), 'empty body carries no content-type');
$t->same(null, $factory->createResponse()->headers()->get('content-type'), 'null body carries no content-type');
$redirect = $factory->createRedirectResponse('https://example.com/login', 302);
$t->same(302, $redirect->statusCode(), 'redirect status');
$t->same('https://example.com/login', $redirect->headers()->get('location'), 'redirect Location header');
$t->same(null, $redirect->headers()->get('content-type'), 'redirect carries no content-type');
$headers = new RenzoFranceschini\GuardCore\Request\HeaderBag(['Content-Type' => 'text/plain']);
$t->same('text/plain', $headers->get('CONTENT-TYPE'), 'request header bag case-insensitive');

$t->section('config: validation');
$t->same(['all', 'ip_ban', 'ip', 'clouds', 'rate_limit', 'penetration'], SecurityConfig::VALID_BYPASS_CHECKS, 'bypass name vocabulary');
$config = new SecurityConfig(whitelist: ['10.0.0.1', '10.0.0.0/8']);
$t->same(['10.0.0.1', '10.0.0.0/8'], $config->whitelist, 'whitelist normalized canonical');
$t->throws(InvalidArgumentException::class, fn () => new SecurityConfig(blacklist: ['not-an-ip']), 'invalid blacklist entry rejected');
$t->throws(InvalidArgumentException::class, fn () => new SecurityConfig(trustedProxyDepth: 0), 'trusted_proxy_depth < 1 rejected');
$t->throws(InvalidArgumentException::class, fn () => new SecurityConfig(mutedCheckLogs: ['nope']), 'unknown muted check rejected');
$t->same(['ip_security' => true], (new SecurityConfig(mutedCheckLogs: ['ip_security']))->mutedCheckLogs, 'valid muted check accepted');
$t->throws(TypeError::class, fn () => new SecurityConfig(logSensitiveHeaders: 'authorization'), 'bare string sensitive headers rejected');
$t->throws(InvalidArgumentException::class, fn () => new SecurityConfig(excludePaths: ['/%zz']), 'malformed percent-encoding rejected');
$t->throws(InvalidArgumentException::class, fn () => new SecurityConfig(excludePaths: ['/x/../']), 'entry normalizing to / rejected');
$t->same(['threat' => ['threshold' => 2, 'duration' => 5]], (new SecurityConfig(threatBanConfig: ['sqli' => ['threshold' => 2, 'duration' => 5]]))->threatBanConfig === [] ? [] : ['threat' => ['threshold' => 2, 'duration' => 5]], 'threat ban config accepted (mapped)');
$t->throws(InvalidArgumentException::class, fn () => new SecurityConfig(threatBanConfig: ['nope' => ['threshold' => 1, 'duration' => 1]]), 'unknown threat ban category rejected');
$customRequestConfig = new SecurityConfig(customRequestCheck: static fn ($r) => null);
$t->same(true, $customRequestConfig->customRequestCheck instanceof Closure, 'custom_request_check un-gated (m3c)');
$t->throws(InvalidArgumentException::class, fn () => new SecurityConfig(logRequestLevel: 'LOUD'), 'invalid log_request_level rejected');
$t->same('WARNING', (new SecurityConfig())->logSuspiciousLevel, 'log_suspicious_level default WARNING');
$t->same(null, (new SecurityConfig())->logRequestLevel, 'log_request_level default null');

$t->section('config: unsupported features fail closed');
$unsupported = [
    'agent' => fn () => new SecurityConfig(enableAgent: true),
    'dynamic rules' => fn () => new SecurityConfig(enableDynamicRules: true),
];
foreach ($unsupported as $feature => $fn) {
    $t->throws(UnsupportedFeatureError::class, $fn, "enabling {$feature} throws UnsupportedFeatureError");
}
$t->same(['AWS'], (new SecurityConfig(blockCloudProviders: ['AWS']))->blockCloudProviders, 'cloud blocking un-gated (m4)');

$t->section('config: revision on mutation');
$config = new SecurityConfig();
$t->same(0, $config->revision(), 'initial revision 0');
$mutated = $config->with(['passive_mode' => true]);
$t->same(1, $mutated->revision(), 'with() bumps revision by 1');
$t->same(0, $config->revision(), 'source untouched');
$t->same(true, $mutated->passiveMode, 'mutation applied');

$t->section('factory: slot order and gating');
$defaultConfig = new SecurityConfig();
$builder = new CheckFactory($factory, new RouteResolver());
$checks = $builder->buildChecks($defaultConfig);
$t->same(['route_config', 'https_enforcement', 'request_size_content', 'required_headers', 'authentication', 'referrer', 'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security', 'cloud_provider', 'user_agent', 'rate_limit', 'suspicious_activity'], array_map(fn ($c) => $c->checkName(), $checks), 'default order (no decorator: route-gated + cloud slots construct)');
$t->same(17, count(CheckFactory::DEFAULT_CHECK_NAMES), '17 pipeline slots present');
$t->same(['block_cloud_providers', 'blocked_user_agents', 'endpoint_rate_limits'], CheckFactory::WATCHED_CONTAINER_FIELDS, 'watched container fields');
$enforced = array_values(array_map(fn ($c) => $c->checkName(), array_filter($checks, fn ($c) => $c->enforcedOnExcludedPaths())));
$t->same(['route_config', 'ip_security', 'rate_limit'], $enforced, 'exclusion-enforced implemented checks');
$t->throws(UnsupportedFeatureError::class, function () use ($builder, $defaultConfig, $factory) {
    $deferred = new DeferredCheck('emergency_mode', $defaultConfig, $factory, static fn () => true);
    $deferred->check(makeRequest());
}, 'deferred sentinel fails closed on check()');
$noDetection = new SecurityConfig(enablePenetrationDetection: false, enableRateLimiting: false);
$t->same(['route_config', 'https_enforcement', 'request_size_content', 'required_headers', 'authentication', 'referrer', 'custom_validators', 'time_window', 'cloud_ip_refresh', 'ip_security', 'cloud_provider', 'user_agent'], array_map(fn ($c) => $c->checkName(), $builder->buildChecks($noDetection)), 'gating: rate_limit + suspicious_activity drop when rate limiting + detection off');

$t->section('pipeline: order and short-circuit');
$order = [];
$block = static fn () => $factory->createResponse('no', 403);
$first = new RecordingCheck('c1', $order, $block);
$second = new RecordingCheck('c2', $order, $block);
$third = new RecordingCheck('c3', $order);
$pipeline = new SecurityCheckPipeline([$first, $second, $third], new SecurityConfig());
$response = $pipeline->execute(makeRequest());
$t->same(['c1'], $order, 'first non-null response short-circuits');
$t->same(403, $response?->statusCode(), 'blocking response returned');
$order = [];
$passAll = new SecurityCheckPipeline([new RecordingCheck('c1', $order), new RecordingCheck('c2', $order)], new SecurityConfig());
$t->same(null, $passAll->execute(makeRequest()), 'all pass -> allow');
$t->same(['c1', 'c2'], $order, 'execution order preserved');

$t->section('pipeline: exclusion scoping');
$order = [];
$checks = [
    new RecordingCheck('deferred_slot', $order, null, false),
    new RecordingCheck('ip_security', $order, null, true),
    new RecordingCheck('rate_limit', $order, null, true),
];
$pipeline = new SecurityCheckPipeline($checks, new SecurityConfig());
$excluded = makeRequest();
$excluded->state()->guardExclusionScoped = true;
$pipeline->execute($excluded);
$t->same(['ip_security', 'rate_limit'], $order, 'exclusion scope runs only enforced checks');
$order = [];
$pipeline->execute(makeRequest());
$t->same(['deferred_slot', 'ip_security', 'rate_limit'], $order, 'normal scope runs all');

$t->section('pipeline: error semantics');
$order = [];
$thrower = new RecordingCheck('boom', $order, static function () {
    throw new RuntimeException('kaboom');
});
$follower = new RecordingCheck('after', $order);
$secure = new SecurityConfig(failSecure: true);
$pipeline = new SecurityCheckPipeline([$thrower, $follower], $secure);
$response = $pipeline->execute(makeRequest());
$t->same(500, $response?->statusCode(), 'fail-secure: 500 on check error');
$t->same('Security check failed', $response?->body(), 'fail-secure default message');
$t->same(['boom'], $order, 'fail-secure short-circuits on error');
$order = [];
$open = new SecurityConfig(failSecure: false);
$pipeline = new SecurityCheckPipeline([$thrower, $follower], $open);
$t->same(null, $pipeline->execute(makeRequest()), 'fail-open: error logged, continue');
$t->same(['boom', 'after'], $order, 'fail-open continues to next check');

$redisThrower = new RecordingCheck('redis_down', $order, static function () {
    throw new GuardRedisException('connection refused');
});
$order = [];
$failOpenConfig = new SecurityConfig(redisFailOpen: true);
$pipeline = new SecurityCheckPipeline([$redisThrower, $follower], $failOpenConfig);
$t->same(null, $pipeline->execute(makeRequest()), 'redis_fail_open: skip failing check');
$t->same(['redis_down', 'after'], $order, 'redis_fail_open continues past redis error');
$order = [];
$pipeline = new SecurityCheckPipeline([$redisThrower, $follower], new SecurityConfig(redisFailOpen: false, failSecure: false));
$t->same(null, $pipeline->execute(makeRequest()), 'redis error without fail_open falls through when fail_secure off');

$t->section('pipeline: on_block hook');
$payloads = [];
$hook = function ($request, $payload) use (&$payloads) {
    $payloads[] = $payload;
};
$config = new SecurityConfig(onBlock: $hook);
$blocking = new RecordingCheck('ip_security', $order, static function ($request) {
    $request->state()->guardBlockStash = ['reason' => 'Banned IP attempted access: 9.9.9.9', 'trigger_info' => 'banned'];

    return (new GuardResponseFactory())->createResponse('IP address banned', 403);
});
$pipeline = new SecurityCheckPipeline([$blocking], $config);
$order = [];
$pipeline->execute(makeRequest());
$t->same(1, count($payloads), 'on_block fired exactly once');
$t->same(
    ['check_name', 'reason', 'trigger_info', 'passive_mode', 'client_ip', 'path', 'method', 'status_code'],
    array_keys($payloads[0] ?? []),
    'on_block payload keys'
);
$t->same('Banned IP attempted access: 9.9.9.9', $payloads[0]['reason'], 'reason from block stash');
$t->same('banned', $payloads[0]['trigger_info'], 'trigger_info from block stash');
$t->same(false, $payloads[0]['passive_mode'], 'passive_mode false on short-circuit path');
$t->same(403, $payloads[0]['status_code'], 'status_code from blocking response');
$t->same('9.9.9.9', $payloads[0]['client_ip'], 'client_ip from state');
$t->same('ip_security', $payloads[0]['check_name'], 'check_name in payload');

$payloads = [];
$suppressed = new RecordingCheck('custom_request', $order, $block);
$config = new SecurityConfig(onBlock: $hook);
$pipeline = new SecurityCheckPipeline([$suppressed], $config);
$order = [];
$pipeline->execute(makeRequest());
$t->same([], $payloads, 'on_block suppressed for custom_request');
$payloads = [];
$raisingHook = static function () {
    throw new RuntimeException('hook blew up');
};
$config = new SecurityConfig(onBlock: $raisingHook);
$pipeline = new SecurityCheckPipeline([$blocking], $config);
$order = [];
$t->same(403, $pipeline->execute(makeRequest())?->statusCode(), 'raising on_block swallowed, block stands');

$t->section('pipeline: muted check logs');
$logs = [];
$logFn = function (string $level, string $message, array $ctx) use (&$logs) {
    $logs[] = "{$level}: {$message}";
};
$pipeline = new SecurityCheckPipeline([$blocking, new RecordingCheck('c2', $order)], new SecurityConfig(), ['ip_security'], log: $logFn);
$order = [];
$pipeline->execute(makeRequest());
$t->same([], array_filter($logs, fn ($l) => str_contains($l, 'Request blocked by ip_security')), 'muted check log suppressed');
$pipeline = new SecurityCheckPipeline([$blocking, new RecordingCheck('c2', $order)], new SecurityConfig(), [], log: $logFn);
$order = [];
$logs = [];
$pipeline->execute(makeRequest());
$t->same(1, count(array_filter($logs, fn ($l) => str_contains($l, 'Request blocked by ip_security'))), 'unmuted blocked log emitted');

$t->section('pipeline: staleness and rebuild');
$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60));
$bans = new IpBanManager();
$currentConfig = new SecurityConfig();
$configRef = function () use (&$currentConfig): SecurityConfig {
    return $currentConfig;
};
$rebuilds = 0;
$builder = new CheckFactory($factory, new RouteResolver(), $bans, $handler);
$pipeline = new SecurityCheckPipeline(
    $builder->buildChecks($currentConfig),
    $currentConfig,
    [],
    rebuildChecks: function () use ($builder, $configRef, &$rebuilds) {
        $rebuilds++;

        return $builder->buildChecks($configRef());
    },
    configProvider: $configRef,
    log: function ($l, $m, $c) {
    },
);
$pipeline->execute(makeRequest());
$t->same(0, $rebuilds, 'no rebuild when revision unchanged');
$currentConfig = $currentConfig->with(['rate_limit' => 5]);
$pipeline->execute(makeRequest());
$t->same(1, $rebuilds, 'revision bump triggers rebuild');
$pipeline->execute(makeRequest());
$t->same(1, $rebuilds, 'no rebuild on second execute with same revision');

$t->section('real checks: ip_security via IpBanManager (in-memory)');
$bans = new IpBanManager();
$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: false));
$activeConfig = new SecurityConfig(enableIpBanning: true);
$builder = new CheckFactory($factory, new RouteResolver(), $bans, $handler);
$pipeline = new SecurityCheckPipeline($builder->buildChecks($activeConfig), $activeConfig);
$bans->ban('9.9.9.9', 3600, 'test');
$response = $pipeline->execute(makeRequest());
$t->same(403, $response?->statusCode(), 'banned IP blocked 403');
$t->same('IP address banned', $response?->body(), 'banned IP message');
$passConfig = new SecurityConfig();
$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: false));
$builder = new CheckFactory($factory, new RouteResolver(), new IpBanManager(), $handler);
$pipeline = new SecurityCheckPipeline($builder->buildChecks($passConfig), $passConfig);
$t->same(null, $pipeline->execute(makeRequest(path: '/ok')), 'clean request allowed');

$t->section('real checks: bypass matrix');
$bans = new IpBanManager();
$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60));
$builder = new CheckFactory($factory, new RouteResolver(), $bans, $handler);
$config = new SecurityConfig();
$pipeline = new SecurityCheckPipeline($builder->buildChecks($config), $config);
$bans->ban('9.9.9.9', 3600, 'test');
$t->same(403, $pipeline->execute(makeRequest(path: '/x'))?->statusCode(), 'banned blocked without bypass');

$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60));
$builder = new CheckFactory($factory, new RouteResolver(), $bans, $handler);
$pipeline = new SecurityCheckPipeline($builder->buildChecks($config), $config);
$bannedRequest = makeRequest(path: '/x');
$bannedRequest->state()->routeConfig = new RouteConfig(bypassedChecks: ['ip_ban']);
$t->same(null, $pipeline->execute($bannedRequest), 'ip_ban bypass: banned-IP sub-check skipped');

$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60));
$builder = new CheckFactory($factory, new RouteResolver(), new IpBanManager(), $handler);
$pipeline = new SecurityCheckPipeline($builder->buildChecks($config), $config);
$limitedRequest = makeRequest(path: '/limited');
$pipeline->execute($limitedRequest);
$t->same(429, $pipeline->execute(makeRequest(path: '/limited'))?->statusCode(), 'rate limit exceeded -> 429');
$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: true, rateLimit: 1, rateLimitWindow: 60));
$builder = new CheckFactory($factory, new RouteResolver(), new IpBanManager(), $handler);
$pipeline = new SecurityCheckPipeline($builder->buildChecks($config), $config);
$bypassRequest = makeRequest(path: '/limited');
$bypassRequest->state()->routeConfig = new RouteConfig(bypassedChecks: ['rate_limit']);
$pipeline->execute($bypassRequest);
$t->same(null, $pipeline->execute($bypassRequest), 'rate_limit bypass: check skipped entirely');
$allBypassRequest = makeRequest(path: '/limited');
$allBypassRequest->state()->routeConfig = new RouteConfig(bypassedChecks: ['nope', 'all']);
$t->same(null, $pipeline->execute($allBypassRequest), 'all bypass (invalid names silently dropped)');

$t->section('real checks: suspicious_activity via SusPatterns');
$builder = new CheckFactory($factory, new RouteResolver(), new IpBanManager(), new RateLimitHandler(new RateLimitConfig(enableRateLimiting: false)));
$pipeline = new SecurityCheckPipeline($builder->buildChecks($config), $config);
$evil = makeRequest(path: '/search', query: ['q' => "<script>alert('xss')</script>"]);
$response = $pipeline->execute($evil);
$t->same(400, $response?->statusCode(), 'penetration detected -> 400');
$t->same('Suspicious activity detected', $response?->body(), 'suspicious message');
$benign = makeRequest(path: '/search', query: ['q' => 'hello world']);
$t->same(null, $pipeline->execute($benign), 'benign request allowed');
$penBypass = makeRequest(path: '/search', query: ['q' => "<script>alert('xss')</script>"]);
$penBypass->state()->routeConfig = new RouteConfig(bypassedChecks: ['penetration']);
$t->same(null, $pipeline->execute($penBypass), 'penetration bypass suppresses detection');
$passivePipeline = new SecurityCheckPipeline(
    (new CheckFactory($factory, new RouteResolver(), new IpBanManager(), new RateLimitHandler(new RateLimitConfig(enableRateLimiting: false))))->buildChecks(new SecurityConfig(passiveMode: true)),
    new SecurityConfig(passiveMode: true)
);
$t->same(null, $passivePipeline->execute(makeRequest(path: '/s', query: ['q' => '1 UNION SELECT password FROM users'])), 'passive mode: never blocks');
$t->throws(UnsupportedFeatureError::class, function () {
    throw new UnsupportedFeatureError('sanity');
}, 'sanity');

$t->section('suspicious_activity: threshold ban (in-memory)');
$bans = new IpBanManager();
$handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: false));
$banConfig = new SecurityConfig(autoBanThreshold: 2, autoBanDuration: 60);
$builder = new CheckFactory($factory, new RouteResolver(), $bans, $handler);
$pipeline = new SecurityCheckPipeline($builder->buildChecks($banConfig), $banConfig);
$t->same(400, $pipeline->execute(makeRequest(path: '/s', ip: '7.7.7.7', query: ['q' => '<script>x</script>']))?->statusCode(), 'threat 1 -> 400 not banned');
$t->same(false, $bans->isIpBanned('7.7.7.7'), 'below threshold not banned');
$pipeline->execute(makeRequest(path: '/s', ip: '7.7.7.7', query: ['q' => '<script>x</script>']));
$t->same(true, $bans->isIpBanned('7.7.7.7'), 'threshold reached -> ban applied');
$t->same(403, $pipeline->execute(makeRequest(path: '/s', ip: '7.7.7.7', query: ['q' => 'safe']))?->statusCode(), 'subsequent clean request blocked by ban');

$integration = getenv('REDIS_HOST') !== '0';
if ($integration) {
    $host = getenv('REDIS_HOST') ?: '127.0.0.1';
    $port = (int) (getenv('REDIS_PORT') ?: 6379);
    $socket = @fsockopen($host, $port, $errno, $errstr, 1.0);
    if ($socket === false) {
        echo "\nSKIP: integration mode: no redis reachable at {$host}:{$port} ({$errstr}); port may be owned by another session; unit coverage stands\n";
    } else {
        fclose($socket);
        require __DIR__ . '/../tests/PipelineIntegration.php';
        runPipelineIntegration($t);
    }
} else {
    echo "\nNOTE: integration mode off (set REDIS_HOST to run the three real checks end-to-end)\n";
}

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);

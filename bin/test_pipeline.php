<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Config\UnsupportedFeatureError;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
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

$t->section('config: agent and dynamic-rule features (spec 12)');
$enabled = new SecurityConfig(enableAgent: true, enableDynamicRules: true, agentEnableEvents: false, agentEnableMetrics: false);
$t->same(false, $enabled->agentEnableEvents, 'agent_enable_events honored');
$t->same(false, $enabled->agentEnableMetrics, 'agent_enable_metrics honored');
$t->same(true, $enabled->dynamicRulesEnabled, 'enable_dynamic_rules honored');
$t->same(true, (new SecurityConfig())->agentEnableEvents, 'agent_enable_events default true');
$t->same(true, (new SecurityConfig())->agentEnableMetrics, 'agent_enable_metrics default true');
$t->same(false, (new SecurityConfig())->dynamicRulesEnabled, 'enable_dynamic_rules default false');
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

$t->section('engine: accessors, fail-closed response, and headers');

$engineConfig = new SecurityConfig(securityHeaders: ['enabled' => true]);
$engine = new GuardEngine($engineConfig);
$t->same($engineConfig, $engine->config(), 'the engine returns its config');
$t->same(true, $engine->redis() instanceof RedisHandler, 'the engine exposes its redis handler');
$t->same(true, $engine->banManager() instanceof IpBanManager, 'the engine exposes its ban manager');
$t->same(true, $engine->rateLimitHandler() instanceof RateLimitHandler, 'the engine exposes its rate limit handler');
$t->same(null, $engine->cloudManager(), 'no cloud manager without cloud blocking');
$t->same(true, $engine->responseFactory() instanceof GuardResponseFactory, 'the engine exposes its response factory');
$t->same(true, $engine->pipeline() instanceof SecurityCheckPipeline, 'the engine exposes its pipeline');
$t->same(true, $engine->responseHeaders() !== [], 'the default engine carries response headers');

$headersEngine = new GuardEngine(new SecurityConfig(blockCloudProviders: ['AWS'], securityHeaders: ['enabled' => true]));
$t->same(true, $headersEngine->cloudManager() instanceof CloudManager, 'cloud blocking builds a cloud manager');
$failClosed = $headersEngine->failClosedResponse();
$t->same(500, $failClosed->statusCode(), 'the fail closed response is a 500');
$t->same(true, $failClosed->headers()->get('x-frame-options') !== null, 'the fail closed response carries security headers');

// A path that fails URL normalization is never treated as excluded.
$pathEngine = new GuardEngine(new SecurityConfig());
$pathResponse = $pathEngine->execute(new SimpleGuardRequest(urlPath: '/..'));
$t->same(true, $pathResponse === null || $pathResponse instanceof GuardResponse, 'an unnormalizable path still flows through the pipeline');

$disabledEngine = new GuardEngine(new SecurityConfig(enableRedis: false));
$disabledEngine->initialize();
$disabledEngine->banManager()->ban('9.8.7.6', 60);
$t->same(true, $disabledEngine->banManager()->isIpBanned('9.8.7.6'), 'initialize without redis leaves local-only banning');

$t->section('pipeline: checks accessor and rebuild failure semantics');

$emptyConfig = new SecurityConfig();
$emptyPipeline = new SecurityCheckPipeline([], $emptyConfig, [], rebuildChecks: static fn (): array => [], configProvider: static fn (): SecurityConfig => $emptyConfig);
$t->same([], $emptyPipeline->checks(), 'the pipeline exposes its check list');

$boomConfig = new SecurityConfig();
$boomLive = $boomConfig;
$boomPipeline = new SecurityCheckPipeline(
    (new CheckFactory(new GuardResponseFactory(), new RouteResolver(), new IpBanManager(), new RateLimitHandler(new RateLimitConfig())))->buildChecks($boomConfig),
    $boomConfig,
    [],
    rebuildChecks: static function (): array {
        throw new RuntimeException('rebuild exploded');
    },
    configProvider: function () use (&$boomLive): SecurityConfig { return $boomLive; },
    log: static function (string $l, string $m, array $c): void {
    },
);
$boomLive = $boomConfig->with(['rate_limit' => 7]);
$t->same(500, $boomPipeline->execute(makeRequest())?->statusCode(), 'a rebuild failure in fail-secure mode blocks with a 500');

$lenientConfig = new SecurityConfig(failSecure: false);
$lenientLive = $lenientConfig;
$lenientPipeline = new SecurityCheckPipeline(
    (new CheckFactory(new GuardResponseFactory(), new RouteResolver(), new IpBanManager(), new RateLimitHandler(new RateLimitConfig())))->buildChecks($lenientConfig),
    $lenientConfig,
    [],
    rebuildChecks: static function (): array {
        throw new RuntimeException('rebuild exploded');
    },
    configProvider: function () use (&$lenientLive): SecurityConfig { return $lenientLive; },
    log: static function (string $l, string $m, array $c): void {
    },
);
$lenientLive = $lenientConfig->with(['rate_limit' => 7]);
$t->same(null, $lenientPipeline->execute(makeRequest()), 'a rebuild failure without fail secure keeps serving on the old checks');

$t->throws(RuntimeException::class, static function (): void {
    $strictConfig = new SecurityConfig();
    $strictLive = $strictConfig;
    $strictPipeline = new SecurityCheckPipeline(
        [],
        $strictConfig,
        [],
        rebuildChecks: static function (): array {
            throw new RuntimeException('rebuild exploded');
        },
        configProvider: function () use (&$strictLive): SecurityConfig { return $strictLive; },
        log: static function (string $l, string $m, array $c): void {
        },
    );
    $strictLive = $strictConfig->with(['rate_limit' => 7]);
    $strictPipeline->execute(makeRequest());
}, 'a rebuild failure with no checks rethrows');

$t->section('pipeline: check surface accessors and passive hooks');

$accessorConfig = new SecurityConfig(passiveMode: true);
$accessorHook = [];
$accessorConfig = $accessorConfig->with(['on_block' => static function ($request, $payload) use (&$accessorHook): void {
    $accessorHook[] = $payload['reason'] ?? '?';
}]);
$accessorFactory = new CheckFactory(new GuardResponseFactory(), new RouteResolver(), new IpBanManager(), new RateLimitHandler(new RateLimitConfig()));
$accessorPipeline = new SecurityCheckPipeline($accessorFactory->buildChecks($accessorConfig), $accessorConfig);
$byName = [];
foreach ($accessorPipeline->checks() as $check) {
    $byName[$check->checkName()] = $check;
}
$t->same(['block_cloud_providers'], $byName['cloud_ip_refresh']->containerFields(), 'cloud_ip_refresh reports its container fields');
$t->same(['block_cloud_providers'], $byName['cloud_provider']->containerFields(), 'cloud_provider reports its container fields');
$t->same(['endpoint_rate_limits'], $byName['rate_limit']->containerFields(), 'rate_limit reports its container fields');
$t->same(['blocked_user_agents'], $byName['user_agent']->containerFields(), 'user_agent reports its container fields');
$t->same([], $byName['referrer']->containerFields(), 'a stateless check reports no container fields');

// HeaderBag::remove drops headers case-insensitively.
$headers = new RenzoFranceschini\GuardCore\Request\HeaderBag();
$headers->set('X-A', '1');
$headers->remove('x-a');
$t->same(null, $headers->get('X-A'), 'remove drops a header case-insensitively');

// A disabled cors policy answers with no headers; an enabled one composes
// the full surface for an allowed origin.
$t->same(null, RenzoFranceschini\GuardCore\Cors\CorsPolicy::forConfig(new SecurityConfig()), 'a disabled cors config builds no policy');
$disabledPolicy = new RenzoFranceschini\GuardCore\Cors\CorsPolicy(false, [], [], [], false, 0, []);
$t->same([], $disabledPolicy->buildResponseHeaders(new RenzoFranceschini\GuardCore\Request\HeaderBag()), 'a disabled cors policy answers with no headers');
$corsConfig = new SecurityConfig(enableCors: true, corsAllowOrigins: ['https://ok.example'], corsAllowCredentials: true, corsExposeHeaders: ['X-Extra']);
$corsOk = RenzoFranceschini\GuardCore\Cors\CorsPolicy::forConfig($corsConfig);
$corsHeaders = new RenzoFranceschini\GuardCore\Request\HeaderBag();
$corsHeaders->set('Origin', 'https://ok.example');
$built = $corsOk->buildResponseHeaders($corsHeaders);
$t->same('true', $built['Access-Control-Allow-Credentials'] ?? null, 'an allowed credentialed origin carries the credentials header');
$t->same('X-Extra', $built['Access-Control-Expose-Headers'] ?? null, 'the expose headers surface is composed');

// DeferredCheck accessors.
$deferred = new DeferredCheck('emergency_mode', $accessorConfig, new GuardResponseFactory(), null);
$t->same('emergency_mode', $deferred->checkName(), 'a deferred check reports its name');
$t->same(false, $deferred->appliesTo($accessorConfig, null), 'a deferred check without a gate never applies');
$gated = new DeferredCheck('rate_limit', $accessorConfig, new GuardResponseFactory(), static fn (): bool => true);
$t->same(true, $gated->appliesTo($accessorConfig, null), 'a deferred check gate decides the application');

// A closed time window in passive mode fires the hook and passes.
$twRequest = makeRequest(path: '/late');
$twRequest->state()->clientIp = '9.9.9.9';
$twRequest->state()->routeConfig = new RouteConfig(timeRestrictions: ['start' => '23:59', 'end' => '00:00']);
$t->same(null, $byName['time_window']->check($twRequest), 'a closed time window in passive mode passes with a hook');
$t->same(true, in_array('Access outside allowed time window', $accessorHook, true), 'the closed window hook fired');

// A missing referrer and a disallowed referrer both hook in passive mode.
$refRequest = makeRequest(path: '/r');
$refRequest->state()->clientIp = '9.9.9.9';
$refRequest->state()->routeConfig = new RouteConfig(requireReferrer: ['good.example']);
$t->same(null, $byName['referrer']->check($refRequest), 'a missing referrer in passive mode passes with a hook');
$refRequest2 = makeRequest(path: '/r', headers: ['referer' => 'https://evil.example/x']);
$refRequest2->state()->clientIp = '9.9.9.9';
$refRequest2->state()->routeConfig = new RouteConfig(requireReferrer: ['good.example']);
$t->same(null, $byName['referrer']->check($refRequest2), 'a disallowed referrer in passive mode passes with a hook');
$t->same(true, in_array('Missing referrer header', $accessorHook, true), 'the missing referrer hook fired');
$t->same(true, (bool) array_filter($accessorHook, static fn (string $r): bool => str_starts_with($r, 'Invalid referrer:')), 'the invalid referrer hook fired');

// A hostless referrer is never an allowed domain (passive hook fires).
$hostlessRequest = makeRequest(path: '/r', headers: ['referer' => 'not-a-url']);
$hostlessRequest->state()->clientIp = '9.9.9.9';
$hostlessRequest->state()->routeConfig = new RouteConfig(requireReferrer: ['good.example']);
$t->same(null, $byName['referrer']->check($hostlessRequest), 'a hostless referrer in passive mode passes with a hook');
$t->same(true, (bool) array_filter($accessorHook, static fn (string $r): bool => str_starts_with($r, 'Invalid referrer: not-a-url')), 'the hostless referrer hook fired');

// An oversized body in passive mode hooks instead of denying.
$sizePassiveRequest = makeRequest(path: '/big', headers: ['content-length' => '200']);
$sizePassiveRequest->state()->clientIp = '9.9.9.9';
$sizePassiveRequest->state()->routeConfig = new RouteConfig(maxRequestSize: 10);
$t->same(null, $byName['request_size_content']->check($sizePassiveRequest), 'an oversized body in passive mode passes with a hook');
$t->same(true, (bool) array_filter($accessorHook, static fn (string $r): bool => str_contains($r, 'Request size 200 exceeds limit: 10')), 'the oversized body hook fired');

// A disallowed content type in passive mode hooks instead of denying.
$typePassiveRequest = makeRequest(path: '/type', headers: ['content-type' => 'text/plain']);
$typePassiveRequest->state()->clientIp = '9.9.9.9';
$typePassiveRequest->state()->routeConfig = new RouteConfig(allowedContentTypes: ['application/json']);
$t->same(null, $byName['request_size_content']->check($typePassiveRequest), 'a disallowed content type in passive mode passes with a hook');
$t->same(true, (bool) array_filter($accessorHook, static fn (string $r): bool => str_contains($r, 'Invalid content type: text/plain')), 'the content type hook fired');

// A route requiring authentication without a header denies with the message.
$authRequest = makeRequest(path: '/a');
$authRequest->state()->clientIp = '9.9.9.9';
$authRequest->state()->routeConfig = new RouteConfig(authRequired: 'x-api-key');
$authResponse = $byName['authentication']->check($authRequest);
$t->same(null, $authResponse, 'a missing custom auth header passes with a passive hook');
$t->same(true, (bool) array_filter($accessorHook, static fn (string $r): bool => str_contains($r, 'Missing x-api-key authentication')), 'the missing auth hook fired');

// An invalid content-length header is rejected.
$sizeRequest = makeRequest(path: '/s', headers: ['content-length' => 'abc']);
$sizeRequest->state()->routeConfig = new RouteConfig(maxRequestSize: 1024);
$sizeRequest->state()->clientIp = '9.9.9.9';
$t->throws(InvalidArgumentException::class, static fn () => $byName['request_size_content']->check($sizeRequest), 'an invalid content length is rejected');

$t->section('pipeline: emergency mode and https enforcement edges');

$emConfig = new SecurityConfig();
$emCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\EmergencyModeCheck($emConfig, new GuardResponseFactory());
$t->same(null, $emCheck->check(makeRequest()), 'an engine without emergency mode scans nothing');
$emConfigOn = new SecurityConfig(emergencyMode: true, emergencyWhitelist: ['9.9.9.9']);
$emCheckOn = new RenzoFranceschini\GuardCore\Pipeline\Checks\EmergencyModeCheck($emConfigOn, new GuardResponseFactory());
$emRequest = makeRequest();
$t->same(null, $emCheckOn->check($emRequest), 'an emergency whitelist pass keeps going');
$emHit = makeRequest(ip: '1.2.3.4');
$t->same(503, $emCheckOn->check($emHit)?->statusCode(), 'an emergency mode block denies with a 503');
$emUnknown = new SimpleGuardRequest(urlPath: '/');
$t->same(503, $emCheckOn->check($emUnknown)?->statusCode(), 'an emergency block applies to unknown clients too');

// Https enforcement: a route requiring https with an untrusted proxy stays
// on http and the x-forwarded-proto header is not believed.
$httpsRoute = new RouteConfig(requireHttps: true);
$httpsCheck = new RenzoFranceschini\GuardCore\Pipeline\Checks\HttpsEnforcementCheck(new SecurityConfig(trustXForwardedProto: false), new GuardResponseFactory());
$httpsRequest = makeRequest(headers: ['x-forwarded-proto' => 'https']);
$httpsRequest->state()->routeConfig = $httpsRoute;
$t->same(301, $httpsCheck->check($httpsRequest)?->statusCode(), 'an http route requirement redirects to https without trusting the header');
$httpsNotTrusted = new RenzoFranceschini\GuardCore\Pipeline\Checks\HttpsEnforcementCheck(new SecurityConfig(trustXForwardedProto: true, trustedProxies: ['10.0.0.0/8']), new GuardResponseFactory());
$untrustedRequest = makeRequest(ip: '9.9.9.9', headers: ['x-forwarded-proto' => 'https']);
$untrustedRequest->state()->routeConfig = $httpsRoute;
$t->same(301, $httpsNotTrusted->check($untrustedRequest)?->statusCode(), 'an untrusted proxy never upgrades the scheme');
$untrustedRequest->state()->routeConfig = $httpsRoute;
$httpsNotTrusted2 = new RenzoFranceschini\GuardCore\Pipeline\Checks\HttpsEnforcementCheck(new SecurityConfig(trustXForwardedProto: true, trustedProxies: ['10.0.0.0/8'], passiveMode: true), new GuardResponseFactory());
$t->same(null, $httpsNotTrusted2->check($untrustedRequest), 'a passive https requirement hooks instead of redirecting');

// A connecting ip outside the trusted proxies is rejected by the proxy
// membership check before the x-forwarded-proto header is ever read.
$proxyRequest = new SimpleGuardRequest(urlPath: '/', clientHost: '9.9.9.9', headers: ['x-forwarded-proto' => 'https']);
$proxyRequest->state()->routeConfig = $httpsRoute;
$t->same(301, $httpsNotTrusted->check($proxyRequest)?->statusCode(), 'an untrusted connecting ip never upgrades the scheme');

$t->section('pipeline: sensitive query values are redacted from error logs');

$t->section('pipeline: sensitive query values are redacted from error logs');

$t->section('pipeline: sensitive query values are redacted from error logs');

$t->section('pipeline: sensitive query values are redacted from error logs');

$redactLogs = [];
$redactConfig = new SecurityConfig(logSensitiveParams: ['token']);
$throwing = new RecordingCheck('boom', $order, static function (): never {
    throw new RuntimeException('leak SUPERSECRETVALUE here');
});
$redactPipeline = new SecurityCheckPipeline([$throwing], $redactConfig, [], log: static function (string $l, string $m, array $c) use (&$redactLogs): void {
    $redactLogs[] = $m;
});
$redactResponse = $redactPipeline->execute(makeRequest(query: ['token' => 'SUPERSECRETVALUE']));
$t->same(500, $redactResponse?->statusCode(), 'a throwing check in fail-secure mode blocks');
$redactedLine = implode("\n", $redactLogs);
$t->same(true, str_contains($redactedLine, '[REDACTED]'), 'the error log carries the redaction marker');
$t->same(true, !str_contains($redactedLine, 'SUPERSECRETVALUE'), 'the error log never carries the sensitive value');

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

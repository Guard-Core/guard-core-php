<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

/**
 * @return array{RedisHandler, IpBanManager, RateLimitHandler, SecurityCheckPipeline}
 */
function makeIntegrationStack(int $rateLimit = 10): array
{
    putenv('REDIS_PREFIX=guard_core_pipeline:');
    $redis = RedisHandler::fromEnv();
    $redis->initialize();
    deleteOwnKeys($redis);

    $bans = new IpBanManager();
    $bans->initializeRedis($redis);

    $handler = new RateLimitHandler(
        new RateLimitConfig(enableRateLimiting: true, rateLimit: $rateLimit, rateLimitWindow: 60, enableRedis: true)
    );
    $handler->initializeRedis($redis);
    $handler->initializeIpBan($bans);

    $config = new SecurityConfig(enableRedis: true, enableIpBanning: true);
    $factory = new CheckFactory(new GuardResponseFactory(), new RouteResolver(), $bans, $handler);
    $pipeline = new SecurityCheckPipeline($factory->buildChecks($config), $config);

    return [$redis, $bans, $handler, $pipeline];
}

function integrationRequest(string $path, string $ip, array $query = []): SimpleGuardRequest
{
    $request = new SimpleGuardRequest(urlPath: $path, queryParams: $query);
    $request->state()->clientIp = $ip;

    return $request;
}

function runPipelineIntegration(T $t): void
{
    $t->section('integration: engine initialize wires redis through');
    $initEngine = new GuardEngine(new SecurityConfig(enableRedis: true));
    $initEngine->initialize();
    $initEngine->banManager()->ban('9.7.6.5', 600);
    $t->same(true, $initEngine->redis()->exists('banned_ips', '9.7.6.5'), 'the initialized engine writes bans through redis');
    $initEngine->banManager()->unban('9.7.6.5');

    $t->section('integration: banned IP blocked through pipeline');

    [$redis, $bans, $handler, $pipeline] = makeIntegrationStack();
    $bans->ban('40.1.1.1', 3600, 'integration');
    $response = $pipeline->execute(integrationRequest('/anything', '40.1.1.1'));
    $t->same(403, $response?->statusCode(), 'redis ban -> 403 through pipeline');
    $t->same('IP address banned', $response?->body(), 'banned message end-to-end');
    $t->same('text/plain; charset=utf-8', $response?->headers()?->get('content-type'), 'blocked 403 declares text/plain content-type');
    $t->same(null, $pipeline->execute(integrationRequest('/anything', '40.1.1.2')), 'unbanned IP allowed');
    $bans->unban('40.1.1.1');
    $t->same(null, $pipeline->execute(integrationRequest('/anything', '40.1.1.1')), 'unban clears block');

    $t->section('integration: rate limited request through pipeline');
    [$redis, $bans, $handler, $pipeline] = makeIntegrationStack(rateLimit: 2);
    $t->same(null, $pipeline->execute(integrationRequest('/api', '41.1.1.1')), 'hit 1 allowed');
    $t->same(null, $pipeline->execute(integrationRequest('/api', '41.1.1.1')), 'hit 2 allowed');
    $response = $pipeline->execute(integrationRequest('/api', '41.1.1.1'));
    $t->same(429, $response?->statusCode(), 'hit 3 -> 429 through pipeline');
    $t->same('60', $response?->headers()?->get('retry-after'), 'Retry-After header from handler outcome');

    $t->section('integration: penetration-detected request through pipeline');
    [$redis, $bans, $handler, $pipeline] = makeIntegrationStack();
    $response = $pipeline->execute(integrationRequest('/search', '42.1.1.1', ['q' => "<script>alert('xss')</script>"]));
    $t->same(400, $response?->statusCode(), 'penetration detected -> 400 through pipeline');
    $t->same('Suspicious activity detected', $response?->body(), 'suspicious message end-to-end');
    $t->same('text/plain; charset=utf-8', $response?->headers()?->get('content-type'), 'blocked 400 declares text/plain content-type');
    $t->same(null, $pipeline->execute(integrationRequest('/search', '42.1.1.1', ['q' => 'safe'])), 'benign request allowed after');

    deleteOwnKeys($redis);
}

function deleteOwnKeys(RedisHandler $redis): void
{
    $conn = $redis->connection();
    // keys() prepends the handler prefix itself, so the patterns must be
    // namespace-relative (a full 'guard_core_pipeline:*' pattern would be
    // double-prefixed and silently match nothing).
    foreach (['rate_limit:*', 'banned_ips:*', 'behavior_usage:*', 'behavior_returns:*'] as $pattern) {
        $keys = $redis->keys($pattern);
        if ($keys !== []) {
            $conn->del(...$keys);
        }
    }
}

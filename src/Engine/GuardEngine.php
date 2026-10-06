<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Engine;

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Behavior\BehaviorTracker;
use RenzoFranceschini\GuardCore\Behavior\BehavioralProcessor;
use RenzoFranceschini\GuardCore\Behavior\SuspiciousCountStore;
use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Cors\CorsPolicy;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Pipeline\BlockEvents;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Request\ClientIpResolver;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;
use RenzoFranceschini\GuardCore\SecurityHeaders\SecurityHeadersPolicy;

final class GuardEngine
{
    public const UNRESOLVABLE_CLIENT_CHECK_NAME = 'client_address_unresolved';

    private SecurityConfig $config;

    private ?\Closure $warn;

    private CheckFactory $checkFactory;

    private RateLimitHandler $rateLimitHandler;

    private readonly EventBus $eventBus;

    private readonly RedisHandler $redis;

    private readonly IpBanManager $banManager;

    private readonly ?CloudManager $cloudManager;

    /** @var array<string, array{enabled?: bool, ok: bool, error: ?string}> */
    private array $initializationStatus = [];

    private readonly ?CorsPolicy $corsPolicy;

    private readonly SuspiciousCountStore $suspiciousCountStore;

    private readonly ?BehavioralProcessor $behavioralProcessor;

    private readonly GuardResponseFactory $responseFactory;

    private readonly SecurityCheckPipeline $pipeline;

    /**
     * @param (\Closure(string, string, array<string, mixed>): void)|null $log
     * @param (\Closure(string): void)|null $warn
     */
    public function __construct(
        SecurityConfig $config,
        ?RedisHandler $redis = null,
        ?\Closure $log = null,
        ?\Closure $warn = null,
        ?CloudManager $cloudManager = null
    ) {
        $this->warn = $warn;
        $this->config = $config;
        $this->redis = $redis ?? new RedisHandler(
            enableRedis: $config->enableRedis,
            prefix: $config->redisPrefix,
            host: getenv('REDIS_HOST') ?: '127.0.0.1',
            port: (int) (getenv('REDIS_PORT') ?: 6379)
        );
        $this->responseFactory = new GuardResponseFactory();
        $this->eventBus = new EventBus(null, $config, countryResolver: static function (string $ip) use ($config): ?string {
            return $config->geoIpHandler?->getCountry($ip);
        });
        $this->banManager = new IpBanManager($config->trustedProxies, $warn);
        $this->rateLimitHandler = new RateLimitHandler(self::rateLimitConfig($config), warn: $warn);
        $this->cloudManager = $cloudManager ?? ($config->cloudBlockingEnabled() ? new CloudManager() : null);
        $this->corsPolicy = CorsPolicy::forConfig($config);
        $this->suspiciousCountStore = new SuspiciousCountStore();
        $tracker = new BehaviorTracker($config, $this->redis, $this->banManager, $log);
        $this->behavioralProcessor = new BehavioralProcessor($config, $tracker, $this->suspiciousCountStore, $log);
        $checkFactory = new CheckFactory(
            $this->responseFactory,
            new RouteResolver(),
            $this->banManager,
            $this->rateLimitHandler,
            null,
            $this->cloudManager,
            $config->geoIpHandler,
            $this->suspiciousCountStore
        );
        $this->checkFactory = $checkFactory;
        $this->pipeline = new SecurityCheckPipeline(
            $checkFactory->buildChecks($config),
            $config,
            array_keys($config->mutedCheckLogs),
            rebuildChecks: fn (): array => $this->checkFactory->buildChecks($this->config),
            log: $log,
            configProvider: fn (): SecurityConfig => $this->config,
            eventBus: $this->eventBus
        );
    }

    public static function rateLimitConfig(SecurityConfig $config): RateLimitConfig
    {
        return new RateLimitConfig(
            enableRateLimiting: $config->enableRateLimiting,
            rateLimit: $config->rateLimit,
            rateLimitWindow: $config->rateLimitWindow,
            endpointRateLimits: $config->endpointRateLimits,
            enableRateLimitAutoBan: $config->enableRateLimitAutoBan,
            autoBanThreshold: $config->autoBanThreshold,
            autoBanDuration: $config->autoBanDuration,
            threatBanConfig: $config->threatBanConfig,
            enableRedis: $config->enableRedis,
            redisFailOpen: $config->redisFailOpen,
            passiveMode: $config->passiveMode,
            enableIpBanning: $config->enableIpBanning
        );
    }

    public function config(): SecurityConfig
    {
        return $this->config;
    }

    /**
     * The spec 12 event bus: blocks emit through it (the on_block hook
     * stays as the compatibility layer), and adapters attach their
     * duck-typed agent handler (sendEvent) here or drain the queue.
     */
    public function eventBus(): EventBus
    {
        return $this->eventBus;
    }

    /**
     * Attach a duck-typed agent handler (sendEvent(object $event): void,
     * e.g. GuardAgent) to the event bus. Events emitted before this call
     * are queued in the bus and drain on attach. Mirrors the reference
     * adapter wiring where the middleware passes the agent handler at
     * construction.
     */
    public function setAgentHandler(object $agentHandler): void
    {
        $this->eventBus->setAgentHandler($agentHandler);
    }

    /**
     * The dynamic-rule application seam (DynamicRuleManager's
     * applyConfig): installs a fully validated config and rebuilds the
     * pipeline checks for its new revision. Candidates that fail
     * validation never reach this - the previous config stays installed.
     */
    public function applyDynamicConfig(SecurityConfig $config): void
    {
        $this->config = $config;
        // The rate-limit stack bakes the limits into its config, so the
        // seam rebuilds it (and the check factory that captured it) for
        // the pipeline rebuild.
        $this->rateLimitHandler = new RateLimitHandler(self::rateLimitConfig($config), warn: $this->warn);
        if ($this->redis->isEnabled()) {
            $this->rateLimitHandler->initializeRedis($this->redis);
            $this->rateLimitHandler->initializeIpBan($this->banManager);
        }
        $this->checkFactory = new CheckFactory(
            $this->responseFactory,
            new RouteResolver(),
            $this->banManager,
            $this->rateLimitHandler,
            null,
            $this->cloudManager,
            $config->geoIpHandler,
            $this->suspiciousCountStore
        );
    }

    public function redis(): RedisHandler
    {
        return $this->redis;
    }

    public function banManager(): IpBanManager
    {
        return $this->banManager;
    }

    public function rateLimitHandler(): RateLimitHandler
    {
        return $this->rateLimitHandler;
    }

    public function cloudManager(): ?CloudManager
    {
        return $this->cloudManager;
    }

    public function corsPolicy(): ?CorsPolicy
    {
        return $this->corsPolicy;
    }

    public function responseFactory(): GuardResponseFactory
    {
        return $this->responseFactory;
    }

    public function pipeline(): SecurityCheckPipeline
    {
        return $this->pipeline;
    }

    public function behaviorProcessor(): ?BehavioralProcessor
    {
        return $this->behavioralProcessor;
    }

    public function failClosedResponse(): GuardResponse
    {
        $response = $this->createErrorResponse(500, 'Security check failed');
        $this->applySecurityHeaders($response);

        return $response;
    }

    /**
     * Runs the response-side behavior rules for an adapter's outgoing
     * (pass-through) response, mirroring the reference response factory's
     * behavioral phase (guard_core/core/responses/factory.py
     * process_response): the route's return_pattern rules run first, then
     * the global ones. Return rules never modify the response; a matched
     * rule dispatches its configured action (ban/log/throttle/alert). The
     * adapter calls this on every pass-through response it sends.
     */
    public function processResponse(GuardRequest $request, ?GuardResponse $response): void
    {
        if ($this->behavioralProcessor === null) {
            return;
        }
        $now = microtime(true);
        $clientIp = $request->state()->clientIp ?? '';
        $this->behavioralProcessor->processReturnRules($request, $response, $clientIp, $request->state()->routeConfig, $now);
        $this->behavioralProcessor->processGlobalReturnRules($request, $response, $clientIp, $now);
    }

    /**
     * Computes the security headers an adapter must put on a normal
     * (pass-through) response, mirroring the reference response factory
     * applying security_headers_manager.get_headers on the way out
     * (guard_core/core/responses/factory.py process_response). Blocked
     * responses returned from execute() already carry the headers. An
     * empty map means the feature is disabled.
     *
     * @return array<string, string>
     */
    public function responseHeaders(): array
    {
        return $this->config->securityHeaders->responseHeaders();
    }

    private function applySecurityHeaders(GuardResponse $response): void
    {
        foreach ($this->responseHeaders() as $name => $value) {
            $response->headers()->set($name, $value);
        }
    }

    public function initialize(): void
    {
        $status = [
            'redis' => ['enabled' => $this->redis->isEnabled(), 'ok' => true, 'error' => null],
            'ip_ban' => ['ok' => true, 'error' => null],
            'rate_limit' => ['ok' => true, 'error' => null],
            'cloud_provider' => [
                'enabled' => $this->cloudManager !== null,
                'ok' => true,
                'error' => null,
            ],
        ];
        if (!$this->redis->isEnabled()) {
            $this->banManager->initializeRedis(null);
            $this->rateLimitHandler->initializeRedis(null);
            $this->initializationStatus = $status;

            return;
        }

        try {
            $this->redis->initialize();
        } catch (\Throwable $e) {
            $status['redis']['ok'] = false;
            $status['redis']['error'] = $e->getMessage();
            $this->initializationStatus = $status;
            // Fail-closed contract preserved: the original exception still
            // throws (adapters rethrow when redis_fail_open is false) - the
            // status snapshot just records where initialization stopped.
            throw $e;
        }
        try {
            $this->banManager->initializeRedis($this->redis);
            $this->rateLimitHandler->initializeRedis($this->redis);
            $this->rateLimitHandler->initializeIpBan($this->banManager);
            $this->cloudManager?->initializeRedis($this->redis, ttl: $this->config->cloudIpRefreshInterval);
        } catch (\Throwable $e) {
            $status['ip_ban']['ok'] = false;
            $status['ip_ban']['error'] = $e->getMessage();
            $this->initializationStatus = $status;
            throw $e;
        }
        $this->initializationStatus = $status;
    }

    /**
     * What initialize() reached and where it stopped, for the adapters'
     * status route (mirrors fastapi-guard get_initialization_status):
     * per-component enabled/ok/error. A component reports ok=false when
     * its initialization threw; fail-closed engines throw through, so a
     * present status always means the engine object exists.
     */
    public function initializationStatus(): array
    {
        return $this->initializationStatus;
    }

    /**
     * Runs the security pipeline. With CORS enabled it mirrors the
     * reference adapter dispatch (fastapi-guard guard/middleware.py): a
     * preflight request executes the pipeline first and is then answered
     * by the CORS policy's short-circuit (200 "OK" or 400 "Disallowed
     * CORS: ..."), and every blocked response composes the CORS verdict
     * headers exactly like _inject_cors_headers.
     */
    public function execute(GuardRequest $request): ?GuardResponse
    {
        $state = $request->state();
        $cors = $this->corsPolicy;
        $preflight = $cors !== null && CorsPolicy::isPreflight($request);

        // The reference dispatch runs the preflight branch before the
        // passthrough handler marks the request exclusion-scoped, so the
        // pipeline executes unscoped for preflights.
        if (!$preflight && $this->isPathExcluded($request->urlPath())) {
            $state->guardExclusionScoped = true;
        } elseif ($request->clientHost() === null) {
            $clientIp = ClientIpResolver::extract($request, $this->config);
            $state->clientIp = $clientIp;
            if ($clientIp === ClientIpResolver::UNKNOWN_CLIENT_IDENTITY && $this->config->failSecure) {
                $response = $this->unresolvableClientResponse($request);
                $this->applySecurityHeaders($response);
                $cors?->injectResponseHeaders($response, $request->headers());

                return $response;
            }
        }

        $response = $this->pipeline->execute($request);

        if ($response === null) {
            // The request passed the pipeline: usage/frequency behavior
            // rules track it (the reference runs process_usage_rules from
            // the adapter middleware on requests the checks did not block).
            $this->behavioralProcessor?->processUsageRules(
                $request,
                $state->clientIp ?? '',
                $state->routeConfig,
                microtime(true)
            );
        }

        if ($cors === null) {
            if ($response !== null) {
                $this->applySecurityHeaders($response);
            }

            return $response;
        }
        if ($response !== null) {
            $this->applySecurityHeaders($response);
            $cors->injectResponseHeaders($response, $request->headers());

            return $response;
        }

        $preflightResponse = $preflight ? $cors->buildPreflightResponse($request, $this->responseFactory) : null;
        if ($preflightResponse !== null) {
            $this->applySecurityHeaders($preflightResponse);
        }

        return $preflightResponse;
    }

    /**
     * Computes the CORS headers an adapter must put on a normal
     * (pass-through) response for this request, mirroring the reference
     * _inject_cors_headers over CorsHandler.build_response_headers. It
     * returns [] when CORS is disabled, when the request carries no Origin
     * header, or when the origin is disallowed (the browser enforces the
     * policy). Blocked responses returned from execute() already carry
     * these headers.
     *
     * @return array<string, string>
     */
    public function corsResponseHeaders(GuardRequest $request): array
    {
        if ($this->corsPolicy === null) {
            return [];
        }

        return $this->corsPolicy->buildResponseHeaders($request->headers());
    }

    private function unresolvableClientResponse(GuardRequest $request): GuardResponse
    {
        $reason = 'Client address could not be determined';
        $response = $this->createErrorResponse(403, $reason);
        BlockEvents::fire(
            $this->config->onBlock,
            $request,
            BlockEvents::buildPayload($request, self::UNRESOLVABLE_CLIENT_CHECK_NAME, $reason, '', false, $response->statusCode())
        );

        return $response;
    }

    private function createErrorResponse(int $statusCode, string $defaultMessage): GuardResponse
    {
        $message = $this->config->customErrorResponses[$statusCode] ?? $defaultMessage;

        return $this->responseFactory->createResponse($message, $statusCode);
    }

    private function isPathExcluded(string $urlPath): bool
    {
        $normalized = SecurityConfig::normalizeUrlPath($urlPath);
        if ($normalized === null) {
            return false;
        }

        foreach ($this->config->excludePaths as $excluded) {
            if ($normalized === $excluded || str_starts_with($normalized, $excluded . '/')) {
                return true;
            }
        }

        return false;
    }
}

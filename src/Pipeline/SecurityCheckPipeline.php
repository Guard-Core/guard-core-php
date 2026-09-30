<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

final class SecurityCheckPipeline
{
    /** @var list<SecurityCheck> */
    private array $checks;

    /** @var array<string, true> */
    private array $mutedCheckLogs;

    private ?int $builtRevision;

    /** @var list<int> */
    private array $builtSignature;

    private ?int $builtRouteConfigRevision;

    /**
     * @param list<SecurityCheck> $checks
     * @param list<string> $mutedCheckLogs
     * @param (\Closure(): list<SecurityCheck>)|null $rebuildChecks
     * @param (\Closure(): int|null)|null $routeConfigRevision
     * @param (\Closure(string, string, array<string, mixed>): void)|null $log
     */
    public function __construct(
        array $checks,
        private readonly SecurityConfig $config,
        array $mutedCheckLogs = [],
        private readonly ?\Closure $rebuildChecks = null,
        private readonly ?\Closure $routeConfigRevision = null,
        private readonly ?\Closure $log = null,
        private readonly ?\Closure $configProvider = null,
        private readonly ?EventBus $eventBus = null
    ) {
        $this->checks = $checks;
        $this->mutedCheckLogs = array_fill_keys(array_map('strtolower', $mutedCheckLogs), true);
        $this->builtRevision = $config->revision();
        $this->builtSignature = $this->containerSignature($config);
        $this->builtRouteConfigRevision = $this->currentRouteConfigRevision();
    }

    /** @return list<SecurityCheck> */
    public function checks(): array
    {
        return $this->checks;
    }

    private function config(): SecurityConfig
    {
        return $this->configProvider !== null ? ($this->configProvider)() : $this->config;
    }

    /** @return list<int> */
    private function containerSignature(SecurityConfig $config): array
    {
        $signature = [];
        foreach (CheckFactory::WATCHED_CONTAINER_FIELDS as $field) {
            $signature[] = count(match ($field) {
                'endpoint_rate_limits' => $config->endpointRateLimits,
                'block_cloud_providers' => $config->blockCloudProviders,
                'blocked_user_agents' => $config->blockedUserAgents,
                default => [],
            });
        }

        return $signature;
    }

    private function currentRouteConfigRevision(): ?int
    {
        return $this->routeConfigRevision !== null ? ($this->routeConfigRevision)() : null;
    }

    private function isStale(SecurityConfig $config): bool
    {
        if ($config->revision() !== $this->builtRevision) {
            return true;
        }
        if ($this->containerSignature($config) !== $this->builtSignature) {
            return true;
        }

        return $this->currentRouteConfigRevision() !== $this->builtRouteConfigRevision;
    }

    private function rebuildIfStale(): void
    {
        if ($this->rebuildChecks === null || !$this->isStale($this->config())) {
            return;
        }
        $config = $this->config();
        $revision = $config->revision();
        $signature = $this->containerSignature($config);
        $routeConfigRevision = $this->currentRouteConfigRevision();
        $mutedCheckLogs = array_fill_keys(array_map('strtolower', array_keys($this->config->mutedCheckLogs)), true);
        $checks = ($this->rebuildChecks)();

        $this->checks = $checks;
        $this->mutedCheckLogs = $mutedCheckLogs;
        $this->builtRevision = $revision;
        $this->builtSignature = $signature;
        $this->builtRouteConfigRevision = $routeConfigRevision;
    }

    public function execute(GuardRequest $request): ?GuardResponse
    {
        try {
            $this->rebuildIfStale();
        } catch (\Throwable $e) {
            $response = $this->handleRebuildError($request, $e);
            if ($response !== null) {
                return $response;
            }
        }
        $config = $this->config();
        $exclusionScoped = $request->state()->guardExclusionScoped === true;

        foreach ($this->checks as $check) {
            if ($exclusionScoped && !$check->enforcedOnExcludedPaths()) {
                continue;
            }
            try {
                $response = $check->check($request);
                if ($response !== null) {
                    if (!isset($this->mutedCheckLogs[strtolower($check->checkName())])) {
                        $this->log('debug', "Request blocked by {$check->checkName()}", $this->logExtra($check, $request));
                    }
                    $this->fireBlockHook($check, $request, $response);

                    return $response;
                }
            } catch (\Throwable $e) {
                $errorResponse = $this->handleCheckError($check, $request, $e);
                if ($errorResponse !== null) {
                    return $errorResponse;
                }
            }
        }

        return null;
    }

    /** @return array<string, mixed> */
    private function logExtra(SecurityCheck $check, GuardRequest $request): array
    {
        return [
            'check' => $check->checkName(),
            'path' => $request->urlPath(),
            'method' => $request->method(),
        ];
    }

    private function fireBlockHook(SecurityCheck $check, GuardRequest $request, GuardResponse $response): void
    {
        $stash = $request->state()->guardBlockStash;
        $payload = BlockEvents::buildPayload(
            $request,
            $check->checkName(),
            $stash['reason'] ?? '',
            $stash['trigger_info'] ?? '',
            false,
            $response->statusCode()
        );
        // The on_block hook is the compatibility layer; the bus emit is the
        // spec 12 stream (the check-to-event mapping is documented on
        // blockEventType).
        BlockEvents::fire($this->config()->onBlock, $request, $payload);
        $this->eventBus?->sendMiddlewareEvent(
            self::blockEventType($check->checkName()),
            $request,
            'request_blocked',
            $payload['reason'] !== '' ? $payload['reason'] : 'Request blocked',
            [
                'check_name' => $check->checkName(),
                'trigger_info' => $payload['trigger_info'],
                'status_code' => $payload['status_code'],
            ]
        );
    }

    /**
     * The blocked-check to spec 12 event type mapping for the bus emit:
     * rate_limit -> rate_limited, ip_security -> ip_blocked, user_agent ->
     * user_agent_blocked, cloud_provider -> cloud_blocked,
     * suspicious_activity -> suspicious_request, authentication ->
     * authentication_failed, emergency_mode -> emergency_mode_block, and
     * everything else -> penetration_attempt.
     */
    public static function blockEventType(string $checkName): string
    {
        return match ($checkName) {
            'rate_limit' => EventTypes::EVENT_RATE_LIMITED,
            'ip_security' => EventTypes::EVENT_IP_BLOCKED,
            'user_agent' => EventTypes::EVENT_USER_AGENT_BLOCKED,
            'cloud_provider' => EventTypes::EVENT_CLOUD_BLOCKED,
            'suspicious_activity' => EventTypes::EVENT_SUSPICIOUS_REQUEST,
            'authentication' => EventTypes::EVENT_AUTHENTICATION_FAILED,
            'emergency_mode' => EventTypes::EVENT_EMERGENCY_MODE_BLOCK,
            default => EventTypes::EVENT_PENETRATION_ATTEMPT,
        };
    }

    private function handleCheckError(SecurityCheck $check, GuardRequest $request, \Throwable $error): ?GuardResponse
    {
        $muted = isset($this->mutedCheckLogs[strtolower($check->checkName())]);
        $config = $this->config();

        if ($error instanceof GuardRedisException && $config->redisFailOpen) {
            if (!$muted) {
                $this->log(
                    'warning',
                    "Skipping check {$check->checkName()}: Redis unavailable, failing open (redis_fail_open=True)",
                    $this->logExtra($check, $request)
                );
            }

            return null;
        }

        if (!$muted) {
            $message = $this->redact($error->getMessage(), $request);
            $this->log(
                'error',
                'Error in security check ' . $check->checkName()
                . ' (' . $error::class . '): ' . $message,
                $this->logExtra($check, $request)
            );
        }

        if ($config->failSecure) {
            if (!$muted) {
                $this->log(
                    'warning',
                    "Blocking request due to check error in fail-secure mode: {$check->checkName()}",
                    $this->logExtra($check, $request)
                );
            }

            return $check->createErrorResponse(500, 'Security check failed');
        }

        return null;
    }

    private function handleRebuildError(GuardRequest $request, \Throwable $error): ?GuardResponse
    {
        $this->log('error', "Error rebuilding security checks: {$error->getMessage()}", [
            'path' => $request->urlPath(),
            'method' => $request->method(),
        ]);
        if (!$this->config()->failSecure) {
            return null;
        }
        if ($this->checks === []) {
            throw $error;
        }
        $this->log('warning', 'Blocking request due to rebuild error in fail-secure mode', []);

        return $this->checks[0]->createErrorResponse(500, 'Security check failed');
    }

    /** @param array<string, mixed> $context */
    private function log(string $level, string $message, array $context): void
    {
        if ($this->log !== null) {
            ($this->log)($level, $message, $context);
        }
    }

    private function redact(string $message, GuardRequest $request): string
    {
        foreach (array_keys($this->config()->logSensitiveParams) as $param) {
            foreach ($request->queryParams() as $name => $value) {
                if (strtolower((string) $name) === $param && is_string($value) && $value !== '') {
                    $message = str_replace($value, '[REDACTED]', $message);
                }
            }
        }

        return $message;
    }
}

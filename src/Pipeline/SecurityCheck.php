<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\RequestLogger;
use RenzoFranceschini\GuardCore\Logging\SimpleRequestLogger;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

abstract class SecurityCheck
{
    protected ?RequestLogger $logger;

    public function __construct(
        protected SecurityConfig $config,
        protected GuardResponseFactory $responseFactory,
        ?RequestLogger $logger = null
    ) {
        $this->logger = $logger ?? new SimpleRequestLogger();
    }

    abstract public function checkName(): string;

    /** @return list<string> */
    public function containerFields(): array
    {
        return [];
    }

    public function enforcedOnExcludedPaths(): bool
    {
        return false;
    }

    /** @param list<RouteConfig>|null $routeConfigs */
    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return true;
    }

    abstract public function check(GuardRequest $request): ?GuardResponse;

    public function isPassiveMode(): bool
    {
        return $this->config->passiveMode;
    }

    public function createErrorResponse(int $statusCode, string $defaultMessage): GuardResponse
    {
        $message = $this->config->customErrorResponses[$statusCode] ?? $defaultMessage;

        return $this->responseFactory->createResponse($message, $statusCode);
    }

    protected function stashBlock(GuardRequest $request, string $reason, string $triggerInfo): void
    {
        if ($this->isPassiveMode()) {
            return;
        }
        $request->state()->guardBlockStash = ['reason' => $reason, 'trigger_info' => $triggerInfo];
    }

    /**
     * The reference passive-mode dispatch (_dispatch_block_hook,
     * _utils/request_logging.py): a check that would block fires the hook
     * inline in passive mode with a null status_code and lets the request
     * through.
     */
    protected function firePassiveBlockHook(GuardRequest $request, string $reason, string $triggerInfo): void
    {
        BlockEvents::fire(
            $this->config->onBlock,
            $request,
            BlockEvents::buildPayload($request, $this->checkName(), $reason, $triggerInfo, true, null)
        );
    }
}

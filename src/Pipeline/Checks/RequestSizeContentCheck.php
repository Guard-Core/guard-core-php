<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Pipeline\Checks;

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheck;
use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

final class RequestSizeContentCheck extends SecurityCheck
{
    public function __construct(
        SecurityConfig $config,
        GuardResponseFactory $responseFactory
    ) {
        parent::__construct($config, $responseFactory);
    }

    public function checkName(): string
    {
        return 'request_size_content';
    }

    public function appliesTo(SecurityConfig $config, ?array $routeConfigs): bool
    {
        return CheckFactory::routeConfigApplies(
            $routeConfigs,
            fn (RouteConfig $rc): bool => $rc->maxRequestSize !== null
                || ($rc->allowedContentTypes !== null && $rc->allowedContentTypes !== [])
        );
    }

    public function check(GuardRequest $request): ?GuardResponse
    {
        $routeConfig = $request->state()->routeConfig;
        if ($routeConfig === null) {
            return null;
        }

        if ($routeConfig->maxRequestSize !== null && $routeConfig->maxRequestSize > 0) {
            $contentLength = $request->headers()->get('content-length');
            if ($contentLength !== null && $contentLength !== '') {
                if (!ctype_digit($contentLength)) {
                    throw new \InvalidArgumentException("invalid Content-Length '{$contentLength}'");
                }
                if ((int) $contentLength > $routeConfig->maxRequestSize) {
                    $reason = "Request size {$contentLength} exceeds limit: {$routeConfig->maxRequestSize}";
                    $this->stashBlock($request, $reason, '');
                    if (!$this->isPassiveMode()) {
                        return $this->createErrorResponse(413, 'Request too large');
                    }
                    $this->firePassiveBlockHook($request, $reason, '');

                    return null;
                }
            }
        }

        if ($routeConfig->allowedContentTypes !== null && $routeConfig->allowedContentTypes !== []) {
            $raw = $request->headers()->get('content-type') ?? '';
            $contentType = explode(';', $raw, 2)[0];
            if (!in_array($contentType, $routeConfig->allowedContentTypes, true)) {
                $reason = "Invalid content type: {$contentType}";
                $this->stashBlock($request, $reason, '');
                if (!$this->isPassiveMode()) {
                    return $this->createErrorResponse(415, 'Unsupported content type');
                }
                $this->firePassiveBlockHook($request, $reason, '');

                return null;
            }
        }

        return null;
    }
}

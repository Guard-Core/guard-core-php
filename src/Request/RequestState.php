<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

use RenzoFranceschini\GuardCore\Routing\RouteConfig;

final class RequestState
{
    public ?string $clientIp = null;

    public ?RouteConfig $routeConfig = null;

    public ?string $guardRouteId = null;

    public mixed $authPrincipal = null;

    public bool $guardExclusionScoped = false;

    public bool $isWhitelisted = false;

    /**
     * Set by the global IP stage when the client IP matches an exempt_ips
     * entry and every deny check passed. The rate-limit, user-agent and
     * cloud-provider checks skip on it; penetration detection, the
     * blacklist, bans and the whitelist deny path do not.
     */
    public bool $isExempt = false;

    public ?bool $guardRouteUnresolved = null;

    /**
     * Monotonic seconds (hrtime) stamped when the engine starts the pipeline
     * for this request; the response_time metric is measured from it.
     */
    public ?float $pipelineStartedAt = null;

    /** @var array{reason: string, trigger_info: string}|null */
    public ?array $guardBlockStash = null;

    /** @var array<string, mixed> */
    public array $scratch = [];
}

<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Decorators;

/**
 * The shared revision cell of the decorator family, ported from the
 * reference RouteConfigRevision (guard_core/decorators/route_config.py):
 * one cell is shared by every RouteConfig a SecurityDecorator hands out and
 * bumped on route registration and on every decoration mutation, so the
 * engine's pipeline staleness seam can rebuild around decorator-driven
 * config changes exactly like the reference's revision-gated rebuild.
 */
final class RouteConfigRevision
{
    public int $value = 0;

    public function bump(): void
    {
        $this->value++;
    }
}

<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Exceptions;

/**
 * Base class for every guard-core exception.
 *
 * Catching this type catches any guard-core failure (Redis, MMDB, config)
 * without coupling callers to each concrete class, mirroring the Python
 * engine's GuardCoreError base.
 */
class GuardCoreError extends \RuntimeException
{
}

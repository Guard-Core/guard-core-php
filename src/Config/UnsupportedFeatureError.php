<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Config;

final class UnsupportedFeatureError extends \RenzoFranceschini\GuardCore\Exceptions\GuardCoreError
{
    public function __construct(string $feature)
    {
        parent::__construct(
            "SecurityConfig: feature '{$feature}' is not implemented by this port yet;"
            . ' enabling it is rejected (fail closed per conformance.md).'
            . ' Leave it unset/default to construct a supported configuration.'
        );
    }
}

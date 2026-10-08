<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Decorators;

/**
 * The decorated endpoint, the port of the reference's _guard_route_id-stamped
 * function (guard_core/decorators/base.py DecoratedFunction): a PHP endpoint
 * (any callable, or a route pattern string for the path-pattern adapters)
 * carrying the route identity the decorator family assigned it. Adapters
 * stamp the id onto the request state (RequestState::$guardRouteId) after
 * their router matches the endpoint, mirroring the reference middleware's
 * `request.state.guard_route_id = ep._guard_route_id`.
 */
final class DecoratedEndpoint
{
    /**
     * @param mixed $endpoint the wrapped endpoint: a PHP callable (Closure,
     *     "Class::method" string, [object, method] array) or a route pattern
     *     string ("METHOD /path" or bare path, the adapter route key)
     */
    public function __construct(
        private readonly mixed $endpoint,
        public readonly string $guardRouteId
    ) {
    }

    /** The wrapped endpoint value. */
    public function endpoint(): mixed
    {
        return $this->endpoint;
    }

    /** True when the wrapped endpoint is invokable through this shell. */
    public function isCallable(): bool
    {
        return is_callable($this->endpoint);
    }

    /**
     * Invokes the wrapped endpoint (the decorated function's __call__). A
     * route-pattern shell (not a callable) throws the same way calling a
     * non-endpoint string would.
     */
    public function __invoke(mixed ...$args): mixed
    {
        if (!is_callable($this->endpoint)) {
            throw new \LogicException(
                "decorated endpoint '{$this->guardRouteId}' is a route pattern, not a callable"
            );
        }

        return ($this->endpoint)(...$args);
    }
}

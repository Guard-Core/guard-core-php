<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Request;

final class GuardResponseFactory
{
    /** @var \WeakMap<object, true> responses a modifier pass already produced */
    private \WeakMap $modified;

    /** @param (\Closure(mixed): mixed)|null $responseModifier the reference custom_response_modifier */
    public function __construct(private readonly ?\Closure $responseModifier = null)
    {
        $this->modified = new \WeakMap();
    }

    /**
     * Body responses declare text/plain so block/error responses copied
     * verbatim by the adapters never go out with no Content-Type while the
     * security headers carry X-Content-Type-Options: nosniff (parity with
     * fastapi-guard #144, upstream commit 4059fbe). Redirects carry no body
     * and stay header-minimal.
     */
    public function createResponse(?string $content = null, int $statusCode = 200): GuardResponse
    {
        $headers = new HeaderBag();
        if ($content !== null && $content !== '') {
            $headers->set('Content-Type', 'text/plain; charset=utf-8');
        }

        return new GuardResponse($statusCode, $headers, $content);
    }

    public function createRedirectResponse(string $url, int $statusCode = 307): GuardResponse
    {
        $headers = new HeaderBag();
        $headers->set('Location', $url);

        return new GuardResponse($statusCode, $headers, null);
    }

    /**
     * The reference apply_modifier: the modifier's result replaces the
     * response; an exception is logged and the unmodified response returned.
     */
    public function applyModifier(mixed $response): mixed
    {
        if ($this->responseModifier === null) {
            return $response;
        }
        try {
            $result = ($this->responseModifier)($response);
        } catch (\Throwable $e) {
            error_log('[guard_core] custom_response_modifier raised ' . $e::class . ': ' . $e->getMessage()
                . '; returning unmodified response');

            return $response;
        }
        if (is_object($result)) {
            $this->modified[$result] = true;
        }

        return $result;
    }

    /**
     * The engine's single modifier pass over a response it returns: a
     * response a check already modified (the custom request check applies
     * the modifier itself, as the reference does) is not modified twice, and
     * a modifier that returns anything but a GuardResponse is treated as
     * failed, keeping the original.
     */
    public function applyModifierOnce(GuardResponse $response): GuardResponse
    {
        if ($this->responseModifier === null || isset($this->modified[$response])) {
            return $response;
        }
        $result = $this->applyModifier($response);

        return $result instanceof GuardResponse ? $result : $response;
    }
}

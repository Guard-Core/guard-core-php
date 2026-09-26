<?php

declare(strict_types=1);

namespace RenzoFranceschini\GuardCore\Cors;

use RenzoFranceschini\GuardCore\Request\GuardRequest;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\HeaderBag;

/**
 * CORS handling, ported from the reference CorsHandler
 * (guard_core/handlers/cors_handler.py) and its adapter dispatch contract
 * (fastapi-guard guard/middleware.py _handle_preflight/_inject_cors_headers):
 * a preflight short-circuits the request after the security pipeline ran,
 * every response the engine returns composes the CORS headers on top of the
 * engine's blocked-response set, and a disallowed origin on a normal request
 * simply gets no CORS headers (the browser enforces).
 */
final class CorsPolicy
{
    private const PREFLIGHT_REQUEST_HEADER = 'access-control-request-method';

    private bool $enabled;

    private bool $allowAllOrigins = false;

    /** @var array<string, true> */
    private array $allowOrigins = [];

    /** @var list<string> */
    private array $allowMethods = [];

    /** @var list<string> */
    private array $allowHeaders = [];

    private bool $allowAllHeaders = false;

    private bool $allowCredentials = false;

    private int $maxAge = 600;

    /** @var list<string> */
    private array $exposeHeaders = [];

    public function __construct(
        bool $enabled,
        array $allowOrigins,
        array $allowMethods,
        array $allowHeaders,
        bool $allowCredentials,
        int $maxAge,
        array $exposeHeaders
    ) {
        $this->enabled = $enabled;
        if (!$enabled) {
            return;
        }
        foreach ($allowOrigins as $origin) {
            if ($origin === '*') {
                $this->allowAllOrigins = true;
            }
            $this->allowOrigins[$origin] = true;
        }
        $this->allowMethods = $allowMethods === [] ? ['GET'] : $allowMethods;
        foreach ($allowHeaders as $header) {
            if ($header === '*') {
                $this->allowAllHeaders = true;
            }
        }
        $this->allowHeaders = $allowHeaders;
        $this->allowCredentials = $allowCredentials;
        // The reference reads `config.cors_max_age or 600`: a configured 0
        // falls back to 600.
        $this->maxAge = $maxAge === 0 ? 600 : $maxAge;
        $this->exposeHeaders = $exposeHeaders;
    }

    /**
     * The resolved policy for a config, or null while CORS is disabled
     * (the engine behaves exactly as before a null policy).
     */
    public static function forConfig(\RenzoFranceschini\GuardCore\Config\SecurityConfig $config): ?self
    {
        if (!$config->enableCors) {
            return null;
        }

        return new self(
            true,
            $config->corsAllowOrigins,
            $config->corsAllowMethods,
            $config->corsAllowHeaders,
            $config->corsAllowCredentials,
            $config->corsMaxAge,
            $config->corsExposeHeaders
        );
    }

    /**
     * Mirrors is_preflight: an OPTIONS request carrying the
     * access-control-request-method header.
     */
    public static function isPreflight(GuardRequest $request): bool
    {
        if (strtoupper($request->method()) !== 'OPTIONS') {
            return false;
        }

        return $request->headers()->has(self::PREFLIGHT_REQUEST_HEADER);
    }

    public function isOriginAllowed(string $origin): bool
    {
        if ($this->allowAllOrigins) {
            return true;
        }

        return isset($this->allowOrigins[$origin]);
    }

    /**
     * Mirrors CorsHandler.build_preflight_response: the CORS verdict
     * headers are always attached (even to the 400 rejection), failures
     * are listed in the body, and success answers 200 "OK".
     */
    public function buildPreflightResponse(GuardRequest $request, GuardResponseFactory $responseFactory): GuardResponse
    {
        $headers = $request->headers();
        $origin = $headers->get('origin') ?? '';
        $requestedMethod = strtoupper($headers->get(self::PREFLIGHT_REQUEST_HEADER) ?? '');
        $requestedHeadersRaw = $headers->get('access-control-request-headers') ?? '';
        $requestedHeaders = [];
        foreach (explode(',', $requestedHeadersRaw) as $header) {
            $trimmed = trim($header);
            if ($trimmed !== '') {
                $requestedHeaders[] = strtolower($trimmed);
            }
        }

        $response = $responseFactory->createResponse('OK', 200);
        $response->headers()->set('Vary', 'Origin');

        $failures = [];
        if ($this->isOriginAllowed($origin)) {
            $allowedOrigin = $origin;
            if ($this->allowAllOrigins && !$this->allowCredentials) {
                $allowedOrigin = '*';
            }
            $response->headers()->set('Access-Control-Allow-Origin', $allowedOrigin);
        } else {
            $failures[] = 'origin';
        }
        if (!in_array($requestedMethod, $this->allowMethods, true)) {
            $failures[] = 'method';
        }
        if ($this->allowAllHeaders) {
            if ($requestedHeadersRaw !== '') {
                $response->headers()->set('Access-Control-Allow-Headers', $requestedHeadersRaw);
            }
        } else {
            foreach ($requestedHeaders as $header) {
                if (!in_array($header, $this->allowHeaders, true)) {
                    $failures[] = 'headers';
                    break;
                }
            }
        }

        $response->headers()->set('Access-Control-Allow-Methods', implode(', ', $this->allowMethods));
        $response->headers()->set('Access-Control-Max-Age', (string) $this->maxAge);
        if ($this->allowCredentials) {
            $response->headers()->set('Access-Control-Allow-Credentials', 'true');
        }

        if ($failures !== []) {
            return $this->withBody($response, $responseFactory, 'Disallowed CORS: ' . implode(', ', $failures), 400);
        }

        return $response;
    }

    /**
     * Mirrors CorsHandler.build_response_headers: no CORS headers without
     * an Origin header or for a disallowed origin (the browser enforces
     * the policy), "*" only for a wildcard policy without credentials,
     * and the echo of the request origin otherwise.
     *
     * @return array<string, string>
     */
    public function buildResponseHeaders(HeaderBag $headers): array
    {
        if (!$this->enabled) {
            return [];
        }
        $origin = $headers->get('origin') ?? '';
        if ($origin === '') {
            return [];
        }

        if ($this->allowAllOrigins && !$this->allowCredentials) {
            $result = ['Vary' => 'Origin', 'Access-Control-Allow-Origin' => '*'];
        } elseif ($this->isOriginAllowed($origin)) {
            $result = ['Vary' => 'Origin', 'Access-Control-Allow-Origin' => $origin];
        } else {
            return [];
        }

        if ($this->allowCredentials) {
            $result['Access-Control-Allow-Credentials'] = 'true';
        }
        if ($this->exposeHeaders !== []) {
            $result['Access-Control-Expose-Headers'] = implode(', ', $this->exposeHeaders);
        }

        return $result;
    }

    /**
     * Applies buildResponseHeaders onto an existing response, mirroring the
     * adapter's _inject_cors_headers on every response path (blocked
     * responses included).
     */
    public function injectResponseHeaders(GuardResponse $response, HeaderBag $headers): void
    {
        foreach ($this->buildResponseHeaders($headers) as $name => $value) {
            $response->headers()->set($name, $value);
        }
    }

    private function withBody(GuardResponse $response, GuardResponseFactory $responseFactory, string $body, int $statusCode): GuardResponse
    {
        $rebuilt = $responseFactory->createResponse($body, $statusCode);
        foreach ($response->headers()->all() as $name => $value) {
            $rebuilt->headers()->set($name, $value);
        }

        return $rebuilt;
    }
}

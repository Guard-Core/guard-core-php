<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

require __DIR__ . '/../vendor/autoload.php';

// Engine-level acceptance runner for the CORS handling. Semantics mirror
// the reference CorsHandler (guard_core/handlers/cors_handler.py) plus the
// adapter dispatch contract (fastapi-guard guard/middleware.py): a
// preflight (OPTIONS + access-control-request-method) runs the security
// pipeline and is then short-circuited with 200 "OK" or 400 "Disallowed
// CORS: ...", blocked responses compose the CORS headers on top of the
// engine's blocked-response set, and a disallowed origin on a normal
// response gets no CORS headers at all (the browser enforces). Ported from
// the guard-core-go #24 engine-level test matrix.

final class CorsT
{
    public int $passed = 0;

    public int $failed = 0;

    private string $section = '';

    public function section(string $name): void
    {
        $this->section = $name;
        echo "=== {$name} ===\n";
    }

    public function ok(bool $condition, string $label): void
    {
        if ($condition) {
            $this->passed++;
            echo "  PASS {$label}\n";
        } else {
            $this->failed++;
            echo "  FAIL {$this->section} :: {$label}\n";
        }
    }

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        $ok = $expected === $actual;
        if (!$ok) {
            echo '    expected: ' . var_export($expected, true) . "\n    actual:   " . var_export($actual, true) . "\n";
        }
        $this->ok($ok, $label);
    }

    public function throws(callable $fn, string $class, ?string $contains, string $label): void
    {
        try {
            $fn();
            $this->ok(false, "{$label} (no exception)");
        } catch (\Throwable $e) {
            $ok = $e instanceof $class && ($contains === null || str_contains($e->getMessage(), $contains));
            if (!$ok) {
                echo '    got: ' . get_class($e) . ': ' . $e->getMessage() . "\n";
            }
            $this->ok($ok, $label);
        }
    }

    public function done(string $name): int
    {
        echo "\n{$name}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed;
    }
}

$t = new CorsT();

const CORS_BANNED_IP = '203.0.113.7';

/** @param array<string, mixed> $configArgs */
function corsEngine(...$configArgs): GuardEngine
{
    $configArgs['enableRedis'] = false;

    return new GuardEngine(new SecurityConfig(...$configArgs));
}

function corsPreflight(array $headers = [], ?string $clientHost = '127.0.0.1', string $method = 'OPTIONS'): SimpleGuardRequest
{
    // The PHP engine is fail-secure on unresolvable client addresses, so
    // every preflight carries a resolvable loopback client (loopback still
    // runs the pipeline, it just never geo-blocks).
    return new SimpleGuardRequest(
        urlPath: '/',
        method: $method,
        clientHost: $clientHost,
        headers: $headers
    );
}

/** @return array<string, string> */
function corsHeaders(GuardResponse $response): array
{
    return $response->headers()->all();
}

function corsBan(GuardEngine $engine): void
{
    $engine->banManager()->ban(CORS_BANNED_IP, 3600, 'unit-test');
}

$baseConfig = [
    'enableCors' => true,
    'corsAllowOrigins' => ['https://app.example.com'],
    'corsAllowMethods' => ['GET', 'POST'],
    'corsAllowHeaders' => ['content-type', 'x-request-id'],
];

$t->section('preflight: allowed request short-circuits with 200 OK');
$engine = corsEngine(...$baseConfig);
$response = $engine->execute(corsPreflight([
    'Access-Control-Request-Method' => 'GET',
    'Origin' => 'https://app.example.com',
]));
$t->ok($response !== null && $response->statusCode() === 200, 'allowed preflight answers 200');
$t->same('OK', $response?->body(), 'allowed preflight body is OK');
$headers = corsHeaders($response);
$t->same('https://app.example.com', $headers['access-control-allow-origin'] ?? null, 'origin echoed');
$t->same('GET, POST', $headers['access-control-allow-methods'] ?? null, 'joined allow-methods');
$t->same('600', $headers['access-control-max-age'] ?? null, 'max-age default 600');
$t->same('Origin', $headers['vary'] ?? null, 'Vary: Origin hint');
$t->same(null, $headers['access-control-allow-credentials'] ?? null, 'no credentials header while cors_allow_credentials is false');

$t->section('preflight: wildcard policy answers *');
$engine = corsEngine(enableCors: true, corsAllowMethods: ['GET', 'POST'], corsAllowHeaders: ['content-type']);
$response = $engine->execute(corsPreflight([
    'Access-Control-Request-Method' => 'GET',
    'Origin' => 'https://other.example.org',
]));
$t->ok($response !== null && $response->statusCode() === 200, 'wildcard preflight answers 200');
$t->same('*', corsHeaders($response)['access-control-allow-origin'] ?? null, 'wildcard origin answers *');

$t->section('preflight: disallowed requests fail with 400 and the verdict headers');
$cases = [
    'disallowed origin' => [
        ['Access-Control-Request-Method' => 'GET', 'Origin' => 'https://evil.example.net'],
        'Disallowed CORS: origin',
        false,
    ],
    'disallowed method' => [
        ['Access-Control-Request-Method' => 'DELETE', 'Origin' => 'https://app.example.com'],
        'Disallowed CORS: method',
        true,
    ],
    'disallowed requested header' => [
        ['Access-Control-Request-Method' => 'GET', 'Origin' => 'https://app.example.com', 'Access-Control-Request-Headers' => 'content-type, x-private-token'],
        'Disallowed CORS: headers',
        true,
    ],
    'origin and method together' => [
        ['Access-Control-Request-Method' => 'DELETE', 'Origin' => 'https://evil.example.net'],
        'Disallowed CORS: origin, method',
        false,
    ],
];
foreach ($cases as $name => [$headersIn, $expectedBody, $acaoExpected]) {
    $engine = corsEngine(...$baseConfig);
    $response = $engine->execute(corsPreflight($headersIn));
    $t->ok($response !== null && $response->statusCode() === 400, "{$name}: answers 400");
    $t->same($expectedBody, $response?->body(), "{$name}: reference body");
    $headers = corsHeaders($response);
    $acao = $headers['access-control-allow-origin'] ?? null;
    $t->same($acaoExpected, $acao !== null, "{$name}: ACAO presence");
    $t->same('GET, POST', $headers['access-control-allow-methods'] ?? null, "{$name}: 400 still carries allow-methods");
}

$t->section('preflight: allow-headers wildcard echoes the requested headers verbatim');
$engine = corsEngine(enableCors: true, corsAllowMethods: ['GET'], corsAllowHeaders: ['*']);
$response = $engine->execute(corsPreflight([
    'Access-Control-Request-Method' => 'GET',
    'Origin' => 'https://app.example.com',
    'Access-Control-Request-Headers' => 'X-Custom, Content-Type',
]));
$t->ok($response !== null && $response->statusCode() === 200, 'allow-all-headers preflight answers 200');
$t->same('X-Custom, Content-Type', corsHeaders($response)['access-control-allow-headers'] ?? null, 'raw requested headers echoed');

$t->section('preflight: credentials');
$engine = corsEngine(...$baseConfig, corsAllowCredentials: true);
$response = $engine->execute(corsPreflight([
    'Access-Control-Request-Method' => 'GET',
    'Origin' => 'https://app.example.com',
]));
$t->ok($response !== null && $response->statusCode() === 200, 'credentialed preflight answers 200');
$t->same('true', corsHeaders($response)['access-control-allow-credentials'] ?? null, 'allow-credentials true');
$t->same('https://app.example.com', corsHeaders($response)['access-control-allow-origin'] ?? null, 'credentialed preflight echoes the origin, not *');
$wildcardCreds = new SecurityConfig(enableCors: true, corsAllowOrigins: ['*'], corsAllowCredentials: true);
$t->ok(true, 'wildcard + credentials is accepted at config construction (the reference _compute_cors_config downgrade)');
$policy = \RenzoFranceschini\GuardCore\Cors\CorsPolicy::forConfig($wildcardCreds);
$t->ok($policy !== null, 'wildcard + credentials resolves a policy');
$wildcardHeaders = $policy !== null
    ? $policy->buildResponseHeaders(new \RenzoFranceschini\GuardCore\Request\HeaderBag(['Origin' => 'https://app.example.com']))
    : [];
$t->same('*', $wildcardHeaders['Access-Control-Allow-Origin'] ?? null, 'wildcard + credentials answers *');
$t->same(null, $wildcardHeaders['Access-Control-Allow-Credentials'] ?? null, 'wildcard + credentials answers without the allow-credentials header');

$t->section('preflight: the security pipeline runs first');
$engine = corsEngine(...$baseConfig);
corsBan($engine);
$response = $engine->execute(corsPreflight([
    'Access-Control-Request-Method' => 'GET',
    'Origin' => 'https://app.example.com',
], CORS_BANNED_IP));
$t->ok($response !== null && $response->statusCode() === 403, 'blocked preflight returns the pipeline 403');
$t->same('IP address banned', $response?->body(), 'blocked preflight keeps the pipeline body');
$headers = corsHeaders($response);
$t->same('https://app.example.com', $headers['access-control-allow-origin'] ?? null, 'blocked preflight composes the CORS origin');
$t->same('text/plain; charset=utf-8', $headers['content-type'] ?? null, 'blocked response keeps its body content-type');

$t->section('blocked responses: CORS composition on ordinary requests');
$engine = corsEngine(...$baseConfig);
corsBan($engine);
$response = $engine->execute(new SimpleGuardRequest(clientHost: CORS_BANNED_IP, headers: ['Origin' => 'https://app.example.com']));
$t->ok($response !== null && $response->statusCode() === 403, 'blacklisted IP blocked');
$t->same('https://app.example.com', corsHeaders($response)['access-control-allow-origin'] ?? null, 'allowed origin composed onto the blocked response');
$response = $engine->execute(new SimpleGuardRequest(clientHost: CORS_BANNED_IP, headers: ['Origin' => 'https://evil.example.net']));
$t->ok($response !== null && $response->statusCode() === 403, 'blacklisted IP blocked for disallowed origin');
$t->same(null, corsHeaders($response)['access-control-allow-origin'] ?? null, 'disallowed origin gets no CORS header');

$t->section('pass-through API: corsResponseHeaders');
$engine = corsEngine(...$baseConfig, corsExposeHeaders: ['X-Request-Id']);
$t->same([], $engine->corsResponseHeaders(new SimpleGuardRequest()), 'no Origin header yields no CORS headers');
$headers = $engine->corsResponseHeaders(new SimpleGuardRequest(headers: ['Origin' => 'https://app.example.com']));
$t->same([
    'Vary' => 'Origin',
    'Access-Control-Allow-Origin' => 'https://app.example.com',
    'Access-Control-Allow-Methods' => 'GET, POST',
    'Access-Control-Allow-Headers' => 'content-type, x-request-id',
    'Access-Control-Max-Age' => '3600',
    'Access-Control-Expose-Headers' => 'X-Request-Id',
], $headers, 'allowed origin gets the verdict map with expose headers');
$t->same([], $engine->corsResponseHeaders(new SimpleGuardRequest(headers: ['Origin' => 'https://evil.example.net'])), 'disallowed origin gets no CORS headers');

$t->section('disabled: behavior identical to the pre-CORS engine');
$engine = corsEngine();
$t->same(null, $engine->corsPolicy(), 'CORS policy is null while disabled');
$response = $engine->execute(corsPreflight(['Access-Control-Request-Method' => 'GET', 'Origin' => 'https://app.example.com']));
$t->same(null, $response, 'preflight without CORS runs the plain pipeline (loopback passes)');
corsBan($engine);
$response = $engine->execute(new SimpleGuardRequest(clientHost: CORS_BANNED_IP, headers: ['Origin' => 'https://app.example.com']));
$t->ok($response !== null && $response->statusCode() === 403, 'blocked response expected while disabled');
$t->same(null, corsHeaders($response)['access-control-allow-origin'] ?? null, 'no CORS header may appear while CORS is disabled');
$t->same([], $engine->corsResponseHeaders(corsPreflight(['Origin' => 'https://app.example.com'])), 'corsResponseHeaders empty while disabled');

$t->section('detection: OPTIONS without the preflight header is ordinary');
$engine = corsEngine(...$baseConfig);
$request = corsPreflight(['Origin' => 'https://app.example.com'], null);
$response = $engine->execute($request);
$t->ok($response !== null && $response->statusCode() === 403, 'unresolvable client still fails secure on an ordinary OPTIONS');
$t->same('Client address could not be determined', $response?->body(), 'ordinary OPTIONS failure is the fail-secure path, not CORS');

$t->section('config: normalization and defaults');
$config = new SecurityConfig(
    enableCors: true,
    corsAllowOrigins: ['https://App.example.com'],
    corsAllowMethods: ['get', 'Post'],
    corsAllowHeaders: ['Content-Type', 'X-Request-Id']
);
$t->same(['GET', 'POST'], $config->corsAllowMethods, 'methods uppercased');
$t->same(['content-type', 'x-request-id'], $config->corsAllowHeaders, 'headers lowercased');
$defaults = new SecurityConfig();
$t->same(false, $defaults->enableCors, 'enable_cors defaults false');
$t->same(['*'], $defaults->corsAllowOrigins, 'default origins are the wildcard');
$t->same(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], $defaults->corsAllowMethods, 'default methods cover the six verbs');
$t->same(['*'], $defaults->corsAllowHeaders, 'default headers are the wildcard');
$t->same(false, $defaults->corsAllowCredentials, 'default credentials false');
$t->same([], $defaults->corsExposeHeaders, 'default expose headers empty');
$t->same(600, $defaults->corsMaxAge, 'default max-age 600');
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(corsAllowMethods: ['get', 42]),
    InvalidArgumentException::class,
    null,
    'non-string method entry fails closed'
);

$t->section('runtime: reference `or` fallbacks');
$engine = corsEngine(enableCors: true, corsAllowMethods: [], corsMaxAge: 0);
$response = $engine->execute(corsPreflight(['Access-Control-Request-Method' => 'GET', 'Origin' => 'https://app.example.com']));
$t->ok($response !== null && $response->statusCode() === 200, 'GET preflight passes the GET fallback policy');
$headers = corsHeaders($response);
$t->same('GET', $headers['access-control-allow-methods'] ?? null, 'empty method list falls back to GET');
$t->same('600', $headers['access-control-max-age'] ?? null, 'zero max-age falls back to 600');

$t->section('config: with() immutability');
$base = new SecurityConfig();
$copy = $base->with(['enable_cors' => true, 'cors_allow_origins' => ['https://x.example']]);
$t->same(true, $copy->enableCors, 'with() sets enable_cors on the copy');
$t->same(['https://x.example'], $copy->corsAllowOrigins, 'with() sets cors_allow_origins on the copy');
$t->same(1, $copy->revision(), 'with() bumps revision');
$t->same(false, $base->enableCors, 'source untouched');
$widened = $base->with(['enable_cors' => true, 'cors_allow_origins' => ['*'], 'cors_allow_credentials' => true]);
$t->same(['*'], $widened->corsAllowOrigins, 'with() accepts the wildcard + credentials combination at construction');

exit($t->done('test_cors'));

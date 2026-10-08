<?php

declare(strict_types=1);

/**
 * Router script for the PHP built-in server:
 *
 *   php -S 0.0.0.0:8080 examples/simple_app/index.php
 *
 * simple_app is a minimal guarded HTTP server built directly on the
 * guard-core-php engine, in a single file. It demonstrates the canonical
 * engine wiring:
 *
 *   SecurityConfig -> GuardEngine -> initialize() -> per-request execute()
 *
 * guard-core-php is framework-agnostic, so this app also contains a tiny
 * SAPI shim (the guard() function below) that mirrors what the official
 * adapters (psr15-guard, slim-guard, laravel-guard, symfony-guard) do
 * internally. For real services prefer an adapter; this shim exists to show
 * the full contract.
 */

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

require __DIR__ . '/../../vendor/autoload.php';

// Address headers the Python engine skips when scanning for ssrf patterns.
// This port has no dedicated excluded-detection-headers knob yet; it does
// skip headers listed in logSensitiveHeaders during detection scanning, so
// we route the address headers through it. Without this, a plain
// "Host: localhost" request is flagged as an ssrf attempt.
const ADDRESS_HEADERS = [
    'host', 'origin', 'via', 'x-forwarded-for', 'x-forwarded-host',
    'x-forwarded-proto', 'x-real-ip', 'x-client-ip', 'x-cluster-client-ip',
    'cf-connecting-ip', 'true-client-ip', 'fly-client-ip',
    'x-envoy-external-address',
];

/**
 * Engine holder. Runtimes that keep the process alive across requests
 * (worker mode under FrankenPHP/RoadRunner-style loops) reuse the instance
 * and its in-process state. Note that the PHP built-in server starts a
 * fresh process per request, so anything tracked in memory (like the
 * auto-ban violation counters) resets between requests there; Redis-backed
 * state (rate limits, bans) is unaffected.
 */
function simple_engine(): GuardEngine
{
    static $engine = null;
    if ($engine !== null) {
        return $engine;
    }

    $config = new SecurityConfig(
    // Redis: enabled unless ENABLE_REDIS=0 (compose wires REDIS_HOST in;
    // without Redis the managers fall back to in-process state, which is
    // fine for a demo but not for replicas).
    enableRedis: getenv('ENABLE_REDIS') !== '0',
    redisPrefix: getenv('REDIS_PREFIX') ?: 'guard_core:',
    // Rate limiting: global 30 req/60s per client, with a strict
    // per-endpoint override used by the demo and the live smoke test.
    enableRateLimiting: true,
    rateLimit: 30,
    rateLimitWindow: 60,
    endpointRateLimits: [
        '/rate/strict' => ['limit' => 1, 'window' => 10],
    ],
    // IP banning: 5 violations in the window earns a 5 minute ban.
    enableIpBanning: true,
    autoBanThreshold: 5,
    autoBanDuration: 300,
    // Penetration detection: all categories, default thresholds.
    enablePenetrationDetection: true,
    // See ADDRESS_HEADERS above.
    logSensitiveHeaders: ADDRESS_HEADERS,
    // Blocked user agents (regex patterns).
    blockedUserAgents: ['badbot', 'evil-crawler', 'sqlmap'],
    // Custom block bodies, keyed by status code.
    customErrorResponses: [403 => 'Blocked by guard-core-php'],
    // Paths the pipeline never sees.
    excludePaths: [
        '/docs', '/redoc', '/openapi.json', '/favicon.ico', '/static', '/health',
    ],
    // onBlock is the telemetry seam of this port. Guard Agent integration
    // is not implemented in guard-core-php yet (setting enableAgent fails
    // config validation), so wire the agent from here: forward these
    // payloads to guard-agent-php
    // (https://github.com/Guard-Core/guard-agent-php) once its event pipeline
    // accepts engine events. The payload carries check_name, reason,
    // trigger_info, passive_mode, client_ip, path, method, and status_code.
    onBlock: static function (object $request, array $payload): void {
        file_put_contents('php://stderr', sprintf(
            "guard blocked %s %s from %s via %s: %s\n",
            $payload['method'],
            $payload['path'],
            $payload['client_ip'],
            $payload['check_name'],
            $payload['reason'],
        ));
    });

    $engine = new GuardEngine($config);
    // Connects Redis when enabled and initializes ban/rate-limit state.
    // Call once before the first execute().
    $engine->initialize();

    return $engine;
}

/** @param array<string, string> $headers */
function respond(array $headers, int $status, ?string $body): void
{
    http_response_code($status);
    foreach ($headers as $name => $value) {
        header("{$name}: {$value}");
    }
    if ($body !== null) {
        echo $body;
    }
}

/**
 * The minimal SAPI adapter. It mirrors the official PSR-15 adapter shim:
 * strip the port from REMOTE_ADDR, keep one value per header, and hand the
 * engine a SimpleGuardRequest. A non-null verdict is written back verbatim.
 */
function guard(GuardEngine $engine, string $path, string $method): ?array
{
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (str_starts_with($key, 'HTTP_')) {
            $name = strtolower(str_replace('_', '-', substr($key, 5)));
            $headers[$name] = (string) $value;
        }
    }
    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
    }

    $body = '';
    if ($method === 'POST' || $method === 'PUT' || $method === 'PATCH') {
        $body = (string) file_get_contents('php://input');
    }

    $request = new SimpleGuardRequest(
        urlPath: $path,
        urlScheme: 'http',
        host: $_SERVER['HTTP_HOST'] ?? 'localhost',
        method: $method,
        clientHost: $_SERVER['REMOTE_ADDR'] ?? null,
        headers: $headers,
        queryParams: $_GET,
        rawQuery: $_SERVER['QUERY_STRING'] ?? '',
        body: $body,
    );

    $verdict = $engine->execute($request);
    if ($verdict === null) {
        return null;
    }

    return [$verdict->headers()->all(), $verdict->statusCode(), $verdict->body()];
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

$engine = simple_engine();

$verdict = guard($engine, $path, $method);
if ($verdict !== null) {
    respond(...$verdict);

    return;
}

// From here on these handlers only run for requests the guard allowed.
if ($path === '/health') {
    header('Content-Type: application/json');
    echo "{\"status\":\"ok\"}\n";

    return;
}

if ($path === '/') {
    header('Content-Type: application/json');
    echo '{"app":"guard-core-php simple_app","endpoints":["/health","/echo (POST)","/rate/strict","/search?q="]}', "\n";

    return;
}

if ($path === '/echo') {
    if ($method !== 'POST') {
        http_response_code(405);
        echo "method not allowed\n";

        return;
    }
    header('Content-Type: application/json');
    echo "{\"echo\":true}\n";

    return;
}

if ($path === '/rate/strict') {
    header('Content-Type: application/json');
    echo '{"endpoint":"/rate/strict","limit":"1 request per 10 seconds"}', "\n";

    return;
}

if ($path === '/search') {
    $q = (string) ($_GET['q'] ?? '');
    if (str_contains($q, '<') || str_contains($q, "'")) {
        // The engine should have blocked requests that reach this handler
        // with hostile input; treat this as defense in depth.
        http_response_code(403);
        echo "Blocked by guard-core-php\n";

        return;
    }
    header('Content-Type: application/json');
    echo json_encode(['query' => $q, 'results' => []]), "\n";

    return;
}

http_response_code(404);
echo "not found\n";

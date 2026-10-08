<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Behavior\BehaviorRule;
use RenzoFranceschini\GuardCore\Cloud\CloudProviderRegistry;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Decorators\DecoratedEndpoint;
use RenzoFranceschini\GuardCore\Decorators\RouteConfigRevision;
use RenzoFranceschini\GuardCore\Decorators\SecurityDecorator;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

require __DIR__ . '/../vendor/autoload.php';

// Engine-level acceptance runner for the decorator family, mirroring the
// reference decorator tests (tests/test_decorators/{test_base,
// test_mixins,test_route_id_per_function,test_access_control_*,
// test_advanced_edge_cases,test_detection_exclusion}.py of guard-core): the
// SecurityDecorator mixin surface (25 config methods + the base infra),
// the route-identity mechanism (the _guard_route_id equivalent), the
// shared revision cell, and the engine's set_decorator_handler seam.

final class DT
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

    /** @param class-string<\Throwable> $expectedClass */
    public function throws(string $needle, callable $fn, string $label, string $expectedClass = \InvalidArgumentException::class): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            $this->ok(str_contains($e->getMessage(), $needle), "{$label} (" . $e::class . ")");
            $this->same(true, $e instanceof $expectedClass, "{$label}: {$expectedClass}");

            return;
        }
        $this->failed++;
        echo "  FAIL {$this->section} :: {$label} (no exception)\n";
    }

    public function done(string $name): int
    {
        echo "\n{$name}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed;
    }
}

$t = new DT();

function dtGuard(?SecurityConfig $config = null): SecurityDecorator
{
    return new SecurityDecorator($config ?? new SecurityConfig(enableRedis: false));
}

function dtRequest(string $urlPath = '/', array $headers = [], string $method = 'GET', string $body = ''): SimpleGuardRequest
{
    return new SimpleGuardRequest(urlPath: $urlPath, method: $method, clientHost: '192.0.2.7', headers: $headers, body: $body);
}

/** A duck-typed agent handler collecting the events it is sent. */
final class DtAgentHandler
{
    /** @var list<object> */
    public array $events = [];

    public function sendEvent(object $event): void
    {
        $this->events[] = $event;
    }
}

// A controller pair sharing one method base id (the qualname collision case).
final class DtEndpointHolder
{
    public function show(): string
    {
        return 'show';
    }
}

// An invokable-object endpoint (the get_class base id case).
final class DtInvokableEndpoint
{
    public function __invoke(): string
    {
        return 'invoked';
    }
}

$t->section('route config: reference defaults');
$bare = new RouteConfig();
$t->same(null, $bare->rateLimit, 'rate_limit defaults null');
$t->same(null, $bare->rateLimitWindow, 'rate_limit_window defaults null');
$t->same([], $bare->ipWhitelist, 'ip_whitelist defaults empty');
$t->same([], $bare->ipBlacklist, 'ip_blacklist defaults empty');
$t->same([], $bare->blockedCountries, 'blocked_countries defaults empty');
$t->same([], $bare->whitelistCountries, 'whitelist_countries defaults empty');
$t->same([], $bare->bypassedChecks, 'bypassed_checks defaults empty set');
$t->same(false, $bare->requireHttps, 'require_https defaults false');
$t->same(null, $bare->authRequired, 'auth_required defaults null');
$t->same([], $bare->customValidators, 'custom_validators defaults empty');
$t->same([], $bare->blockedUserAgents, 'blocked_user_agents defaults empty');
$t->same([], $bare->requiredHeaders, 'required_headers defaults empty map');
$t->same([], $bare->behaviorRules, 'behavior_rules defaults empty');
$t->same([], $bare->blockCloudProviders, 'block_cloud_providers defaults empty set');
$t->same(null, $bare->maxRequestSize, 'max_request_size defaults null');
$t->same(null, $bare->allowedContentTypes, 'allowed_content_types defaults null');
$t->same(null, $bare->timeRestrictions, 'time_restrictions defaults null');
$t->same(true, $bare->enableSuspiciousDetection, 'enable_suspicious_detection defaults true');
$t->same(null, $bare->requireReferrer, 'require_referrer defaults null');
$t->same(false, $bare->apiKeyRequired, 'api_key_required defaults false');
$t->same(null, $bare->authVerifier, 'auth_verifier defaults null');
$t->same(null, $bare->apiKeyVerifier, 'api_key_verifier defaults null');
$t->same(null, $bare->apiKeyHeader, 'api_key_header defaults null');
$t->same(null, $bare->authorizationHeaderRequired, 'authorization_header_required defaults null');
$t->same([], $bare->geoRateLimits, 'geo_rate_limits defaults empty');
$t->same(null, $bare->excludedDetectionHeaders, 'excluded_detection_headers defaults null');
$t->same(null, $bare->excludedDetectionParams, 'excluded_detection_params defaults null');
$t->same(null, $bare->excludedDetectionBodyFields, 'excluded_detection_body_fields defaults null');
$t->same(null, $bare->enabledDetectionCategories, 'enabled_detection_categories defaults null');
$t->same(null, $bare->detectionScanBody, 'detection_scan_body defaults null');

$t->section('shared revision cell');
$revision = new RouteConfigRevision();
$t->same(0, $revision->value, 'a fresh cell is zero');
$revision->bump();
$t->same(1, $revision->value, 'bump increments');
$revision->bump();
$t->same(2, $revision->value, 'bump accumulates');

$t->section('base decorator: registry and route identity');
$config = new SecurityConfig(enableRedis: false);
$guard = dtGuard($config);
$t->same($config, $guard->config(), 'the decorator keeps its config');
$t->same(0, $guard->routeConfigRevision(), 'a fresh handler has revision zero');

$fn = static fn (): string => 'ok';
$decorated = $guard->rateLimit(7, 30)->decorate($fn);
$t->same(true, $decorated instanceof DecoratedEndpoint, 'decorating returns a DecoratedEndpoint');
$t->same('closure#' . spl_object_id($fn), $decorated->guardRouteId, 'a closure id is closure#{object id}');
$rc = $guard->getRouteConfig($decorated->guardRouteId);
$t->same(true, $rc !== null, 'the registry holds the decorated route');
$t->same(true, $config->enablePenetrationDetection === $rc->enableSuspiciousDetection, 'the route is seeded with enable_penetration_detection');
$t->same(2, $guard->routeConfigRevision(), 'the registration and its mutation each bump once');
$t->same($rc, SecurityDecorator::getRouteDecoratorConfig((static function () use ($decorated) {
    $r = dtRequest();
    $r->state()->guardRouteId = $decorated->guardRouteId;

    return $r;
})(), $guard), 'the stamped id resolves the registry instance');
$decoratedAgain = $guard->bypass(['rate_limit'])->decorate($fn);
$t->same($decorated->guardRouteId, $decoratedAgain->guardRouteId, 're-decorating the same endpoint joins its route');
$t->same(['rate_limit'], $guard->getRouteConfig($decorated->guardRouteId)->bypassedChecks, 'joined routes share one config');
$t->same(null, $guard->getRouteConfig('non.existent.route'), 'an unknown id resolves null');
$registry = $guard->routeConfigs();
$t->same(true, isset($registry[$decorated->guardRouteId]), 'routeConfigs exposes the registry');

$t->section('base decorator: get_route_decorator_config');
$noId = dtRequest();
$t->same(null, SecurityDecorator::getRouteDecoratorConfig($noId, $guard), 'no stamped id resolves null');
$request = dtRequest();
$request->state()->guardRouteId = $decorated->guardRouteId;
$t->same(true, SecurityDecorator::getRouteDecoratorConfig($request, $guard) !== null, 'the stamped id resolves its config');
$request->state()->guardRouteId = 'unknown.route';
$t->same(null, SecurityDecorator::getRouteDecoratorConfig($request, $guard), 'an unknown stamped id resolves null');

$t->section('base decorator: behavior tracking and agent wiring');
$guard->initializeBehaviorTracking();
$trackerBefore = $guard->behaviorTracker();
$guard->initializeBehaviorTracking(null);
$t->same($trackerBefore, $guard->behaviorTracker(), 'a null redis handler keeps the tracker');
$guard->initializeBehaviorTracking(new RenzoFranceschini\GuardCore\Redis\RedisHandler(enableRedis: false));
$t->same(true, $guard->behaviorTracker() !== $trackerBefore, 'a redis handler rewires the tracker');
$agent = new DtAgentHandler();
$guard->initializeAgent($agent);
$t->same(true, true, 'initializeAgent accepts a handler');

$t->section('access control mixin');
$g = dtGuard();
$ep = $g->requireIp(whitelist: ['10.0.0.1'])->decorate('/ip-w');
$rc = $g->getRouteConfig('/ip-w');
$t->same(['10.0.0.1'], $rc->ipWhitelist, 'require_ip whitelist lands');
$g = dtGuard();
$ep = $g->requireIp(blacklist: ['10.0.0.2'])->decorate('/ip-b');
$rc = $g->getRouteConfig('/ip-b');
$t->same(['10.0.0.2'], $rc->ipBlacklist, 'require_ip blacklist lands');
$g = dtGuard();
$g->requireIp(whitelist: ['10.0.0.1'], blacklist: ['10.0.0.3'])->decorate('/ip-both');
$rc = $g->getRouteConfig('/ip-both');
$t->same(['10.0.0.1'], $rc->ipWhitelist, 'require_ip both: whitelist');
$t->same(['10.0.0.3'], $rc->ipBlacklist, 'require_ip both: blacklist');
$g = dtGuard();
$g->requireIp()->decorate('/ip-none');
$rc = $g->getRouteConfig('/ip-none');
$t->same([], $rc->ipWhitelist, 'require_ip without lists is a no-op registration');

$g = dtGuard();
$g->blockCountries(['cn', 'ru'])->decorate('/cc-b');
$t->same(['CN', 'RU'], $g->getRouteConfig('/cc-b')->blockedCountries, 'block_countries uppercases');
$g = dtGuard();
$g->allowCountries(['us', 'uk'])->decorate('/cc-w');
$t->same(['US', 'UK'], $g->getRouteConfig('/cc-w')->whitelistCountries, 'allow_countries uppercases');

$g = dtGuard();
$g->blockClouds()->decorate('/cloud-all');
$t->same(CloudProviderRegistry::PROVIDERS, $g->getRouteConfig('/cloud-all')->blockCloudProviders, 'block_clouds without providers blocks every provider');
$g = dtGuard();
$g->blockClouds(['AWS', 'GCP:!us'])->decorate('/cloud-some');
$t->same(['AWS', 'GCP:!us'], $g->getRouteConfig('/cloud-some')->blockCloudProviders, 'block_clouds keeps valid selectors including regions');
$g = dtGuard();
$g->blockClouds(['AWS', 'NotACloud'])->decorate('/cloud-bad');
$t->same(['AWS'], $g->getRouteConfig('/cloud-bad')->blockCloudProviders, 'block_clouds drops unknown providers');

$g = dtGuard();
$g->bypass(['ip', 'rate_limit'])->decorate('/bypass-1');
$rc = $g->getRouteConfig('/bypass-1');
$t->same(true, in_array('ip', $rc->bypassedChecks, true), 'bypass keeps ip');
$t->same(true, in_array('rate_limit', $rc->bypassedChecks, true), 'bypass keeps rate_limit');
$g->bypass(['all', 'not-a-check'])->decorate('/bypass-1');
$rc = $g->getRouteConfig('/bypass-1');
$t->same(['ip', 'rate_limit', 'all'], $rc->bypassedChecks, 'bypass unions across applications and drops unknown names');

$t->section('rate limiting mixin');
$g = dtGuard();
$g->rateLimit(100, 30)->decorate('/rl');
$rc = $g->getRouteConfig('/rl');
$t->same(100, $rc->rateLimit, 'rate_limit sets the limit');
$t->same(30, $rc->rateLimitWindow, 'rate_limit sets the window');
$g = dtGuard();
$g->rateLimit(50)->decorate('/rl-default');
$t->same(60, $g->getRouteConfig('/rl-default')->rateLimitWindow, 'rate_limit window defaults to 60');
$g = dtGuard();
$g->geoRateLimit(['US' => ['limit' => 100, 'window' => 60], '*' => ['limit' => 50, 'window' => 60]])->decorate('/geo');
$rc = $g->getRouteConfig('/geo');
$t->same(true, isset($rc->geoRateLimits['US']), 'geo_rate_limit registers a tier');
$t->same(true, isset($rc->geoRateLimits['*']), 'geo_rate_limit registers the fallback tier');

$t->section('behavioral mixin');
$g = dtGuard();
$g->usageMonitor(maxCalls: 100, window: 3600, action: 'ban')->decorate('/usage');
$rules = $g->getRouteConfig('/usage')->behaviorRules;
$t->same(1, count($rules), 'usage_monitor appends one rule');
$t->same('usage', $rules[0]->ruleType, 'usage_monitor rule type');
$t->same(100, $rules[0]->threshold, 'usage_monitor threshold');
$t->same(3600, $rules[0]->window, 'usage_monitor window');
$t->same('ban', $rules[0]->action, 'usage_monitor action');

$g = dtGuard(new SecurityConfig(enableRedis: false, behaviorScanResponseBody: true));
$g->returnMonitor(pattern: 'error', maxOccurrences: 5, window: 86400, action: 'log')->decorate('/return');
$rules = $g->getRouteConfig('/return')->behaviorRules;
$t->same(1, count($rules), 'return_monitor appends one rule');
$t->same('return_pattern', $rules[0]->ruleType, 'return_monitor rule type');
$t->same('error', $rules[0]->pattern, 'return_monitor pattern');

$g = dtGuard();
$g->returnMonitor(pattern: 'status:500', maxOccurrences: 5, window: 86400, action: 'log')->decorate('/return-status');
$t->same('status:500', $g->getRouteConfig('/return-status')->behaviorRules[0]->pattern, 'a status: return pattern never needs the body scan');
$g = dtGuard();
$t->throws('behavior_scan_response_body', static fn () => $g->returnMonitor('error', 5), 'return_monitor body pattern rejected with the scan off');

$g = dtGuard();
$g->returnMonitor('', 5)->decorate('/return-empty');
$emptyRules = $g->getRouteConfig('/return-empty')->behaviorRules;
$t->same(1, count($emptyRules), 'an empty pattern skips the scan gate like the list validator');
$t->same('', $emptyRules[0]->pattern, 'the empty-pattern rule still lands');

$g = dtGuard();
$g->behaviorAnalysis([new BehaviorRule(ruleType: 'usage', threshold: 10, window: 60, action: 'log')])->decorate('/behavior');
$rules = $g->getRouteConfig('/behavior')->behaviorRules;
$t->same(1, count($rules), 'behavior_analysis extends the route rules');
$g = dtGuard();
$t->throws('behavior_scan_response_body', static fn () => $g->behaviorAnalysis([new BehaviorRule(ruleType: 'return_pattern', threshold: 5, pattern: 'json:status==ok')]), 'behavior_analysis body rule rejected with the scan off');

$g = dtGuard();
$g->suspiciousFrequency(maxFrequency: 2.0, window: 300, action: 'alert')->decorate('/freq');
$rules = $g->getRouteConfig('/freq')->behaviorRules;
$t->same('frequency', $rules[0]->ruleType, 'suspicious_frequency rule type');
$t->same(600, $rules[0]->threshold, 'suspicious_frequency threshold is max_frequency * window');
$t->same('alert', $rules[0]->action, 'suspicious_frequency action');

$t->section('authentication mixin');
$g = dtGuard();
$g->requireHttps()->decorate('/https');
$t->same(true, $g->getRouteConfig('/https')->requireHttps, 'require_https flags the route');

$g = dtGuard();
$g->requireAuth(type: 'bearer')->decorate('/auth-bearer');
$rc = $g->getRouteConfig('/auth-bearer');
$t->same('bearer', $rc->authRequired, 'require_auth bearer');
$t->same(null, $rc->authVerifier, 'require_auth without a verifier');
$verifier = static fn (object $request, string $credential): string => $credential;
$g = dtGuard();
$g->requireAuth(type: 'bearer', verifier: $verifier)->decorate('/auth-verifier');
$t->same($verifier, $g->getRouteConfig('/auth-verifier')->authVerifier, 'require_auth keeps its verifier');
$g = dtGuard();
$g->requireAuth(type: 'basic')->decorate('/auth-basic');
$t->same('basic', $g->getRouteConfig('/auth-basic')->authRequired, 'require_auth basic');

$g = dtGuard();
$g->apiKeyAuth(headerName: 'X-API-Key')->decorate('/key');
$rc = $g->getRouteConfig('/key');
$t->same(true, $rc->apiKeyRequired, 'api_key_auth flags the route');
$t->same('required', $rc->requiredHeaders['X-API-Key'], 'api_key_auth requires its header');
$t->same('X-API-Key', $rc->apiKeyHeader, 'api_key_auth records the header');
$t->same(null, $rc->apiKeyVerifier, 'api_key_auth without a verifier');
$g = dtGuard();
$g->apiKeyAuth(headerName: 'X-Key', verifier: $verifier)->decorate('/key2');
$rc = $g->getRouteConfig('/key2');
$t->same('X-Key', $rc->apiKeyHeader, 'api_key_auth custom header');
$t->same($verifier, $rc->apiKeyVerifier, 'api_key_auth keeps its verifier');

$g = dtGuard();
$g->requireAuthorizationHeader(scheme: 'bearer')->decorate('/authz');
$rc = $g->getRouteConfig('/authz');
$t->same('bearer', $rc->authorizationHeaderRequired, 'require_authorization_header records the scheme');
$t->same(null, $rc->authRequired, 'require_authorization_header leaves auth empty');
$t->same(null, $rc->authVerifier, 'require_authorization_header leaves the verifier empty');

$g = dtGuard();
$g->requireAuthorizationHeader('bearer')->decorate('/conflict-1');
$t->throws('require_authorization_header', static fn () => $g->requireAuth('bearer')->decorate('/conflict-1'), 'require_auth conflicts with require_authorization_header');
$g = dtGuard();
$g->requireAuthorizationHeader('bearer')->decorate('/conflict-2');
$t->throws('require_authorization_header', static fn () => $g->apiKeyAuth('X-Key')->decorate('/conflict-2'), 'api_key_auth conflicts with require_authorization_header');
$g = dtGuard();
$g->requireAuth('bearer')->decorate('/conflict-3');
$t->throws('require_authorization_header', static fn () => $g->requireAuthorizationHeader('bearer')->decorate('/conflict-3'), 'require_authorization_header conflicts with require_auth');
$g = dtGuard();
$g->apiKeyAuth('X-Key')->decorate('/conflict-4');
$t->throws('require_authorization_header', static fn () => $g->requireAuthorizationHeader('bearer')->decorate('/conflict-4'), 'require_authorization_header conflicts with api_key_auth');

$g = dtGuard();
$g->requireHeaders(['X-Custom' => 'required'])->decorate('/headers');
$t->same('required', $g->getRouteConfig('/headers')->requiredHeaders['X-Custom'], 'require_headers records the header');
$g->requireHeaders(['X-Other' => 'yes'])->decorate('/headers');
$rc = $g->getRouteConfig('/headers');
$t->same(true, isset($rc->requiredHeaders['X-Custom'], $rc->requiredHeaders['X-Other']), 'require_headers merges across applications');

$t->section('content filtering mixin');
$g = dtGuard();
$g->blockUserAgents(['badbot', 'scanner'])->decorate('/ua');
$t->same(true, in_array('badbot', $g->getRouteConfig('/ua')->blockedUserAgents, true), 'block_user_agents extends the route list');
$g->blockUserAgents(['crawler'])->decorate('/ua');
$t->same(['badbot', 'scanner', 'crawler'], $g->getRouteConfig('/ua')->blockedUserAgents, 'block_user_agents merges across applications');
$g = dtGuard();
$t->throws('rejected by ReDoS validator', static fn () => $g->blockUserAgents(['(?:a+)+$']), 'block_user_agents rejects a catastrophic pattern before decoration');

$g = dtGuard();
$g->contentTypeFilter(['application/json'])->decorate('/ct');
$t->same(['application/json'], $g->getRouteConfig('/ct')->allowedContentTypes, 'content_type_filter sets the allow list');

$g = dtGuard();
$g->maxRequestSize(1024)->decorate('/size');
$t->same(1024, $g->getRouteConfig('/size')->maxRequestSize, 'max_request_size sets the bound');

$g = dtGuard();
$g->requireReferrer(['example.com'])->decorate('/ref');
$t->same(['example.com'], $g->getRouteConfig('/ref')->requireReferrer, 'require_referrer sets the domains');

$g = dtGuard();
$called = false;
$validator = static function (object $request) use (&$called) {
    $called = true;

    return null;
};
$g->customValidation($validator)->decorate('/custom');
$validators = $g->getRouteConfig('/custom')->customValidators;
$t->same(1, count($validators), 'custom_validation appends the validator');
$t->same(true, $validators[0] === $validator, 'custom_validation keeps the exact closure');

$g = dtGuard();
$g->detectionExclusion(headers: ['X-Noise'], params: ['q'], bodyFields: ['secret'], categories: ['sqli'], scanBody: false)->decorate('/dex');
$rc = $g->getRouteConfig('/dex');
$t->same(['X-Noise'], $rc->excludedDetectionHeaders, 'detection_exclusion headers');
$t->same(['q'], $rc->excludedDetectionParams, 'detection_exclusion params');
$t->same(['secret'], $rc->excludedDetectionBodyFields, 'detection_exclusion body fields');
$t->same(['sqli'], $rc->enabledDetectionCategories, 'detection_exclusion categories');
$t->same(false, $rc->detectionScanBody, 'detection_exclusion scan body');
$g = dtGuard();
$g->detectionExclusion(params: ['only-one'])->decorate('/dex-partial');
$rc = $g->getRouteConfig('/dex-partial');
$t->same(['only-one'], $rc->excludedDetectionParams, 'detection_exclusion partial application');
$t->same(null, $rc->excludedDetectionHeaders, 'detection_exclusion untouched fields stay null');
$t->same(null, $rc->detectionScanBody, 'detection_exclusion untouched scan body stays null');
$g = dtGuard();
$g->detectionExclusion()->decorate('/dex-none');
$t->same(null, $g->getRouteConfig('/dex-none')->excludedDetectionParams, 'detection_exclusion without arguments is a registration no-op');

$t->section('advanced mixin');
$g = dtGuard();
$g->timeWindow('09:00', '17:00', 'US/Eastern')->decorate('/window');
$rc = $g->getRouteConfig('/window');
$t->same('09:00', $rc->timeRestrictions['start'], 'time_window start');
$t->same('17:00', $rc->timeRestrictions['end'], 'time_window end');
$t->same('US/Eastern', $rc->timeRestrictions['timezone'], 'time_window timezone');
$g = dtGuard();
$g->timeWindow('09:00', '17:00')->decorate('/window-default');
$t->same('UTC', $g->getRouteConfig('/window-default')->timeRestrictions['timezone'], 'time_window timezone defaults to UTC');

$g = dtGuard();
$g->suspiciousDetection(enabled: false)->decorate('/susp');
$t->same(false, $g->getRouteConfig('/susp')->enableSuspiciousDetection, 'suspicious_detection disables the route gate');
$g = dtGuard();
$g->suspiciousDetection()->decorate('/susp-default');
$t->same(true, $g->getRouteConfig('/susp-default')->enableSuspiciousDetection, 'suspicious_detection defaults enabled');

$t->section('honeypot detection');
$honeypotGuard = dtGuard();
$honeypotGuard->honeypotDetection(['honeypot'])->decorate('/hp');
$hpValidators = $honeypotGuard->getRouteConfig('/hp')->customValidators;
$t->same(1, count($hpValidators), 'honeypot_detection appends one validator');
$hp = $hpValidators[0];

$hpJsonHit = $hp(dtRequest('/hp', ['content-type' => 'application/json'], 'POST', '{"honeypot": "filled"}'));
$t->same(403, $hpJsonHit?->statusCode(), 'honeypot json trigger returns 403');
$t->same('Forbidden', $hpJsonHit?->body(), 'honeypot json trigger body');
$t->same(null, $hp(dtRequest('/hp', ['content-type' => 'application/json'], 'POST', '{"name": "test"}')), 'honeypot json clean body passes');
$t->same(null, $hp(dtRequest('/hp', ['content-type' => 'application/json'], 'POST', 'not json at all')), 'honeypot invalid json skips');
$t->same(null, $hp(dtRequest('/hp', ['content-type' => 'application/json'], 'POST', '{"honeypot": 0}')), 'honeypot json zero value is falsy');
$hpJsonStringZero = $hp(dtRequest('/hp', ['content-type' => 'application/json'], 'POST', '{"honeypot": "0"}'));
$t->same(403, $hpJsonStringZero?->statusCode(), 'honeypot json "0" string is truthy like the reference');
$hpFormHit = $hp(dtRequest('/hp', ['content-type' => 'application/x-www-form-urlencoded'], 'POST', 'name=x&honeypot=filled'));
$t->same(403, $hpFormHit?->statusCode(), 'honeypot form trigger returns 403');
$t->same(null, $hp(dtRequest('/hp', ['content-type' => 'application/x-www-form-urlencoded'], 'POST', 'name=test')), 'honeypot form clean body passes');
$t->same(null, $hp(dtRequest('/hp', ['content-type' => 'application/x-www-form-urlencoded'], 'POST', 'honeypot=')), 'honeypot empty trap value passes');
$t->same(null, $hp(dtRequest('/hp'), 'GET'), 'honeypot ignores GET');
$t->same(null, $hp(dtRequest('/hp', ['content-type' => 'text/plain'], 'POST', 'honeypot=filled')), 'honeypot unknown content type skips');

$t->section('route identity: per endpoint, per instance');
$g = dtGuard();
$strict = $g->rateLimit(2, 60)->decorate(static fn (): string => 'strict');
$loose = $g->rateLimit(100, 60)->decorate(static fn (): string => 'loose');
$t->same(true, $strict->guardRouteId !== $loose->guardRouteId, 'two endpoints built by one factory keep distinct ids');
$strictRequest = dtRequest();
$strictRequest->state()->guardRouteId = $strict->guardRouteId;
$looseRequest = dtRequest();
$looseRequest->state()->guardRouteId = $loose->guardRouteId;
$t->same(2, SecurityDecorator::getRouteDecoratorConfig($strictRequest, $g)?->rateLimit, 'the strict endpoint keeps its own limit');
$t->same(100, SecurityDecorator::getRouteDecoratorConfig($looseRequest, $g)?->rateLimit, 'the loose endpoint keeps its own limit');

$g = dtGuard();
$admin = $g->requireIp(whitelist: ['10.0.0.1'])->decorate('/admin-endpoint');
$health = $g->bypass(['all'])->decorate('/health-endpoint');
$t->same([], $g->getRouteConfig('/admin-endpoint')->bypassedChecks, 'one endpoint never gains another endpoint knobs');
$t->same([], $g->getRouteConfig('/health-endpoint')->ipWhitelist, 'the other endpoint never gains the first knobs');

$g = dtGuard();
$first = $g->rateLimit(2, 60)->decorate('/endpoint');
$second = $g->rateLimit(100, 60)->decorate('/endpoint#2');
$t->same('/endpoint', $first->guardRouteId, 'a pattern endpoint keeps the pattern as its id');

$g = dtGuard();
$holderA = new DtEndpointHolder();
$holderB = new DtEndpointHolder();
$epA = $g->rateLimit(1, 60)->decorate([$holderA, 'show']);
$epB = $g->rateLimit(2, 60)->decorate([$holderB, 'show']);
$t->same(true, $epA->guardRouteId !== $epB->guardRouteId, 'two instances of one method get distinct route ids');
$t->same(true, str_starts_with($epB->guardRouteId, $epA->guardRouteId), 'the second instance suffixes the shared base id');

$g = dtGuard();
$stacked = $g->requireIp(whitelist: ['10.0.0.1'])->decorate(static fn (): string => 'stacked');
$g->rateLimit(5, 60)->decorate($stacked->endpoint());
$t->same(1, count($g->routeConfigs()), 'stacked decorations share one route');
$stackedConfig = $g->getRouteConfig($stacked->guardRouteId);
$t->same(['10.0.0.1'], $stackedConfig->ipWhitelist, 'stacked: the first knob');
$t->same(5, $stackedConfig->rateLimit, 'stacked: the second knob');

$guardA = dtGuard();
$guardB = dtGuard();
$firstEp = $guardA->rateLimit(2, 60)->decorate(static fn (): string => 'first');
$secondEp = $guardB->bypass(['all'])->decorate(static fn (): string => 'second');
$redecorated = $guardB->requireIp(whitelist: ['10.0.0.1'])->decorate($firstEp->endpoint());
$firstConfig = $guardB->getRouteConfig($redecorated->guardRouteId);
$secondConfig = $guardB->getRouteConfig($secondEp->guardRouteId);
$t->same(true, $redecorated->guardRouteId !== $secondEp->guardRouteId, 'a stamped id is not reused across decorator instances');
$t->same(['10.0.0.1'], $firstConfig->ipWhitelist, 'the re-decorated endpoint carries its own knobs');
$t->same(['all'], $secondConfig->bypassedChecks, 'the other instance endpoint keeps its knobs');
$t->same([], $firstConfig->bypassedChecks, 'the re-decorated endpoint never joined the other route');

$t->section('route identity: exotic endpoint forms');
$g = dtGuard();
$invokable = new DtInvokableEndpoint();
$invokableEp = $g->rateLimit(1, 60)->decorate($invokable);
$t->same(DtInvokableEndpoint::class, $invokableEp->guardRouteId, 'an invokable object ids by its class');
$t->same('invoked', $invokableEp(), 'an invokable object still calls through');

$g = dtGuard();
$staticEp = $g->requireHttps()->decorate([DtEndpointHolder::class, 'show']);
$t->same(DtEndpointHolder::class . '::show', $staticEp->guardRouteId, 'a class-string method array ids by Class::method');

$g = dtGuard();
$oddEp = $g->requireHttps()->decorate(42);
$t->same('endpoint', $oddEp->guardRouteId, 'an unform endpoint falls back to the generic id');

$hpGuard = dtGuard();
$hpGuard->honeypotDetection(['honeypot'])->decorate('/hp2');
$hp2 = $hpGuard->getRouteConfig('/hp2')->customValidators[0];
$t->same(403, $hp2(dtRequest('/hp2', ['content-type' => 'application/x-www-form-urlencoded'], 'POST', 'honeypot=filled&&x=1'))?->statusCode(), 'honeypot form parse skips empty pairs');
$t->same(null, $hp2(dtRequest('/hp2', ['content-type' => 'application/x-www-form-urlencoded'], 'POST', 'honeypot')), 'honeypot bare key carries an empty value');

$t->section('decorated endpoint shell');
$shell = new DecoratedEndpoint(static fn (string $greeting): string => "{$greeting} world", 'route');
$t->same(true, $shell->isCallable(), 'a callable shell reports callable');
$t->same('hello world', $shell('hello'), 'the shell invokes through');
$patternShell = new DecoratedEndpoint('GET /path', 'GET /path');
$t->same('GET /path', $patternShell->endpoint(), 'a pattern shell keeps the pattern');
$t->same(false, $patternShell->isCallable(), 'a pattern shell reports not callable');
$t->throws('is a route pattern', static fn () => $patternShell(), 'invoking a pattern shell throws', \LogicException::class);

$t->section('infra events');
$eventGuard = dtGuard();
$quiet = dtRequest();
$eventGuard->sendDecoratorEvent(EventTypes::EVENT_ACCESS_DENIED, $quiet, 'blocked', 'no handler', 'access_control');
$t->same(true, true, 'sending with no agent handler is a no-op');
$eventGuard->sendAccessDeniedEvent($quiet, 'no handler', 'access_control');
$t->same(true, true, 'access denied with no handler is a no-op');

$eventConfig = new SecurityConfig(enableRedis: false, agentEnableEvents: false);
$mutedGuard = dtGuard($eventConfig);
$mutedAgent = new DtAgentHandler();
$mutedGuard->initializeAgent($mutedAgent);
$mutedGuard->sendDecoratorEvent(EventTypes::EVENT_ACCESS_DENIED, dtRequest(), 'blocked', 'muted', 'access_control');
$t->same([], $mutedAgent->events, 'agent_enable_events false silences the emitters');

$sendingGuard = dtGuard();
$agent = new DtAgentHandler();
$sendingGuard->initializeAgent($agent);
$eventRequest = dtRequest('/api/data', ['user-agent' => 'test-agent']);
$sendingGuard->sendDecoratorEvent(EventTypes::EVENT_ACCESS_DENIED, $eventRequest, 'blocked', 'nope', 'access_control');
$t->same(1, count($agent->events), 'send_decorator_event dispatches');
$event = $agent->events[0];
$t->same(EventTypes::EVENT_ACCESS_DENIED, $event->eventType, 'envelope event_type');
$t->same('blocked', $event->actionTaken, 'envelope action_taken');
$t->same('nope', $event->reason, 'envelope reason');
$t->same('access_control', $event->metadata['decorator_type'] ?? null, 'envelope decorator_type');
$t->same('middleware', $event->handlerName, 'envelope handler_name');

$agent = new DtAgentHandler();
$sendingGuard->initializeAgent($agent);
$sendingGuard->sendAccessDeniedEvent($eventRequest, 'ip denied', 'ip_security');
$t->same(EventTypes::EVENT_ACCESS_DENIED, $agent->events[0]->eventType, 'send_access_denied_event type');
$t->same('ip_security', $agent->events[0]->metadata['decorator_type'] ?? null, 'send_access_denied_event decorator type');

$sendingGuard->sendAuthenticationFailedEvent($eventRequest, 'bad token', 'bearer');
$t->same(EventTypes::EVENT_AUTHENTICATION_FAILED, $agent->events[1]->eventType, 'send_authentication_failed_event type');
$t->same('authentication', $agent->events[1]->metadata['decorator_type'] ?? null, 'send_authentication_failed_event decorator type');
$t->same('bearer', $agent->events[1]->metadata['auth_type'] ?? null, 'send_authentication_failed_event auth_type');

$sendingGuard->sendRateLimitEvent($eventRequest, 100, 60);
$t->same(EventTypes::EVENT_RATE_LIMITED, $agent->events[2]->eventType, 'send_rate_limit_event type');
$t->same('Rate limit exceeded: 100 requests per 60s', $agent->events[2]->reason, 'send_rate_limit_event reason');
$t->same('rate_limiting', $agent->events[2]->metadata['decorator_type'] ?? null, 'send_rate_limit_event decorator type');
$t->same(100, $agent->events[2]->metadata['limit'] ?? null, 'send_rate_limit_event limit');
$t->same(60, $agent->events[2]->metadata['window'] ?? null, 'send_rate_limit_event window');

$sendingGuard->sendDecoratorViolationEvent($eventRequest, 'content_filter', 'bad content');
$t->same(EventTypes::EVENT_DECORATOR_VIOLATION, $agent->events[3]->eventType, 'send_decorator_violation_event type');
$t->same('content_filter', $agent->events[3]->metadata['decorator_type'] ?? null, 'send_decorator_violation_event decorator type');

$geoAgent = new DtAgentHandler();
$geoGuard = dtGuard();
$geoGuard->initializeAgent($geoAgent, new class implements RenzoFranceschini\GuardCore\GeoIp\CountryResolver {
    public function getCountry(string $ip): ?string
    {
        return 'US';
    }
});
$geoGuard->sendDecoratorEvent(EventTypes::EVENT_ACCESS_DENIED, dtRequest(), 'blocked', 'geo wired', 'access_control');
$t->same(1, count($geoAgent->events), 'the geo handler wiring keeps the emitter live');

$t->section('revision semantics');
$g = dtGuard();
$t->same(0, $g->routeConfigRevision(), 'no routes: revision zero');
$g->rateLimit(1, 60)->decorate('/rev-a');
$revisionAfterFirst = $g->routeConfigRevision();
$t->same(true, $revisionAfterFirst > 0, 'the first registration bumps the shared revision');
$g->bypass(['ip'])->decorate('/rev-a');
$t->same($revisionAfterFirst + 1, $g->routeConfigRevision(), 'a mutation bumps again');
$g->requireHttps()->decorate('/rev-b');
$t->same(true, $g->routeConfigRevision() > $revisionAfterFirst + 1, 'a second registration bumps again');
$before = $g->routeConfigRevision();
$g->maxRequestSize(5)->decorate('/rev-a');
$g->maxRequestSize(5)->decorate('/rev-a');
$t->same(true, $g->routeConfigRevision() >= $before + 2, 'each applied decoration bumps once');

$t->section('engine seam: set_decorator_handler');
$engineConfig = new SecurityConfig(enableRedis: false);
$engine = new GuardEngine($engineConfig);
$sec = dtGuard($engineConfig);
$protected = $sec->requireHeaders(['X-Token' => 'required'])->decorate('GET /admin');
$t->same(null, $engine->decoratorHandler(), 'a fresh engine has no decorator handler');
$engine->setDecoratorHandler($sec);
$t->same($sec, $engine->decoratorHandler(), 'set_decorator_handler wires the handler');
$blocked = $engine->execute((static function () {
    $r = dtRequest('/admin');
    $r->state()->clientIp = '192.0.2.7';
    $r->state()->guardRouteId = 'GET /admin';

    return $r;
})());
$t->same(400, $blocked?->statusCode(), 'the decorated route enforces its header through the pipeline');
$allowed = $engine->execute((static function () {
    $r = dtRequest('/admin', ['X-Token' => 'required']);
    $r->state()->clientIp = '192.0.2.7';
    $r->state()->guardRouteId = 'GET /admin';

    return $r;
})());
$t->same(null, $allowed, 'a conforming request passes the decorated route');

$unstamped = dtRequest('/admin');
$unstamped->state()->clientIp = '192.0.2.7';
$t->same(null, $engine->execute($unstamped), 'an unstamped request runs unscoped');

$noHandlerEngine = new GuardEngine(new SecurityConfig(enableRedis: false));
$unresolved = dtRequest('/admin');
$unresolved->state()->clientIp = '192.0.2.7';
$unresolved->state()->guardRouteId = 'GET /admin';
$t->same(null, $noHandlerEngine->execute($unresolved), 'without a handler a stamped id resolves nothing');

$t->section('adapter seam: the registry feeds a path-pattern route map');
$adapterGuard = dtGuard();
$adapterGuard->requireHttps()->decorate('GET /secure');
$adapterGuard->rateLimit(3, 60)->decorate('/throttled');
$routes = $adapterGuard->routeConfigs();
$t->same(true, isset($routes['GET /secure'], $routes['/throttled']), 'the registry keys by pattern');
$t->same(true, $routes['GET /secure']->requireHttps, 'the decorated config rides the plain route map');

exit($t->done('test_decorators'));

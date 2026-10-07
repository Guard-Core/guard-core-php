<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Cloud\CloudManager;
use RenzoFranceschini\GuardCore\Cloud\HttpClient;
use RenzoFranceschini\GuardCore\Cloud\HttpResponse;
use RenzoFranceschini\GuardCore\Cloud\InMemoryCloudIpStore;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;

require __DIR__ . '/../vendor/autoload.php';

// The parity event emitters (GAP-P4): cloud_blocked through the bus's
// send_cloud_detection_events port, the route block_clouds
// decorator_violation, country_blocked and geo_lookup_failed from the
// ip_security check, and security_headers_applied behind the reference
// headers TTL cache.

final class EvT
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

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }

    public function finish(string $label): int
    {
        echo "\n{$label}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed === 0 ? 0 : 1;
    }
}

final class EvAgent
{
    /** @var list<SecurityEvent> */
    public array $received = [];

    public function sendEvent(object $event): void
    {
        $this->received[] = $event;
    }

    /** @return list<string> */
    public function types(): array
    {
        return array_map(static fn (object $e): string => $e->eventType, $this->received);
    }
}

final class StaticCountry implements CountryResolver
{
    public function __construct(private readonly ?string $country)
    {
    }

    public function getCountry(string $ip): ?string
    {
        return $this->country;
    }
}

final class ExplodingResolver implements CountryResolver
{
    public function getCountry(string $ip): ?string
    {
        throw new RuntimeException('mmdb exploded');
    }
}

final class AwsStubClient implements HttpClient
{
    public function get(string $url, array $options = []): HttpResponse
    {
        return new HttpResponse(200, (string) json_encode([
            'prefixes' => [
                ['ip_prefix' => '203.0.113.0/24', 'region' => 'us-east-1', 'service' => 'AMAZON'],
            ],
        ]));
    }
}

$t = new EvT();

// ---------------------------------------------------------------------
// 1. The bus cloud-detection method
// ---------------------------------------------------------------------
$t->section('send_cloud_detection_events');
$agent = new EvAgent();
$config = new SecurityConfig();
$bus = new EventBus($agent, $config);
$cloudManager = new CloudManager(new AwsStubClient(), new InMemoryCloudIpStore());
$cloudManager->refreshAsync(['AWS'], 3600);
$request = new SimpleGuardRequest(urlPath: '/api', clientHost: '203.0.113.9');

$bus->sendCloudDetectionEvents($request, '203.0.113.9', ['AWS'], null, $cloudManager, false);
$cloudEvents = array_values(array_filter($agent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_CLOUD_BLOCKED));
$t->same(1, count($cloudEvents), 'a cloud ip emits cloud_blocked');
$cloudEvent = $cloudEvents[0];
$t->same('cloud', $cloudEvent->handlerName, 'the cloud handler name');
$t->same('request_blocked', $cloudEvent->actionTaken, 'the active-mode action');
$t->same('IP belongs to blocked cloud provider: AWS', $cloudEvent->reason, 'the reference reason');
$t->same('AWS', $cloudEvent->metadata['cloud_provider'] ?? null, 'the provider metadata');
$t->truthy(str_contains((string) $cloudEvent->metadata['network'], '203.0.113.0/24'), 'the network metadata');
$t->same(null, $cloudEvent->country, 'no country on the cloud event');

$bus->sendCloudDetectionEvents($request, '203.0.113.9', ['AWS'], null, $cloudManager, true);
$cloudEvents = array_values(array_filter($agent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_CLOUD_BLOCKED));
$t->same(2, count($cloudEvents), 'the second lookup emits again');
$t->same('logged_only', $cloudEvents[1]->actionTaken, 'the passive-mode action');

$agent->received = [];
$bus->sendCloudDetectionEvents($request, '198.51.100.1', ['AWS'], null, $cloudManager, false);
$t->same([], $agent->received, 'a non-cloud ip emits nothing');

$agent->received = [];
$routeBlocks = new RouteConfig(blockCloudProviders: ['AWS']);
$bus->sendCloudDetectionEvents($request, '203.0.113.9', ['AWS'], $routeBlocks, $cloudManager, false);
$types = $agent->types();
$t->truthy(in_array(EventTypes::EVENT_DECORATOR_VIOLATION, $types, true), 'a blocking route emits decorator_violation');
$decorator = $agent->received[array_search(EventTypes::EVENT_DECORATOR_VIOLATION, $types, true)];
$t->same('access_control', $decorator->metadata['decorator_type'] ?? null, 'the access_control decorator type');
$t->same('cloud_provider', $decorator->metadata['violation_type'] ?? null, 'the cloud_provider violation type');
$t->same(['AWS'], $decorator->metadata['blocked_providers'] ?? null, 'the blocked providers metadata');

$agent->received = [];
$bus->sendCloudDetectionEvents($request, '203.0.113.9', ['AWS'], new RouteConfig(), $cloudManager, false);
$t->truthy(!in_array(EventTypes::EVENT_DECORATOR_VIOLATION, $agent->types(), true), 'a route without cloud rules emits no decorator event');

// ---------------------------------------------------------------------
// 2. The cloud_provider check through the engine
// ---------------------------------------------------------------------
$t->section('cloud_provider check emissions');
$globalAgent = new EvAgent();
$globalEngine = new GuardEngine(
    new SecurityConfig(enableRedis: false, blockCloudProviders: ['AWS']),
    cloudManager: $cloudManager
);
$globalEngine->setAgentHandler($globalAgent);
$globalEngine->initialize();
$blocked = $globalEngine->execute(new SimpleGuardRequest(urlPath: '/download', clientHost: '203.0.113.9'));
$t->same(403, $blocked?->statusCode(), 'the global cloud block denies');
$t->truthy(in_array(EventTypes::EVENT_CLOUD_BLOCKED, $globalAgent->types(), true), 'the pipeline emits cloud_blocked');
$t->truthy(!in_array(EventTypes::EVENT_DECORATOR_VIOLATION, $globalAgent->types(), true), 'a global block emits no decorator violation');

$routeAgent = new EvAgent();
$routeEngine = new GuardEngine(
    new SecurityConfig(enableRedis: false, blockCloudProviders: ['AWS']),
    cloudManager: $cloudManager
);
$routeEngine->setAgentHandler($routeAgent);
$routeEngine->initialize();
$routeRequest = new SimpleGuardRequest(urlPath: '/download', clientHost: '203.0.113.9');
$routeRequest->state()->routeConfig = new RouteConfig(blockCloudProviders: ['AWS']);
$routeBlocked = $routeEngine->execute($routeRequest);
$t->same(403, $routeBlocked?->statusCode(), 'the route cloud block denies');
$t->truthy(in_array(EventTypes::EVENT_CLOUD_BLOCKED, $routeAgent->types(), true), 'the route block emits cloud_blocked');
$blockClouds = array_values(array_filter($routeAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_DECORATOR_VIOLATION));
$t->same(1, count($blockClouds), 'exactly one decorator violation');
$t->same('block_clouds', $blockClouds[0]->metadata['decorator_type'] ?? null, 'the block_clouds decorator type');
$t->same('cloud_provider', $blockClouds[0]->metadata['violation_type'] ?? null, 'the violation type');

// ---------------------------------------------------------------------
// 3. Country events through the ip_security check
// ---------------------------------------------------------------------
$t->section('country events');
$countryAgent = new EvAgent();
$blacklistEngine = new GuardEngine(
    new SecurityConfig(enableRedis: false, blockedCountries: ['RU'], geoIpHandler: new StaticCountry('RU'))
);
$blacklistEngine->setAgentHandler($countryAgent);
$blacklistEngine->initialize();
$denied = $blacklistEngine->execute(new SimpleGuardRequest(urlPath: '/', clientHost: '198.51.100.7'));
$t->same(403, $denied?->statusCode(), 'a blocked-country ip denies');
$countryEvents = array_values(array_filter($countryAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_COUNTRY_BLOCKED));
$t->same(1, count($countryEvents), 'the blacklist deny emits country_blocked');
$t->same('ipinfo', $countryEvents[0]->handlerName, 'the ipinfo handler name');
$t->same('Country RU is blocked', $countryEvents[0]->reason, 'the blacklist reason');
$t->same('RU', $countryEvents[0]->metadata['country'] ?? null, 'the country metadata');
$t->same('country_blacklist', $countryEvents[0]->metadata['rule_type'] ?? null, 'the blacklist rule type');

$whitelistAgent = new EvAgent();
$whitelistEngine = new GuardEngine(
    new SecurityConfig(enableRedis: false, whitelistCountries: ['US'], geoIpHandler: new StaticCountry('CA'))
);
$whitelistEngine->setAgentHandler($whitelistAgent);
$whitelistEngine->initialize();
$denied = $whitelistEngine->execute(new SimpleGuardRequest(urlPath: '/', clientHost: '198.51.100.7'));
$t->same(403, $denied?->statusCode(), 'an allowlist miss denies');
$countryEvents = array_values(array_filter($whitelistAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_COUNTRY_BLOCKED));
$t->same(1, count($countryEvents), 'the allowlist deny emits country_blocked');
$t->same('Country CA not in allowed list', $countryEvents[0]->reason, 'the allowlist reason');
$t->same('country_whitelist', $countryEvents[0]->metadata['rule_type'] ?? null, 'the whitelist rule type');

$passAgent = new EvAgent();
$passEngine = new GuardEngine(
    new SecurityConfig(enableRedis: false, blockedCountries: ['RU'], geoIpHandler: new StaticCountry('CA'))
);
$passEngine->setAgentHandler($passAgent);
$passEngine->initialize();
$t->same(null, $passEngine->execute(new SimpleGuardRequest(urlPath: '/', clientHost: '198.51.100.7'))?->statusCode(), 'a non-blocked country passes');
$t->truthy(!in_array(EventTypes::EVENT_COUNTRY_BLOCKED, $passAgent->types(), true), 'a passing country emits no country_blocked');

$geoFailAgent = new EvAgent();
$geoFailEngine = new GuardEngine(
    new SecurityConfig(enableRedis: false, whitelistCountries: ['US'], geoIpHandler: new ExplodingResolver())
);
$geoFailEngine->setAgentHandler($geoFailAgent);
$geoFailEngine->initialize();
$denied = $geoFailEngine->execute(new SimpleGuardRequest(urlPath: '/', clientHost: '198.51.100.7'));
$t->same(403, $denied?->statusCode(), 'a failing resolver under a restrictive allowlist denies (unresolved)');
$geoEvents = array_values(array_filter($geoFailAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_GEO_LOOKUP_FAILED));
$t->same(1, count($geoEvents), 'the resolver failure emits geo_lookup_failed');
$t->same('lookup_failed', $geoEvents[0]->actionTaken, 'the lookup_failed action');
$t->same('Geographic lookup failed: RuntimeException', $geoEvents[0]->reason, 'the failure reason names the exception');
$t->same('198.51.100.7', $geoEvents[0]->ipAddress, 'the failing lookup carries the scanned ip');

// ---------------------------------------------------------------------
// 4. security_headers_applied behind the TTL cache
// ---------------------------------------------------------------------
$t->section('security_headers_applied');
$headersAgent = new EvAgent();
$headersEngine = new GuardEngine(new SecurityConfig(enableRedis: false));
$headersEngine->setAgentHandler($headersAgent);
$headersEngine->initialize();
$first = $headersEngine->execute(new SimpleGuardRequest(urlPath: '/page', clientHost: '198.51.100.8'));
$t->truthy($first === null, 'the pass-through request executes');
$headerEvents = array_values(array_filter($headersAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_SECURITY_HEADERS_APPLIED));
$t->same(1, count($headerEvents), 'the first response emits security_headers_applied');
$headerEvent = $headerEvents[0];
$t->same('security_headers', $headerEvent->handlerName, 'the security_headers handler name');
$t->same('headers_added', $headerEvent->actionTaken, 'the headers_added action');
$t->same('/page', $headerEvent->metadata['path'] ?? null, 'the path metadata');
$t->truthy(($headerEvent->metadata['headers_count'] ?? 0) > 0, 'the headers_count metadata');
$t->truthy(is_bool($headerEvent->metadata['has_csp'] ?? null), 'the has_csp metadata');
$t->truthy(is_bool($headerEvent->metadata['has_hsts'] ?? null), 'the has_hsts metadata');

$headersEngine->execute(new SimpleGuardRequest(urlPath: '/page', clientHost: '198.51.100.8'));
$headerEvents = array_values(array_filter($headersAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_SECURITY_HEADERS_APPLIED));
$t->same(1, count($headerEvents), 'a second response on the same path does not re-emit inside the TTL window');

$headersEngine->execute(new SimpleGuardRequest(urlPath: '/other', clientHost: '198.51.100.8'));
$headerEvents = array_values(array_filter($headersAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_SECURITY_HEADERS_APPLIED));
$t->same(2, count($headerEvents), 'a different path emits again');

$blockedHeadersEngine = new GuardEngine(new SecurityConfig(enableRedis: false, blacklist: ['192.0.2.9']));
$blockedHeadersEngine->setAgentHandler($headersAgent);
$blockedHeadersEngine->initialize();
$blockedHeadersEngine->execute(new SimpleGuardRequest(urlPath: '/blocked-page', clientHost: '192.0.2.9'));
$headerEvents = array_values(array_filter($headersAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_SECURITY_HEADERS_APPLIED));
$t->same(3, count($headerEvents), 'a blocked response emits on its own path');

// The eviction branch: flood past the maxsize and the cache stays bounded.
$floodAgent = new EvAgent();
$floodEngine = new GuardEngine(new SecurityConfig(enableRedis: false));
$floodEngine->setAgentHandler($floodAgent);
$floodEngine->initialize();
for ($i = 0; $i < 1001; $i++) {
    $floodEngine->execute(new SimpleGuardRequest(urlPath: '/flood/' . $i, clientHost: '198.51.100.8'));
}
$t->same(1001, count(array_filter($floodAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_SECURITY_HEADERS_APPLIED)), 'each distinct path emits exactly once through the flood');

$emptyPathAgent = new EvAgent();
$emptyPathEngine = new GuardEngine(new SecurityConfig(enableRedis: false));
$emptyPathEngine->setAgentHandler($emptyPathAgent);
$emptyPathEngine->initialize();
$emptyPathEngine->execute(new SimpleGuardRequest(urlPath: '', clientHost: '198.51.100.8'));
$t->truthy(!in_array(EventTypes::EVENT_SECURITY_HEADERS_APPLIED, $emptyPathAgent->types(), true), 'an empty path emits nothing (the reference gates on request_path)');

$disabledAgent = new EvAgent();
$disabledEngine = new GuardEngine(new SecurityConfig(enableRedis: false, securityHeaders: ['enabled' => false]));
$disabledEngine->setAgentHandler($disabledAgent);
$disabledEngine->initialize();
$disabledEngine->execute(new SimpleGuardRequest(urlPath: '/quiet', clientHost: '198.51.100.8'));
$t->truthy(!in_array(EventTypes::EVENT_SECURITY_HEADERS_APPLIED, $disabledAgent->types(), true), 'disabled headers emit nothing');

$t->section('sensitive-set redaction through the headers event');
// The sensitive-log config fields are array<string, true> membership maps;
// the emission converts them to the redactor's name lists (a non-empty set
// must not fatal the request, the regression behind this case).
$sensitiveAgent = new EvAgent();
$sensitiveEngine = new GuardEngine(new SecurityConfig(
    enableRedis: false,
    logSensitiveHeaders: ['x-forwarded-for', 'x-real-ip'],
    logSensitiveParams: ['token']
));
$sensitiveEngine->setAgentHandler($sensitiveAgent);
$sensitiveEngine->initialize();
$sensitiveEngine->execute(new SimpleGuardRequest(urlPath: '/redact-check', clientHost: '198.51.100.8'));
$sensitiveEvents = array_values(array_filter($sensitiveAgent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_SECURITY_HEADERS_APPLIED));
$t->same(1, count($sensitiveEvents), 'a non-empty sensitive set still emits the headers event');
$t->same('/redact-check', $sensitiveEvents[0]->metadata['path'] ?? null, 'the plain path survives the redaction pass');

$t->same(0, $t->failed, 'no failures above');
exit($t->finish('event emitters'));

<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\GeoIp\CountryResolver;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Rules\DynamicRuleManager;
use RenzoFranceschini\GuardCore\Rules\DynamicRules;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/FakeRespConnection.php';

// Dynamic rule parity with the Python reference (guard-core 4.3.x):
// _dynamic_rule_application.py (the exact effect of every rule field),
// dynamic_rule_handler.py (the overlay over the base config, guard-core #169,
// whose 8 tests tests/test_dynamic_rule_overlay.py are ported first below),
// the engine wiring (handler_initializer.initialize_dynamic_rule_manager,
// the update loop expressed as a per-request interval gate) and the custom
// response modifier (core/responses/factory.py apply_modifier). No Redis, no
// network: the last-known store is the cache file.

final class T
{
    public int $passed = 0;

    public int $failed = 0;

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";

            return;
        }
        $this->failed++;
        echo "FAIL - {$label}\n";
        echo '  expected: ' . var_export($expected, true) . "\n";
        echo '  actual:   ' . var_export($actual, true) . "\n";
    }

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }

    public function throws(string $class, \Closure $fn, string $label): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            $this->same(true, $e instanceof $class, $label . ' (' . $e::class . ')');

            return;
        }
        $this->same(true, false, $label . ' (nothing thrown)');
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

final class Agent
{
    /** @var list<object> */
    public array $received = [];

    /** @var list<DynamicRules|array<string, mixed>|object|null> */
    public array $queue = [];

    public int $fetches = 0;

    public function sendEvent(object $event): void
    {
        $this->received[] = $event;
    }

    public function getDynamicRules(): mixed
    {
        $this->fetches++;

        return $this->queue === [] ? null : array_shift($this->queue);
    }
}

final class NoGeo implements CountryResolver
{
    public function getCountry(string $ip): ?string
    {
        return null;
    }
}

function baseOf(DynamicRuleManager $manager): ?SecurityConfig
{
    return method_exists($manager, 'activeBaseSnapshot') ? $manager->activeBaseSnapshot() : null;
}

function rules(int $version = 1, string $id = 'r1', array $extra = []): DynamicRules
{
    return DynamicRules::fromArray(array_merge([
        'rule_id' => $id,
        'version' => $version,
        'timestamp' => '2026-01-01T00:00:00+00:00',
    ], $extra));
}

final class Harness
{
    public SecurityConfig $live;

    public Agent $agent;

    /** @var list<string> */
    public array $logs = [];

    public int $clock = 1_800_000_000;

    public DynamicRuleManager $manager;

    public function __construct(public SecurityConfig $base, ?SusPatterns $patterns = null, ?IpBanManager $ban = null)
    {
        $this->live = $base;
        $this->agent = new Agent();
        $args = [
            'config' => $base,
            'agentHandler' => $this->agent,
            'eventBus' => new EventBus($this->agent, $base),
            'applyConfig' => function (SecurityConfig $c): void {
                $this->live = $c;
            },
            'logger' => function (string $level, string $message): void {
                $this->logs[] = $level . ': ' . $message;
            },
            'clock' => fn (): int => $this->clock,
            'susPatterns' => $patterns,
        ];
        if ($ban !== null) {
            $args['banManager'] = $ban;
        }
        $this->manager = new DynamicRuleManager(...$args);
    }

    /** Delivers one rule version through the real update flow. */
    public function push(mixed $rules): void
    {
        $this->agent->queue = [$rules];
        $this->manager->updateRules();
    }

    public function logged(string $needle): bool
    {
        foreach ($this->logs as $line) {
            if (str_contains($line, $needle)) {
                return true;
            }
        }

        return false;
    }
}

$t = new T();

// ---------------------------------------------------------------------
// guard-core #169: the 8 overlay tests (tests/test_dynamic_rule_overlay.py)
// ---------------------------------------------------------------------

$t->section('overlay 1: emergency halving does not compound across versions');
$h = new Harness(new SecurityConfig(autoBanThreshold: 16, enableAgent: true, enableDynamicRules: true));
$seen = [];
foreach ([1, 2, 3] as $version) {
    $h->push(rules($version, 'r1', ['emergency_mode' => true, 'emergency_whitelist' => []]));
    $seen[] = $h->live->autoBanThreshold;
}
$t->same([8, 8, 8], $seen, 'v1..v3 keep the threshold at 8 from a base of 16');
$t->same(16, baseOf($h->manager)?->autoBanThreshold, 'the active base snapshot holds the true base threshold');

$t->section('overlay 2: collection values do not accumulate across versions');
$h = new Harness(new SecurityConfig(
    geoIpHandler: new NoGeo(),
    blockedUserAgents: ['base-bot'],
    blockCloudProviders: ['AWS'],
    enableAgent: true,
    enableDynamicRules: true
));
$h->push(rules(1, 'r1', [
    'blocked_user_agents' => ['bot-a'],
    'blocked_cloud_providers' => ['GCP'],
    'blocked_countries' => ['AA'],
    'endpoint_rate_limits' => ['/a' => [1, 60]],
]));
$h->push(rules(2, 'r1', [
    'blocked_user_agents' => ['bot-b'],
    'blocked_cloud_providers' => ['Azure'],
    'blocked_countries' => ['BB'],
    'endpoint_rate_limits' => ['/b' => [2, 60]],
]));
$t->same(['bot-b'], $h->live->blockedUserAgents, 'blocked_user_agents replaced by v2');
$t->same(['Azure'], $h->live->blockCloudProviders, 'block_cloud_providers replaced by v2');
$t->same(['BB'], $h->live->blockedCountries, 'blocked_countries replaced by v2');
$t->same(['/b' => ['limit' => 2, 'window' => 60]], $h->live->endpointRateLimits, 'endpoint_rate_limits replaced by v2');

$t->section('overlay 3: a new version drops the change from the previous version');
$h = new Harness(new SecurityConfig(rateLimit: 100, enableIpBanning: true, autoBanThreshold: 5, enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['global_rate_limit' => 7, 'enable_ip_banning' => false, 'auto_ban_threshold' => 2]));
$t->same([7, false], [$h->live->rateLimit, $h->live->enableIpBanning], 'v1 applied');
$h->push(rules(2, 'r1', ['global_rate_limit' => 9]));
$t->same(9, $h->live->rateLimit, 'v2 rate limit');
$t->same(true, $h->live->enableIpBanning, 'v2 restores enable_ip_banning to the base');
$t->same(5, $h->live->autoBanThreshold, 'v2 restores auto_ban_threshold to the base');

$t->section('overlay 4: a different rule id overlays the base');
$h = new Harness(new SecurityConfig(rateLimit: 100, autoBanThreshold: 16, enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['emergency_mode' => true, 'emergency_whitelist' => []]));
$h->push(rules(1, 'r2', ['global_rate_limit' => 3]));
$t->same(3, $h->live->rateLimit, 'r2 rate limit');
$t->same(16, $h->live->autoBanThreshold, 'r2 does not inherit the halved threshold');
$t->same(false, $h->live->emergencyMode, 'r2 does not inherit emergency mode');

$t->section('overlay 5: a failed apply rolls back to the active version');
$h = new Harness(new SecurityConfig(rateLimit: 100, autoBanThreshold: 16, enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['global_rate_limit' => 7, 'auto_ban_threshold' => 4]));
$h->push(rules(2, 'r1', ['global_rate_limit' => 9, 'emergency_mode' => true, 'emergency_whitelist' => ['not-an-ip']]));
$t->same(7, $h->live->rateLimit, 'rate limit stays at the active version after the failed apply');
$t->same(4, $h->live->autoBanThreshold, 'threshold stays at the active version after the failed apply');
$t->same(1, $h->manager->currentRules()?->version, 'the active rule is still v1');
$t->truthy($h->logged('error: Failed to apply dynamic rules'), 'the failure is logged');
$t->same(100, baseOf($h->manager)?->rateLimit, 'the active base snapshot still holds the base rate limit');

$t->section('overlay 6: expiry restores the true base after several versions');
$h = new Harness(new SecurityConfig(autoBanThreshold: 16, enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['emergency_mode' => true, 'emergency_whitelist' => []]));
$h->push(rules(2, 'r1', [
    'emergency_mode' => true,
    'emergency_whitelist' => [],
    'expires_at' => gmdate('c', $h->clock + 10),
]));
$t->same(8, $h->live->autoBanThreshold, 'two emergency versions hold 8');
$h->clock += 11;
$h->push(null);
$t->same(16, $h->live->autoBanThreshold, 'expiry restores 16');
$t->same(false, $h->live->emergencyMode, 'expiry clears emergency mode');
$t->same(null, $h->manager->currentRules(), 'expiry clears the current rules');
$t->same(null, baseOf($h->manager), 'expiry clears the base snapshot');

$t->section('overlay 7: a new version after hydration overlays the base');
$cache = sys_get_temp_dir() . '/gcphp-dynrules-' . getmypid() . '.json';
file_put_contents($cache, rules(1, 'r1', ['emergency_mode' => true, 'emergency_whitelist' => []])->dumpSnapshot());
$h = new Harness(new SecurityConfig(autoBanThreshold: 16, enableAgent: true, enableDynamicRules: true, dynamicRulesCachePath: $cache));
$h->manager->hydrateLastKnownRules();
$t->same(8, $h->live->autoBanThreshold, 'hydration applied v1 over the base');
$h->push(rules(2, 'r1', ['emergency_mode' => true, 'emergency_whitelist' => []]));
$t->same(2, $h->manager->currentRules()?->version, 'v2 is current');
$t->same(8, $h->live->autoBanThreshold, 'v2 over the base stays at 8, not 4');
$h->push(rules(3, 'r1', []));
$t->same(16, $h->live->autoBanThreshold, 'v3 without emergency restores 16');
@unlink($cache);

$t->section('overlay 8: suspicious patterns are not duplicated across versions');
$registry = new SusPatterns(0.99);
$pattern = 'overlay-unique-marker-[0-9]{3}';
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true), $registry);
foreach ([1, 2, 3] as $version) {
    $h->push(rules($version, 'r1', ['suspicious_patterns' => [$pattern]]));
}
$t->same(1, count(array_keys($registry->getDefaultPatterns(), $pattern, true)), 'the pattern is in the registry exactly once');
$registry->removePattern($pattern);

// ---------------------------------------------------------------------
// _dynamic_rule_application.py: the exact effect of every field
// ---------------------------------------------------------------------

$t->section('ip_blacklist is a timed ban, ip_whitelist an unban');
$ban = new IpBanManager([]);
$h = new Harness(new SecurityConfig(blacklist: ['198.51.100.1'], whitelist: ['198.51.100.2'], enableAgent: true, enableDynamicRules: true), null, $ban);
$h->push(rules(1, 'r1', ['ip_blacklist' => ['203.0.113.5'], 'ip_ban_duration' => 120]));
$t->same(true, $ban->isIpBanned('203.0.113.5'), 'ip_blacklist IP is banned');
$t->same(['198.51.100.1'], $h->live->blacklist, 'the static blacklist is untouched');
$t->truthy($h->logged('info: Dynamic rule: Banned IP 203.0.113.5 for 120s'), 'the ban is logged with its duration');
$h->push(rules(2, 'r1', ['ip_whitelist' => ['203.0.113.5']]));
$t->same(false, $ban->isIpBanned('203.0.113.5'), 'ip_whitelist IP is unbanned');
$t->same(['198.51.100.2'], $h->live->whitelist, 'the static whitelist is untouched');
$t->truthy($h->logged('info: Dynamic rule: Whitelisted IP 203.0.113.5'), 'the unban is logged');

$t->section('an unban failure is logged and does not abort the rule');
$brokenConnection = new FakeRespConnection();
$brokenBan = new IpBanManager([]);
$brokenBan->initializeRedis(new RedisHandler(true, 'dr_unban:', connection: $brokenConnection));
$brokenConnection->failWrites = true;
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true), null, $brokenBan);
$h->push(rules(1, 'r1', ['ip_whitelist' => ['203.0.113.78'], 'global_rate_limit' => 13]));
$t->truthy($h->logged('error: Failed to whitelist IP 203.0.113.78'), 'the failed unban is logged');
$t->same(13, $h->live->rateLimit, 'the rest of the rule still applies');
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['ip_blacklist' => ['203.0.113.77']]));
$t->truthy($h->logged('warning: Dynamic rule: ip_blacklist and ip_whitelist are skipped: no ban manager'), 'IP rules without a ban manager warn and skip');

$t->section('a ban failure is logged and does not abort the rule');
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true), null, new IpBanManager([]));
$h->push(rules(1, 'r1', ['ip_blacklist' => ['203.0.113.6'], 'ip_ban_duration' => 0, 'global_rate_limit' => 11]));
$t->truthy($h->logged('error: Failed to ban IP 203.0.113.6'), 'the failed ban is logged');
$t->same(11, $h->live->rateLimit, 'the rest of the rule still applies');

$t->section('cloud providers: replace, filter by bare name, warn on unknown');
$h = new Harness(new SecurityConfig(blockCloudProviders: ['AWS'], enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['blocked_cloud_providers' => ['GCP', 'Bogus', 'Azure:!eu-west']]));
$t->same(['GCP', 'Azure:!eu-west'], $h->live->blockCloudProviders, 'valid selectors replace the list, unknown dropped');
$t->truthy($h->logged("warning: Dynamic rule: ignored unknown cloud providers ['Bogus']"), 'unknown providers are warned');
$h->push(rules(2, 'r1', ['blocked_cloud_providers' => ['Bogus']]));
$t->same([], $h->live->blockCloudProviders, 'all-invalid replaces with an empty list');

$t->section('blocked_user_agents: replaced by the validated list, even when empty');
$h = new Harness(new SecurityConfig(blockedUserAgents: ['base-bot'], enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['blocked_user_agents' => ['(.+)+']]));
$t->same([], $h->live->blockedUserAgents, 'a rule whose patterns all fail validation empties the list');
$t->truthy($h->logged('warning: Dynamic rule: rejected blocked_user_agents patterns failing the ReDoS validator'), 'rejection is warned');

$t->section('country rules need a geo resolver, else warn and skip');
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['blocked_countries' => ['br'], 'whitelist_countries' => ['us'], 'global_rate_limit' => 12]));
$t->same([], $h->live->blockedCountries, 'no resolver: blocked_countries not applied');
$t->same(12, $h->live->rateLimit, 'the rule is still applied');
$t->same(1, $h->manager->currentRules()?->version, 'the rule is current');
$t->truthy($h->logged('warning: Dynamic rule: country rules cannot take effect'), 'the skip is warned');
$h = new Harness(new SecurityConfig(geoIpHandler: new NoGeo(), enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['blocked_countries' => ['br'], 'whitelist_countries' => ['us']]));
$t->same(['BR'], $h->live->blockedCountries, 'with a resolver: upper-cased blocked_countries');
$t->same(['US'], $h->live->whitelistCountries, 'with a resolver: upper-cased whitelist_countries');

$t->section('global_rate_window only applies with a global_rate_limit');
$h = new Harness(new SecurityConfig(rateLimit: 100, rateLimitWindow: 60, enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['global_rate_window' => 5]));
$t->same([100, 60], [$h->live->rateLimit, $h->live->rateLimitWindow], 'a window alone changes nothing');
$h->push(rules(2, 'r1', ['global_rate_limit' => 20, 'global_rate_window' => 5]));
$t->same([20, 5], [$h->live->rateLimit, $h->live->rateLimitWindow], 'limit and window together apply');

$t->section('emergency mode always halves the threshold in effect');
$h = new Harness(new SecurityConfig(autoBanThreshold: 10, enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['emergency_mode' => true, 'emergency_whitelist' => ['10.0.0.1']]));
$t->same(5, $h->live->autoBanThreshold, 'a non-empty whitelist still halves the base threshold');
$t->same(['10.0.0.1'], $h->live->emergencyWhitelist, 'the emergency whitelist is applied');
$h->push(rules(2, 'r1', ['emergency_mode' => true, 'auto_ban_threshold' => 7]));
$t->same(3, $h->live->autoBanThreshold, 'the rule threshold is halved: 7 // 2');
$h->push(rules(3, 'r1', ['emergency_mode' => true, 'auto_ban_threshold' => 1]));
$t->same(1, $h->live->autoBanThreshold, 'never below 1');

$t->section('events carry the reference envelopes');
$h = new Harness(new SecurityConfig(autoBanThreshold: 10, enableAgent: true, enableDynamicRules: true));
$h->push(rules(4, 'r9', ['emergency_mode' => true, 'emergency_whitelist' => array_map(static fn (int $i): string => "10.0.0.{$i}", range(1, 12)), 'ip_blacklist' => ['203.0.113.7'], 'blocked_countries' => []]));
$types = array_map(static fn (object $e): string => $e->eventType, $h->agent->received);
$t->same([EventTypes::EVENT_DYNAMIC_RULE_UPDATED, EventTypes::EVENT_EMERGENCY_MODE, EventTypes::EVENT_DYNAMIC_RULE_APPLIED], $types, 'updated, emergency_mode_activated, applied in order');
$e = $h->agent->received;
$t->same(['dynamic_rules', 'system', 'rules_received', 'Received updated rules r9 v4'], [$e[0]->handlerName, $e[0]->ipAddress, $e[0]->actionTaken, $e[0]->reason], 'updated envelope');
$t->same(['rule_id' => 'r9', 'version' => 4, 'previous_version' => 0], $e[0]->metadata, 'updated metadata');
$t->same(['emergency_lockdown', '[EMERGENCY MODE] activated via dynamic rules'], [$e[1]->actionTaken, $e[1]->reason], 'emergency envelope');
$t->same(['whitelist_count' => 12, 'whitelist' => array_slice(array_map(static fn (int $i): string => "10.0.0.{$i}", range(1, 12)), 0, 10)], $e[1]->metadata, 'emergency metadata');
$t->same(['rule_id' => 'r9', 'version' => 4, 'ip_bans' => 1, 'country_blocks' => 0, 'emergency_mode' => true], $e[2]->metadata, 'applied metadata');
$h->agent->received = [];
$h->push(rules(5, 'r9', []));
$t->same(4, $h->agent->received[0]->metadata['previous_version'] ?? null, 'previous_version tracks the current rule');

// ---------------------------------------------------------------------
// DynamicRules parsing and snapshot
// ---------------------------------------------------------------------

$t->section('rule model');
$t->throws(\InvalidArgumentException::class, static fn () => rules(1, 'r1', ['auto_ban_threshold' => 0]), 'auto_ban_threshold below 1 is rejected (ge=1)');
$t->throws(\InvalidArgumentException::class, static fn () => rules(1, 'r1', ['auto_ban_duration' => 0]), 'auto_ban_duration below 1 is rejected (ge=1)');
$agentShaped = new class {
    public string $ruleId = 'agent-1';

    public int $version = 3;

    public \DateTimeImmutable $timestamp;

    public ?\DateTimeImmutable $expiresAt = null;

    public int $ipBanDuration = 90;

    public array $ipBlacklist = ['203.0.113.8'];

    public array $endpointRateLimits = ['/x' => [4, 30]];

    public array $suspiciousPatterns = [];

    public bool $emergencyMode = false;

    public bool $emergencyWhitelistOnly = true;

    public ?string $message = 'ignored';

    public function __construct()
    {
        $this->timestamp = new \DateTimeImmutable('2026-01-01T00:00:00+00:00');
    }
};
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true), null, new IpBanManager([]));
$h->push($agentShaped);
$t->same('agent-1', $h->manager->currentRules()?->ruleId, 'a guard-agent-php DynamicRules object is accepted as delivered');
$t->same(90, $h->manager->currentRules()?->ipBanDuration, 'its camelCase fields map across');
$t->same(['/x' => ['limit' => 4, 'window' => 30]], $h->live->endpointRateLimits, 'its endpoint rate limit pairs apply');
$timestampless = DynamicRules::fromObject(new class {
    public string $ruleId = 'agent-2';

    public int $version = 1;

    public ?\DateTimeImmutable $timestamp = null;
});
$t->same('agent-2', $timestampless->ruleId, 'an agent rules object without a timestamp is stamped now');
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true));
$h->push(42);
$t->truthy($h->logged('error: Failed to update dynamic rules: the agent returned an unusable dynamic rules payload'), 'an unusable agent payload is logged, not applied');
$t->same(null, $h->manager->currentRules(), 'and leaves no current rules');
$snapshot = json_decode(rules(1, 'r1')->dumpSnapshot());
$t->same('2026-01-01T00:00:00Z', $snapshot->rules->timestamp, 'the snapshot timestamp renders as the reference does (Z)');
$t->same(true, $snapshot->rules->endpoint_rate_limits instanceof \stdClass, 'an empty endpoint_rate_limits map encodes as an object');
$roundTrip = DynamicRules::loadSnapshot(rules(2, 'r1', ['endpoint_rate_limits' => ['/a' => [1, 60]]])->dumpSnapshot());
$t->same(['/a' => [1, 60]], $roundTrip->endpointRateLimits, 'the snapshot round-trips');

// ---------------------------------------------------------------------
// SecurityConfig: with() round trip and the agent dependency rules
// ---------------------------------------------------------------------

$t->section('config');
$cfg = new SecurityConfig(enableAgent: true, enableDynamicRules: true, agentEnableEvents: false, agentEnableMetrics: false, dynamicRulesCachePath: '/tmp/x.json', dynamicRuleInterval: 120);
$copy = $cfg->with(['rate_limit' => 3]);
$t->same(
    [true, true, false, false, '/tmp/x.json', 120],
    [$copy->enableAgent, $copy->dynamicRulesEnabled, $copy->agentEnableEvents, $copy->agentEnableMetrics, $copy->dynamicRulesCachePath, $copy->dynamicRuleInterval],
    'with() keeps the agent and dynamic-rule fields'
);
$t->same(true, (new SecurityConfig(enableAgent: true))->enableAgent, 'enable_agent is stored');
$t->same(false, (new SecurityConfig())->enableAgent, 'enable_agent defaults to false');
$t->same(300, (new SecurityConfig())->dynamicRuleInterval, 'dynamic_rule_interval defaults to 300');
$t->throws(\InvalidArgumentException::class, static fn () => new SecurityConfig(enableDynamicRules: true), 'enable_dynamic_rules requires enable_agent');
$t->throws(\InvalidArgumentException::class, static fn () => new SecurityConfig(enableEnrichment: true), 'enable_enrichment requires enable_agent');
$t->throws(\InvalidArgumentException::class, static fn () => new SecurityConfig(dynamicRuleInterval: 59), 'dynamic_rule_interval has a floor of 60');
$h = new Harness(new SecurityConfig(enableAgent: true, enableDynamicRules: true));
$h->push(rules(1, 'r1', ['global_rate_limit' => 3]));
$first = $h->live->revision();
$h->push(rules(2, 'r1', ['global_rate_limit' => 4]));
$t->truthy($h->live->revision() > $first, 'each applied version carries a fresh revision so the pipeline rebuilds');

// ---------------------------------------------------------------------
// Engine wiring
// ---------------------------------------------------------------------

$t->section('engine builds and drives the manager from config');
$engineAgent = new Agent();
$engineAgent->queue = [rules(1, 'e1', ['global_rate_limit' => 77, 'ip_blacklist' => ['203.0.113.9'], 'ip_ban_duration' => 600])];
$clock = 1_800_000_000;
$engine = new GuardEngine(
    new SecurityConfig(enableRedis: false, enableAgent: true, enableDynamicRules: true, dynamicRuleInterval: 120),
    clock: static function () use (&$clock): int {
        return $clock;
    }
);
$engine->setAgentHandler($engineAgent);
$engine->initialize();
$t->truthy($engine->dynamicRuleManager() !== null, 'the engine instantiated a DynamicRuleManager');
$t->same(0, $engineAgent->fetches, 'no fetch before the first request');
$engine->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '198.51.100.20'));
$t->same(1, $engineAgent->fetches, 'the first request fetches (the loop updates immediately)');
$t->same(77, $engine->config()->rateLimit, 'the rule is installed on the engine config');
$t->same(true, $engine->config()->dynamicRulesEnabled, 'the installed config still has dynamic rules on');
$t->same(true, $engine->banManager()->isIpBanned('203.0.113.9'), 'the rule ban reached the engine ban manager');
$blocked = $engine->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '203.0.113.9'));
$t->same(403, $blocked?->statusCode(), 'the banned IP is blocked');
$t->same(1, $engineAgent->fetches, 'requests inside the interval do not fetch');
$clock += 119;
$engine->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '198.51.100.20'));
$t->same(1, $engineAgent->fetches, 'still inside dynamic_rule_interval at +119s');
$engineAgent->queue = [rules(2, 'e1', ['global_rate_limit' => 88])];
$clock += 1;
$engine->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '198.51.100.20'));
$t->same(2, $engineAgent->fetches, 'the interval elapsed: the next request fetches');
$t->same(88, $engine->config()->rateLimit, 'v2 installed over the base');

$gate = new DynamicRuleManager(config: new SecurityConfig(enableAgent: true, enableDynamicRules: true), agentHandler: null);
$gate->maybeUpdate();
$t->same(null, $gate->currentRules(), 'maybeUpdate without an agent handler is a no-op');
$gate = new DynamicRuleManager(config: new SecurityConfig(), agentHandler: new Agent());
$gate->maybeUpdate();
$t->same(null, $gate->currentRules(), 'maybeUpdate with dynamic rules off is a no-op');

$t->section('engine logging routes through the engine log closure, else error_log');
$engineLogs = [];
$logged = new GuardEngine(
    new SecurityConfig(enableRedis: false, enableAgent: true, enableDynamicRules: true),
    log: static function (string $level, string $message, array $context) use (&$engineLogs): void {
        $engineLogs[] = $level . ': ' . $message;
    }
);
$loggedAgent = new Agent();
$loggedAgent->queue = [rules(1, 'l1', ['global_rate_limit' => 21])];
$logged->setAgentHandler($loggedAgent);
$logged->initialize();
$logged->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '198.51.100.20'));
$t->truthy(in_array('info: Applying dynamic rules: l1 v1', $engineLogs, true), 'manager logs reach the engine log closure');
$errorLog = sys_get_temp_dir() . '/gcphp-dynrules-errorlog-' . getmypid() . '.txt';
$previousErrorLog = ini_set('error_log', $errorLog);
$bare = new GuardEngine(new SecurityConfig(enableRedis: false, enableAgent: true, enableDynamicRules: true));
$bareAgent = new Agent();
$bareAgent->queue = [rules(1, 'b1', ['blocked_cloud_providers' => ['Bogus']])];
$bare->setAgentHandler($bareAgent);
$bare->initialize();
$bare->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '198.51.100.20'));
$noAgentEither = new GuardEngine(new SecurityConfig(enableRedis: false, enableAgent: true, enableDynamicRules: true));
$noAgentEither->initialize();
ini_set('error_log', (string) $previousErrorLog);
$errorLogText = (string) @file_get_contents($errorLog);
@unlink($errorLog);
$t->truthy(str_contains($errorLogText, 'dynamic rules warning: Dynamic rule: ignored unknown cloud providers'), 'without a log closure non-info manager logs go to error_log');
$t->truthy(!str_contains($errorLogText, 'Applying dynamic rules'), 'info lines stay quiet');
$t->truthy(str_contains($errorLogText, 'Dynamic rules enabled but agent unavailable'), 'without a warn closure the missing-agent warning goes to error_log');

$t->section('engine hydrates the last-known rules at initialize');
$cache = sys_get_temp_dir() . '/gcphp-dynrules-engine-' . getmypid() . '.json';
file_put_contents($cache, rules(5, 'h1', ['global_rate_limit' => 55])->dumpSnapshot());
$hydrating = new GuardEngine(new SecurityConfig(enableRedis: false, enableAgent: true, enableDynamicRules: true, dynamicRulesCachePath: $cache));
$hydrating->setAgentHandler(new Agent());
$hydrating->initialize();
$t->same(55, $hydrating->config()->rateLimit, 'hydrated before the first request');
@unlink($cache);

$t->section('dynamic rules without an agent warn and stay on the static config');
$warnings = [];
$noAgent = new GuardEngine(
    new SecurityConfig(enableRedis: false, enableAgent: true, enableDynamicRules: true),
    warn: static function (string $m) use (&$warnings): void {
        $warnings[] = $m;
    }
);
$noAgent->initialize();
$t->same(null, $noAgent->dynamicRuleManager(), 'no manager without an agent handler');
$t->truthy((bool) array_filter($warnings, static fn (string $m): bool => str_contains($m, 'Dynamic rules enabled but agent unavailable')), 'the reference warning is emitted');
$off = new GuardEngine(new SecurityConfig(enableRedis: false));
$off->setAgentHandler(new Agent());
$off->initialize();
$t->same(null, $off->dynamicRuleManager(), 'no manager when enable_dynamic_rules is off');

// ---------------------------------------------------------------------
// Custom response modifier
// ---------------------------------------------------------------------

$t->section('custom_response_modifier');
$calls = 0;
$modifier = static function (GuardResponse $response) use (&$calls): GuardResponse {
    $calls++;
    $response->headers()->set('X-Modified', 'yes');

    return $response;
};
$engine = new GuardEngine(new SecurityConfig(enableRedis: false, blacklist: ['203.0.113.50'], customResponseModifier: $modifier));
$blocked = $engine->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '203.0.113.50'));
$t->same('yes', $blocked?->headers()->get('X-Modified'), 'a blocked response passes through the modifier');
$t->same(1, $calls, 'applied exactly once');
$passthrough = $engine->applyResponseModifier(new GuardResponse(200));
$t->same('yes', $passthrough->headers()->get('X-Modified'), 'the pass-through seam applies the modifier');

$calls = 0;
$engine = new GuardEngine(new SecurityConfig(
    enableRedis: false,
    customRequestCheck: static fn ($request) => new GuardResponse(418),
    customResponseModifier: $modifier
));
$custom = $engine->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '198.51.100.20'));
$t->same(418, $custom?->statusCode(), 'the custom request check response is returned');
$t->same(1, $calls, 'the custom request check response is modified exactly once');

$throwing = new GuardEngine(new SecurityConfig(
    enableRedis: false,
    blacklist: ['203.0.113.51'],
    customResponseModifier: static function (GuardResponse $response): GuardResponse {
        throw new \RuntimeException('boom');
    }
));
$unmodified = $throwing->execute(new SimpleGuardRequest(urlPath: '/a', clientHost: '203.0.113.51'));
$t->same(403, $unmodified?->statusCode(), 'a throwing modifier returns the unmodified response');

echo "\ndynamic rules parity: {$t->passed} passed, {$t->failed} failed\n";
exit($t->failed === 0 ? 0 : 1);

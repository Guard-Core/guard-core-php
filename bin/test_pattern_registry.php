<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventBus;
use RenzoFranceschini\GuardCore\Events\EventFilter;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Events\SecurityEvent;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;
use RenzoFranceschini\GuardCore\Redis\RedisHandler;
use RenzoFranceschini\GuardCore\Rules\DynamicRuleManager;
use RenzoFranceschini\GuardCore\Support\Generated\PatternData;

require __DIR__ . '/../vendor/autoload.php';

// The runtime custom-pattern registry (the reference _suspatterns_registry
// mixin): add/remove/query pattern families with the ReDoS gate, the
// detect() integration, detect_pattern_match, the pattern_added /
// pattern_removed events, the Redis persistence and restore, the engine
// wiring, and the dynamic-rule suspicious_patterns application.

final class RegT
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

final class RegAgent
{
    /** @var list<SecurityEvent> */
    public array $received = [];

    public bool $alwaysFail = false;

    public function sendEvent(object $event): void
    {
        if ($this->alwaysFail) {
            throw new RuntimeException('agent down');
        }
        $this->received[] = $event;
    }
}

$t = new RegT();

// ---------------------------------------------------------------------
// 1. Add and query
// ---------------------------------------------------------------------
$t->section('add and query');
$sus = new SusPatterns(0.99);
$catalogCount = count($sus->getDefaultPatterns());
$t->truthy($catalogCount > 0, 'the default pool starts as the catalog');
$t->same([], $sus->getCustomPatterns(), 'the custom pool starts empty');

$t->truthy($sus->addPattern('zzregprobe001', custom: true), 'a safe custom pattern is accepted');
$t->same(['zzregprobe001'], $sus->getCustomPatterns(), 'the custom pool holds the pattern');
$t->truthy($sus->addPattern('zzregprobe001', custom: true), 're-adding a custom pattern reports success');
$t->same(['zzregprobe001'], $sus->getCustomPatterns(), 'the custom pool has no duplicate');
$t->truthy($sus->addPattern('zzregadded002'), 'a safe default-appended pattern is accepted');
$t->truthy(in_array('zzregadded002', $sus->getDefaultPatterns(), true), 'the default pool holds the addition');
$t->same($catalogCount + 1, count($sus->getDefaultPatterns()), 'the default pool grew by one');
$t->truthy(in_array('zzregadded002', $sus->getAllPatterns(), true), 'all patterns contains the additions');
$t->truthy(in_array('zzregprobe001', $sus->getAllPatterns(), true), 'all patterns contains the custom pool');

// ---------------------------------------------------------------------
// 2. Unsafe rejection
// ---------------------------------------------------------------------
$t->section('unsafe rejection');
$t->same(false, $sus->addPattern('(.*)+'), 'a dangerous construct is rejected');
$t->same([], array_values(array_diff($sus->getCustomPatterns(), ['zzregprobe001'])), 'the rejected pattern never joined the custom pool');
$t->same(false, $sus->addPattern('('), 'a pattern that cannot compile is rejected');

// ---------------------------------------------------------------------
// 3. Detection integration
// ---------------------------------------------------------------------
$t->section('detection integration');
$result = $sus->detect('hello zzregprobezz world', '1.2.3.4', 'query_param');
$t->truthy($result['is_threat'] === false, 'clean content stays clean');

$result = $sus->detect('hello zzregprobe001 world', '1.2.3.4', 'query_param');
$t->truthy($result['is_threat'], 'a custom pattern match is a threat');
$t->truthy(isset($result['threats'][0]) && $result['threats'][0]['pattern'] === 'zzregprobe001', 'the threat names the custom pattern');
$t->same('custom', $result['threats'][0]['category'] ?? null, 'the custom category');

$result = $sus->detect('hello zzregadded002 world', '1.2.3.4', 'query_param');
$t->truthy($result['is_threat'], 'a default-appended pattern match is a threat');
$t->truthy(isset($result['threats'][0]) && $result['threats'][0]['pattern'] === 'zzregadded002', 'the threat names the added pattern');
$t->same('custom', $result['threats'][0]['category'] ?? null, 'the added default scans with the custom category');

// ---------------------------------------------------------------------
// 4. Removal
// ---------------------------------------------------------------------
$t->section('removal');
$t->same(false, $sus->removePattern('zzneveradded003', custom: true), 'removing an unknown custom pattern reports false');
$t->same(false, $sus->removePattern('zzneveradded003'), 'removing an unknown default pattern reports false');
$t->truthy($sus->removePattern('zzregprobe001', custom: true), 'removing the custom pattern reports true');
$t->same([], $sus->getCustomPatterns(), 'the custom pool is empty again');
$t->truthy($sus->removePattern('zzregadded002'), 'removing the added default reports true');
$t->same($catalogCount, count($sus->getDefaultPatterns()), 'the default pool is back to the catalog size');

$t->truthy($sus->removePattern(PatternData::PATTERNS[3][0]), 'removing a catalog row reports true');
$t->truthy(!in_array(PatternData::PATTERNS[3][0], $sus->getDefaultPatterns(), true), 'the catalog row left the default pool');
$skipResult = $sus->detect('hello world', '1.2.3.4', 'query_param');
$t->truthy(!$skipResult['is_threat'], 'a scan after removals walks past the removed catalog rows');
$t->truthy($sus->addPattern(PatternData::PATTERNS[3][0]), 're-adding a removed catalog row is accepted');
$t->truthy(in_array(PatternData::PATTERNS[3][0], $sus->getDefaultPatterns(), true), 'the re-added row is in the default pool once');
$t->same(1, count(array_keys($sus->getDefaultPatterns(), PatternData::PATTERNS[3][0], true)), 'exactly one active instance');
$t->truthy($sus->removePattern(PatternData::PATTERNS[3][0]), 'the re-added row removes again');

// ---------------------------------------------------------------------
// 5. detect_pattern_match
// ---------------------------------------------------------------------
$t->section('detect_pattern_match');
$sus2 = new SusPatterns(0.99);
$sus2->addPattern('zzmatchprobe004', custom: true);
$t->same([false, null], $sus2->detectPatternMatch('clean content here', '1.2.3.4', 'query_param'), 'a clean scan reports no match');
[$matched, $pattern] = $sus2->detectPatternMatch('zzmatchprobe004 payload', '1.2.3.4', 'query_param');
$t->truthy($matched, 'a regex hit reports matched');
$t->truthy($pattern !== null && str_contains($pattern, 'zzmatchprobe004'), 'the hit reports the redacted pattern source');

$t->same([true, 'semantic:xss'], SusPatterns::patternMatchFromResult(['is_threat' => true, 'threats' => [['type' => 'semantic', 'attack_type' => 'xss']]]), 'a semantic threat reports the attack type');
$t->same([true, 'unknown'], SusPatterns::patternMatchFromResult(['is_threat' => true, 'threats' => [['type' => 'pattern_timeout', 'pattern' => 'p']]]), 'an unclassified threat reports unknown');
$t->same([true, 'unknown'], SusPatterns::patternMatchFromResult(['is_threat' => true, 'threats' => []]), 'a threat with no threat rows reports unknown');
$t->same([false, null], SusPatterns::patternMatchFromResult(['is_threat' => false, 'threats' => []]), 'a clean result reports no match');

// ---------------------------------------------------------------------
// 6. Events
// ---------------------------------------------------------------------
$t->section('events');
$agent = new RegAgent();
$eventConfig = new SecurityConfig();
$bus = new EventBus($agent, $eventConfig);
$sus3 = new SusPatterns(0.99, eventBus: $bus);
$sus3->addPattern('zzeventprobe005', custom: true);
$sus3->addPattern('zzeventadded006');
$sus3->removePattern('zzeventprobe005', custom: true);
$added = array_values(array_filter($agent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_PATTERN_ADDED));
$removed = array_values(array_filter($agent->received, static fn (object $e): bool => $e->eventType === EventTypes::EVENT_PATTERN_REMOVED));
$t->same(2, count($added), 'both adds emitted pattern_added');
$t->truthy($added[0]->handlerName === 'sus_patterns' && $added[0]->ipAddress === 'system', 'the registry events carry the sus_patterns handler and the system ip');
$t->same('pattern_added', $added[0]->actionTaken, 'the action is pattern_added');
$t->same('custom', $added[0]->metadata['pattern_type'] ?? null, 'the custom add names its pool');
$t->same(1, $added[0]->metadata['total_patterns'] ?? null, 'the custom add counts the pool');
$t->same('default', $added[1]->metadata['pattern_type'] ?? null, 'the default add names its pool');
$t->truthy(str_contains((string) $added[0]->metadata['pattern'], 'zzeventprobe005'), 'the event carries the redacted source');
$t->same(1, count($removed), 'the removal emitted pattern_removed');
$t->truthy(str_contains((string) $removed[0]->reason, 'Custom pattern removed'), 'the removal reason names the pool');

$agent->received = [];
$strictBus = new EventBus($agent, new SecurityConfig(agentEnableEvents: false));
(new SusPatterns(0.99, eventBus: $strictBus))->addPattern('zzmutedprobe007', custom: true);
$t->same([], $agent->received, 'agent_enable_events false gates the registry events');

$agent->received = [];
$mutedBus = new EventBus($agent, $eventConfig, new EventFilter(mutedEventTypes: [EventTypes::EVENT_PATTERN_ADDED]));
(new SusPatterns(0.99, eventBus: $mutedBus))->addPattern('zzmutedprobe008', custom: true);
$t->same([], $agent->received, 'the event filter mutes pattern_added');

$agent->received = [];
$agent->alwaysFail = true;
$failingBus = new EventBus($agent, $eventConfig);
(new SusPatterns(0.99, eventBus: $failingBus))->addPattern('zzfailprobe009', custom: true);
$t->truthy(true, 'a failing handler dispatch is swallowed, never raised');
$agent->alwaysFail = false;

// A registry with no bus at all must not crash.
(new SusPatterns(0.99))->addPattern('zznobusprobe010', custom: true);
$t->truthy(true, 'no event bus means no event and no crash');

// ---------------------------------------------------------------------
// 7. Redis persistence and restore
// ---------------------------------------------------------------------
$t->section('redis persistence and restore');
$redis = new RedisHandler(
    host: getenv('REDIS_HOST') ?: '127.0.0.1',
    port: (int) (getenv('REDIS_PORT') ?: 6379)
);
$redis->initialize();
$redis->delete('patterns', 'custom');

$persistor = new SusPatterns(0.99, redisHandler: $redis);
$persistor->addPattern('zzpersisted011', custom: true);
$t->truthy($redis->exists('patterns', 'custom'), 'the custom pool persisted to redis');
$t->same('zzpersisted011', $redis->getKey('patterns', 'custom'), 'the persisted payload is the comma-joined pool');

$restored = new SusPatterns(0.99, redisHandler: $redis);
$restored->initializeRedis($redis);
$t->same(['zzpersisted011'], $restored->getCustomPatterns(), 'a fresh instance restores the persisted pool');

$restored->initializeRedis($redis);
$t->same(['zzpersisted011'], $restored->getCustomPatterns(), 'a second restore does not duplicate');

$skipper = new SusPatterns(0.99, redisHandler: $redis);
$redis->setKey('patterns', 'custom', '(.*)+,zzpersisted011');
$skipper->initializeRedis($redis);
$t->truthy(in_array('zzpersisted011', $skipper->getCustomPatterns(), true), 'the safe persisted pattern restores');
$t->truthy(!in_array('(.*)+', $skipper->getCustomPatterns(), true), 'the unsafe persisted pattern is skipped');

$empty = new SusPatterns(0.99, redisHandler: $redis);
$redis->setKey('patterns', 'custom', '');
$empty->initializeRedis($redis);
$t->same([], $empty->getCustomPatterns(), 'an empty persisted payload restores nothing');

$throwing = new class(true) extends RedisHandler {
    public function __construct(private bool $explode)
    {
        parent::__construct();
    }

    public function getKey(string $namespace, string $key): ?string
    {
        if ($this->explode) {
            throw new GuardRedisException('store down');
        }

        return null;
    }
};
$unrestorable = new SusPatterns(0.99);
$unrestorable->initializeRedis($throwing);
$t->same([], $unrestorable->getCustomPatterns(), 'a failing store skips the restore with a warning');
$unrestorable->initializeRedis(null);
$t->same([], $unrestorable->getCustomPatterns(), 'a null handler restores nothing');

// ---------------------------------------------------------------------
// 8. Engine wiring
// ---------------------------------------------------------------------
$t->section('engine wiring');
$engineConfig = new SecurityConfig(enableRedis: false);
$engine = new GuardEngine($engineConfig);
$engineSus = $engine->susPatterns();
$t->truthy($engineSus->addPattern('zzengineprobe012', custom: true), 'the engine registry accepts a pattern');
$engine->applyDynamicConfig(new SecurityConfig(enableRedis: false));
$t->truthy($engine->susPatterns() === $engineSus, 'the registry survives a config rebuild');
$t->truthy(in_array('zzengineprobe012', $engine->susPatterns()->getCustomPatterns(), true), 'the registered pattern is still registered');

$engine->initialize();
$t->truthy(true, 'initialize without redis is a no-op for the registry');

$redis->delete('patterns', 'custom');
$redis->setKey('patterns', 'custom', 'zzenginerestore013');
$redisEngine = new GuardEngine(new SecurityConfig());
$redisEngine->initialize();
$t->truthy(in_array('zzenginerestore013', $redisEngine->susPatterns()->getCustomPatterns(), true), 'engine initialize restores the persisted custom pool');

$blocked = $redisEngine->execute(new SimpleGuardRequest(urlPath: '/scan', clientHost: '9.9.9.9', queryParams: ['q' => 'zzenginerestore013 payload']));
$t->truthy($blocked !== null && $blocked->statusCode() === 400, 'the pipeline detects through the restored registry pattern');
$redis->delete('patterns', 'custom');

// ---------------------------------------------------------------------
// 9. Registry timeout gate and redis-backed removal
// ---------------------------------------------------------------------
$t->section('registry scan gates');
$gatedSus = new SusPatterns(0.99);
$gatedSus->addPattern('zzgateprobe016', custom: true);
$previousTimeout = SusPatterns::$compilerTimeoutOverride;
SusPatterns::$compilerTimeoutOverride = 0.0000001;
try {
    $gatedResult = $gatedSus->detect(str_repeat('unrelated gate padding ', 5000), '1.2.3.4', 'query_param');
} finally {
    SusPatterns::$compilerTimeoutOverride = $previousTimeout;
}
$t->truthy(in_array('zzgateprobe016', $gatedResult['timeouts'] ?? [], true), 'a registry pattern over its scan budget reports a timeout');
$t->truthy((bool) array_filter($gatedResult['threats'], static fn (array $threat): bool => $threat['type'] === 'pattern_timeout'), 'the timeout threat is a custom-category row');

$redisGate = new RedisHandler(
    host: getenv('REDIS_HOST') ?: '127.0.0.1',
    port: (int) (getenv('REDIS_PORT') ?: 6379)
);
$redisGate->initialize();
$redisGate->delete('patterns', 'custom');
$redisRemover = new SusPatterns(0.99, redisHandler: $redisGate);
$redisRemover->addPattern('zzredisremove017', custom: true);
$t->truthy($redisRemover->removePattern('zzredisremove017', custom: true), 'removing a custom pattern with a store attached reports true');
$t->same('', $redisGate->getKey('patterns', 'custom'), 'the removal persisted to the store');

// ---------------------------------------------------------------------
// 10. Dynamic rule application
// ---------------------------------------------------------------------
$t->section('dynamic rule application');
$ruleConfig = new SecurityConfig(enableDynamicRules: true);
$ruleAgent = new RegAgent();
$ruleLogs = [];
$ruleRegistry = new SusPatterns(0.99, eventBus: new EventBus($ruleAgent, $ruleConfig));
$payloadAgent = new class {
    public array $rules = [];

    public function getDynamicRules(): ?array
    {
        return $this->rules;
    }
};
$payloadAgent->rules = [
    'rule_id' => 'rule-patterns',
    'version' => 1,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'suspicious_patterns' => ['zzdynprobe014', '(.*)+'],
];
$installed = [];
$manager = new DynamicRuleManager(
    config: $ruleConfig,
    agentHandler: $payloadAgent,
    eventBus: new EventBus($ruleAgent, $ruleConfig),
    applyConfig: static function (SecurityConfig $c) use (&$installed): void {
        $installed[] = $c;
    },
    logger: static function (string $level, string $message) use (&$ruleLogs): void {
        $ruleLogs[] = $level . ': ' . $message;
    },
    susPatterns: $ruleRegistry
);
$manager->updateRules();
$t->truthy(in_array('zzdynprobe014', $ruleRegistry->getAllPatterns(), true), 'the dynamic-rule pattern registered with the detection engine');
$t->truthy(!in_array('(.*)+', $ruleRegistry->getAllPatterns(), true), 'the unsafe dynamic-rule pattern was rejected');
$t->truthy(in_array('info: Dynamic rule: Added suspicious patterns zzdynprobe014', $ruleLogs, true), 'the applied pattern is reported at info');
$t->truthy(in_array('warning: Dynamic rule: rejected patterns (.*)+', $ruleLogs, true), 'the rejected pattern is reported at warning');

$result = $ruleRegistry->detect('zzdynprobe014 in the wild', '1.2.3.4', 'query_param');
$t->truthy($result['is_threat'], 'the dynamic-rule pattern feeds the detection engine');

$noRegistryLogs = [];
$noRegistry = new DynamicRuleManager(
    config: new SecurityConfig(enableDynamicRules: true),
    agentHandler: $payloadAgent,
    logger: static function (string $level, string $message) use (&$noRegistryLogs): void {
        $noRegistryLogs[] = $level . ': ' . $message;
    }
);
$payloadAgent->rules = [
    'rule_id' => 'rule-noregistry',
    'version' => 1,
    'timestamp' => '2026-01-01T00:00:00+00:00',
    'suspicious_patterns' => ['zznoregistry015'],
];
$noRegistry->updateRules();
$t->truthy((bool) array_filter($noRegistryLogs, static fn (string $line): bool => str_contains($line, 'no pattern registry is attached')), 'a manager without a registry warns and skips');

$t->same(0, $t->failed, 'no failures above');
exit($t->finish('pattern registry'));

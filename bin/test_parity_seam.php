<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Engine\GuardEngine;
use RenzoFranceschini\GuardCore\Events\EventTypes;
use RenzoFranceschini\GuardCore\Exceptions\GuardCoreError;
use RenzoFranceschini\GuardCore\Redis\GuardRedisException;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../tests/FakeRespConnection.php';

// Parity seam: the engine-level agent wiring (setAgentHandler drains the
// queued events through the bus), the initialization status snapshot the
// adapters' status route serves, and the GuardCoreError base class.

final class SeamT
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
            echo '  expected: '.var_export($expected, true)."\n";
            echo '  actual:   '.var_export($actual, true)."\n";
        }
    }

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }
}

$t = new SeamT();

final class RecordingAgent
{
    public array $events = [];

    public function sendEvent(object $event): void
    {
        $this->events[] = $event;
    }
}

// 1. setAgentHandler drains queued events and receives new ones.
$config = new SecurityConfig(enableRedis: false, agentEnableEvents: true);
$engine = new GuardEngine($config);
$engine->initialize();
$bus = $engine->eventBus();
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

$request = new SimpleGuardRequest('GET', '/articles', '203.0.113.7');
$bus->sendMiddlewareEvent(EventTypes::EVENT_RATE_LIMITED, $request, 'throttled', 'over limit');
$agent = new RecordingAgent();
$engine->setAgentHandler($agent);
$t->truthy(count($agent->events) >= 1, 'queued events drain to the agent on setAgentHandler');
$bus->sendMiddlewareEvent(EventTypes::EVENT_RATE_LIMITED, $request, 'throttled', 'over limit again');
$t->truthy(count($agent->events) >= 2, 'subsequent events flow to the agent');

// 2. initializationStatus: disabled redis (per-instance mode) reports each
// component ok with redis disabled.
$status = $engine->initializationStatus();
$t->same(false, $status['redis']['enabled'], 'redis disabled in status');
$t->truthy($status['redis']['ok'], 'disabled redis is an ok state');
$t->truthy($status['ip_ban']['ok'], 'ip_ban ok without redis');
$t->truthy($status['rate_limit']['ok'], 'rate_limit ok without redis');

// 3. GuardCoreError is the base for the family.
$t->truthy(new GuardRedisException('x') instanceof GuardCoreError, 'GuardRedisException extends GuardCoreError');

// 4. Dead redis under fail-open: the initialize catch arm records the
// failure in the status and the engine keeps serving per-instance.
putenv('REDIS_PORT=1');
$deadConfig = new SecurityConfig(enableRedis: true, redisFailOpen: true);
$deadEngine = new GuardEngine($deadConfig);
$threw = false;
try {
    $deadEngine->initialize();
} catch (\Throwable $e) {
    $threw = true; // the engine throws; the ADAPTER consults redis_fail_open
}
$t->truthy($threw, 'dead redis must fail closed at the engine level');
$status = $deadEngine->initializationStatus();
$t->same(false, $status['redis']['ok'], 'dead redis recorded as not ok');
$t->truthy($status['redis']['error'] !== null, 'dead redis carries the error');
putenv('REDIS_PORT');

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}".($t->failed === 0 ? ' GREEN' : ' RED')."\n";
exit($t->failed === 0 ? 0 : 1);

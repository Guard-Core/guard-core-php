<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\JsonFormatter;
use RenzoFranceschini\GuardCore\Logging\LogSetup;

require __DIR__ . '/../vendor/autoload.php';

// B6 parity: the JSON structured-logging surface (reference
// _utils/logging_utils.py JsonFormatter + setup_custom_logging): the four
// fixed fields in order, the text layout, the INFO+ level gate, the
// optional log file with on-demand directory creation and console-only
// fallback, the host-owns-logging yield flag, and the log_format config
// switch. The bounded body reader finding is documented in the PR body:
// the PHP SAPI model (the host hands the engine an already-read body)
// leaves python's read timeout / concurrency cap / straddle over-read
// inapplicable.
//
// Run: php bin/test_json_logging.php

final class LogT
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

function tmpDir(): string
{
    $dir = sys_get_temp_dir() . '/guard_json_log_' . bin2hex(random_bytes(4));
    if (!is_dir($dir) && !mkdir($dir, 0777, true)) {
        throw new RuntimeException('tmp dir failed');
    }

    return $dir;
}

$t = new LogT();

// ---------------------------------------------------------------------
// 1. JsonFormatter
// ---------------------------------------------------------------------

$t->section('json formatter');
$formatter = new JsonFormatter();
$at = new DateTimeImmutable('2026-10-06T12:34:56+00:00');
$line = $formatter->format('warning', 'guard_core', 'blocked request', $at);
$decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
$t->same(['timestamp', 'level', 'logger', 'message'], array_keys($decoded), 'exactly four fields in reference order');
$t->same('WARNING', $decoded['level'], 'level uppercased');
$t->same('guard_core', $decoded['logger'], 'logger channel passthrough');
$t->same('blocked request', $decoded['message'], 'message passthrough');
$t->truthy(preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/', (string) $decoded['timestamp']) === 1, 'timestamp is the python asctime shape with millis');
$t->truthy(str_starts_with($line, '{"timestamp":'), 'json key order starts with timestamp');

$raw = $formatter->format('INFO', 'guard_core', "line1\nline2 \"quoted\"", $at);
$recoded = json_decode($raw, true);
$t->same("line1\nline2 \"quoted\"", $recoded['message'], 'control characters survive the round trip');

$binary = $formatter->format('INFO', 'guard_core', "bad \xB1\x31 utf8", $at);
$t->truthy(json_decode($binary, true) !== null, 'malformed utf-8 substitutes instead of dropping the line');

// ---------------------------------------------------------------------
// 2. LogSetup console emission (stderr captured from a child process)
// ---------------------------------------------------------------------

$t->section('setup console emission');

/**
 * Runs a child PHP process whose stderr is captured; the child installs
 * the setup logger in the requested format and emits two records (one
 * warning, one dropped debug).
 *
 * @return list<string> captured stderr lines
 */
function captureConsole(string $format, bool $hostOwnsLogging): array
{
    $child = tmpDir() . '/child.php';
    $guard = var_export(__DIR__ . '/../vendor/autoload.php', true);
    $hostFlag = $hostOwnsLogging ? 'true' : 'false';
    file_put_contents($child, <<<PHP
    <?php
    require {$guard};
    \$logger = RenzoFranceschini\\GuardCore\\Logging\\LogSetup::setupCustomLogging(null, '{$format}', {$hostFlag});
    \$logger->log('warning', 'hello from child', ['check' => 'ip_security']);
    \$logger->log('debug', 'too chatty', []);

    PHP);
    $stderr = tmpDir() . '/stderr.txt';
    $cmd = sprintf('%s %s 2> %s', escapeshellarg(PHP_BINARY), escapeshellarg($child), escapeshellarg($stderr));
    shell_exec($cmd);
    $lines = file($stderr, FILE_IGNORE_NEW_LINES) ?: [];
    unlink($child);

    return $lines;
}

$consoleLines = captureConsole('json', false);
$t->same(1, count($consoleLines), 'one console line per record (debug dropped)');
$record = json_decode((string) $consoleLines[0], true);
$t->truthy(is_array($record) && ($record['level'] ?? null) === 'WARNING', 'json layout reaches the console');
$t->truthy(is_array($record) && ($record['message'] ?? null) === 'hello from child', 'message survives the console path');
$t->truthy(is_array($record) && !isset($record['check']), 'context is not rendered (formatter formats the message only)');

$textLines = captureConsole('text', false);
$t->truthy(preg_match('/^\[guard_core\] \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} - WARNING - hello from child$/', (string) $textLines[0]) === 1, 'text layout mirrors the reference pattern');

$hostLines = captureConsole('json', true);
$t->same([], $hostLines, 'host-owns-logging suppresses console emission');

// ---------------------------------------------------------------------
// 3. LogSetup file target
// ---------------------------------------------------------------------

$t->section('setup file target');
$fileDir = tmpDir();
$nested = $fileDir . '/deep/nested/guard.log';
$fileLogger = LogSetup::setupCustomLogging($nested, 'json');
$fileLogger->log('error', 'file line', []);
$t->truthy(is_file($nested), 'log directories created on demand');
$lines = file($nested, FILE_IGNORE_NEW_LINES) ?: [];
$t->same(1, count($lines), 'one line appended to the file');
$t->truthy(json_decode((string) $lines[0], true) !== null, 'file lines are json records');
$fileLogger->log('info', 'file line 2', []);
$t->same(2, count(file($nested, FILE_IGNORE_NEW_LINES) ?: []), 'records append (no truncation)');

$t->section('setup file failure fallback');
$blocked = tmpDir() . '/regular.txt';
file_put_contents($blocked, 'x');
$blockedLogger = LogSetup::setupCustomLogging($blocked . '/guard.log', 'json');
$blockedLogger->log('warning', 'still logged', []);
$t->truthy(true, 'file failure stays console-only (warning path, never throws)');

// ---------------------------------------------------------------------
// 4. Config switch
// ---------------------------------------------------------------------

$t->section('log_format config switch');
$t->same('text', (new SecurityConfig())->logFormat, 'log_format defaults to text');
$t->same('json', (new SecurityConfig(logFormat: 'json'))->logFormat, 'json accepted');
$flipped = (new SecurityConfig(logFormat: 'json'))->with(['log_format' => 'text']);
$t->same('text', $flipped->logFormat, 'with() can flip the format');

// Parent-process coverage for the branches the stderr-capturing child
// cannot carry: the text layout and the debug gate (console suppressed),
// plus a live engine-closure call (one line lands on the suite's stderr).
$silent = LogSetup::setupCustomLogging(null, 'text', hostOwnsLogging: true);
$silent->log('warning', 'text layout branch', []);
$silent->log('debug', 'dropped in the parent too', []);
$t->truthy(true, 'the text layout + debug gate run clean with console suppressed');
$engineClosure = LogSetup::engineLogClosure(new SecurityConfig(logFormat: 'json'));
$engineClosure('warning', 'via the engine closure', []);
$t->truthy(true, 'the engine closure emits without error');

$threw = false;
try {
    new SecurityConfig(logFormat: 'yaml');
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'unknown log_format rejected at construction');

$threw = false;
try {
    new SecurityConfig(otelResourceAttributes: ['a' => 42]);
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'non-string otel_resource_attributes values rejected');

$closure = LogSetup::engineLogClosure(new SecurityConfig(logFormat: 'json'));
$t->truthy($closure instanceof Closure, 'engine log closure factory returns a closure');
$threw = false;
try {
    LogSetup::setupCustomLogging(null, 'yaml');
} catch (InvalidArgumentException) {
    $threw = true;
}
$t->truthy($threw, 'setup rejects unknown formats independently of the config');

// ---------------------------------------------------------------------
// 5. Enrichment/observability config defaults
// ---------------------------------------------------------------------

$t->section('observability config defaults');
$defaults = new SecurityConfig();
$t->truthy(!$defaults->enableEnrichment, 'enable_enrichment defaults false');
$t->truthy(!$defaults->enableOtel, 'enable_otel defaults false');
$t->truthy(!$defaults->enableLogfire, 'enable_logfire defaults false');
$t->same('guard-core', $defaults->otelServiceName, 'otel_service_name default');
$t->same('guard-core', $defaults->logfireServiceName, 'logfire_service_name default');
$t->same(null, $defaults->agentProjectId, 'agent_project_id default null');
$t->same(null, $defaults->otelExporterEndpoint, 'otel_exporter_endpoint default null');
$t->same([], $defaults->otelResourceAttributes, 'otel_resource_attributes default empty');

exit($t->finish('json logging'));

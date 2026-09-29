<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Logging\LogActivity;
use RenzoFranceschini\GuardCore\Logging\LogRedactor;
use RenzoFranceschini\GuardCore\Logging\SimpleRequestLogger;
use RenzoFranceschini\GuardCore\Pipeline\CheckFactory;
use RenzoFranceschini\GuardCore\Pipeline\Checks\CustomRequestCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\CustomValidatorsCheck;
use RenzoFranceschini\GuardCore\Pipeline\Checks\RequestLoggingCheck;
use RenzoFranceschini\GuardCore\Pipeline\SecurityCheckPipeline;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;

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

    public function truthy(mixed $actual, string $label): void
    {
        $this->same(true, (bool) $actual, $label);
    }

    public function throws(callable $fn, string $class, string $label): void
    {
        try {
            $fn();
            $this->failed++;
            echo "FAIL - {$label}: no exception\n";
        } catch (Throwable $e) {
            $this->same($class, $e::class, $label);
        }
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

$t = new T();
$responseFactory = new GuardResponseFactory();

function m3cRequest(string $path = '/', string $ip = '9.9.9.9', array $headers = [], string $rawQuery = '', string $host = 'localhost', string $method = 'GET'): SimpleGuardRequest
{
    $request = new SimpleGuardRequest(urlPath: $path, host: $host, method: $method, headers: $headers, rawQuery: $rawQuery);
    $request->state()->clientIp = $ip;

    return $request;
}

/** @param array<string, \RenzoFranceschini\GuardCore\Routing\RouteConfig> $routeConfigs */
function m3cPipeline(SecurityConfig $config, array $routeConfigs = []): SecurityCheckPipeline
{
    $factory = new CheckFactory($responseFactory = new GuardResponseFactory(), new RenzoFranceschini\GuardCore\Routing\RouteResolver($routeConfigs));

    return new SecurityCheckPipeline($factory->buildChecks($config), $config);
}

$t->section('redaction: sensitive headers');
$redacted = LogRedactor::redactHeaders([
    'Authorization' => 'Bearer abc123',
    'x-api-key' => 'key-42',
    'cookie' => 'session=xyz',
    'X-Custom' => 'visible',
]);
$t->same('[REDACTED]', $redacted['Authorization'], 'default sensitive header masked');
$t->same('[REDACTED]', $redacted['x-api-key'], 'x-api-key masked');
$t->same('[REDACTED]', $redacted['cookie'], 'cookie masked');
$t->same('visible', $redacted['X-Custom'], 'non-sensitive header passthrough');
$redacted = LogRedactor::redactHeaders(['X-Secret' => 'hush'], extraHeaders: ['x-secret']);
$t->same('[REDACTED]', $redacted['X-Secret'], 'config extra sensitive header masked (case-insensitive)');
$redacted = LogRedactor::redactHeaders(['X-Data' => '{"password":"p","keep":"k"}']);
$t->same('{"password":"[REDACTED]","keep":"k"}', $redacted['X-Data'], 'non-sensitive header value JSON-body-field redacted');

$t->section('redaction: url / query / path');
$t->same('http://h/p?token=[REDACTED]&page=1', LogRedactor::redactUrlForDisplay('http://h/p?token=x&page=1'), 'default sensitive field token redacted in query');
$t->same('http://h/p?user=bob&page=1', LogRedactor::redactUrlForDisplay('http://h/p?user=bob&page=1'), 'non-sensitive query passthrough');
$extra = ['session_id'];
$t->same('http://h/p?session_id=[REDACTED]&ok=1', LogRedactor::redactUrlForDisplay('http://h/p?session_id=abc&ok=1', extraParams: $extra), 'extra config param redacted');
$t->same('http://user:[REDACTED]@h/p', LogRedactor::redactUrlForDisplay('http://user:pw@h/p'), 'userinfo password redacted');
$t->same('http://h/a%09b', LogRedactor::redactUrlForDisplay("http://h/a\tb"), 'control chars escaped');
$t->same('http://h/api/token/zzz', LogRedactor::redactUrlForDisplay('http://h/api/token/zzz'), 'path segment without pairs untouched');
$t->same('http://h/p?signature=[REDACTED]&x=1', LogRedactor::redactUrlForDisplay('http://h/p?signature=deadbeef&x=1'), 'signature (shared default set) redacted');
$blob = LogRedactor::redactBlob('{"access_token":"t","n":1}');
$t->same('{"access_token":"[REDACTED]","n":1}', $blob, 'JSON blob field redaction');
$blob = LogRedactor::redactBlob('%7B%22password%22%3A%22p%22%7D');
$t->same('{"password":"[REDACTED]"}', $blob, 'percent-encoded JSON blob redaction');
$blob = LogRedactor::redactBlob('<password>hunter2</password><keep>x</keep>');
$t->same('<password>[REDACTED]</password><keep>x</keep>', $blob, 'XML element redaction');
$blob = LogRedactor::redactBlob('a=1;password=zz&b=2');
$t->same('a=1;password=[REDACTED]&b=2', $blob, 'pair redaction');
$t->same('plain', LogRedactor::redactBlob('plain'), 'plain value untouched');

$t->section('redaction: json depth cap collapses whole-value (guard-core 4.0.4 parity, upstream 8bae9459)');
$deep = str_repeat('[', 80) . '{"password":"hunter2"}' . str_repeat(']', 80);
$t->same('[REDACTED]', LogRedactor::redactBlob($deep), 'deep json past the cap redacts whole-value');
$deepHeader = LogRedactor::redactHeaders(['X-Deep' => $deep]);
$t->same('[REDACTED]', $deepHeader['X-Deep'], 'deep json header redacts whole-value');
$t->same('[REDACTED]', LogRedactor::redactBlob(rawurlencode($deep)), 'percent-encoded deep json redacts whole-value');
$shallow = str_repeat('[', 30) . '{"password":"x"}' . str_repeat(']', 30);
$t->same(str_repeat('[', 30) . '{"password":"[REDACTED]"}' . str_repeat(']', 30), LogRedactor::redactBlob($shallow), 'nested json within the cap still tree-redacts');
$t->same('{"password":"x"', LogRedactor::redactBlob('{"password":"x"'), 'malformed json still falls through to raw fallbacks');

$t->section('log_activity: request logging');
$logger = new SimpleRequestLogger();
$config = new SecurityConfig(logRequestLevel: 'INFO');
$request = m3cRequest('/api/x', headers: ['Authorization' => 'Bearer z', 'X-Ok' => '1'], rawQuery: 'token=abc&q=2', host: 'h');
LogActivity::log($request, $logger, $config, logType: 'request', level: $config->logRequestLevel, checkName: 'request_logging');
$t->same(1, count($logger->records()), 'one request log line');
$record = $logger->records()[0];
$t->same('info', $record['level'], 'level normalized lowercase');
$t->truthy(str_contains($record['message'], 'Request from 9.9.9.9: GET http://h/api/x?token=[REDACTED]&q=2 - '), 'request line format with redacted query');
$t->truthy(str_contains($record['message'], 'authorization='), 'headers echoed (canonical lowercase names)');
$t->truthy(preg_match('/authorization *= *\\[REDACTED\\]/', $record['message']) === 1, 'authorization header redacted in line');
$t->same('request_logging', $record['context']['check'], 'check context');

$logger = new SimpleRequestLogger();
$muted = new SecurityConfig(logRequestLevel: 'INFO', mutedCheckLogs: ['request_logging']);
LogActivity::log($request, $logger, $muted, logType: 'request', level: 'INFO', checkName: 'request_logging');
$t->same(0, count($logger->records()), 'muted check log suppressed');

$logger = new SimpleRequestLogger();
LogActivity::log($request, $logger, new SecurityConfig(), logType: 'request', level: null, checkName: 'request_logging');
$t->same(0, count($logger->records()), 'null level -> no log line');

$t->section('log_activity: console-safe lines (guard-core 4.0.4 parity, upstream f5d53ca5)');
$logger = new SimpleRequestLogger();
$safeConfig = new SecurityConfig(logRequestLevel: 'INFO');
$safeRequest = m3cRequest('/api/x', headers: [
    'X-Probe' => "a\x01b\xc3\xa9c\xf0\x9f\xa6\x8a",
    'X-Multi' => "line1\nline2\tend",
    'X-Raw' => "\xc3(",
], rawQuery: 'q=1', host: 'h');
LogActivity::log($safeRequest, $logger, $safeConfig, logType: 'request', level: 'INFO', checkName: 'request_logging');
$safeMessage = $logger->records()[0]['message'];
$t->truthy(str_contains($safeMessage, 'x-probe=a\u0001b\u00e9c\u1f98a'), 'control char and unicode escaped as \uXXXX');
$t->truthy(str_contains($safeMessage, 'x-multi=line1\nline2\tend'), 'newline and tab use the short escapes');
$t->truthy(str_contains($safeMessage, 'x-raw=\xc3('), 'invalid utf-8 byte escaped as \xNN');
$t->same(0, preg_match('/[\x00-\x1f\x7f]/', $safeMessage), 'no raw control characters in the line');
$t->same(0, preg_match('/[\x80-\xff]/', $safeMessage), 'line is pure printable ASCII');

$logger = new SimpleRequestLogger();
$unsafeRequest = m3cRequest('/login', headers: ['X-Reason' => "trig\xc2\xa0ger"], rawQuery: 'password=hunter2');
LogActivity::log($unsafeRequest, $logger, new SecurityConfig(), logType: 'suspicious', level: 'WARNING', reason: "custom\xc2\xa0fail", passiveMode: false, checkName: 'custom_validators');
$t->same(0, preg_match('/[\x80-\xff]/', $logger->records()[0]['message']), 'suspicious line is pure ASCII too');

$t->section('log_activity: suspicious + passive paths');
$logger = new SimpleRequestLogger();
$req = m3cRequest('/login', rawQuery: 'password=hunter2');
LogActivity::log($req, $logger, new SecurityConfig(), logType: 'suspicious', level: 'WARNING', reason: 'Custom validation failed', passiveMode: false, checkName: 'custom_validators');
$t->same(['reason' => 'Custom validation failed', 'trigger_info' => ''], $req->state()->guardBlockStash, 'non-passive suspicious stashes block info');
$t->truthy(str_contains($logger->records()[0]['message'], 'Suspicious activity detected from 9.9.9.9'), 'suspicious line lead');
$t->truthy(str_contains($logger->records()[0]['message'], 'Reason: Custom validation failed'), 'suspicious reason segment');
$t->truthy(str_contains($logger->records()[0]['message'], 'password=[REDACTED]'), 'suspicious line redacts url');
$t->same('warning', $logger->records()[0]['level'], 'suspicious level');

$logger = new SimpleRequestLogger();
$req = m3cRequest('/login');
$passiveConfig = new SecurityConfig(passiveMode: true);
LogActivity::log($req, $logger, $passiveConfig, logType: 'suspicious', level: 'WARNING', reason: 'r', passiveMode: true, triggerInfo: 'trig', checkName: 'custom_validators');
$t->same(null, $req->state()->guardBlockStash, 'passive suspicious does not stash');
$t->truthy(str_contains($logger->records()[0]['message'], '[PASSIVE MODE] Penetration attempt detected from'), 'passive line lead');
$t->truthy(str_contains($logger->records()[0]['message'], 'Trigger: trig - Headers:'), 'passive trigger segment');

$payloads = [];
$hook = function ($request, $payload) use (&$payloads) {
    $payloads[] = $payload;
};
$logger = new SimpleRequestLogger();
$req = m3cRequest('/login');
$hookConfig = new SecurityConfig(passiveMode: true, onBlock: $hook);
LogActivity::log($req, $logger, $hookConfig, logType: 'suspicious', level: 'WARNING', reason: 'r', passiveMode: true, triggerInfo: 'trig', checkName: 'custom_validators');
$t->same([], $payloads, 'custom_validators excluded from on_block');

$payloads = [];
$logger = new SimpleRequestLogger();
$req = m3cRequest('/login');
$hookConfig = new SecurityConfig(passiveMode: true, onBlock: $hook);
LogActivity::log($req, $logger, $hookConfig, logType: 'suspicious', level: 'WARNING', reason: 'r', passiveMode: true, triggerInfo: 'trig', checkName: 'custom_request');
$t->same([], $payloads, 'custom_request excluded from on_block');
$req = m3cRequest('/x');
$hookConfig2 = new SecurityConfig(passiveMode: true, onBlock: $hook);
LogActivity::log($req, $logger, $hookConfig2, logType: 'suspicious', level: 'WARNING', reason: 'r', passiveMode: true, triggerInfo: 'trig', checkName: 'https_enforcement');
$t->same([], $payloads, 'https_enforcement excluded from on_block');

$logger = new SimpleRequestLogger();
LogActivity::log(m3cRequest('/x'), $logger, new SecurityConfig(), logType: 'error', level: 'ERROR', reason: 'boom');
$t->truthy(str_contains($logger->records()[0]['message'], 'Error from 9.9.9.9'), 'generic log type ucfirst lead');
$t->truthy(str_contains($logger->records()[0]['message'], 'Details: boom'), 'generic details segment');

$t->section('applies_to gates');
$config = new SecurityConfig();
$factory = new CheckFactory(new GuardResponseFactory(), new RenzoFranceschini\GuardCore\Routing\RouteResolver());
$requestLogging = new RequestLoggingCheck($config, $responseFactory);
$customValidators = new CustomValidatorsCheck($config, $responseFactory);
$customRequest = new CustomRequestCheck($config, $responseFactory);
$t->same(false, $requestLogging->appliesTo(new SecurityConfig(), null), 'request_logging off when log_request_level null');
$t->same(true, $requestLogging->appliesTo(new SecurityConfig(logRequestLevel: 'DEBUG'), null), 'request_logging on when log_request_level set');
$t->same(true, $customValidators->appliesTo($config, null), 'custom_validators: null routes satisfies route predicate');
$plainRoute = new RenzoFranceschini\GuardCore\Routing\RouteConfig();
$t->same(false, $customValidators->appliesTo($config, [$plainRoute]), 'custom_validators off without route validators');
$validatorRoute = new RenzoFranceschini\GuardCore\Routing\RouteConfig(customValidators: [static fn ($r) => null]);
$t->same(true, $customValidators->appliesTo($config, [$plainRoute, $validatorRoute]), 'custom_validators on when any route has validators');
$t->same(false, $customRequest->appliesTo(new SecurityConfig(), null), 'custom_request off when callback null');
$t->same(true, $customRequest->appliesTo(new SecurityConfig(customRequestCheck: static fn ($r) => null), null), 'custom_request on when callback set');

$t->section('request_logging check');
$logger = new SimpleRequestLogger();
$config = new SecurityConfig(logRequestLevel: 'DEBUG');
$check = new RequestLoggingCheck($config, $responseFactory, $logger);
$req = m3cRequest('/', rawQuery: 'api_key=k');
$t->same(null, $check->check($req), 'request_logging never blocks');
$t->same(1, count($logger->records()), 'request log emitted at configured level');
$t->same('debug', $logger->records()[0]['level'], 'configured level used');
$t->truthy(str_contains($logger->records()[0]['message'], 'api_key=[REDACTED]'), 'config-driven redaction applied');
$offConfig = new SecurityConfig();
$gatedFactory = new CheckFactory(new GuardResponseFactory(), new RenzoFranceschini\GuardCore\Routing\RouteResolver());
$t->same(false, in_array('request_logging', array_map(fn ($c) => $c->checkName(), $gatedFactory->buildChecks($offConfig)), true), 'request_logging not constructed by default');

$t->section('custom_validators check');
$config = new SecurityConfig();
$check = new CustomValidatorsCheck($config, $responseFactory);
$req = m3cRequest('/v');
$t->same(null, $check->check($req), 'no route config -> allow');
$req = m3cRequest('/v');
$req->state()->routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig();
$t->same(null, $check->check($req), 'route without validators -> allow');

$blockingResponse = new GuardResponse(418, new RenzoFranceschini\GuardCore\Request\HeaderBag(), 'validator says no');
$req = m3cRequest('/v');
$req->state()->routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig(customValidators: [
    static fn ($r) => null,
    static fn ($r) => $blockingResponse,
]);
$logger = new SimpleRequestLogger();
$check = new CustomValidatorsCheck($config, $responseFactory, $logger);
$response = $check->check($req);
$t->same(418, $response?->statusCode(), 'validator GuardResponse returned raw');
$t->same('validator says no', $response?->body(), 'raw passthrough, not create_error_response');
$t->same('validator says no', $response?->body(), 'body not replaced by custom 418 message');
$t->truthy(str_contains($logger->records()[0]['message'], 'Custom validation failed'), 'failure logged suspicious');
$t->same(['reason' => 'Custom validation failed', 'trigger_info' => ''], $req->state()->guardBlockStash, 'stash written for pipeline hook');

$req = m3cRequest('/v');
$req->state()->routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig(customValidators: [static fn ($r) => 'truthy-but-not-response']);
$logger = new SimpleRequestLogger();
$check = new CustomValidatorsCheck($config, $responseFactory, $logger);
$t->same(null, $check->check($req), 'truthy non-GuardResponse logs but does not block');
$t->same(1, count($logger->records()), 'non-response truthy still logged');

$req = m3cRequest('/v');
$req->state()->routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig(customValidators: [static fn ($r) => false]);
$check = new CustomValidatorsCheck($config, $responseFactory);
$t->same(null, $check->check($req), 'falsy validator passes');

$passiveConfig = new SecurityConfig(passiveMode: true);
$req = m3cRequest('/v');
$req->state()->routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig(customValidators: [static fn ($r) => $blockingResponse]);
$logger = new SimpleRequestLogger();
$check = new CustomValidatorsCheck($passiveConfig, $responseFactory, $logger);
$t->same(null, $check->check($req), 'passive mode: validator block observed, not returned');
$t->same(1, count($logger->records()), 'passive mode still logs');
$t->same(null, $req->state()->guardBlockStash, 'passive mode does not stash');

$payloads = [];
$hookConfig = new SecurityConfig(onBlock: $hook);
$req = m3cRequest('/v');
$req->state()->routeConfig = new RenzoFranceschini\GuardCore\Routing\RouteConfig(customValidators: [static fn ($r) => $blockingResponse]);
$pipeline = new SecurityCheckPipeline([new CustomValidatorsCheck($hookConfig, $responseFactory)], $hookConfig);
$pipeline->execute($req);
$t->same([], $payloads, 'on_block suppressed for custom_validators');

$t->section('custom_request check');
$config = new SecurityConfig();
$check = new CustomRequestCheck($config, $responseFactory);
$t->same(null, $check->check(m3cRequest('/c')), 'null callback -> allow');
$customResponse = new GuardResponse(429, new RenzoFranceschini\GuardCore\Request\HeaderBag(), 'too many');
$config = new SecurityConfig(customRequestCheck: static fn ($r) => $customResponse);
$check = new CustomRequestCheck($config, $responseFactory);
$response = $check->check(m3cRequest('/c'));
$t->same(429, $response?->statusCode(), 'custom response returned non-passive');
$t->same('too many', $response?->body(), 'custom response body passthrough');

$falsyConfig = new SecurityConfig(customRequestCheck: static fn ($r) => null);
$t->same(null, (new CustomRequestCheck($falsyConfig, $responseFactory))->check(m3cRequest('/c')), 'falsy callback -> allow');

$passiveConfig = new SecurityConfig(passiveMode: true, customRequestCheck: static fn ($r) => $customResponse);
$t->same(null, (new CustomRequestCheck($passiveConfig, $responseFactory))->check(m3cRequest('/c')), 'passive mode returns None, skips custom response');

$modifierCalls = [];
$modifyingFactory = new GuardResponseFactory(static function ($response) use (&$modifierCalls) {
    $modifierCalls[] = $response->statusCode();

    return new GuardResponse(403, new RenzoFranceschini\GuardCore\Request\HeaderBag(), 'modified');
});
$config = new SecurityConfig(customRequestCheck: static fn ($r) => $customResponse);
$response = (new CustomRequestCheck($config, $modifyingFactory))->check(m3cRequest('/c'));
$t->same([429], $modifierCalls, 'response modifier invoked with custom response');
$t->same(403, $response?->statusCode(), 'modified response returned');
$t->same('modified', $response?->body(), 'modified body');
$failingFactory = new GuardResponseFactory(static function () {
    throw new RuntimeException('modifier blew up');
});
$response = (new CustomRequestCheck($config, $failingFactory))->check(m3cRequest('/c'));
$t->same(429, $response?->statusCode(), 'modifier exception returns unmodified response');

$t->section('pipeline level: slots, verdicts, hooks');
$routeConfigs = ['v' => new RenzoFranceschini\GuardCore\Routing\RouteConfig(customValidators: [static fn ($r) => $blockingResponse])];
$config = new SecurityConfig();
$pipeline = m3cPipeline($config, $routeConfigs);
$req = m3cRequest('/v');
$req->state()->guardRouteId = 'v';
$req->state()->routeConfig = $routeConfigs['v'];
$t->same(418, $pipeline->execute($req)?->statusCode(), 'pipeline: validator block short-circuits');

$payloads = [];
$hookConfig = new SecurityConfig(onBlock: $hook, customRequestCheck: static fn ($r) => $customResponse);
$factory = new CheckFactory(new GuardResponseFactory(), new RenzoFranceschini\GuardCore\Routing\RouteResolver());
$pipeline = new SecurityCheckPipeline($factory->buildChecks($hookConfig), $hookConfig);
$req = m3cRequest('/c');
$t->same(429, $pipeline->execute($req)?->statusCode(), 'pipeline: custom_request blocks with its response');
$t->same([], $payloads, 'pipeline: on_block suppressed for custom_request');

$loggedConfig = new SecurityConfig(logRequestLevel: 'INFO', mutedCheckLogs: ['request_logging']);
$factory = new CheckFactory(new GuardResponseFactory(), new RenzoFranceschini\GuardCore\Routing\RouteResolver());
$pipeline = new SecurityCheckPipeline($factory->buildChecks($loggedConfig), $loggedConfig);
$req = m3cRequest('/p');
$t->same(null, $pipeline->execute($req), 'pipeline: request_logging slot allows');
$built = array_map(fn ($c) => $c->checkName(), $factory->buildChecks($loggedConfig));
$position = array_search('request_logging', $built, true);
$t->truthy($position !== false, 'request_logging present when gated on');
$names = array_keys(array_flip(CheckFactory::DEFAULT_CHECK_NAMES));
$t->truthy(array_search('request_logging', CheckFactory::DEFAULT_CHECK_NAMES, true) < array_search('request_size_content', CheckFactory::DEFAULT_CHECK_NAMES, true), 'request_logging is slot 4');
$t->truthy(array_search('custom_validators', CheckFactory::DEFAULT_CHECK_NAMES, true) < array_search('time_window', CheckFactory::DEFAULT_CHECK_NAMES, true), 'custom_validators is slot 9');
$t->truthy(array_search('custom_request', CheckFactory::DEFAULT_CHECK_NAMES, true) === 16, 'custom_request is slot 17');

$t->section('config: validation edges');

$t->throws(static fn () => new SecurityConfig(autoBanThreshold: 0), InvalidArgumentException::class, 'auto_ban_threshold below 1 rejected');
$t->throws(static fn () => new SecurityConfig(autoBanDuration: 0), InvalidArgumentException::class, 'auto_ban_duration below 1 rejected');
$t->throws(static fn () => new SecurityConfig(detectionSemanticThreshold: 1.5), InvalidArgumentException::class, 'semantic threshold above 1 rejected');
$t->throws(static fn () => new SecurityConfig(whitelistCountries: ['US'], blockedCountries: ['CN']), InvalidArgumentException::class, 'blocked countries alongside whitelist rejected');
$t->throws(static fn () => new SecurityConfig(customErrorResponses: ['oops' => 'x']), InvalidArgumentException::class, 'non-int status in custom responses rejected');
$t->throws(static fn () => new SecurityConfig(blockedUserAgents: ['']), InvalidArgumentException::class, 'empty user agent pattern rejected');
$t->throws(static fn () => new SecurityConfig(blockCloudProviders: [5]), InvalidArgumentException::class, 'non-string cloud selector rejected');
$t->throws(static fn () => (new SecurityConfig())->with(['definitely_not_a_field' => 1]), InvalidArgumentException::class, 'unknown config field rejected');
$t->throws(static fn () => new SecurityConfig(threatBanConfig: ['xss' => ['threshold' => 1]]), InvalidArgumentException::class, 'threat ban config missing duration rejected');
$t->throws(static fn () => new SecurityConfig(endpointRateLimits: ['/x' => ['limit' => 5]]), InvalidArgumentException::class, 'endpoint rate limit missing window rejected');

$t->section('redaction: remaining url edges');

$escapedUrl = LogRedactor::redactUrlForDisplay('no colon space slashes here');
$t->same('no colon space slashes here', $escapedUrl, 'unparseable urls survive');
$portUrl = LogRedactor::redactUrlForDisplay('https://example.test:8443/p?a=1#frag');
$t->same(true, str_contains($portUrl, ':8443'), 'ports survive redaction');
$t->same(true, str_contains($portUrl, '#frag'), 'fragments survive redaction');
$t->same(true, LogRedactor::sensitiveNames(['extra_param'], ['extra_body'], ['Extra_Header']) !== [], 'sensitive names merge extras');

$total = $t->passed + $t->failed;

echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);

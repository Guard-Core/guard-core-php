<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\JsonWalk;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

/**
 * Honesty tests for the ordered JSON walk (parity with
 * guard_core/_utils/body_json_scan.py and embedded_json_scan.py, mirroring
 * the Go engine's guardcore/jsonwalk.go).
 *
 * JSON-content-type bodies walk insertion-ordered: mongo-operator keys hit
 * nosql straight from the walk, plain keys scan as request_body components,
 * scalar leaves scan str(value) with the plain request_body context, and
 * objects or arrays at the depth cap (32) scan as compact serializations.
 * Query parameters and headers scan with their own context, and any of
 * those values that itself parses as embedded JSON walks leaf-first with
 * the :embedded_json context suffix, so the per-context gates (recon
 * leading separator, binary noise) apply to the leaves. Malformed or
 * scalar JSON falls back to the raw blob scan.
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

function makeCheck(): SuspiciousActivityCheck
{
    $config = new SecurityConfig();

    return new SuspiciousActivityCheck(
        $config,
        new GuardResponseFactory(),
        new SusPatterns($config->detectionSemanticThreshold),
        null,
        new RouteResolver()
    );
}

function blocked(SuspiciousActivityCheck $check, string $body, string $contentType): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', method: 'POST', headers: ['content-type' => $contentType], body: $body);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

function blockedQuery(SuspiciousActivityCheck $check, string $value): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', queryParams: ['v' => $value]);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

function blockedHeader(SuspiciousActivityCheck $check, string $value): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', headers: ['x-trace' => $value]);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

use RenzoFranceschini\GuardCore\Detection\BodyFormScan;

const JSON_CT = 'application/json';
const LD_JSON_CT = 'application/ld+json';
const SCRIPT = '<script>alert(1)</script>';
const TAUTOLOGY = '1 OR 1=1';

$t = new T();
$check = makeCheck();

$t->section('parse gate: only JSON objects and arrays walk');
$t->same(true, JsonWalk::parse('{"a":1}') !== null, 'object parses');
$t->same(true, JsonWalk::parse('[1,2]') !== null, 'array parses');
$t->same(null, JsonWalk::parse('"scalar"'), 'string root does not walk');
$t->same(null, JsonWalk::parse('123'), 'number root does not walk');
$t->same(null, JsonWalk::parse('true'), 'bool root does not walk');
$t->same(null, JsonWalk::parse('null'), 'null root does not walk');
$t->same(null, JsonWalk::parse('{"a":1'), 'malformed does not parse');
$t->same(null, JsonWalk::parse('[1,2] trailing'), 'trailing data does not parse');
$t->same(null, JsonWalk::parse(''), 'empty does not parse');

$t->section('walk: insertion order, duplicate keys keep first position and last value');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"z": "1", "a": "2", "z": "3"}'), 'request_body');
$t->same([
    ['z', 'request_body', null, "JSON key 'z': "],
    ['3', 'request_body', null, "Request body field 'z': "],
    ['a', 'request_body', null, "JSON key 'a': "],
    ['2', 'request_body', null, "Request body field 'a': "],
], $entries, 'keys in insertion order, duplicate key keeps first position and last value');

$t->section('walk: scalar renderings and leaf contexts');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"s": "x", "n": 1.5, "i": -7, "b": true, "z": null}'), 'request_body');
$t->same([
    ['s', 'request_body', null, "JSON key 's': "],
    ['x', 'request_body', null, "Request body field 's': "],
    ['n', 'request_body', null, "JSON key 'n': "],
    ['1.5', 'request_body', null, "Request body field 'n': "],
    ['i', 'request_body', null, "JSON key 'i': "],
    ['-7', 'request_body', null, "Request body field 'i': "],
    ['b', 'request_body', null, "JSON key 'b': "],
    ['True', 'request_body', null, "Request body field 'b': "],
    ['z', 'request_body', null, "JSON key 'z': "],
    ['None', 'request_body', null, "Request body field 'z': "],
], $entries, 'str(value) renderings, plain request_body leaf context, no suffix on the body walk');

$t->section('walk: mongo operator keys hit nosql straight from the walk');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"$where": "1==1", "user": "x"}'), 'request_body');
$t->same(true, ($entries[0][2] ?? null) === 'nosql' && str_starts_with((string) ($entries[0][3] ?? ''), "JSON operator key '\$where': matched pattern "), 'mongo operator key is a forced nosql hit with the reference trigger message');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"query": {"$gt": ""}}'), 'request_body');
$t->same(true, (function () use ($entries): bool {
    foreach ($entries as $e) {
        if (($e[2] ?? null) === 'nosql' && ($e[0] ?? null) === '$gt') {
            return true;
        }
    }

    return false;
})(), 'nested mongo operator key hits');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"$nonoperator": "x", "where": "x"}'), 'request_body');
$forced = array_filter($entries, static fn (array $e): bool => $e[2] !== null);
$t->same([], $forced, 'non-operator dollar keys and plain keys never force');

$t->section('walk: depth cap serializes compactly at frame depth 32');
$deep = '"x"';
for ($i = 0; $i < 32; $i++) {
    $deep = '{"k":' . $deep . '}';
}
$entries = JsonWalk::walkEntries(JsonWalk::parse($deep), 'request_body');
$t->same(32, count($entries), '31 key scans plus one compact serialization');
$last = $entries[count($entries) - 1];
$t->same('{"k":"x"}', $last[0], 'innermost object serialized compactly');
$t->same('request_body', $last[1], 'serialized subtree carries the walk context');
$t->same('{"k":1,"a":[1,2]}', JsonWalk::serializeCompact(JsonWalk::parse('{"k": 1, "a": [1, 2]}')), 'compact separators, insertion order');
$t->same('{"e":"a\\"b\\\\c\\u0007"}', JsonWalk::serializeCompact(JsonWalk::parse('{"e": "a\\"b\\\\c\\u0007"}')), 'json.dumps escaping: quote, backslash, C0 control');

$t->section('pipeline: mongo operator key in a JSON body detected');
$t->same(true, blocked($check, '{"$where": "malicious", "user": "benign"}', JSON_CT), '$where key blocks');
$t->same(true, blocked($check, '{"login": {"$ne": null}}', JSON_CT), 'nested $ne key blocks');
$t->same(false, blocked($check, '{"$nonoperator": "benign", "where": "benign"}', JSON_CT), 'non-operator keys pass');
$t->same(false, blocked($check, '{"user": "benign", "count": 3}', JSON_CT), 'benign JSON passes');

$t->section('pipeline: sqli in a JSON string leaf detected');
$t->same(true, blocked($check, '{"comment": "' . TAUTOLOGY . '"}', JSON_CT), 'sqli string leaf blocks');
$t->same(true, blocked($check, '{"query": {"$regex": "^(\'; DROP TABLE users;--)"}}', JSON_CT), 'sqli in nested leaf blocks');
$t->same(true, blocked($check, '{"\'; DROP TABLE users;--": "benign"}', JSON_CT), 'sqli in a JSON key blocks');

$t->section('pipeline: deeply nested JSON past the cap falls back cleanly');
$attackDeep = '"' . SCRIPT . '"';
for ($i = 0; $i < 40; $i++) {
    $attackDeep = '{"k":' . $attackDeep . '}';
}
$t->same(true, blocked($check, $attackDeep, JSON_CT), 'script nested 40 deep detected through the cap serialization');
$benignDeep = '"x"';
for ($i = 0; $i < 40; $i++) {
    $benignDeep = '{"k":' . $benignDeep . '}';
}
$t->same(false, blocked($check, $benignDeep, JSON_CT), 'benign 40-deep JSON stays clean');
$t->same(false, blocked($check, str_repeat('[', 600) . str_repeat(']', 600), JSON_CT), 'past the parser depth cap: no crash, blob stays clean');

$t->section('pipeline: JSON content-type variants route through the walk');
$t->same(true, blocked($check, '{"$where": "x"}', LD_JSON_CT), 'ld+json content type walks');
$t->same(true, blocked($check, '{"$where": "x"}', 'text/json; charset=utf-8'), 'text/json content type walks');

$t->section('pipeline: malformed or scalar JSON falls back to the blob scan');
$t->same(true, blocked($check, '{"comment": "' . TAUTOLOGY . '"', JSON_CT), 'truncated JSON blob still detects');
$t->same(true, blocked($check, '"' . TAUTOLOGY . '"', JSON_CT), 'scalar string root scans as the raw blob');
$t->same(true, blocked($check, TAUTOLOGY, JSON_CT), 'non-JSON body with a json content type scans as the blob');

$t->section('pipeline: JSON in a query param walks leaves with the suffix');
$t->same(true, blockedQuery($check, '{"url": "/default.asp"}'), 'recon probe in a query JSON leaf blocks');
$t->same(true, blockedQuery($check, '{"$where": "1==1"}'), 'mongo operator key in a query JSON blocks');
$t->same(true, blockedQuery($check, '{"comment": "' . TAUTOLOGY . '"}'), 'sqli in a query JSON leaf blocks');
$t->same(false, blockedQuery($check, '{"url": "default"}'), 'bare word in a query JSON leaf stays innocent');
$t->same(false, blockedQuery($check, 'plain query value'), 'non-JSON query value scans as itself');

$t->section('pipeline: JSON in a header walks leaves with the suffix');
$t->same(true, blockedHeader($check, '{"h": "' . SCRIPT . '"}'), 'xss in a header JSON leaf blocks');
$t->same(true, blockedHeader($check, '{"$where": "1==1"}'), 'mongo operator key in a header JSON blocks');
$t->same(false, blockedHeader($check, '{"h": "benign trace"}'), 'benign header JSON passes');

$t->section('walk: embedded walks suffix recursively for string leaves that re-parse');
$formField = '{"a": "{\\"b\\": \\"' . SCRIPT . '\\"}"}';
$entries = JsonWalk::walkEntries(JsonWalk::parse($formField), 'request_body:form_field:embedded_json');
$contexts = array_map(static fn (array $e): string => $e[1], $entries);
$t->same(true, in_array('request_body:form_field:embedded_json:embedded_json', $contexts, true), 're-parsed leaf walks with a second suffix');
$values = array_map(static fn (array $e): string => $e[0], $entries);
$t->same(true, in_array(SCRIPT, $values, true), 'script inside the re-parsed leaf is scanned');
$t->same(true, in_array('request_body', $contexts, true), 'walk keys always scan as request_body');

$t->section('walk: clean-parse fall-through rescans the raw leaf string');
$inner = str_replace('"', '\\"', '{"a": "' . SCRIPT . '", "a": "safe"}');
$rawLeaf = '{"a": "' . SCRIPT . '", "a": "safe"}';
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"outer": "' . $inner . '"}'), 'request_body:form_field:embedded_json');
$values = array_map(static fn (array $e): string => $e[0], $entries);
$t->same(true, in_array($rawLeaf, $values, true), 'raw leaf string scans after a clean nested walk');
$rawLeafEntry = $entries[array_search($rawLeaf, $values, true)];
$t->same('request_body:form_field:embedded_json', $rawLeafEntry[1], 'raw leaf rescans with the walk context, not the nested suffix');
$contexts = array_map(static fn (array $e): string => $e[1], $entries);
$t->same(true, in_array('request_body:form_field:embedded_json:embedded_json', $contexts, true), 'nested leaves still carry the second suffix');
$t->same(true, in_array('safe', $values, true), 'nested leaves still scan');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"outer": "plain"}'), 'request_body:form_field:embedded_json');
$values = array_map(static fn (array $e): string => $e[0], $entries);
$t->same(2, count($entries), 'non-parsing leaf keeps the single plain entry');

$t->section('pipeline: payload confined to structural text one nesting level down detects');
$nested = '{"outer": "' . str_replace('"', '\\"', '{"a": "' . SCRIPT . '", "a": "safe"}') . '"}';
$t->same(true, blocked($check, 'data=' . $nested, 'application/x-www-form-urlencoded'), 'duplicate-key remnant in a nested form leaf still blocks');
$multipartBody = "--B0\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n" . $nested . "\r\n--B0--\r\n";
$t->same(true, blocked($check, $multipartBody, 'multipart/form-data; boundary=B0'), 'duplicate-key remnant in a nested multipart leaf still blocks');
$t->same(true, blockedHeader($check, $nested), 'duplicate-key remnant in a header JSON still blocks');

$t->section('body routing: json content types walk, others keep the blob');
$entries = BodyFormScan::bodyScanEntries('{"url": "/default.asp"}', JSON_CT, 16);
$contexts = array_map(static fn (array $e): string => $e[1], $entries);
$t->same(false, in_array('request_body:embedded_json', $contexts, true), 'body JSON leaves never carry the suffix');
$t->same(true, in_array('/default.asp', array_map(static fn (array $e): string => $e[0], $entries), true), 'leaf value present');
$entries = BodyFormScan::bodyScanEntries('{"url": "x"}', 'text/plain', 16);
$t->same([['{"url": "x"}', 'request_body', null, '']], $entries, 'non-json content types scan as the one raw body');

$t->section('walk: excluded keys skip their whole subtree');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"secret": {"a": "' . SCRIPT . '"}, "ok": 1}'), 'request_body', ['secret' => true]);
$values = array_map(static fn (array $e): string => $e[0], $entries);
$t->same(false, in_array(SCRIPT, $values, true), 'excluded key subtree never scans');
$t->same(false, in_array('a', $values, true), 'excluded key descendants never scan');
$t->same(true, in_array('ok', $values, true), 'non-excluded siblings still scan');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"$where": "1==1", "secret": 1}'), 'request_body', ['secret' => true]);
$t->same('nosql', $entries[0][2] ?? null, 'mongo operator key outside the excluded subtree still reports');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"$where": "1==1"}'), 'request_body', ['$where' => true]);
$t->same([], $entries, 'exclusion is checked before the mongo-operator registry');
$inner = str_replace('"', '\\"', '{"secret": "' . SCRIPT . '"}');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"outer": "' . $inner . '"}'), 'request_body:form_field:embedded_json', ['secret' => true]);
$values = array_map(static fn (array $e): string => $e[0], $entries);
$t->same(false, in_array(SCRIPT, $values, true), 'exclusion threads into re-parsed leaf walks');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"Note": "x"}'), 'request_body', ['note' => true]);
$values = array_map(static fn (array $e): string => $e[0], $entries);
$t->same(false, in_array('Note', $values, true), 'keys compare lowercased against verbatim entries');
$entries = JsonWalk::walkEntries(JsonWalk::parse('{"note": "x"}'), 'request_body', ['Note' => true]);
$t->same(2, count($entries), 'entries never lowercase against the exclusion set');

$t->section('json walk: depth cap and compact serialization');

// An object nested past the depth cap serializes as one compact entry.
$deep = '';
for ($i = 0; $i < 40; $i++) {
    $deep .= '{"n":';
}
$deep .= '"bottom"';
$deep .= str_repeat('}', 40);
$deepEntries = JsonWalk::walkEntries(JsonWalk::parse($deep), 'request_body');
$capped = array_values(array_filter(
    $deepEntries,
    static fn (array $e): bool => str_starts_with($e[0], '{"n":') && str_contains($e[0], '"bottom"')
));
$t->same(1, count($capped), 'a deep chain walks until the cap and serializes the rest compactly');

$t->same('{}', JsonWalk::serializeCompact(json_decode('{}')), 'an empty object serializes to braces');
$t->same('[]', JsonWalk::serializeCompact([]), 'an empty array serializes to brackets');
$t->same('true', JsonWalk::serializeCompact(true), 'a boolean serializes lowercase');
$t->same('false', JsonWalk::serializeCompact(false), 'false serializes lowercase');
$t->same('null', JsonWalk::serializeCompact(null), 'null serializes bare');
$t->same('1.5', JsonWalk::serializeCompact(1.5), 'a float serializes shortest round-trip');
$t->same('"a\\nb"', JsonWalk::serializeCompact("a\nb"), 'a newline escapes');
$t->same('"a\\rb"', JsonWalk::serializeCompact("a\rb"), 'a carriage return escapes');
$t->same('"a\\tb"', JsonWalk::serializeCompact("a\tb"), 'a tab escapes');
$t->same('"a\\bb"', JsonWalk::serializeCompact("a\x08b"), 'a backspace escapes');
$t->same('"a\\fb"', JsonWalk::serializeCompact("a\x0cb"), 'a form feed escapes');
$t->same('"a\\u0001b"', JsonWalk::serializeCompact("a\x01b"), 'other controls escape as unicode');
$t->same('"a\'\\"b"', JsonWalk::serializeCompact("a'\"b"), 'quotes and backslashes escape');

echo "\npassed={$t->passed} failed={$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);

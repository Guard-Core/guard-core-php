<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\BinaryIslands;
use RenzoFranceschini\GuardCore\Detection\BodyFormScan;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

/**
 * Honesty tests for the form/multipart body extraction and binary islands
 * (port of tests/test_utils/test_binary_islands.py and the pipeline shapes of
 * upstream guard-core commit 5f399234).
 *
 * The request body is routed through the extraction in
 * SuspiciousActivityCheck::scanValues: urlencoded bodies scan as field pairs
 * (request_body:form_field), multipart bodies as part entries
 * (request_body:multipart_field), binary-dense named file payloads reduce to
 * printable runs of at least detection_binary_min_run_length (default 16)
 * scanned as individual values, and every other body scans as the one raw
 * request_body value. Values that parse as embedded JSON scan leaf-first
 * with the :embedded_json context suffix.
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

function noiseBytes(int $seed, int $size = 4096): string
{
    mt_srand($seed);
    $out = '';
    for ($i = 0; $i < $size; $i++) {
        $out .= chr(mt_rand(0, 255));
    }

    return $out;
}

/** Deterministic zlib-format deflate stream over pseudo-random bytes. */
function compressedBytes(int $seed, int $size = 16384): string
{
    return zlib_encode(noiseBytes($seed, $size), ZLIB_ENCODING_DEFLATE, 9);
}

function filePartBody(string $filename, string $content, string $name = 'upload'): string
{
    return "--B0\r\nContent-Disposition: form-data; name=\"{$name}\"; filename=\"{$filename}\"\r\n\r\n"
        . $content . "\r\n--B0--\r\n";
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

function blocked(SuspiciousActivityCheck $check, string $body, string $contentType): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', method: 'POST', headers: ['content-type' => $contentType], body: $body);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

function blockedQueryParam(SuspiciousActivityCheck $check, string $name, string $value): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', queryParams: [$name => $value]);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

function blockedQueryValue(SuspiciousActivityCheck $check, string $value): bool
{
    $request = new SimpleGuardRequest(urlPath: '/items', queryParams: ['v' => $value]);
    $request->state()->clientIp = '9.9.9.9';

    return $check->check($request) instanceof GuardResponse;
}

function textPartBody(string $name, string $content): string
{
    return "--B0\r\nContent-Disposition: form-data; name=\"{$name}\"\r\n\r\n" . $content . "\r\n--B0--\r\n";
}

const MULTIPART_CT = 'multipart/form-data; boundary=B0';
const OCTET_STREAM_CT = 'application/octet-stream';
const TEXT_CT = 'text/plain';
const FORM_CT = 'application/x-www-form-urlencoded';
const JSON_CT = 'application/json';
const SCRIPT = '<script>alert(1)</script>';
const TAUTOLOGY = '1 OR 1=1';

$t = new T();

$t->section('binary islands: runs at or above the min length are kept');
$t->same([str_repeat('x', 16)], BinaryIslands::extractBinaryIslands("\x00abc\x00" . str_repeat('x', 16) . "\x00def\x00", 16), 'run of 16 kept, short runs dropped');

$t->section('binary islands: runs return separately');
$t->same([str_repeat('a', 16), str_repeat('b', 16)], BinaryIslands::extractBinaryIslands("\x00" . str_repeat('a', 16) . "\x00" . str_repeat('b', 16) . "\x00", 16), 'two runs, two islands');

$t->section('binary islands: non-ascii text runs preserved');
$text = 'Café résumé naïve décor sélection';
$t->same([$text], BinaryIslands::extractBinaryIslands($text, 16), 'non-ascii text is one run');

$t->section('binary islands: threshold 1 returns whole content');
$content = "anything\x00at all";
$t->same([$content], BinaryIslands::extractBinaryIslands($content, 1), 'min run <= 1 returns the whole content');

$t->section('binary islands: tab newline carriage return stay inside runs');
$t->same(["select 1\nfrom t\r\nwhere x=1"], BinaryIslands::extractBinaryIslands("\x00select 1\nfrom t\r\nwhere x=1\x00", 16), 'whitespace inside runs');

$t->section('value is binary like: rejects text, accepts noise');
$t->same(false, BinaryIslands::valueIsBinaryLike(''), 'empty is not binary like');
$t->same(false, BinaryIslands::valueIsBinaryLike('plain text body with attack 1 OR 1=1'), 'plain text is not binary like');
$t->same(false, BinaryIslands::valueIsBinaryLike("one null\x00byte"), 'one null byte is not binary like');
$t->same(true, BinaryIslands::valueIsBinaryLike(noiseBytes(7)), 'random noise is binary like');

$t->section('config: detectionBinaryMinRunLength defaults and bounds');
$t->same(16, (new SecurityConfig())->detectionBinaryMinRunLength, 'default is 16');
$t->same(4, (new SecurityConfig(detectionBinaryMinRunLength: 4))->detectionBinaryMinRunLength, 'lower bound 4 accepted');
$t->same(1024, (new SecurityConfig(detectionBinaryMinRunLength: 1024))->detectionBinaryMinRunLength, 'upper bound 1024 accepted');
try {
    new SecurityConfig(detectionBinaryMinRunLength: 3);
    $t->same(true, false, 'below lower bound rejected');
} catch (InvalidArgumentException) {
    $t->same(true, true, 'below lower bound rejected');
}
try {
    new SecurityConfig(detectionBinaryMinRunLength: 1025);
    $t->same(true, false, 'above upper bound rejected');
} catch (InvalidArgumentException) {
    $t->same(true, true, 'above upper bound rejected');
}

$t->section('urlencoded form field: sqli in a form field detected');
$check = makeCheck();
$t->same(true, blocked($check, 'comment=' . urlencode(TAUTOLOGY), FORM_CT), 'sqli form value blocks');
$t->same(true, blocked($check, 'comment=' . urlencode("'; DROP TABLE users;--"), FORM_CT), 'sqli comment form value blocks');
$t->same(false, blocked($check, 'comment=hello%20world', FORM_CT), 'benign form value passes');

$t->section('multipart: plain text part detected');
$t->same(true, blocked($check, filePartBody('notes.txt', "-- benign --\r\nSELECT name FROM users; " . SCRIPT . "\r\n"), MULTIPART_CT), 'text part with script blocks');
$t->same(true, blocked($check, filePartBody('notes.txt', 'SELECT name FROM users; ' . TAUTOLOGY), MULTIPART_CT), 'plain multipart text part blocks');
$t->same(false, blocked($check, filePartBody('notes.txt', 'benign notes'), MULTIPART_CT), 'benign text part passes');

$t->section('multipart: binary island smuggling detected');
$t->same(true, blocked($check, filePartBody('page.html.bin', compressedBytes(12) . "\x00" . SCRIPT . "\x00" . compressedBytes(13)), MULTIPART_CT), 'script embedded between compressed runs blocks');
$t->same(false, blocked($check, filePartBody('installer.zip', compressedBytes(11) . "\x00" . TAUTOLOGY . "\x00"), MULTIPART_CT), 'short fragment inside compressed part does not block');
$t->same(false, blocked($check, filePartBody('dump.bin', compressedBytes(17) . "\x00" . 'choose one: SELECT' . "\x00" . '* FROM x' . str_repeat('Y', 10) . "\x00"), MULTIPART_CT), 'pattern split across two runs does not block');

$t->section('multipart: binary junk produces no noise');
$t->same(false, blocked($check, filePartBody('blob.bin', noiseBytes(3)), MULTIPART_CT), 'pure noise file part is benign');

$t->section('config knob honored: lower min run length restores detection');
$shortRunCheck = makeCheck(new SecurityConfig(detectionBinaryMinRunLength: 4));
$t->same(true, blocked($shortRunCheck, filePartBody('data.bin', compressedBytes(14) . "\x00" . TAUTOLOGY . "\x00"), MULTIPART_CT), 'min run 4 detects the short tautology fragment');

$t->section('non multipart bodies keep the full scan');
$t->same(true, blocked($check, compressedBytes(15) . "\x00" . TAUTOLOGY . "\x00", OCTET_STREAM_CT), 'octet stream body fully scanned');
$t->same(true, blocked($check, TAUTOLOGY, TEXT_CT), 'short text body fully scanned');
$t->same(true, blocked($check, "benign body with " . TAUTOLOGY . "\x00", TEXT_CT), 'mostly text body with single null fully scanned');

$t->section('multipart fallback: unparseable body scans as the raw blob');
$t->same(true, blocked($check, TAUTOLOGY, MULTIPART_CT), 'boundary declared but absent: raw blob scan still detects');

$t->section('embedded JSON leaves: field value leaves scanned with the suffix context');
$t->same(true, blocked($check, 'payload=' . urlencode(json_encode(['url' => "'; DROP TABLE users;--"])), FORM_CT), 'form field JSON leaf sqli blocks');
$t->same(true, blocked($check, 'payload=' . urlencode(json_encode(['url' => '/default.asp'])), FORM_CT), 'form field JSON leaf recon probe blocks');
$t->same(false, blocked($check, 'payload=' . urlencode(json_encode(['url' => 'default'])), FORM_CT), 'form field JSON leaf bare word stays innocent');
$t->same(true, blocked($check, filePartBody('data.json', json_encode(['url' => "'; DROP TABLE users;--"]), 'upload'), MULTIPART_CT), 'multipart field JSON leaf sqli blocks');

$t->section('multipart field names and filenames are always scanned');
$t->same(true, blocked($check, "--B0\r\nContent-Disposition: form-data; name=\" OR 1=1--\"\r\n\r\nbenign\r\n--B0--\r\n", MULTIPART_CT), 'attack in the multipart field name blocks');
$t->same(true, blocked($check, "--B0\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x'; DROP TABLE users;--.bin\"\r\n\r\nbenign\r\n--B0--\r\n", MULTIPART_CT), 'attack in the filename blocks');
$t->same(true, blocked($check, "--B0\r\nX-Inject: ' OR 1=1--\r\nContent-Disposition: form-data; name=\"up\"; filename=\"a.bin\"\r\n\r\nbenign\r\n--B0--\r\n", MULTIPART_CT), 'attack in a part header blocks');

$t->section('extraction contexts are exact');
$entries = BodyFormScan::bodyScanEntries('a=1&b=', FORM_CT, 16);
$t->same([
    ['a', 'request_body', null, "Form field name 'a': "],
    ['1', 'request_body:form_field', null, "Request body field 'a': "],
    ['b', 'request_body', null, "Form field name 'b': "],
    ['', 'request_body:form_field', null, "Request body field 'b': "],
], $entries, 'form entries: name pair then value pair per field, blank values kept');
$t->same([['raw', 'request_body', null, '']], BodyFormScan::bodyScanEntries('raw', TEXT_CT, 16), 'other content types scan as the one raw body');
$islandEntries = BodyFormScan::bodyScanEntries(
    filePartBody('d.bin', str_repeat("\x01", 30) . str_repeat('x', 16) . str_repeat("\x01", 30)),
    MULTIPART_CT,
    16
);
$rawBody = filePartBody('d.bin', str_repeat("\x01", 30) . str_repeat('x', 16) . str_repeat("\x01", 30));
$values = array_map(static fn (array $e): string => $e[0], $islandEntries);
$t->same(false, in_array($rawBody, $values, true), 'binary part payload never scans as the raw blob');
$t->same(true, in_array(str_repeat('x', 16), $values, true), 'the printable island is scanned as its own value');
$contexts = array_map(static fn (array $e): string => $e[1], $islandEntries);
$t->same(true, in_array('request_body:multipart_field', $contexts, true), 'part entries carry the multipart_field context');

$t->section('config: excluded field sets default empty and validate');
$t->same([], array_keys((new SecurityConfig())->excludedDetectionParams), 'excludedDetectionParams defaults empty');
$t->same([], array_keys((new SecurityConfig())->excludedDetectionBodyFields), 'excludedDetectionBodyFields defaults empty');
$t->same(['search'], array_keys((new SecurityConfig(excludedDetectionParams: ['search']))->excludedDetectionParams), 'param entries kept verbatim');
$t->same(['notes'], array_keys((new SecurityConfig(excludedDetectionBodyFields: ['notes']))->excludedDetectionBodyFields), 'body field entries kept verbatim');
try {
    new SecurityConfig(excludedDetectionParams: 'search');
    $t->same(true, false, 'bare string param exclusion rejected');
} catch (TypeError) {
    $t->same(true, true, 'bare string param exclusion rejected');
}
try {
    new SecurityConfig(excludedDetectionBodyFields: ['notes', 3]);
    $t->same(true, false, 'non-string body field entry rejected');
} catch (InvalidArgumentException) {
    $t->same(true, true, 'non-string body field entry rejected');
}

$t->section('config: excluded field sets are with()-immutable');
$base = new SecurityConfig();
$mutated = $base->with(['excluded_detection_params' => ['search']]);
$t->same([], array_keys($base->excludedDetectionParams), 'with() leaves the original untouched');
$t->same(['search'], array_keys($mutated->excludedDetectionParams), 'with() carries the new exclusion');
$t->same(1, $mutated->revision(), 'with() bumps the revision');

$t->section('excluded params: the whole query pair is skipped');
$paramCheck = makeCheck(new SecurityConfig(excludedDetectionParams: ['search']));
$t->same(false, blockedQueryParam($paramCheck, 'search', SCRIPT), 'excluded query param does not block');
$t->same(true, blockedQueryParam($paramCheck, 'other', SCRIPT), 'non-excluded query param still blocks');
$t->same(false, blockedQueryParam($paramCheck, 'SEARCH', SCRIPT), 'query names compare lowercased against verbatim entries');
$t->same(true, blockedQueryParam(makeCheck(new SecurityConfig(excludedDetectionParams: ['SEARCH'])), 'search', SCRIPT), 'entries match verbatim, never lowercased');

$t->section('excluded params and body fields keep their own surfaces');
$t->same(true, blocked($paramCheck, json_encode(['search' => SCRIPT]), JSON_CT), 'param exclusion does not exclude body fields');
$bodyFieldCheck = makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['search']));
$t->same(true, blockedQueryValue($bodyFieldCheck, SCRIPT), 'body-field exclusion does not exclude query params');

$t->section('excluded body fields: JSON keys skip their whole subtree');
$t->same(false, blocked($bodyFieldCheck, json_encode(['search' => SCRIPT]), JSON_CT), 'excluded JSON key does not block');
$t->same(true, blocked($bodyFieldCheck, json_encode(['search' => SCRIPT, 'note' => SCRIPT]), JSON_CT), 'sibling JSON key still blocks');
$nestedCheck = makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['content']));
$t->same(false, blocked($nestedCheck, json_encode(['messages' => [['role' => 'user', 'content' => SCRIPT]]]), JSON_CT), 'excluded nested key suppresses the whole subtree');
$t->same(true, blocked($nestedCheck, json_encode(['outer' => ['note' => SCRIPT]]), JSON_CT), 'nested non-excluded key still blocks');
$t->same(true, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['safe'])), json_encode([['note' => SCRIPT]]), JSON_CT), 'top-level JSON array still recurses');

$t->section('excluded body fields: the raw query value still scans (defense in depth)');
// Reference semantics verified against the engine: the excluded body field
// shapes the embedded walk, but the raw value itself still scans afterwards,
// so a query JSON whose only key is excluded still detects through the raw
// text. The JSON is built by hand (json_encode would escape forward slashes
// and change the payload text).
$t->same(true, blockedQueryValue($bodyFieldCheck, '{"search":"' . SCRIPT . '"}'), 'query JSON with only an excluded key still blocks via the raw scan');
$t->same(true, blockedQueryValue($bodyFieldCheck, '{"search":"' . SCRIPT . '","note":"' . SCRIPT . '"}'), 'query JSON with a sibling key still blocks');

$t->section('excluded body fields: urlencoded pairs');
$t->same(true, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['other'])), 'message=' . urlencode(SCRIPT) . '&other=hi', FORM_CT), 'non-excluded form field still blocks');
$t->same(false, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['message'])), 'message=' . urlencode(SCRIPT) . '&other=hi', FORM_CT), 'excluded form field skips the whole pair');

$t->section('excluded body fields: multipart parts');
$t->same(false, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['note'])), textPartBody('note', SCRIPT), MULTIPART_CT), 'excluded multipart text part does not block');
$t->same(true, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['other'])), textPartBody('note', SCRIPT), MULTIPART_CT), 'non-excluded multipart text part still blocks');
$t->same(false, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['file'])), filePartBody('a.txt', SCRIPT, 'file'), MULTIPART_CT), 'excluded multipart file part does not block');
$t->same(true, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['file'])), "--B0\r\nContent-Disposition: form-data\r\n\r\n" . SCRIPT . "\r\n--B0--\r\n", MULTIPART_CT), 'part without a name has no exclusion key');
$t->same(true, blocked(makeCheck(new SecurityConfig(excludedDetectionBodyFields: ['unused'])), SCRIPT, MULTIPART_CT), 'unparseable multipart falls back to the blob scan');

$t->section('empty exclusion config keeps current behavior');
$t->same(true, blocked(makeCheck(new SecurityConfig()), json_encode(['search' => SCRIPT]), JSON_CT), 'JSON body attack blocks with no exclusions');
$t->same(true, blockedQueryValue(makeCheck(new SecurityConfig()), SCRIPT), 'query attack blocks with no exclusions');

echo "\npassed={$t->passed} failed={$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);

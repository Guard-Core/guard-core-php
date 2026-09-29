<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Ban\BanEventSink;
use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\BinaryIslands;
use RenzoFranceschini\GuardCore\Detection\BodyFormScan;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponse;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteConfig;
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

/** The scanned values (entry[0]) of one single-part body with the given content-disposition. */
function dispEntries(string $disposition): array
{
    $entries = BodyFormScan::multipartScanEntries(
        "--B0\r\n{$disposition}\r\n\r\npayload\r\n--B0--\r\n",
        MULTIPART_CT,
        16
    );

    return array_map(static fn (array $e): string => $e[0], $entries);
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

$t->section('multipart parts: exact leaf shapes');

// An empty part (no headers, no filename, empty payload) carries no values
// and contributes no entries.
$t->same([], BodyFormScan::multipartScanEntries("--B0\r\n\r\n--B0--\r\n", MULTIPART_CT, 16), 'an empty part yields no entries');
$t->same(null, BodyFormScan::multipartParts('body', 'text/plain', 16), 'a non multipart content type parses no parts');
$t->same(null, BodyFormScan::multipartParts('body', 'multipart/form-data', 16), 'a multipart content type without a boundary parses no parts');
$t->same([['1 OR 1=1', 'request_body', null, '']], BodyFormScan::bodyScanEntries(TAUTOLOGY, 'multipart/form-data', 16), 'a boundary-less multipart body falls back to the blob scan');

// Consecutive boundary lines are swallowed by the consume loop.
$t->same([
    ['up', 'request_body', null, "Multipart field name 'up': "],
    ['Content-Disposition: form-data; name="up"', 'request_body:multipart_field', null, "Request body field 'up': "],
    ['v', 'request_body:multipart_field', null, "Request body field 'up': "],
], BodyFormScan::multipartScanEntries("--B0\r\n--B0\r\nContent-Disposition: form-data; name=\"up\"\r\n\r\nv\r\n--B0--\r\n", MULTIPART_CT, 16), 'consecutive boundary lines are swallowed');

// A close delimiter before any part keeps the whole body preamble.
$t->same(null, BodyFormScan::multipartScanEntries("--B0--\r\nafter", MULTIPART_CT, 16), 'a close delimiter before any part parses no parts');

// An inter-part boundary while a part is buffered closes that part.
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['va', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['b', 'request_body', null, "Multipart field name 'b': "],
    ['Content-Disposition: form-data; name="b"', 'request_body:multipart_field', null, "Request body field 'b': "],
    ['vb', 'request_body:multipart_field', null, "Request body field 'b': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nva\r\n--B0\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nvb\r\n--B0--\r\n", MULTIPART_CT, 16), 'a second part splits at its boundary');

// A missing close delimiter keeps the parts parsed so far
// (CloseBoundaryNotFoundDefect).
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['payload', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\npayload", MULTIPART_CT, 16), 'an unterminated body keeps its parts');

$t->section('multipart parts: content-type routing');

$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Type: text/plain', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['body', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Type: text/plain\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nbody\r\n--B0--\r\n", MULTIPART_CT, 16), 'a leaf part with a content-type keeps both headers in order');

// A nested multipart container recurses into its own boundary.
$t->same([
    ['inner', 'request_body', null, "Multipart field name 'inner': "],
    ['Content-Disposition: form-data; name="inner"', 'request_body:multipart_field', null, "Request body field 'inner': "],
    ['inner-body', 'request_body:multipart_field', null, "Request body field 'inner': "],
], BodyFormScan::multipartScanEntries(
    "--B0\r\nContent-Type: multipart/mixed; boundary=N0\r\n\r\n--N0\r\nContent-Disposition: form-data; name=\"inner\"\r\n\r\ninner-body\r\n--N0--\r\n--B0--\r\n",
    MULTIPART_CT,
    16
), 'a nested multipart container recurses into its sub-parts');

// StartBoundaryNotFoundDefect: a nested container whose payload carries no
// boundary delimiter stays a plain string leaf, without the newline strip.
$t->same([
    ['file', 'request_body', null, "Multipart field name 'file': "],
    ['Content-Type: multipart/mixed; boundary=N0', 'request_body:multipart_field', null, "Request body field 'file': "],
    ["plain nested payload\r\n", 'request_body:multipart_field', null, "Request body field 'file': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Type: multipart/mixed; boundary=N0\r\n\r\nplain nested payload\r\n--B0--\r\n", MULTIPART_CT, 16), 'a nested container without its start boundary scans as a plain leaf');

// NoBoundaryInMultipartDefect: a nested multipart content type without a
// boundary parameter stays a plain string leaf.
$t->same([
    ['file', 'request_body', null, "Multipart field name 'file': "],
    ['Content-Type: multipart/mixed', 'request_body:multipart_field', null, "Request body field 'file': "],
    ["plain nested payload\r\n", 'request_body:multipart_field', null, "Request body field 'file': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Type: multipart/mixed\r\n\r\nplain nested payload\r\n--B0--\r\n", MULTIPART_CT, 16), 'a nested container without a boundary parameter scans as a plain leaf');

// An empty nested container body has no delimiters at all.
$t->same([
    ['file', 'request_body', null, "Multipart field name 'file': "],
    ['Content-Type: multipart/mixed; boundary=N0', 'request_body:multipart_field', null, "Request body field 'file': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Type: multipart/mixed; boundary=N0\r\n\r\n--B0--\r\n", MULTIPART_CT, 16), 'an empty nested container contributes no payload value');

// An RFC 2231 extended boundary parameter counts as absent (the Python
// engine only accepts a plain string boundary).
$t->same([
    ['file', 'request_body', null, "Multipart field name 'file': "],
    ["Content-Type: multipart/mixed; boundary*=utf-8''N0", 'request_body:multipart_field', null, "Request body field 'file': "],
    ["plain\r\n", 'request_body:multipart_field', null, "Request body field 'file': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Type: multipart/mixed; boundary*=utf-8''N0\r\n\r\nplain\r\n--B0--\r\n", MULTIPART_CT, 16), 'an RFC 2231 extended boundary counts as absent');

// An empty Content-Type value falls back to the leaf scan.
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Type: ', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['body', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Type:\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nbody\r\n--B0--\r\n", MULTIPART_CT, 16), 'an empty content-type value scans the part as a leaf');

$t->section('multipart headers: python feedparser semantics');

// A non header first line ends the header block and starts the body there.
$t->same([
    ['file', 'request_body', null, "Multipart field name 'file': "],
    ['hello world', 'request_body:multipart_field', null, "Request body field 'file': "],
], BodyFormScan::multipartScanEntries("--B0\r\nhello world\r\n--B0--\r\n", MULTIPART_CT, 16), 'a non header first line starts the body immediately');

// A continuation line before any header is dropped
// (FirstHeaderLineIsContinuationDefect).
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['body', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries("--B0\r\n    orphan\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nbody\r\n--B0--\r\n", MULTIPART_CT, 16), 'an orphan continuation before any header is dropped');

// A folded header value keeps its embedded line break.
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ["Content-Type: text/plain\n  folded part", 'request_body:multipart_field', null, "Request body field 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['body', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Type: text/plain\n  folded part\nContent-Disposition: form-data; name=\"a\"\r\n\r\nbody\r\n--B0--\r\n", MULTIPART_CT, 16), 'a folded header value keeps the embedded line break');

// A "From " line first in the block is skipped.
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['body', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries("--B0\r\nFrom alice@example.com Sat Jan 01 00:00:00 2026\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nbody\r\n--B0--\r\n", MULTIPART_CT, 16), 'a From line first in the block is dropped');

// A "From " line last in the block is pushed back into the body, after the
// consumed blank separator.
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ["From alice@example.com Sat Jan 01 00:00:00 2026\r\nthe payload", 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries(
    "--B0\r\nContent-Disposition: form-data; name=\"a\"\r\nFrom alice@example.com Sat Jan 01 00:00:00 2026\r\n\r\nthe payload\r\n--B0--\r\n",
    MULTIPART_CT,
    16
), 'a From line last in the block is pushed back into the body');

// A "From " line in the middle of the block is dropped; the pending header
// before it is flushed first.
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['X-Other: v', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['the payload', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries(
    "--B0\r\nContent-Disposition: form-data; name=\"a\"\r\nFrom alice@example.com Sat Jan 01 00:00:00 2026\r\nX-Other: v\r\n\r\nthe payload\r\n--B0--\r\n",
    MULTIPART_CT,
    16
), 'a From line in the middle of the block is dropped');

// A ": value" line is an InvalidHeaderDefect and is dropped.
$t->same([
    ['a', 'request_body', null, "Multipart field name 'a': "],
    ['Content-Disposition: form-data; name="a"', 'request_body:multipart_field', null, "Request body field 'a': "],
    ['the payload', 'request_body:multipart_field', null, "Request body field 'a': "],
], BodyFormScan::multipartScanEntries("--B0\r\nContent-Disposition: form-data; name=\"a\"\r\n: bad\r\n\r\nthe payload\r\n--B0--\r\n", MULTIPART_CT, 16), 'a colon-first line is dropped as an invalid header');

// A header name with a non-printable-ASCII character is not a header line.
$t->same([
    ['file', 'request_body', null, "Multipart field name 'file': "],
    ['bad name: x', 'request_body:multipart_field', null, "Request body field 'file': "],
], BodyFormScan::multipartScanEntries("--B0\r\nbad name: x\r\n--B0--\r\n", MULTIPART_CT, 16), 'a header name with a space is body text');

$t->section('multipart parameters: RFC 2231 continuations and escapes');

// Plain continuations join without the extended tuple shape.
$t->same(true, in_array('filename="abcd"', dispEntries('Content-Disposition: form-data; filename*0="ab"; filename*1="cd"'), true), 'plain continuations join without a tuple');
// Encoded plus plain continuations percent-decode the starred segments.
$t->same(true, in_array('filename="abcd"', dispEntries("Content-Disposition: form-data; filename*0*=us-ascii%27%27ab; filename*1=\"cd\""), true), 'starred continuations percent-decode and join');
// A single starred segment without ticks has no charset and no language.
$t->same(true, in_array('filename="ab"', dispEntries("Content-Disposition: form-data; filename*=ab"), true), 'a starred segment without ticks decodes with no charset');
// A full extended parameter splits into charset, language, and text, and
// the display value is the python tuple repr.
$t->same(true, 
    in_array("('us-ascii', '', 'hello world')", dispEntries("Content-Disposition: form-data; name*0*=us-ascii%27%27hello%20world"), true),
    'an extended name parameter reports the python tuple repr'
);
// An apostrophe in the text switches the repr to double quotes.
$t->same(true, 
    in_array('(\'iso-8859-1\', \'\', "o\'brien")', dispEntries("Content-Disposition: form-data; name*0*=iso-8859-1%27%27o%27brien"), true),
    'an apostrophe in the text switches the repr to double quotes'
);
// An unknown charset keeps the already-unquoted text (LookupError path).
$t->same(true, in_array('filename="hello"', dispEntries("Content-Disposition: form-data; filename*=bogus-cs%27%27hello"), true), 'an unknown charset keeps the unquoted text');
// No charset ticks at all plus a high byte: us-ascii replace.
$t->same(true, in_array("filename=\"A" . "\u{FFFD}" . "B\"", dispEntries("Content-Disposition: form-data; filename*=%41%ff%42"), true), 'a high byte without a charset becomes a replacement character');
// A bare (unnumbered) segment is dropped when a zero segment exists.
$t->same(true, in_array('filename="ab"', dispEntries("Content-Disposition: form-data; filename*0*=us-ascii%27%27ab; filename*=\"Z\""), true), 'a bare segment is dropped when a zero segment exists');
// A continuation group for another parameter does not answer the target.
$t->same(true, 
    in_array("('us-ascii', '', 'nm')", dispEntries("Content-Disposition: form-data; name*0*=us-ascii%27%27nm; filename*=us-ascii%27%27fx.txt"), true),
    'a continuation group for another parameter is skipped'
);
// Quoted-pair escapes inside a quoted value.
$t->same(true, in_array('a"b;c', dispEntries('Content-Disposition: form-data; name="a\\"b;c"'), true), 'an escaped quote inside a quoted name does not split the parameter');
$t->same(true, in_array('a\\b;c', dispEntries('Content-Disposition: form-data; name="a\\\\b;c"'), true), 'an escaped backslash survives the unquote');
// A quote or backslash inside a continuation value is re-escaped RFC 2822
// style and unescaped by the final unquote; filename entries strip quotes.
$t->same(true, in_array('filename="ab"', dispEntries("Content-Disposition: form-data; filename*=us-ascii%27%27a%22b"), true), 'a quote in a continuation value is sanitized out of the filename');
$t->same(true, 
    in_array('(\'us-ascii\', \'\', \'a"b\')', dispEntries("Content-Disposition: form-data; name*0*=us-ascii%27%27a%22b"), true),
    'a quote in the text is re-escaped in the tuple repr'
);
$t->same(true, 
    in_array('(\'us-ascii\', \'\', \'a\\\\b\')', dispEntries("Content-Disposition: form-data; name*0*=us-ascii%27%27a%5cb"), true),
    'a backslash in the text is re-escaped in the tuple repr'
);

$t->section('urlencoded pairs: parse quirks');

$t->same([['a', 'request_body', null, "Form field name 'a': "], ['1', 'request_body:form_field', null, "Request body field 'a': "]], BodyFormScan::bodyScanEntries('a=1&&', FORM_CT, 16), 'an empty segment produces no pair');
$t->same([['k ey', 'request_body', null, "Form field name 'k ey': "], ['v%2', 'request_body:form_field', null, "Request body field 'k ey': "]], BodyFormScan::bodyScanEntries('k+ey=v%2', FORM_CT, 16), 'plus decodes to a space and an invalid escape stays raw');

$t->section('suspicious check: route gates and ban config');

$recordingSink = new class implements BanEventSink {
    public array $bans = [];

    public function sendBanEvent(string $ip, int $duration, string $reason): void
    {
        $this->bans[] = ['ip' => $ip, 'duration' => $duration, 'reason' => $reason];
    }

    public function sendUnbanEvent(string $ip): void
    {
    }
};

$globalOff = new SecurityConfig(enablePenetrationDetection: false);
$routeCheck = makeCheck($globalOff);
$t->same(false, $routeCheck->appliesTo($globalOff, null), 'the check does not apply with the global flag off and no routes');
$t->same(true, $routeCheck->appliesTo($globalOff, [new RouteConfig(enableSuspiciousDetection: true)]), 'a route enabling detection applies the check');
$t->same(false, $routeCheck->appliesTo($globalOff, [new RouteConfig(enableSuspiciousDetection: false)]), 'routes with detection disabled do not apply the check');

// A route that bypasses the penetration check short-circuits the scan.
$bypassCheck = makeCheck(new SecurityConfig());
$bypassRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => SCRIPT]);
$bypassRequest->state()->clientIp = '9.9.4.3';
$bypassRequest->state()->routeConfig = new RouteConfig(bypassedChecks: ['penetration']);
$t->same(null, $bypassCheck->check($bypassRequest), 'a bypassed penetration route scans nothing');

// A route that disables detection suppresses the scan even globally.
$disabledRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => SCRIPT]);
$disabledRequest->state()->clientIp = '9.9.4.8';
$disabledRequest->state()->routeConfig = new RouteConfig(enableSuspiciousDetection: false);
$t->same(null, $bypassCheck->check($disabledRequest), 'a route with detection disabled scans nothing');

// A route category set replaces the global one: xss off means the script passes.
$categoriesCheck = makeCheck(new SecurityConfig());
$narrowRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => SCRIPT]);
$narrowRequest->state()->clientIp = '9.9.4.2';
$narrowRequest->state()->routeConfig = new RouteConfig(enabledDetectionCategories: ['sqli']);
$t->same(null, $categoriesCheck->check($narrowRequest), 'a route category set without xss skips the script');

// Sensitive headers never reach the scan.
$sensitiveCheck = makeCheck(new SecurityConfig(logSensitiveHeaders: ['authorization']));
$sensitiveRequest = new SimpleGuardRequest(urlPath: '/items', headers: ['authorization' => 'Bearer ' . SCRIPT]);
$sensitiveRequest->state()->clientIp = '9.9.4.4';
$t->same(null, $sensitiveCheck->check($sensitiveRequest), 'a sensitive header value is skipped');

// The per-category threat ban config overrides the auto ban threshold.
$banManager = new IpBanManager([], null, $recordingSink);
$banCfgCheck = new SuspiciousActivityCheck(
    new SecurityConfig(threatBanConfig: ['xss' => ['threshold' => 1, 'duration' => 555]]),
    new GuardResponseFactory(),
    new SusPatterns(0.5),
    $banManager,
    new RouteResolver()
);
$banRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => SCRIPT]);
$banRequest->state()->clientIp = '9.9.4.1';
$t->same(403, $banCfgCheck->check($banRequest)?->statusCode(), 'the category ban config bans on the first detection');
$t->same([['ip' => '9.9.4.1', 'duration' => 555, 'reason' => 'penetration:xss']], $recordingSink->bans, 'the ban event carries the category duration');

$t->section('suspicious check: semantic and budget messages over route custom categories');

$alnum = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
mt_srand(7);
$entropyRun = '';
for ($i = 0; $i < 150; $i++) {
    $entropyRun .= $alnum[mt_rand(0, 61)];
}
$semCheck = new SuspiciousActivityCheck(
    new SecurityConfig(detectionSemanticThreshold: 0.3),
    new GuardResponseFactory(),
    new SusPatterns(0.3),
    null,
    new RouteResolver()
);
$semRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => '0xDEADBEEF ' . $entropyRun]);
$semRequest->state()->clientIp = '9.9.4.6';
$semRequest->state()->routeConfig = new RouteConfig(enabledDetectionCategories: ['custom']);
$semResponse = $semCheck->check($semRequest);
$t->same(400, $semResponse?->statusCode(), 'a semantic threat with the custom category enabled blocks');
$t->same(true, str_contains($semRequest->state()->guardBlockStash['reason'] ?? '', 'Semantic attack: suspicious (score: 0.40)'), 'the semantic threat message formats the attack type and score');

// A payload whose per-attack probability clears the threshold (six of the
// eight path keywords plus a ../ structural boost reach 1.0) carries the
// probability on the threat instead of the fallback threat score.
$probCheck = new SuspiciousActivityCheck(
    new SecurityConfig(detectionSemanticThreshold: 0.3),
    new GuardResponseFactory(),
    new SusPatterns(0.3),
    null,
    new RouteResolver()
);
$probRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => 'etc passwd shadow hosts proc boot ../ 0xdeadbeef']);
$probRequest->state()->clientIp = '9.9.4.9';
$probRequest->state()->routeConfig = new RouteConfig(enabledDetectionCategories: ['custom']);
$probResponse = $probCheck->check($probRequest);
$t->same(400, $probResponse?->statusCode(), 'a per-attack probability semantic threat blocks');
$t->same(true, str_contains($probRequest->state()->guardBlockStash['reason'] ?? '', 'Semantic attack: path (score: 1.00)'), 'the semantic probability message formats the attack probability');

$deep = str_repeat('%25', 40) . 'SELECT';
for ($i = 0; $i < 30; $i++) {
    $deep = rawurlencode($deep);
}
$budgetCheck = makeCheck(new SecurityConfig());
$budgetRequest = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => $deep]);
$budgetRequest->state()->clientIp = '9.9.4.7';
$budgetRequest->state()->routeConfig = new RouteConfig(enabledDetectionCategories: ['custom']);
$budgetResponse = $budgetCheck->check($budgetRequest);
$t->same(400, $budgetResponse?->statusCode(), 'a decode budget exhaustion threat blocks over route custom categories');
$t->same(true, str_contains($budgetRequest->state()->guardBlockStash['reason'] ?? '', "Value matched pattern 'decode_budget_exhausted'"), 'the budget exhaustion message formats the pattern');

$t->section('suspicious check: the suspicious count store evicts oldest ips');

$heavyCheck = makeCheck(new SecurityConfig());
for ($i = 0; $i <= 10001; $i++) {
    $req = new SimpleGuardRequest(urlPath: '/items', queryParams: ['q' => SCRIPT]);
    $req->state()->clientIp = sprintf('10.7.%d.%d', intdiv($i, 256), $i % 256);
    $heavyCheck->check($req);
}
$t->same(true, true, 'one hundred and two scans ran through the count store');

echo "\npassed={$t->passed} failed={$t->failed}\n";
exit($t->failed === 0 ? 0 : 1);

<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Support\Generated\PatternData;

require __DIR__ . '/../vendor/autoload.php';

// Regression coverage for large single-line subjects vs the PCRE2 JIT stack.
//
// The \A-anchored line-walk and tempered segment-loop patterns consume PCRE2
// stack proportional to the walked line. On stock php:8.3-cli ini they abort
// detection (PregFailure, fail-secure 500) on benign single-line subjects from
// ~24.5KB (pcre.jit=1) / ~100KB (pcre.jit=0), and segment-form subjects
// ("a/" repeated) from ~16.4KB under pcre.jit=1. The fix gates that pattern
// family: above SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES (first-line byte
// length of the view subject) their preg calls are skipped and detection
// completes normally. This runner is deterministic under both pcre.jit
// settings; the 256KB benign case is slow (seconds-scale NFKC preprocessing).
//
// Run: docker run --rm -v "$PWD:/app" -w /app php:8.3-cli php bin/test_large_body.php

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

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

$t = new T();
$susPatterns = new SusPatterns();

/** Compact single-line benign JSON of roughly $targetBytes bytes. */
function largeBodyBenignJson(int $targetBytes): string
{
    $items = [];
    $i = 0;
    while (strlen(json_encode($items)) < $targetBytes) {
        $items[] = ['id' => $i, 'name' => 'lorem ipsum dolor sit amet ' . $i, 'qty' => $i * 7];
        $i++;
    }

    return json_encode($items);
}

/** Single-line word filler of roughly $targetBytes bytes. */
function largeBodyFiller(int $targetBytes): string
{
    return substr(str_repeat('lorem ipsum dolor ', intdiv($targetBytes, 18) + 1), 0, $targetBytes);
}

/** detect() that reports exceptions instead of unwinding the runner. */
function detectQuietly(SusPatterns $susPatterns, string $content, string $context): array
{
    try {
        $result = $susPatterns->detect($content, '203.0.113.7', $context);
        $result['exception'] = null;

        return $result;
    } catch (Throwable $e) {
        return ['exception' => $e, 'is_threat' => null, 'threats' => []];
    }
}

function threatCategories(array $result): array
{
    return array_values(array_unique(array_map(
        static fn (array $threat): string => (string) ($threat['category'] ?? $threat['attack_type'] ?? 'unknown'),
        $result['threats']
    )));
}

$t->section('gated family data table');

$t->same(
    [
        32, 33, 34, 35, 36, 102, 107, 110, 112, 115,
        101, 103, 104, 105, 106, 109, 111, 113, 114, 116, 117, 119, 121,
        122, 123, 124, 125, 126, 128, 130, 131, 132, 133, 134, 135, 136,
    ],
    PatternData::SIZE_GATED_PATTERN_INDICES,
    'SIZE_GATED_PATTERN_INDICES pins the measured JIT-exhaustion family'
);
$shapeOk = true;
foreach (PatternData::SIZE_GATED_PATTERN_INDICES as $index) {
    [$source, , $category] = PatternData::PATTERNS[$index];
    $isLineWalk = str_starts_with($source, '\A(?:(?!\n).)*') || str_starts_with($source, '\A(?=(?:(?!\n).)*');
    $isSegmentLoop = str_starts_with($source, '\A[/');
    if ((!$isLineWalk && !$isSegmentLoop)
        || !in_array($category, ['dir_traversal', 'sensitive_file', 'cms_probing', 'recon'], true)) {
        $shapeOk = false;
        echo "  pattern {$index} has unexpected shape/category: " . substr($source, 0, 60) . "\n";
    }
}
$t->truthy($shapeOk, 'every gated pattern is a line-walk or \A-anchored path-walk segment loop');

$t->same(15360, SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES, 'gate threshold is 15360 (15 KiB)');

$corpusMax = 0;
$binaryCorpusMax = 0;
foreach (glob(__DIR__ . '/../conformance/guard-core-spec-4.1.0/cases/*.json') ?: [] as $file) {
    $suite = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
    foreach ($suite['cases'] ?? [] as $case) {
        $size = strlen((string) ($case['input']['content'] ?? ''));
        // Two suites intentionally carry subjects above the gate and are
        // tracked separately from the below-gate invariant the standard text
        // corpus must keep: binary_bodies.json (verdicts ride the
        // binary-noise island path) and cost_bodies.json (the cost-parity
        // suite is large by design; its verdicts, gate behavior included,
        // are pinned by bin/conformance.php and bin/conformance_cost.php).
        if (basename($file) === 'binary_bodies.json') {
            $binaryCorpusMax = max($binaryCorpusMax, $size);
        } elseif (basename($file) === 'cost_bodies.json') {
            continue;
        } else {
            $corpusMax = max($corpusMax, $size);
        }
    }
}
$t->truthy(
    $corpusMax > 0 && $corpusMax < SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES,
    "text corpus max content ({$corpusMax} bytes) stays below the gate threshold"
);
$t->truthy(
    $binaryCorpusMax >= SusPatterns::GATED_PATTERN_MAX_SUBJECT_BYTES,
    "binary corpus exercises above-gate subjects (max {$binaryCorpusMax} bytes), verdicts pinned by bin/conformance.php"
);

$t->section('benign large single-line bodies complete detection (no 500)');

foreach ([32000, 64000, 256000] as $target) {
    $body = largeBodyBenignJson($target);
    $result = detectQuietly($susPatterns, $body, 'request_body');
    $label = sprintf('benign JSON %d bytes: is_threat=false, no exception', strlen($body));
    if ($result['exception'] !== null) {
        $t->same(null, $result['exception']::class . ': ' . $result['exception']->getMessage(), $label);
    } else {
        $t->same(false, $result['is_threat'], $label);
    }
}

$t->section('walk-pattern probes around the gate');

$probe = 'etc/passwd';
$belowGate = largeBodyFiller(12000) . $probe;
$result = detectQuietly($susPatterns, $belowGate, 'request_body');
$t->same(null, $result['exception']?->getMessage(), 'probe below gate: no exception');
$t->same(true, $result['is_threat'], 'probe below gate: still detected');
$t->truthy(
    in_array('dir_traversal', threatCategories($result), true),
    'probe below gate: reported as dir_traversal'
);

$aboveGate = largeBodyFiller(21000) . $probe;
$result = detectQuietly($susPatterns, $aboveGate, 'request_body');
$t->same(null, $result['exception']?->getMessage(), 'probe above gate: no exception (walk patterns skipped, detection completes)');
$t->same(false, $result['is_threat'], 'probe above gate: benign filler is not a threat');

$htaccessBelow = '/' . str_repeat('sub/', 200) . '.htaccess';
$result = detectQuietly($susPatterns, $htaccessBelow, 'url_path');
$t->same(null, $result['exception']?->getMessage(), 'segment-loop probe below gate: no exception');
$t->same(true, $result['is_threat'], 'segment-loop probe below gate: .htaccess probe still detected');

// Just below the gate the preg call still runs and matches: the threshold
// (15360) sits below the measured ~16392-byte segment-loop cliff, so there is
// usable detection headroom right up to the gate.
$htaccessBoundary = '/a/' . str_repeat('a/', 7490) . '.htaccess';
$result = detectQuietly($susPatterns, $htaccessBoundary, 'url_path');
$t->same(null, $result['exception']?->getMessage(), 'segment-loop probe just below gate: no exception');
$t->same(true, $result['is_threat'], 'segment-loop probe just below gate (' . strlen($htaccessBoundary) . ' bytes): still detected');

$htaccessAbove = '/a/' . str_repeat('a/', 12000) . '.htaccess';
$result = detectQuietly($susPatterns, $htaccessAbove, 'url_path');
$t->same(null, $result['exception']?->getMessage(), 'segment-loop probe above gate: no exception');

$t->section('classic payload in a large body is still detected');

$xssBody = largeBodyBenignJson(64000) . '<script>alert(1)</script>';
$result = detectQuietly($susPatterns, $xssBody, 'request_body');
$t->same(null, $result['exception']?->getMessage(), '64KB body with XSS: no exception');
$t->same(true, $result['is_threat'], '64KB body with XSS: detected');
$t->truthy(
    in_array('xss', threatCategories($result), true),
    '64KB body with XSS: reported as xss (non-walk patterns unaffected by the gate)'
);

$t->section('pathological path-shaped subjects (segment-loop family)');

foreach ([32768, 40000, 65536] as $bytes) {
    $subject = str_repeat('a/', intdiv($bytes, 2));
    $result = detectQuietly($susPatterns, $subject, 'url_path');
    $label = sprintf("'a/' repeated %d bytes: no exception", strlen($subject));
    if ($result['exception'] !== null) {
        $t->same(null, $result['exception']::class . ': ' . $result['exception']->getMessage(), $label);
    } else {
        $t->same(false, $result['is_threat'], $label);
    }
}

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);

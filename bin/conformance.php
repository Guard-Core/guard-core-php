<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\SusPatterns;

require __DIR__ . '/../vendor/autoload.php';

final class ConformanceRunner
{
    private const FLOAT_PRECISION = 6;

    private string $casesDir;
    private SusPatterns $susPatterns;
    private array $knownGaps;
    private int $passed = 0;
    private int $failed = 0;
    private int $skipped = 0;

    public function __construct(string $casesDir, array $knownGaps)
    {
        $this->casesDir = $casesDir;
        $this->knownGaps = $knownGaps;
        $this->susPatterns = new SusPatterns();
    }

    public static function loadKnownGaps(string $path): array
    {
        if (!is_file($path)) {
            return [];
        }
        $gaps = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES) as $line) {
            if (preg_match('/^-\s+`?([A-Za-z0-9_]+)`?\s*:\s*(.+)$/', trim($line), $m) === 1) {
                $gaps[$m[1]] = $m[2];
            }
        }

        return $gaps;
    }

    public function run(): int
    {
        $files = glob($this->casesDir . '/*.json');
        sort($files);
        $suiteCount = 0;
        foreach ($files as $file) {
            $suite = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);
            if (!isset($suite['cases'])) {
                continue;
            }
            if (($suite['kind'] ?? 'detect') !== 'detect') {
                // Pipeline-kind suites are replayed by bin/conformance_pipeline.php.
                continue;
            }
            $suiteCount++;
            $suiteName = $suite['suite'] ?? basename($file, '.json');
            echo "=== {$suiteName} ===\n";
            foreach ($suite['cases'] as $case) {
                $this->runCase($case);
            }
        }
        if ($suiteCount === 0) {
            echo "FAIL: corpus glob matched zero detect suites in {$this->casesDir}; a vacuous pass is a failure\n";

            return 1;
        }
        echo "\nPassed: {$this->passed}, Failed: {$this->failed}, Skipped: {$this->skipped}\n";
        $total = $this->passed + $this->failed + $this->skipped;

        echo sprintf('%d/%d%s', $this->passed, $total, $this->failed === 0 ? ' GREEN' : ' RED') . "\n";

        return $this->failed === 0 ? 0 : 1;
    }

    private function runCase(array $case): void
    {
        $id = $case['id'];
        if (isset($this->knownGaps[$id])) {
            $this->skipped++;
            echo "  SKIP {$id}: {$this->knownGaps[$id]}\n";

            return;
        }
        $input = $case['input'];
        $expected = $case['expected'];
        try {
            $actual = $this->susPatterns->detect($input['content'], $input['ip'] ?? '203.0.113.7', $input['context']);
        } catch (Throwable $e) {
            $this->failed++;
            echo "  FAIL {$id}: exception {$e->getMessage()} @ {$e->getFile()}:{$e->getLine()}\n";

            return;
        }
        $diffs = self::compare($expected, $actual, $id);
        if ($diffs === []) {
            $this->passed++;
            echo "  PASS {$id}\n";
        } else {
            $this->failed++;
            foreach (array_slice($diffs, 0, 6) as $diff) {
                echo "  FAIL {$id}: {$diff}\n";
            }
        }
    }

    private static function roundFloats(mixed $value): mixed
    {
        if (is_float($value)) {
            return round($value, self::FLOAT_PRECISION);
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $out[$k] = self::roundFloats($v);
            }

            return $out;
        }

        return $value;
    }

    private static function canonicalThreatKey(array $threat): string
    {
        $category = $threat['category'] ?? $threat['attack_type'] ?? '';
        $json = json_encode($threat, JSON_THROW_ON_ERROR);

        return $category . '|' . ($threat['pattern'] ?? '') . '|' . ($threat['position'] ?? 0) . '|' . md5($json);
    }

    private static function compare(array $expected, array $actual, string $id): array
    {
        $diffs = [];
        foreach (['is_threat', 'original_length', 'processed_length', 'detection_method'] as $field) {
            $expectedValue = self::roundFloats($expected[$field]);
            $actualValue = self::roundFloats($actual[$field] ?? null);
            if ($expectedValue !== $actualValue) {
                $diffs[] = "{$field}: expected " . var_export($expectedValue, true) . ' got ' . var_export($actualValue, true);
            }
        }
        if (round($expected['threat_score'], self::FLOAT_PRECISION) !== round($actual['threat_score'] ?? -1.0, self::FLOAT_PRECISION)) {
            $diffs[] = 'threat_score: expected ' . $expected['threat_score'] . ' got ' . ($actual['threat_score'] ?? null);
        }
        $expectedThreats = $expected['threats'];
        $actualThreats = $actual['threats'] ?? [];
        if (count($expectedThreats) !== count($actualThreats)) {
            $diffs[] = 'threats count: expected ' . count($expectedThreats) . ' got ' . count($actualThreats);

            return $diffs;
        }
        usort($expectedThreats, static fn (array $a, array $b): int => self::canonicalThreatKey($a) <=> self::canonicalThreatKey($b));
        usort($actualThreats, static fn (array $a, array $b): int => self::canonicalThreatKey($a) <=> self::canonicalThreatKey($b));
        foreach ($expectedThreats as $i => $expectedThreat) {
            foreach ($expectedThreat as $key => $expectedValue) {
                if (!array_key_exists($key, $actualThreats[$i])) {
                    $diffs[] = "threat[{$i}].{$key}: missing in actual";
                    continue;
                }
                $ev = self::roundFloats($expectedValue);
                $av = self::roundFloats($actualThreats[$i][$key]);
                if ($ev !== $av) {
                    $diffs[] = 'threat[' . $i . '].' . $key . ': expected ' . json_encode($ev) . ' got ' . json_encode($av);
                }
            }
        }

        return $diffs;
    }
}

ini_set('pcre.backtrack_limit', (string) (100 * 1000 * 1000));
ini_set('pcre.recursion_limit', (string) (100 * 1000 * 1000));
ini_set('memory_limit', '2G');

$root = dirname(__DIR__);
$runner = new ConformanceRunner(
    $root . '/conformance/guard-core-spec-4.1.0/cases',
    ConformanceRunner::loadKnownGaps($root . '/KNOWN_GAPS.md'),
);
exit($runner->run());

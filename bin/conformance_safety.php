<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\Redos\Prefilters;

require __DIR__ . '/../vendor/autoload.php';

// pattern_safety-kind conformance suite (spec 4.1.0 safety_gates.json): every
// case runs through the real Prefilters::validatePatternSafety gate chain and
// the verdict reason is mapped to the reference's reason class with the same
// prefix rules the corpus generator used (specs/fixtures/tools/
// generate_safety_gates.py CLASS_RULES). Comparison: expected.safe and
// expected.reason_class only; the numeric parts of over-budget reason strings
// are host-measured and never compared (index.json comparison block
// pattern_safety_records). Documented divergences live in
// guard-core-spec-4.1.0/php_safety_xfail.json with fail-closed drift
// semantics (a failing case NOT baselined is red; a baselined case that
// passes is red).

final class SafetyConformanceRunner
{
    /**
     * The corpus generator's CLASS_RULES, in its exact first-match order.
     * The PHP chain produces every message prefix below except the three
     * structural rules it deliberately does not port (see
     * src/Detection/Redos/Structure.php): unreachable terminator, ambiguous
     * literal boundary, ambiguous optional tail.
     *
     * @var array<string, string>
     */
    private const CLASS_RULES = [
        'Pattern contains dangerous construct' => 'dangerous_construct',
        'Pattern validation failed:' => 'compile_failed',
        'Pattern contains nested unbounded quantifier' => 'structural_nested_unbounded',
        'Pattern contains adjacent broad unbounded quantifiers' => 'structural_adjacent_broad',
        'terminator cannot be reached by' => 'structural_unreachable_terminator',
        'absorb the mandatory literal' => 'structural_literal_absorb',
        'ambiguous optional tail' => 'structural_ambiguous_tail',
        'Pattern timed out on test string' => 'probe_string_timeout',
        'probe exceeded the' => 'probe_subprocess_timeout',
        'could not construct a test string that' => 'unreachable_probe',
        'Pattern extrapolated CPU cost' => 'over_budget',
        'probe construction exceeded its deadline' => 'builder_deadline',
        'Pattern appears safe' => 'safe',
    ];

    private string $casesDir;
    private string $baselinePath;
    private int $passed = 0;
    private int $xfailed = 0;
    private int $failed = 0;
    private int $total = 0;

    public function __construct(string $casesDir, string $baselinePath)
    {
        $this->casesDir = $casesDir;
        $this->baselinePath = $baselinePath;
    }

    /** @return array<string, string> the case id -> reason baseline */
    private function loadBaseline(): array
    {
        if (!is_file($this->baselinePath)) {
            return [];
        }
        $baseline = json_decode((string) file_get_contents($this->baselinePath), true, 512, JSON_THROW_ON_ERROR);
        if (($baseline['spec_version'] ?? null) !== '4.1.0') {
            fwrite(STDERR, "xfail baseline spec pin {$baseline['spec_version']} does not match 4.1.0\n");
            exit(1);
        }

        return $baseline['cases'];
    }

    public function run(): int
    {
        $suite = json_decode(
            (string) file_get_contents($this->casesDir . '/safety_gates.json'),
            true,
            512,
            JSON_THROW_ON_ERROR
        );
        $xfail = $this->loadBaseline();
        $stale = [];
        $failureLines = [];
        $xfailLines = [];

        foreach ($suite['cases'] as $case) {
            $this->total++;
            $id = $case['id'];
            [$safe, $class] = $this->runCase($case['input']);
            $expectedSafe = (bool) $case['expected']['safe'];
            $expectedClass = (string) $case['expected']['reason_class'];
            if ($safe === $expectedSafe && $class === $expectedClass) {
                if (isset($xfail[$id])) {
                    $stale[] = $id;
                } else {
                    $this->passed++;
                }

                continue;
            }
            if (isset($xfail[$id])) {
                $this->xfailed++;
                $xfailLines[] = "xfail {$id} [{$xfail[$id]}]: got safe="
                    . var_export($safe, true) . " class={$class}, want safe="
                    . var_export($expectedSafe, true) . " class={$expectedClass}";

                continue;
            }
            $this->failed++;
            $failureLines[] = "{$id}: got safe=" . var_export($safe, true)
                . " class={$class}, want safe=" . var_export($expectedSafe, true)
                . " class={$expectedClass}";
        }

        foreach ($xfailLines as $line) {
            echo $line . "\n";
        }
        if ($stale !== []) {
            fwrite(STDERR, "stale xfail baseline:\n" . implode("\n", $stale) . "\n");
            $this->failed += count($stale);
        }
        if ($this->failed > 0) {
            fwrite(STDERR, "pattern safety conformance drift: {$this->failed}/{$this->total} cases differ\n"
                . implode("\n", $failureLines) . "\n");
            exit(1);
        }

        $green = $this->total - $this->xfailed;
        echo "pattern safety conformance gate: {$green} passed, {$this->xfailed} xfail, "
            . $this->failed . " failed (spec 4.1.0, {$this->total} cases)\n";

        return 0;
    }

    /**
     * Drives one case through the real gate chain and maps the verdict
     * reason to the corpus reason class.
     *
     * @param array<string, mixed> $input
     * @return array{0: bool, 1: string} [safe, reason_class]
     */
    private function runCase(array $input): array
    {
        try {
            if ($input['mode'] === 'test_strings') {
                /** @var list<string> $strings */
                $strings = $input['test_strings'];
                [$safe, $reason] = Prefilters::validatePatternSafety((string) $input['pattern'], $strings);
            } else {
                $maxContentLength = isset($input['max_content_length']) ? (int) $input['max_content_length'] : null;
                [$safe, $reason] = Prefilters::validatePatternSafety((string) $input['pattern'], null, $maxContentLength);
            }
        } catch (Throwable $e) {
            // A crash inside the chain is a divergence, not a runner
            // failure: the reference oracle never raises.
            return [false, 'other'];
        }

        return [$safe, self::classify($reason)];
    }

    public static function classify(string $reason): string
    {
        foreach (self::CLASS_RULES as $prefix => $class) {
            if (str_contains($reason, $prefix)) {
                return $class;
            }
        }

        return 'other';
    }
}

ini_set('memory_limit', '2G');

$root = dirname(__DIR__);
$runner = new SafetyConformanceRunner(
    $root . '/conformance/guard-core-spec-4.1.0/cases',
    $root . '/conformance/guard-core-spec-4.1.0/php_safety_xfail.json'
);
exit($runner->run());

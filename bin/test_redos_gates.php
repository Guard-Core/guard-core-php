<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\Preg;
use RenzoFranceschini\GuardCore\Detection\PregFailure;
use RenzoFranceschini\GuardCore\Detection\Redos\CostArbiter;
use RenzoFranceschini\GuardCore\Detection\Redos\Prefilters;
use RenzoFranceschini\GuardCore\Detection\Redos\ScanGuard;
use RenzoFranceschini\GuardCore\Detection\Redos\Structure;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;

require __DIR__ . '/../vendor/autoload.php';

// Section 04 ReDoS safety gates on PCRE (spec 04 "Pattern safety gates" and
// "Scan execution", ported per specs/impl/php.md's regex-engine mandate).
// Every gate is exercised on both the allow and the block path, and the
// catastrophic fixtures are genuinely exponential backtracking patterns
// ((a|a)*$) against adversarial subjects, so the engine-budget and
// deadline arms fire deterministically instead of relying on timing luck.

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

    public function finish(string $label): int
    {
        echo "\n{$label}: {$this->passed} passed, {$this->failed} failed\n";

        return $this->failed === 0 ? 0 : 1;
    }
}

$t = new T();

// ---------------------------------------------------------------------
// 1. Dangerous-construct prefilter (unconditional, no timing)
// ---------------------------------------------------------------------

$t->section('dangerous construct prefilter');
$t->same(
    'Pattern contains dangerous construct: \(\.(?:\*|\+|\{[0-9]+,\})\)(?:\+|\{[0-9]+,\})',
    Prefilters::dangerousConstructViolation('(.+)+'),
    'dot atom inside outer + is rejected'
);
$t->same(
    'Pattern contains dangerous construct: \([^)]*(?:\*|\+|\{[0-9]+,\})\)(?:\+|\{[0-9]+,\})',
    Prefilters::dangerousConstructViolation('(a+)+'),
    'non-dot class inside outer + is rejected'
);
$t->same(
    'Pattern contains dangerous construct: (?:\.(?:\*|\+|\{[0-9]+,\})){2,}',
    Prefilters::dangerousConstructViolation('.*.*'),
    'two consecutive .* units are rejected'
);
$t->same(null, Prefilters::dangerousConstructViolation('(.*)*'), 'outer bare * is not in the gate set');
$t->same(null, Prefilters::dangerousConstructViolation('select .* from t'), 'benign pattern passes');
$t->same(null, Prefilters::dangerousConstructViolation('(\s\S)+'), 'broad shorthand without outer quantifier passes');

// Parity table with the reference (values pinned against
// _detect_nested_unbounded_quantifier / _detect_adjacent_broad_unbounded_quantifiers).
$t->section('structural checks (reference parity table)');
$t->same('(.*)*', Structure::detectNestedUnboundedQuantifier('(.*)*'), 'nested: (.*)*');
$t->same(null, Structure::detectNestedUnboundedQuantifier('abc'), 'nested: literal');
$t->same('. and .', Structure::detectAdjacentBroadUnboundedQuantifiers('.*.*'), 'adjacent: .*.*');
$t->same('[^a] and .', Structure::detectAdjacentBroadUnboundedQuantifiers('[^a]*(?:.+)*'), 'adjacent: negated class and dot');
$t->same(null, Structure::detectAdjacentBroadUnboundedQuantifiers('(a+)+'), 'adjacent: single broad atom');
$t->same(
    Structure::NESTING_DEPTH_REJECTION_REASON,
    Structure::detectNestedUnboundedQuantifier(str_repeat('(', 21) . 'a' . str_repeat(')', 21)),
    'nesting beyond depth 20 is a rejection reason'
);

// ---------------------------------------------------------------------
// 2. Compile check and validate_pattern_safety ordering
// ---------------------------------------------------------------------

$t->section('compile check and gate ordering');
$compileViolation = Prefilters::compileViolation('select (.+');
$t->truthy(
    is_string($compileViolation) && str_starts_with($compileViolation, 'Pattern validation failed: '),
    'uncompilable pattern rejects with the reference message shape'
);
$t->same(null, Prefilters::compileViolation('[a-z]+'), 'valid pattern compiles');

[$safe, $reason] = Prefilters::validatePatternSafety('(.*)*', ['test']);
$t->same(false, $safe, 'validate rejects with test strings on structural finding');
$t->same('Pattern contains nested unbounded quantifier: (.*)*', $reason, 'structural finding message');

[$safe, $reason] = Prefilters::validatePatternSafety('(.+)+');
$t->same(false, $safe, 'validate rejects catastrophic pattern on cost path');

[$safe, $reason] = Prefilters::validatePatternSafety('[a-z]+');
$t->same([true, 'Pattern appears safe'], [$safe, $reason], 'benign pattern accepted');

// ---------------------------------------------------------------------
// 3. Interactive probe (test strings): 0.05 s per string, fail closed
// ---------------------------------------------------------------------

$t->section('probe with test strings');
$t->same(
    [true, 'Pattern appears safe'],
    CostArbiter::probeWithTestStrings('[a-z]+', ['abc', 'def']),
    'benign probe accepts'
);
$t->same(
    [true, 'Pattern appears safe'],
    CostArbiter::probeWithTestStrings('(.+)+', [str_repeat('a', 40) . '!']),
    'a matching prefix probe accepts: search semantics, no explosion'
);
$probeResult = CostArbiter::probeWithTestStrings('(a|a)*$', [str_repeat('a', 40) . 'b']);
$t->same(false, $probeResult[0], 'catastrophic probe rejects (fail closed)');
$t->same(
    'Pattern timed out on test string of length 41',
    $probeResult[1],
    'threshold trip carries the reference reason'
);
$probeResult = CostArbiter::probeWithTestStrings('[a-', ['x']);
$t->same(false, $probeResult[0], 'probe rejects uncompilable pattern');
$t->truthy(str_starts_with($probeResult[1], 'Pattern validation failed: '), 'compile failure reason');

// ---------------------------------------------------------------------
// 4. Cost arbiter verdict arithmetic and cost verdict
// ---------------------------------------------------------------------

$t->section('cost arbiter verdict arithmetic');
[$over, $extrapolated, $ratio] = CostArbiter::verdictFromSamples(
    [[0.02, 0.02, 0.02, 0.02, 0.02], [0.2, 0.2, 0.2, 0.2, 0.2]],
    262144
);
$t->same(true, $over, 'superlinear growth extrapolates over budget');
$t->same(10.0, $ratio, 'growth ratio per doubling');
$t->truthy($extrapolated > 200.0 && $extrapolated < 220.0, 'extrapolation 0.2 * 10^log2(8.192)');

[$over, , $ratio] = CostArbiter::verdictFromSamples(
    [[0.0005, 0.0005], [0.0009, 0.0009]],
    262144
);
$t->same(false, $over, 'under the noise floor the ratio is forced to 1.0');
$t->same(1.0, $ratio, 'noise-floor ratio');

$t->same(0.25, CostArbiter::loadFactor(0.0001), 'load factor floor');
$t->same(8.0, CostArbiter::loadFactor(10.0), 'load factor ceiling');
$t->same(40.0, CostArbiter::scaledProbeDeadlineSeconds(0.1), 'deadline floored at combined base');
$t->same(240.0, CostArbiter::scaledProbeDeadlineSeconds(8.0), 'deadline scaled ceiling');

$t->section('large bounded repeat ladder gate');
$t->same(true, CostArbiter::hasLargeBoundedRepeat('a{1,5000}'), 'variable bounded repeat at 5000 flags the ladder');
$t->same(false, CostArbiter::hasLargeBoundedRepeat('a{3,3}'), 'exact repeat is not variable');
$t->same(false, CostArbiter::hasLargeBoundedRepeat('a{10,}'), 'unbounded repeat is not bounded');
$t->same(false, CostArbiter::hasLargeBoundedRepeat('abc'), 'plain literal');

$t->section('cost verdict');
$t->same(
    [true, 'Pattern appears safe'],
    CostArbiter::costVerdict('select .* from t'),
    'linear pattern accepted'
);
$costResult = CostArbiter::costVerdict('(a|a)*$');
$t->same(false, $costResult[0], 'catastrophic pattern rejected on the timed ladder');
$t->truthy(
    str_contains($costResult[1], 'safety budget')
        || str_contains($costResult[1], 'killable-subprocess')
        || str_contains($costResult[1], 'nested unbounded quantifier'),
    'rejection carries the cost or timeout reason: ' . $costResult[1]
);
$t->same(
    [false, CostArbiter::unreachableReason(null)],
    CostArbiter::costVerdict('(?P<x>a)(?P=x)'),
    'unreachable probe rejects rather than certifying'
);

$t->section('probe unit builders and stride sampling');
$builders = CostArbiter::probeUnitBuilders(str_repeat('a', 8000) . 'b' . "\x01", '(a+)+b');
$t->same(5, count($builders), 'full body plus the 20/30/50 prefix cuts plus the literal run');
$t->same([], CostArbiter::probeUnitBuilders('', 'x'), 'empty body has no builders');
$sets = CostArbiter::uniqueProbeSets(['ab', 'ab', 'cd'], [4000, 8000]);
$t->same(2, count($sets), 'duplicate probe sets deduplicated');
$few = [];
for ($i = 0; $i < 5; $i++) {
    $few[] = ['u' . $i];
}
$t->same($few, CostArbiter::strideSampledProbeSets($few), 'under the cap nothing is sampled away');

// ---------------------------------------------------------------------
// 5. ScanGuard: ini budget save/restore, fail-closed trips, deadline
// ---------------------------------------------------------------------

$t->section('scan guard ini budget');
$inner = ScanGuard::runBounded(static fn (): string => (string) ini_get('pcre.backtrack_limit'), ScanGuard::STOCK_BACKTRACK_BUDGET);
$t->same('1000000', $inner->value, 'guarded scan runs under the stock backtrack budget');
ini_set('pcre.backtrack_limit', '123456');
$restored = ScanGuard::runBounded(static fn (): string => (string) ini_get('pcre.backtrack_limit'), ScanGuard::STOCK_BACKTRACK_BUDGET);
$t->same('123456', $restored->value, 'a lowered deployment limit is respected, not raised');
$clamped = ScanGuard::runBounded(static fn (): string => (string) ini_get('pcre.backtrack_limit'), ScanGuard::STOCK_BACKTRACK_BUDGET);
$t->same('123456', $clamped->value, 'scan honors the lowered limit throughout');
$t->same('123456', ini_get('pcre.backtrack_limit'), 'previous limit restored after the scan');
ini_set('pcre.backtrack_limit', '1000000');

$t->section('scan guard fail-closed engine-budget trips');
$catastrophic = Preg::compile('(a|a)*$');
$trip = ScanGuard::runBounded(
    static fn (): int|false => @preg_match($catastrophic, str_repeat('a', 50) . 'b'),
    ScanGuard::STOCK_BACKTRACK_BUDGET
);
$t->same(true, $trip->timedOut, 'PREG_BACKTRACK_LIMIT_ERROR trip is a scan timeout');
$t->same(null, $trip->value, 'timed-out scan value discarded');
$t->truthy($trip->elapsedSeconds !== null && $trip->elapsedSeconds < 1.0, 'budget trip is fast, not a hang');

$t->same(1, ScanGuard::consecutiveTimeouts(), 'timeout increments the consecutive counter');
ScanGuard::reportScanSuccess();
$t->same(0, ScanGuard::consecutiveTimeouts(), 'success resets the counter');
for ($i = 0; $i < ScanGuard::CONSECUTIVE_TIMEOUT_POOL_REPLACEMENT - 1; $i++) {
    ScanGuard::runBounded(
        static fn (): int|false => @preg_match($catastrophic, str_repeat('a', 50) . 'b'),
        ScanGuard::STOCK_BACKTRACK_BUDGET
    );
}
$t->same(
    ScanGuard::CONSECUTIVE_TIMEOUT_POOL_REPLACEMENT - 1,
    ScanGuard::consecutiveTimeouts(),
    'three timeouts accumulate'
);
ScanGuard::runBounded(
    static fn (): int|false => @preg_match($catastrophic, str_repeat('a', 50) . 'b'),
    ScanGuard::STOCK_BACKTRACK_BUDGET
);
$t->same(0, ScanGuard::consecutiveTimeouts(), 'fourth timeout resets the counter (pool replacement)');

$t->section('scan guard wall-clock deadline');
$deadlineStart = hrtime(true);
$deadlineResult = ScanGuard::runBounded(static function (): bool {
    usleep(200000);

    return true;
}, null, 0.05);
$deadlineElapsed = (hrtime(true) - $deadlineStart) / 1e9;
$t->same(true, $deadlineResult->timedOut, 'scan over its deadline reports timedOut');
$t->same(null, $deadlineResult->value, 'deadline trip discards the result');
$t->truthy($deadlineElapsed >= 0.05 && $deadlineElapsed < 2.0, 'deadline measured with hrtime in the test');

$ok = ScanGuard::runBounded(static fn (): int => 1, null, 5.0);
$t->same([false, 1], [$ok->timedOut, $ok->value], 'scan under its deadline passes through');

$t->section('scan guard non-limit preg failures keep fail-secure');
$threw = false;
try {
    ScanGuard::runBounded(static fn (): int|false => throw new PregFailure('synthetic'), null);
} catch (PregFailure) {
    $threw = true;
}
$t->same(true, $threw, 'non-limit PregFailure propagates (fail-secure 500 path)');

$t->section('canary probe before full scan');
$benignCompiled = Preg::compile('select');
$longBenign = str_repeat('select nothing much; ', 2000);
$t->same(false, ScanGuard::probeBeforeScan($benignCompiled, $longBenign, 1.8), 'linear pattern on a large subject scans');
$catastrophicCompiled = Preg::compile('(a|a)*$');
$t->same(
    true,
    ScanGuard::probeBeforeScan($catastrophicCompiled, str_repeat('a', 30000) . '!', 1.8),
    'catastrophic pattern is skipped before the full scan'
);
$t->same(false, ScanGuard::probeBeforeScan($catastrophicCompiled, 'short subject', 1.8), 'short subjects scan unprobed');

// ---------------------------------------------------------------------
// 6. SusPatterns integration: classification and timeout semantics
// ---------------------------------------------------------------------

$t->section('suspatterns scan classification');
$susPatterns = new SusPatterns();
$scanPattern = new ReflectionMethod($susPatterns, 'scanPattern');
$scanPattern->setAccessible(true);
$bigAdversarial = str_repeat('a', 30000) . '!';
$result = $scanPattern->invoke($susPatterns, '(a|a)*$', 'custom', $bigAdversarial, 'request_body', null);
$t->same([null, true], $result, 'plain catastrophic pattern: engine-budget trip reports a timeout');
$literal = $scanPattern->invoke($susPatterns, 'union select', 'request_body', 'select x', 'request_body', null);
$t->same([null, false], $literal, 'plain benign pattern on a small subject: no timeout arm');

$t->section('reference timeout semantics end to end (threats-logged-and-miss)');
$previousTimeout = SusPatterns::$compilerTimeoutOverride;
SusPatterns::$compilerTimeoutOverride = 1e-9;
try {
    $detection = $susPatterns->detect('hello world', '203.0.113.7', 'request_body');
    $timeoutThreats = array_values(array_filter(
        $detection['threats'],
        static fn (array $threat): bool => ($threat['type'] ?? '') === 'pattern_timeout'
    ));
    $t->truthy(count($detection['timeouts']) > 0, 'timeout sources recorded');
    $t->truthy(count($timeoutThreats) > 0, 'pattern_timeout threats emitted');
    $firstTimeout = $timeoutThreats[0];
    $t->same('', $firstTimeout['match'], 'timeout threat matches nothing');
    $t->same(0, $firstTimeout['position'], 'timeout threat position 0');
    $t->same(1.0, $firstTimeout['weight'], 'timeout threat carries the category weight');
    $t->truthy(isset($firstTimeout['execution_time']) && $firstTimeout['execution_time'] >= 0.0, 'timeout threat carries execution_time');
    $t->same(true, $detection['is_threat'], 'a scan timeout fails closed: is_threat');
} finally {
    SusPatterns::$compilerTimeoutOverride = $previousTimeout;
}

$t->section('normal detection unaffected by the gates');
$benign = $susPatterns->detect('hello world', '203.0.113.7', 'request_body');
$t->same(false, $benign['is_threat'], 'benign content passes');
$t->same([], $benign['timeouts'], 'no timeouts on benign content');
$attack = $susPatterns->detect("1' OR '1'='1", '203.0.113.7', 'query_param');
$t->same(true, $attack['is_threat'], 'sqli probe still detected');


// ---------------------------------------------------------------------
// 7. Structure primitives: direct exercises for every branch
// ---------------------------------------------------------------------

$t->section('structure primitives (direct)');
$t->same(4, Structure::skipCharClass('[\\]]x', 0), 'skipCharClass walks an escaped closing bracket');
$t->same(5, Structure::skipCharClass('[abc]x', 0), 'skipCharClass walks plain class members');
$t->same(2, Structure::advancePastEscapeOrCharClass('\\d', 0), 'advancePastEscapeOrCharClass over an escape');
$t->same(4, Structure::advancePastEscapeOrCharClass('[ab]x', 0), 'advancePastEscapeOrCharClass over a class');
$t->same(4, Structure::findGroupEnd('(\\))', 0), 'findGroupEnd skips an escaped paren');
$t->same('(\\n+)+', Structure::detectNestedUnboundedQuantifier('(\\n+)+'), 'nested: escape collapse feeds the unbounded-single rule');
$t->same('(\\d*)+', Structure::detectNestedUnboundedQuantifier('(\\d*)+'), 'nested: class collapse feeds the unbounded-single rule');
$t->same('((?:a+))+', Structure::detectNestedUnboundedQuantifier('((?:a+))+'), 'nested: transparent wrapper unwrapped');
$t->same(null, Structure::detectNestedUnboundedQuantifier('(?:ab){2,}'), 'nested: brace-quantified literal group is clean');
$t->same('(?:x{2,})+', Structure::detectNestedUnboundedQuantifier('(?:x{2,})+'), 'nested: brace unbounded single');
$t->same(null, Structure::detectNestedUnboundedQuantifier('(?:a\\|b|c)+'), 'nested: escaped alternation split');
$t->same(null, Structure::detectNestedUnboundedQuantifier('(?:a(b)c)+'), 'nested: alternation split tracks depth');
$t->same(null, Structure::detectNestedUnboundedQuantifier('(abc'), 'nested: unbalanced group skipped');
$t->same(
    Structure::NESTING_DEPTH_REJECTION_REASON,
    Structure::detectAdjacentBroadUnboundedQuantifiers(str_repeat('(', 21) . 'a' . str_repeat(')', 21)),
    'adjacent: nesting beyond depth 20 is a rejection reason'
);
$t->same(null, Structure::detectAdjacentBroadUnboundedQuantifiers('(abc'), 'adjacent: unbalanced group skipped');

$t->section('structural broad-class table (reference parity)');
$t->same(null, Structure::detectAdjacentBroadUnboundedQuantifiers('[^\\S]*(?:.+)*'), 'adjacent: negated class excluding a shorthand is not broad');
$t->same(null, Structure::detectAdjacentBroadUnboundedQuantifiers('[ab]*(?:.+)*'), 'adjacent: plain class is not broad');
$t->same('\\S and .', Structure::detectAdjacentBroadUnboundedQuantifiers('\\s\\S*(?:.+)*'), 'adjacent: only the uppercase shorthand in the pair class is broad');
$t->same('\\S and .', Structure::detectAdjacentBroadUnboundedQuantifiers('\\S+.*'), 'adjacent: broad shorthand escape');

$t->section('reaching-probe synthesis (direct)');
$t->same(null, Structure::synthesizeReachingProbe('abc\\'), 'trailing escape fails the synthesis');
$t->truthy(Structure::synthesizeReachingProbe('\\Aabc\\Z') !== null, 'zero-width escapes are skipped');
$t->truthy(Structure::synthesizeReachingProbe('(a)\\1') !== null, 'resolvable backreference fills');
$t->same(null, Structure::synthesizeReachingProbe('(?:x)\\1'), 'unresolvable backreference fails the synthesis');
$t->truthy(str_starts_with((string) Structure::synthesizeReachingProbe('\\x41+'), 'A'), 'hex escape resolves to its character');
$t->truthy(Structure::synthesizeReachingProbe('(?<=x)y') !== null, 'lookbehind group is skipped');
$t->truthy(Structure::synthesizeReachingProbe('(?P<n>a)+') !== null, 'named group walks its body');
$t->truthy(Structure::synthesizeReachingProbe('(?i)x') !== null, 'flags-only group is skipped');
$t->truthy(Structure::synthesizeReachingProbe('(?i:abc)+') !== null, 'flags-scoped group walks its body');
$t->truthy(Structure::synthesizeReachingProbe('(?#hi)x') !== null, 'comment group is skipped');
$t->truthy(Structure::synthesizeReachingProbe('ab?c') !== null, 'optional symbol quantifier range');
$t->truthy(Structure::synthesizeReachingProbe('a{3}b') !== null, 'exact brace range');
$t->truthy(Structure::synthesizeReachingProbe('a{3,}b') !== null, 'unbounded brace range');
$t->truthy(Structure::synthesizeReachingProbe('a{2,3}b') !== null, 'bounded brace range');
$t->truthy(Structure::synthesizeReachingProbe('a{2,3}?b') !== null, 'lazy brace range');
$t->truthy(Structure::synthesizeReachingProbe('a{3') !== null, 'unclosed brace is a literal');
$t->truthy(Structure::synthesizeReachingProbe('a{2,x}b') !== null, 'non-digit brace high is a literal');
$t->truthy(Structure::synthesizeReachingProbe('(?#c)+x') !== null, 'empty unit fill');
$t->same(null, Structure::synthesizeReachingProbe('(?:a{20000,}b{20000,})'), 'probe beyond the max length fails the synthesis');
$t->same(null, Structure::synthesizeReachingProbe('(?:abcdefghijklmnopqrstuvwxyz01234){20000,}'), 'mandatory repeat beyond the probe budget fails the synthesis');
$t->same(null, Structure::synthesizeReachingProbe('(unclosed'), 'unbalanced group fails the synthesis');
$t->truthy(Structure::synthesizeReachingProbe('(?)') !== null, 'a flags-only unknown header is skipped like the reference');
$t->same(null, Structure::representativeCharForAtom('(?P<'), 'atom that cannot compile has no representative');
$t->same(null, Structure::representativeCharForAtom('[^ -~\t\n\r\x0b\\x0c]'), 'atom matching no printable character has no representative');
$t->same('0', Structure::representativeCharForAtom('\\d'), 'digit class resolves to 0');
$t->same(null, Structure::firstLiteralChar('\\Q'), 'first literal char skips unresolvable escapes');
$t->same(null, Structure::firstLiteralChar('[\\x80-\\xff]+'), 'first literal char skips unresolvable classes');
$t->same('0', Structure::firstLiteralChar('\\d+'), 'first literal char resolves digit escapes');

// ---------------------------------------------------------------------
// 8. Cost arbiter: message shapes, injection arms, stride sampling
// ---------------------------------------------------------------------

$t->section('cost reason shapes');
$reason = CostArbiter::costReason(null, 0.5, 10.0, 262144, 0.01, 0.02, 1.0);
$t->truthy(str_contains($reason, 'extrapolated CPU cost at cap (262144 chars) is 0.500s'), 'cost reason carries the extrapolation');
$t->truthy(str_contains($reason, 'growth ratio 10.00x per doubling'), 'cost reason carries the growth ratio');
$t->same('structural', CostArbiter::costReason('structural', 0.5, 10.0, 262144, 0.01, 0.02, 1.0), 'a structural violation is the reason');
$t->same('unreachable-structural', CostArbiter::unreachableReason('unreachable-structural'), 'unreachable reason prefers the structural finding');

$t->section('cost verdict injection arms');
$compileFail = CostArbiter::costVerdict('[a-', null, true, null, null);
$t->same(false, $compileFail[0], 'cost verdict surfaces the compile failure');
$t->truthy(str_starts_with($compileFail[1], 'Pattern validation failed: '), 'compile failure reason shape');
$costVerdict = new ReflectionMethod(CostArbiter::class, 'costVerdict');
$t->same(
    [true, 'Pattern appears safe'],
    CostArbiter::costVerdict('[a-z]+', 5000),
    'content cap flows into the verdict'
);
$t->same(
    [false, 'Pattern validation probe construction exceeded its deadline'],
    CostArbiter::costVerdict('[a-z]+', null, true, hrtime(true) - 10),
    'an exhausted verdict deadline rejects the construction'
);
$t->same(
    [true, 'Pattern appears safe'],
    CostArbiter::costVerdict('^$'),
    'no extractable probe unit accepts without timing'
);
$t->same(
    [false, CostArbiter::unreachableReason(null)],
    CostArbiter::costVerdict('[\\x80-\\xff]+'),
    'a class with no printable representative rejects fail-closed'
);
$tooDeep = CostArbiter::costVerdict(str_repeat('(', 21) . 'a' . str_repeat(')', 21));
$t->same(false, $tooDeep[0], 'a pattern deeper than the analyzer rejects');
$t->same(
    'Pattern contains nested unbounded quantifier: ' . Structure::NESTING_DEPTH_REJECTION_REASON,
    $tooDeep[1],
    'the depth rejection rides the structural finding'
);
$t->same(
    [true, 'Pattern appears safe'],
    CostArbiter::costVerdict('(?:\\d+)x'),
    'escape atoms resolve through the synthesis'
);

$t->section('probe timing arms (injected timer)');
$slowTimer = static fn (string $probe): ?float => strlen($probe) > 20000 ? 0.02 : 0.004;
$timed = CostArbiter::costVerdict('[a-z]+', null, true, null, $slowTimer);
$t->same(false, $timed[0], 'superlinear probe samples extrapolate over budget');
$t->truthy(str_contains($timed[1], 'safety budget'), 'timer-driven rejection carries the cost reason');
$nullTimer = static fn (string $probe): ?float => null;
$t->same(
    [false, 'Pattern validation probe exceeded the killable-subprocess timeout while measuring reach-probe cost at scale'],
    CostArbiter::costVerdict('[a-z]+', null, true, null, $nullTimer),
    'a killed timing probe rejects fail-closed'
);
$largeSampleTimer = static fn (string $probe): ?float => 0.3;
$t->same(false, CostArbiter::costVerdict('[a-z]+', null, true, null, $largeSampleTimer)[0], 'large samples abort the sampling loop and reject');

$t->section('probe deadline arm');
$t->same(
    [false, 'Pattern validation probe exceeded the 2.0s killable-subprocess timeout'],
    CostArbiter::probeWithTestStrings('[a-z]+', ['abc'], true, hrtime(true) - 10),
    'an exhausted probe deadline rejects'
);

$t->section('load factor sampling arms');
$t->same(1.0, CostArbiter::measureHostLoadFactor(static fn (): float|false => false), 'a failing reference scan falls back to load factor 1.0');
$t->same(8.0, CostArbiter::measureHostLoadFactor(static function (): float|false {
    usleep(10000);

    return 1.0;
}), 'a slow reference scan scales to the ceiling');
$t->same(
    CostArbiter::LOAD_FACTOR_FLOOR,
    CostArbiter::measureHostLoadFactor(static fn (): float|false => 0.0000001),
    'a fast reference scan floors the load factor'
);

$t->section('stride sampling and probe sets');
$many = [];
for ($i = 0; $i < 600; $i++) {
    $many[] = ['p' . $i];
}
$sampled = CostArbiter::strideSampledProbeSets($many);
$t->same(300, count($sampled), 'stride sampling to the 512 cap');
$t->same('p0', $sampled[0][0], 'stride keeps the first set');
$t->same([['']], CostArbiter::uniqueProbeSets([''], [4000]), 'an empty unit repeats to an empty probe');
$straySet = CostArbiter::uniqueProbeSets(['u'], [4000], "\x01")[0];
$t->truthy(str_ends_with($straySet[0], "\x01") && str_starts_with($straySet[0], 'uuuu'), 'probes end in the stray character');
$t->same("\x01", CostArbiter::chooseProbeStray('[a-z]+', true), 'the stray character is one the pattern cannot match');
$t->same("\x01", CostArbiter::chooseProbeStray('.*', true), 'a pattern matching every candidate falls back');

// ---------------------------------------------------------------------
// 9. Scan guard: canary verdict arithmetic
// ---------------------------------------------------------------------

$t->section('canary verdict arithmetic');
$t->same(true, ScanGuard::canaryExtrapolatesOverBudget(0.002, null, 30000, 1.8), 'a tripped second canary is catastrophic');
$t->same(false, ScanGuard::canaryExtrapolatesOverBudget(0.0005, 0.0005, 30000, 1.8), 'flat canaries under the noise floor stay linear');
$t->same(true, ScanGuard::canaryExtrapolatesOverBudget(0.002, 0.01, 30000, 0.05), 'superlinear canaries extrapolate over budget');
$t->same(false, ScanGuard::canaryExtrapolatesOverBudget(0.002, 0.01, 30000, 1.8), 'superlinear canaries under a generous budget scan');

$t->section('canary gate before full scan');
$catastrophicAtPrefix = Preg::compile('(.*a){20}$');
$t->same(
    true,
    ScanGuard::probeBeforeScan($catastrophicAtPrefix, str_repeat('a', 4095) . 'b' . str_repeat('a', 8192), 1.8),
    'a pattern catastrophic on the prefix is skipped before the full scan'
);


// ---------------------------------------------------------------------
// 10. Remaining gate arms (branch-complete coverage)
// ---------------------------------------------------------------------

$t->section('structure class-collapse and unwrap breaks');
$t->same('([ab]+)+', Structure::detectNestedUnboundedQuantifier('([ab]+)+'), 'nested: character class collapse');
$t->same(null, Structure::detectNestedUnboundedQuantifier('(?:ab|cd)+'), 'overlapping-literal check rejects non-overlapping branches');
$t->same(null, Structure::detectNestedUnboundedQuantifier('(?:a|)+'), 'an empty alternation branch is not a literal branch');
$t->same(null, Structure::detectNestedUnboundedQuantifier('((a+)(b+))+'), 'unwrap stops at a group that does not span the body');
$t->same(null, Structure::detectNestedUnboundedQuantifier('((?P=x))+'), 'unwrap stops at an opaque group');
$t->same('((a+))+', Structure::detectNestedUnboundedQuantifier('((a+))+'), 'nested quantified group flags the unwrapped outer body');

$t->section('synthesis group-walk and brace arms');
$t->same(null, Structure::synthesizeReachingProbe('(?<x)'), 'an unknown question group fails the synthesis');
$t->truthy(Structure::synthesizeReachingProbe('a{b,2}b') !== null, 'non-digit brace low is a literal');
$t->same(null, Structure::synthesizeReachingProbe('(?:)\\1'), 'a non-capturing group leaves its backreference unresolvable');
$t->same(null, Structure::synthesizeReachingProbe('\\Q+'), 'an escape with no representative character fails the synthesis');

$t->section('suspatterns plain-path budget trip end to end');
$result = $scanPattern->invoke(
    $susPatterns,
    '(aa|a){20}$',
    'custom',
    str_repeat(' ', 8192) . str_repeat('a', 20808) . 'b',
    'request_body',
    null
);
$t->same([null, true], $result, 'clean canary windows, catastrophic full scan: PregFailure catch reports a timeout');
$t->same('(a+)+', Structure::detectNestedUnboundedQuantifier('(?:x(a+)+)+'), 'nested quantified group inside a group is yielded first');

$t->section('validate pattern safety dispatch arms');
[$safe, $reason] = Prefilters::validatePatternSafety('[a-');
$t->same(false, $safe, 'uncompilable pattern rejects on the validate path');
$t->truthy(str_starts_with($reason, 'Pattern validation failed: '), 'compile reason on the validate path');
$t->same(
    [true, 'Pattern appears safe'],
    Prefilters::validatePatternSafety('[a-z]+', ['abc']),
    'the probe result flows through the validate path'
);

$t->section('cost verdict accept-with-disagreement');
$t->same(
    [true, 'Pattern appears safe'],
    CostArbiter::costVerdict('(?:x{2,})+'),
    'a structurally flagged but timed-linear pattern is accepted'
);

$t->section('load factor reference-scan failure arm');
$t->same(
    1.0,
    CostArbiter::measureHostLoadFactor(null, null, '(?i)[unclosed'),
    'a reference scan that cannot compile falls back to load factor 1.0'
);
$t->same(
    CostArbiter::LOAD_FACTOR_FLOOR,
    CostArbiter::measureHostLoadFactor(static function (): float|false {
        usleep(2000);

        return 0.0;
    }, 0.0001),
    'the wall budget breaks the sampling loop'
);

$t->section('probe timing deadline mid-loop');
$sleepyTimer = static function (string $probe): ?float {
    usleep(150000);

    return 0.0005;
};
$t->same(
    [false, 'Pattern validation probe exceeded the killable-subprocess timeout while measuring reach-probe cost at scale'],
    CostArbiter::costVerdict('[a-z]+', null, true, hrtime(true) + 200000000, $sleepyTimer),
    'the verdict deadline cuts the timing loop fail-closed'
);
$counter = [0];
$flakyTimer = static function (string $probe) use (&$counter): ?float {
    $counter[0]++;

    return $counter[0] >= 4 ? null : 0.002;
};
$t->same(
    [false, 'Pattern validation probe exceeded the killable-subprocess timeout while measuring reach-probe cost at scale'],
    CostArbiter::costVerdict('[a-z]+', null, true, null, $flakyTimer),
    'a probe that trips its engine budget mid-sampling rejects'
);

exit($t->finish('REDOS GATES'));

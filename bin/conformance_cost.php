<?php

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\SusPatterns;

require __DIR__ . '/../vendor/autoload.php';

// Cost-budget conformance for the cost_bodies suite (index.json
// cost_budgets.method): verdict parity for large inputs is enforced by
// bin/conformance.php; this script enforces scan-cost ceilings. Ceilings
// are self-relative so they survive host variance: best_ms at every
// workload must satisfy best_ms <= K * best8_ms * (size / 8192) + floor,
// with K=5 and floor=250ms, tolerating host speed and fixed overhead while
// catching superlinear scans.

const K = 5.0;
const FLOOR_MS = 250.0;

$casesPath = __DIR__ . '/../conformance/guard-core-spec-4.1.0/cases';
$index = json_decode(file_get_contents($casesPath . '/index.json'), true);
if (!isset($index['cost_budgets'])) {
    fwrite(STDERR, "FAIL: index.json has no cost_budgets block; regenerate the corpus\n");
    exit(1);
}
$suite = json_decode(file_get_contents($casesPath . '/cost_bodies.json'), true);
if (!is_array($suite['cases']) || count($suite['cases']) === 0) {
    fwrite(STDERR, "FAIL: cost_bodies.json matched zero cases; a vacuous pass is a failure\n");
    exit(1);
}

$sus = new SusPatterns();
$runsFor = static fn (int $size): int => $size >= 256 * 1024 ? 1 : ($size >= 64 * 1024 ? 2 : 3);

$measured = [];
$failures = [];
foreach ($suite['cases'] as $case) {
    $body = $case['input']['content'];
    $detect = static fn (): array => $sus->detect($body, '203.0.113.7', $case['input']['context']);
    $detect(); // warmup
    $best = INF;
    $threat = false;
    foreach (range(1, $runsFor(strlen($body))) as $run) {
        $t0 = hrtime(true);
        $verdict = $detect();
        $best = min($best, (hrtime(true) - $t0) / 1e6);
        $threat = (bool) ($verdict['is_threat'] ?? false);
    }
    $measured[$case['id']] = ['best' => $best, 'threat' => $threat, 'size' => strlen($body)];
    if ($threat !== (bool) $case['expected']['is_threat']) {
        $failures[] = "{$case['id']}: verdict drifted from the recorded expectation";
    }
}

$best8 = $measured['cost_prose_8kib']['best'];
foreach ($suite['cases'] as $case) {
    $id = $case['id'];
    $m = $measured[$id];
    $ceiling = K * $best8 * ($m['size'] / 8192) + FLOOR_MS;
    $line = sprintf('cost budgets/%s: best=%.1f ms ceiling=%.1f ms (size %d)', $id, $m['best'], $ceiling, $m['size']);
    if ($m['best'] > $ceiling) {
        $failures[] = "$line exceeds ceiling; scan cost diverged superlinearly from the reference";
    } else {
        echo "$line\n";
    }
}

if ($failures) {
    foreach ($failures as $failure) {
        echo "FAIL: $failure\n";
    }
    exit(1);
}
echo 'cost budgets green: ' . count($suite['cases']) . " workloads under self-relative ceilings\n";

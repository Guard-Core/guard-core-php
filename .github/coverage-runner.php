<?php

declare(strict_types=1);

// Coverage gate for the bespoke bin/test_*.php suites, aggregated across all
// of them: the engine has one runner process per suite and each suite script
// calls exit() itself, so a single process cannot both run the suites and
// gate the merged result. The runner therefore has two modes:
//
//   --collect <suite-script> <out.php>
//       Starts pcov line coverage over src/, requires the suite script, and
//       dumps the raw per-line hit counts to <out.php> from a shutdown
//       function (the suite's own exit() terminates the process and runs the
//       shutdown; the suite's exit status propagates because collect mode
//       never overrides it).
//
//   --merge <collected-file> [<collected-file> ...]
//       Loads every collected dataset through php-code-coverage, prints the
//       combined text report, and fails unless every executable line in src/
//       is covered (hard 100.00% gate).
//
// Suite pass/fail is gated by the regular test job; this runner only gates
// aggregated line coverage.
//
// Usage:
//   php .github/coverage-runner.php --collect bin/test_state.php build/coverage-state.php
//   php .github/coverage-runner.php --merge build/coverage-*.php

use SebastianBergmann\CodeCoverage\CodeCoverage;
use SebastianBergmann\CodeCoverage\Data\RawCodeCoverageData;
use SebastianBergmann\CodeCoverage\Driver\Selector;
use SebastianBergmann\CodeCoverage\Filter;
use SebastianBergmann\CodeCoverage\Report\Text;
use SebastianBergmann\CodeCoverage\Report\Thresholds;

require __DIR__ . '/../vendor/autoload.php';

$mode = $argv[1] ?? null;

$src = __DIR__ . '/../src';

$filter = new Filter();
$files = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src));
foreach ($iterator as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $files[] = $file->getPathname();
    }
}
sort($files);
$filter->includeFiles($files);

if ($mode === '--collect') {
    $suite = $argv[2] ?? null;
    $out = $argv[3] ?? null;
    if ($suite === null || $out === null || ! is_file(__DIR__ . '/../' . $suite)) {
        fwrite(STDERR, "usage: php .github/coverage-runner.php --collect <path/to/bin/test_*.php> <out.php>\n");
        exit(2);
    }

    $driver = (new Selector())->forLineCoverage($filter);
    $driver->start();

    register_shutdown_function(static function () use ($driver, $out): void {
        try {
            $raw = $driver->stop()->lineCoverage();
        } catch (Throwable) {
            // the suite may exit before any covered line executes
            $raw = [];
        }

        $export = "<?php\nreturn " . var_export($raw, true) . ";\n";
        if (@file_put_contents($out, $export) === false) {
            fwrite(STDERR, "failed to write collected coverage to {$out}\n");
            exit(2);
        }

        printf("collected coverage for %d file(s) -> %s\n", count($raw), $out);
    });

    // Forward any arguments after the output path to the suite script (the
    // suites read $argv themselves, e.g. test_state's --integration flag).
    $GLOBALS['argv'] = array_merge([$suite], array_slice($argv, 4));

    require __DIR__ . '/../' . $suite;

    return;
}

if ($mode === '--merge') {
    $collected = array_slice($argv, 2);
    if ($collected === []) {
        fwrite(STDERR, "usage: php .github/coverage-runner.php --merge <collected.php> [<collected.php> ...]\n");
        exit(2);
    }

    foreach ($collected as $file) {
        if (! is_file($file)) {
            fwrite(STDERR, "collected coverage file missing: {$file}\n");
            exit(2);
        }
    }

    $coverage = new CodeCoverage(
        (new Selector())->forLineCoverage($filter),
        $filter,
    );

    foreach ($collected as $file) {
        $data = require $file;
        $coverage->append(
            RawCodeCoverageData::fromXdebugWithoutPathCoverage($data),
            basename($file, '.php'),
        );
    }

    // Text report thresholds are irrelevant here: the gate is
    // covered-or-provably-unreachable (see coverage-unreachable.php).
    $text = new Text(Thresholds::default());
    fwrite(STDOUT, PHP_EOL . $text->process($coverage) . PHP_EOL);

    $lines = $coverage->getReport()->percentageOfExecutedLines()->asFloat();
    printf("COVERAGE: %.2f%% lines\n", $lines);

    // The provably-unreachable inventory: file (relative to the repo root)
    // => list of line numbers, each with its proof in the file itself. An
    // uncovered line that carries a proof does not fail the gate; anything
    // else does.
    $waived = [];
    $inventoryPath = __DIR__ . '/coverage-unreachable.php';
    if (is_file($inventoryPath)) {
        foreach (require $inventoryPath as $file => $lineNumbers) {
            foreach ($lineNumbers as $lineNumber) {
                $waived[$file . ':' . $lineNumber] = true;
            }
        }
    }

    $uncovered = [];
    $srcPrefix = dirname((string) realpath($src)) . '/';
    $stack = [$coverage->getReport()];
    while ($stack !== []) {
        $node = array_pop($stack);
        if ($node instanceof SebastianBergmann\CodeCoverage\Node\Directory) {
            foreach ($node->children() as $child) {
                $stack[] = $child;
            }
        }
        if (! $node instanceof SebastianBergmann\CodeCoverage\Node\File) {
            continue;
        }
        $relative = substr($node->pathAsString(), strlen($srcPrefix));
        foreach ($node->lineCoverageData() as $line => $count) {
            $hits = is_array($count) ? max($count ?: [0]) : $count;
            if ($hits < 1) {
                $uncovered[] = $relative . ':' . $line;
            }
        }
    }

    $waivedHits = 0;
    $blocking = [];
    foreach ($uncovered as $line) {
        if (isset($waived[$line])) {
            $waivedHits++;
        } else {
            $blocking[] = $line;
        }
    }

    printf("PROVABLY UNREACHABLE (waived, proven in coverage-unreachable.php): %d line(s)\n", $waivedHits);

    if ($blocking !== []) {
        printf("GATE: FAIL - %d uncovered line(s) with no proof:\n", count($blocking));
        foreach ($blocking as $line) {
            echo '  ', $line, "\n";
        }
        exit(1);
    }

    echo 'GATE: PASS (every executable line is covered or provably unreachable)', PHP_EOL;

    return;
}

fwrite(STDERR, "usage: php .github/coverage-runner.php --collect <suite> <out.php> | --merge <collected.php> ...\n");
exit(2);

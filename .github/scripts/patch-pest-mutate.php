<?php

declare(strict_types=1);

/*
 * Four small patches to pest-plugin-mutate, applied to `vendor/` before a mutation run. Each closes a
 * way the run reported a score it had not measured. Idempotent; refuses to guess — if a line it rewrites
 * is not the one it expects, it fails the job rather than run unpatched.
 *
 * Usage: php .github/scripts/patch-pest-mutate.php [path/to/vendor]
 *
 * 1. FILTER — hand the child a `--filter` it can actually use.
 *
 *    The plugin hands each mutant's covering tests to its child process as a single
 *    `--filter="A::(.*)x|A::(.*)y|…"` argument, one alternative per test. On a line much of the suite
 *    covers, that argument breaks twice over:
 *
 *    - Past ~35,000 bytes (about 370 tests) PCRE cannot COMPILE it — `preg_match()` answers `false`,
 *      "Internal error" — and PHPUnit, which suppresses that with `@`, reads every test as not matching.
 *      The child spends ~19 s failing to compile it once per test, reports "No tests found", and exits
 *      non-zero; the plugin scores a non-zero exit as a KILL (or, past its budget, a timeout, which it
 *      also counts as caught). Measured here on 2026-11-14: 895 of 4,394 mutants — the service provider,
 *      the `Lukk` hub, the route manifest and the hot paths of login — were "killed" this way without a
 *      single test having run. Every score reported for those lines before this patch was unmeasured.
 *    - Past 131,072 bytes Linux refuses to start the child at all: one argv element is capped at
 *      MAX_ARG_STRLEN (PAGE_SIZE * 32, not tunable — `ulimit -s` moves the total, never the per-element
 *      cap), `proc_open` fails with `ProcessStartFailedException`, and the whole run dies without a
 *      score. macOS has no such cap. The nightly run was red from 2026-10-12, the first night after the
 *      suite crossed that line, for this reason alone.
 *
 *    So the plugin asks `Lukk\Tests\Support\MutationFilter` (tests/Support, unit-tested) for the argument
 *    instead. It factors the class prefix (`A::(.*)(x|y)` — lossless), then collapses classes to a bare
 *    `A::`, heaviest first and only as many as it must, until the filter both fits and COMPILES; and it
 *    throws rather than hand over one that cannot work. A collapsed class selects a superset: a test
 *    that never executes the mutated line cannot tell the mutant from the original, so while the suite
 *    is green the verdict is the same and only the runtime moves.
 *    Upstream: https://github.com/pestphp/pest/issues/1771 and pestphp/pest-plugin-mutate#43, whose
 *    encoding this uses — that change budgets by bytes alone, under which a filter that fits still
 *    compiles to nothing.
 *
 * 2. BUDGET — give a mutant time to reach the test that kills it.
 *
 *    The plugin budgets each mutant at the initial suite duration plus 20% (at least 5 s) and scores one
 *    that runs out as caught, on the theory that the mutation made the code hang. But that duration is
 *    measured across every parallel process, and a mutant's tests run in ONE, beside the other mutants:
 *    a mutant on a line most of the suite covers simply had not reached its failing test yet. A timeout
 *    therefore proves nothing either way. Measured here: a run reporting 100% with 132 timeouts was
 *    really 97.73% (2026-09-20).
 *
 *    The budget becomes ten times the suite duration plus a minute. A mutation that truly hangs still
 *    ends, and `.github/scripts/run-mutation.sh` fails the job on ANY remaining timeout rather than
 *    counting it as caught.
 *
 * 3. REPORT — name the mutants that timed out, as the plugin names the ones that survived, so a timeout
 *    can be looked at instead of merely counted.
 *
 * 4. VERDICT — a child that ran NO tests has caught nothing.
 *
 *    The plugin asks only whether the child exited non-zero. "No tests found" exits non-zero too, which
 *    is how (1) went unnoticed for so long. Such a mutant is now reported as UNTESTED — it survived, as
 *    far as anything measured — so a filter that selects nothing can never again pass for a kill.
 *
 * When a plugin release rewrites the line (1) replaces, this script FAILS rather than skip: a fix that
 * bounds the argument by bytes alone (pestphp/pest-plugin-mutate#43 as proposed) still hands over a filter
 * PCRE cannot compile. Drop (1) only once the plugin's own filter is checked to compile — with (4) in
 * place a run without it reports those mutants UNTESTED, never killed. (2), (3) and (4) have no upstream
 * equivalent.
 */

$vendor = ($argv[1] ?? __DIR__.'/../../vendor').'/pestphp/pest-plugin-mutate/src';

$patches = [
    'filter' => [
        'file' => 'MutationTest.php',
        'from' => <<<'PHP'
'--filter="'.implode('|', $filters).'"',
PHP,
        'to' => <<<'PHP'
\Lukk\Tests\Support\MutationFilter::argument(array_values($filters)), // patched by lukk: .github/scripts/patch-pest-mutate.php
PHP,
    ],
    'budget' => [
        'file' => 'MutationTest.php',
        'from' => <<<'PHP'
return (int) ($initialTestSuiteDuration + max(5, $initialTestSuiteDuration * 0.2));
PHP,
        'to' => <<<'PHP'
return (int) ($initialTestSuiteDuration * 10 + 60); // patched by lukk: .github/scripts/patch-pest-mutate.php
PHP,
    ],
    'verdict' => [
        'file' => 'MutationTest.php',
        'from' => <<<'PHP'
        if ($this->process->isSuccessful()) {
            $this->updateResult(MutationTestResult::Untested);
PHP,
        'to' => <<<'PHP'
        if ($this->process->isSuccessful() || str_contains($this->process->getOutput(), 'No tests found')) { // patched by lukk: .github/scripts/patch-pest-mutate.php
            $this->updateResult(MutationTestResult::Untested);
PHP,
    ],
    'report: which results are listed' => [
        'file' => 'Support/Printers/DefaultPrinter.php',
        'from' => <<<'PHP'
if (! in_array($test->result(), [MutationTestResult::Untested, MutationTestResult::Uncovered], true)) {
PHP,
        'to' => <<<'PHP'
if (! in_array($test->result(), [MutationTestResult::Untested, MutationTestResult::Uncovered, MutationTestResult::Timeout], true)) { // patched by lukk: .github/scripts/patch-pest-mutate.php
PHP,
    ],
    'report: the label' => [
        'file' => 'Support/Printers/DefaultPrinter.php',
        'from' => <<<'PHP'
        if ($test->result() === MutationTestResult::Untested) {
            $color = 'red';
            $label = 'UNTESTED';
        } else {
PHP,
        'to' => <<<'PHP'
        if ($test->result() === MutationTestResult::Untested) {
            $color = 'red';
            $label = 'UNTESTED';
        } elseif ($test->result() === MutationTestResult::Timeout) { // patched by lukk: .github/scripts/patch-pest-mutate.php
            $color = 'yellow';
            $label = 'TIMEOUT';
        } else {
PHP,
    ],
];

$failed = false;

foreach ($patches as $name => $patch) {
    $file = $vendor.'/'.$patch['file'];
    $source = @file_get_contents($file);

    if ($source === false) {
        fwrite(STDERR, "patch-pest-mutate [{$name}]: cannot read {$file} — run composer install first.\n");
        $failed = true;

        continue;
    }

    if (str_contains($source, $patch['to'])) {
        echo "patch-pest-mutate [{$name}]: already applied.\n";

        continue;
    }

    if (substr_count($source, $patch['from']) !== 1) {
        fwrite(STDERR, "patch-pest-mutate [{$name}]: the code in {$file} is not what this patch rewrites. Re-derive the patch for this plugin version; do not run the mutation job without it.\n");
        $failed = true;

        continue;
    }

    file_put_contents($file, str_replace($patch['from'], $patch['to'], $source));
    echo "patch-pest-mutate [{$name}]: applied.\n";
}

exit($failed ? 1 : 0);

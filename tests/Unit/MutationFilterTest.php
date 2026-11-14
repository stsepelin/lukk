<?php

declare(strict_types=1);

use Lukk\Tests\Support\MutationFilter;

/*
 * The filter a mutation run hands each mutant's child process — see `MutationFilter`. Not package code:
 * it is the instrument the package's mutation score is read with, and it was wrong for a fifth of the
 * mutants while reporting 100%, so it is tested like the thing it measures.
 */

/** Does PHPUnit, given this pattern, select this test? Mirrors `NameFilterIterator`. */
function selects(string $pattern, string $test): bool
{
    $regex = @preg_match($pattern, '') === false ? '{'.$pattern.'}i' : $pattern;

    return @preg_match($regex, $test) === 1;
}

/**
 * Fragments shaped like the plugin's, for `$classes` test classes of `$perClass` tests each.
 *
 * @return list<string>
 */
function fragments(int $classes, int $perClass): array
{
    $fragments = [];

    for ($c = 0; $c < $classes; $c++) {
        for ($t = 0; $t < $perClass; $t++) {
            $fragments[] = "Class{$c}Test::(.*)it.does.the.{$t}th.thing.{1,2}with.a.reasonably.long.description.of.what.it.pins";
        }
    }

    return $fragments;
}

/** The test name a fragment was built from, as PHPUnit would present it. */
function testNamed(string $fragment): string
{
    [$class, $tail] = explode('::(.*)', $fragment, 2);

    return 'P\\Tests\\Unit\\'.$class.'::__pest_evaluable_'.str_replace(['.{1,2}', '.'], ['__', '_'], $tail);
}

it('selects exactly the covering tests when the filter is small', function () {
    $fragments = ['LoginTest::(.*)it.signs.in', 'LoginTest::(.*)it.refuses.a.wrong.password', 'TokenTest::(.*)it.mints'];

    [$pattern, $collapsed] = MutationFilter::pattern($fragments);

    expect($collapsed)->toBe([])
        ->and($pattern)->toBe('"LoginTest::(.*)(it.signs.in|it.refuses.a.wrong.password)|TokenTest::(.*)(it.mints)"')
        ->and(selects($pattern, 'P\\Tests\\Feature\\LoginTest::__pest_evaluable_it_signs_in'))->toBeTrue()
        ->and(selects($pattern, 'P\\Tests\\Feature\\LoginTest::__pest_evaluable_it_refuses_a_wrong_password'))->toBeTrue()
        ->and(selects($pattern, 'P\\Tests\\Unit\\TokenTest::__pest_evaluable_it_mints'))->toBeTrue()
        // A test of a covering class that does not cover the line stays out…
        ->and(selects($pattern, 'P\\Tests\\Feature\\LoginTest::__pest_evaluable_it_throttles'))->toBeFalse()
        // …and so does another class's test that happens to share a name. Without the inner parentheses
        // the alternation binds to the whole pattern, and a bare `it.refuses.a.wrong.password` matches anywhere.
        ->and(selects($pattern, 'P\\Tests\\Feature\\ConfirmTest::__pest_evaluable_it_refuses_a_wrong_password'))->toBeFalse();
});

it('hands PHPUnit the whole argv element, quotes included', function () {
    expect(MutationFilter::argument(['LoginTest::(.*)it.signs.in']))->toBe('--filter="LoginTest::(.*)(it.signs.in)"');
});

it('names a test once however many times it covers the line', function () {
    expect(MutationFilter::pattern(['A::(.*)x', 'A::(.*)x', 'A::(.*)y'])[0])->toBe('"A::(.*)(x|y)"');
});

it('passes a fragment of a shape it does not recognise through untouched', function () {
    // If the plugin ever builds fragments differently, this degrades to what the plugin does today
    // rather than dropping a selection.
    [$pattern] = MutationFilter::pattern(['some raw pattern', 'A::(.*)x']);

    expect($pattern)->toBe('"some raw pattern|A::(.*)(x)"')
        ->and(selects($pattern, 'a test matching some raw pattern here'))->toBeTrue();
});

it('gives up exactness, never usability, when the exact filter is too large to compile', function () {
    // 60 classes × 25 tests: ~150,000 bytes one alternative per test — over PCRE's compile limit AND over
    // Linux's cap on one argument. The plugin's own filter for this selects nothing, and scores a kill.
    $fragments = fragments(60, 25);
    $asThePluginBuildsIt = '"'.implode('|', $fragments).'"';
    expect(strlen($asThePluginBuildsIt))->toBeGreaterThan(131072)
        ->and(MutationFilter::usable($asThePluginBuildsIt))->toBeFalse()
        ->and(selects($asThePluginBuildsIt, testNamed($fragments[0])))->toBeFalse();

    [$pattern, $collapsed] = MutationFilter::pattern($fragments);

    expect(MutationFilter::usable($pattern))->toBeTrue()
        ->and(strlen('--filter='.$pattern))->toBeLessThanOrEqual(MutationFilter::BUDGET_BYTES)
        // Some classes had to be collapsed, and not all of them: no more is widened than has to be.
        ->and(count($collapsed))->toBeGreaterThan(0)->toBeLessThan(60);

    // A superset: every covering test is still selected.
    foreach ($fragments as $fragment) {
        expect(selects($pattern, testNamed($fragment)))->toBeTrue();
    }

    // A collapsed class now runs whole; one that was not collapsed still runs only its covering tests.
    $kept = array_values(array_diff(array_map(fn (int $c) => "Class{$c}Test", range(0, 59)), $collapsed))[0];
    expect(selects($pattern, 'P\\Tests\\Unit\\'.$collapsed[0].'::__pest_evaluable_it_is_some_other_test'))->toBeTrue()
        ->and(selects($pattern, 'P\\Tests\\Unit\\'.$kept.'::__pest_evaluable_it_is_some_other_test'))->toBeFalse();
});

it('decides by compiling, not by length: a filter that fits can still select nothing', function () {
    // ~60,000 bytes factored: comfortably inside every byte budget, and PCRE still refuses it. A
    // byte budget alone hands this over, the child runs no test, and the mutant is "killed".
    $fragments = fragments(40, 15);
    $factoredOnly = '"'.implode('|', array_map(
        fn (int $c) => "Class{$c}Test::(.*)(".implode('|', array_map(fn (string $f) => explode('::(.*)', $f, 2)[1], array_slice($fragments, $c * 15, 15))).')',
        range(0, 39),
    )).'"';
    expect(strlen($factoredOnly))->toBeLessThan(MutationFilter::BUDGET_BYTES)
        ->and(MutationFilter::usable($factoredOnly))->toBeFalse();

    [$pattern, $collapsed] = MutationFilter::pattern($fragments);

    expect(MutationFilter::usable($pattern))->toBeTrue()
        ->and($collapsed)->not->toBe([])
        ->and(selects($pattern, testNamed($fragments[0])))->toBeTrue()
        ->and(selects($pattern, testNamed($fragments[599])))->toBeTrue();
});

it('refuses to hand over a filter that cannot work, rather than one that selects nothing', function () {
    // A budget nothing fits in stands in for a suite with more test classes than any filter can name.
    expect(fn () => MutationFilter::pattern(fragments(5, 2), 20))
        ->toThrow(RuntimeException::class, 'No usable mutation filter');
});

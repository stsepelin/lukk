<?php

declare(strict_types=1);

namespace Lukk\Tests\Support;

use RuntimeException;

/**
 * The single `--filter=` argument a mutant's child process is started with.
 *
 * pest-plugin-mutate selects a mutant's covering tests with one regex alternative per test, joined into
 * one argv element: `--filter="A::(.*)x|A::(.*)y|…"`. On a line much of the suite covers that breaks
 * twice, and `.github/scripts/patch-pest-mutate.php` makes the plugin ask this class instead:
 *
 *  - Past ~35,000 bytes PCRE cannot COMPILE the pattern. PHPUnit suppresses that (`@preg_match`) and
 *    reads every test as not matching, so the child reports "No tests found" and exits non-zero — which
 *    the plugin scores as a kill. 895 of this package's 4,394 mutants were "killed" that way, by a child
 *    that ran nothing (2026-11-14).
 *  - Past 131,072 bytes Linux will not start the child at all (MAX_ARG_STRLEN, one argv element), and the
 *    whole run dies. macOS has no such cap.
 *
 * Two encodings, the second only as far as it is needed:
 *
 *  1. FACTOR the class prefix: `A::(.*)x|A::(.*)y` becomes `A::(.*)(x|y)`. Lossless — the same tests,
 *     about a quarter shorter. The inner parentheses are load-bearing: without them the alternation
 *     binds to the whole pattern and a bare `y` matches anywhere.
 *  2. COLLAPSE a class to its bare `A::`, heaviest first, one at a time, until the filter is USABLE.
 *     That selects a superset. A test that never executes the mutated line cannot tell the mutant from
 *     the original, so while the suite is green the verdict is unchanged; only the runtime moves, which
 *     is why no more is collapsed than has to be.
 *
 * USABLE is decided by doing what PHPUnit will do — compiling the value it will be handed — and not by
 * a byte count: the limit depends on the pattern's shape, and a filter that merely fits is the one that
 * selected nothing. (The factoring and the gradual collapse are pestphp/pest-plugin-mutate#43's; that
 * change stops at a byte budget, under which a 96,000-byte filter still compiles to nothing.)
 *
 * If even every class collapsed is unusable it THROWS. Handing over a filter that selects nothing is the
 * defect this exists to end.
 */
class MutationFilter
{
    /**
     * Under Linux's 131,072-byte cap on one argv element, with room: a suite only grows, and a filter
     * sized to the exact limit is one new test away from failing again.
     */
    public const BUDGET_BYTES = 98304;

    /** How many mutants were given a widened filter in this process, for the note at the end of a run. */
    private static int $widened = 0;

    /**
     * @param  list<string>  $fragments  one `Class::(.*)test.name` fragment per covering test
     * @return string the whole argv element, `--filter="…"`
     */
    public static function argument(array $fragments, int $budget = self::BUDGET_BYTES): string
    {
        [$pattern, $collapsed] = self::pattern($fragments, $budget);

        if ($collapsed !== [] && self::$widened++ === 0) {
            // Once, when the run ends: a widening that nobody is told about would let the score claim
            // more precision than the run had.
            register_shutdown_function(static function (): void {
                fwrite(STDERR, sprintf(
                    "\n  %d mutant(s) ran every test of some covering classes rather than the exact covering tests: the exact filter was too large for PCRE to compile. A superset — it cannot fabricate a kill while the suite is green.\n",
                    self::$widened,
                ));
            });
        }

        return '--filter='.$pattern;
    }

    /**
     * The pattern exactly as PHPUnit receives it — quotes included, which it reads as the delimiters —
     * and the classes that had to be collapsed to get there.
     *
     * @param  list<string>  $fragments
     * @return array{0: string, 1: list<string>}
     */
    public static function pattern(array $fragments, int $budget = self::BUDGET_BYTES): array
    {
        /** @var array<string, list<string>> $tails by class, in first-seen order */
        $tails = [];
        /** @var list<string> $raw fragments of a shape this does not recognise, passed through untouched */
        $raw = [];

        foreach ($fragments as $fragment) {
            if (preg_match('/\A([A-Za-z0-9_]+)::\(\.\*\)(.*)\z/s', $fragment, $matches) === 1) {
                $tails[$matches[1]][] = $matches[2];
            } else {
                $raw[] = $fragment;
            }
        }

        $collapsed = [];
        $render = static function () use (&$tails, &$collapsed, $raw): string {
            $parts = $raw;

            foreach ($tails as $class => $names) {
                $parts[] = isset($collapsed[$class])
                    ? $class.'::'
                    : $class.'::(.*)('.implode('|', array_unique($names)).')';
            }

            return '"'.implode('|', $parts).'"';
        };

        // Heaviest class first, so the fewest collapses buy the most room.
        $weights = array_map(static fn (array $names): int => strlen(implode('|', array_unique($names))), $tails);
        arsort($weights);

        $pattern = $render();

        foreach (array_keys($weights) as $class) {
            if (self::usable($pattern, $budget)) {
                break;
            }

            $collapsed[$class] = true;
            $pattern = $render();
        }

        if (! self::usable($pattern, $budget)) {
            throw new RuntimeException(sprintf(
                'No usable mutation filter: with every covering class collapsed to its prefix it is still %d bytes (budget %d) or does not compile. Running it would select no test and score the mutant as killed.',
                strlen($pattern),
                $budget,
            ));
        }

        return [$pattern, array_map('strval', array_keys($collapsed))];
    }

    /**
     * Will PHPUnit be able to select tests with this value?
     *
     * `NameFilterIterator::prepareFilter()` tries the value as a pattern in its own right — the leading
     * quote is a legal delimiter — and wraps it as `{…}i` when that fails. Whichever it ends up with has
     * to compile, or every test is "not matched" and none runs.
     */
    public static function usable(string $pattern, int $budget = self::BUDGET_BYTES): bool
    {
        return strlen('--filter='.$pattern) <= $budget
            && (@preg_match($pattern, '') !== false || @preg_match('{'.$pattern.'}i', '') !== false);
    }
}

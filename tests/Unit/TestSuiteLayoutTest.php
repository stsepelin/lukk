<?php

declare(strict_types=1);

it('runs every directory of tests', function () {
    // `phpunit.xml.dist` lists the test directories one by one, in the order a mutation run should meet
    // them (see the comment there). The price of a list is that a NEW directory is silently not run —
    // green, with nothing in it executed — so every directory under tests/ that holds a test must be on it.
    $root = dirname(__DIR__);
    $listed = [];
    foreach (simplexml_load_file(dirname($root).'/phpunit.xml.dist')->testsuites->testsuite->directory as $directory) {
        $listed[] = (string) $directory;
    }

    $holdingTests = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)) as $file) {
        if (str_ends_with($file->getFilename(), 'Test.php')) {
            // The top-level directory under tests/ the file sits in.
            $holdingTests['tests/'.explode('/', substr($file->getPathname(), strlen($root) + 1))[0]] = true;
        }
    }

    expect($listed)->toEqualCanonicalizing(array_keys($holdingTests))
        // Isolated first, then Unit: the tests that pin the boot path before the bulk of the suite.
        ->and(array_slice($listed, 0, 2))->toBe(['tests/Isolated', 'tests/Unit']);
});

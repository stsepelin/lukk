<?php

declare(strict_types=1);

use Lukk\Support\RecoveryCode;

uses()->group('two-factor');

it('generates two 10-character alphanumeric halves — about 119 bits — joined by a dash', function () {
    // 20 characters from a 62-symbol alphabet is log2(62^20) ≈ 119 bits: the entropy that lets a
    // recovery code skip the consecutive-failure lock. A shorter code would quietly weaken that.
    $codes = array_map(fn () => RecoveryCode::generate(), range(1, 50));

    foreach ($codes as $code) {
        expect($code)->toMatch('/\A[A-Za-z0-9]{10}-[A-Za-z0-9]{10}\z/');
    }

    expect(array_unique($codes))->toHaveCount(50);
});

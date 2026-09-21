<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Lukk\Tests\LimiterDefaultsTestCase;

uses(LimiterDefaultsTestCase::class)->group('multi-guard');

it('falls back to each extra-guard limiter\'s own default when no limits are configured at all', function (string $name, int $max, int $decay) {
    // A missing key must be a sane default, never `Limit(0)` — which locks everyone out. And the
    // default must not be LOOSER than what config/lukk.php ships: `two_factor` fell back to 30
    // against a shipped 5 on these guards, which is the same degraded-config defect the default
    // guard's `$shipped` table fixed, left standing on the higher-privilege audiences multi-guard
    // exists for. (`login`/`refresh`/`claim` really do ship 30.)
    $limits = app(RateLimiter::class)->limiter($name)(Request::create('/', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9']));
    $limit = is_array($limits) ? $limits[0] : $limits;

    expect([$limit->maxAttempts, $limit->decaySeconds])->toBe([$max, $decay]);
})->with([
    ['lukk-admin-login', 30, 60],
    ['lukk-admin-refresh', 30, 60],
    ['lukk-admin-2fa', 5, 60],
    ['lukk-admin-confirm', 5, 60],
    ['lukk-admin-claim', 30, 60],
]);

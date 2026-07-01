<?php

declare(strict_types=1);

use Lukk\Models\RefreshToken;

it('prunes expired tokens but keeps active and revoked-but-unexpired ones', function () {
    // One soon-to-expire token (pruned)...
    config(['lukk.refresh_ttl' => 1]);
    start()(1);

    // ...one long-lived active token (kept)...
    config(['lukk.refresh_ttl' => 2592000]);
    start()(2);

    // ...and one revoked-but-unexpired token — KEPT so a replay still resolves to `reuse`
    // (fires the reuse event + family cascade) instead of a generic `unknown` reject.
    start()(3);
    revokeSession()(RefreshToken::where('user_id', 3)->value('family_id'));

    $this->travel(5)->seconds();

    $this->artisan('lukk:prune')
        ->expectsOutputToContain('Pruned 1 refresh token(s).')
        ->assertSuccessful();

    expect(RefreshToken::count())->toBe(2);
    expect(RefreshToken::where('user_id', 2)->exists())->toBeTrue();
    expect(RefreshToken::where('user_id', 3)->exists())->toBeTrue();
});

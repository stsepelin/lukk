<?php

declare(strict_types=1);

use Lukk\Models\RefreshToken;

it('prunes expired and revoked tokens but keeps active ones', function () {
    // One soon-to-expire token...
    config(['lukk.refresh_ttl' => 1]);
    start()(1);

    // ...one long-lived active token...
    config(['lukk.refresh_ttl' => 2592000]);
    start()(2);

    // ...and one active-but-revoked token.
    start()(3);
    revokeSession()(RefreshToken::where('user_id', 3)->value('family_id'));

    $this->travel(5)->seconds();

    $this->artisan('lukk:prune')
        ->expectsOutputToContain('Pruned 2 refresh token(s).')
        ->assertSuccessful();

    expect(RefreshToken::count())->toBe(1);
    expect(RefreshToken::where('user_id', 2)->exists())->toBeTrue();
});

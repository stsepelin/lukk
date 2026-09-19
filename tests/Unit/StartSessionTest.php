<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Lukk\Actions\StartSession;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Models\RefreshToken;
use Lukk\Support\UnclaimedSessions;

beforeEach(fn () => $this->freezeSecond());

/** Start a session with an unclaimed-marker store; returns the store and the new family id. */
function startMarked(array $config): array
{
    $unclaimed = new UnclaimedSessions(Cache::store('array'));
    (new StartSession(app(RefreshTokenRepository::class), app(TokenIssuer::class), $config, 'api', $unclaimed))(1);

    return [$unclaimed, (string) RefreshToken::query()->value('family_id')];
}

it('keeps the unclaimed marker for the whole refresh lifetime, read from env as a string', function () {
    // Shorter, and a first use still able to arrive would find no marker: a lost sign-in would count
    // as claimed. `claim_seconds` never needs it longer than the refresh token can live.
    [$unclaimed, $family] = startMarked(['refresh_ttl' => '100']);

    $this->travel(99)->seconds();
    expect($unclaimed->issuedAt($family))->not->toBeNull();

    $this->travel(1)->seconds();
    expect($unclaimed->issuedAt($family))->toBeNull();
});

it('keeps the unclaimed marker thirty days when refresh_ttl is unset', function () {
    [$unclaimed, $family] = startMarked([]);

    $this->travel(2591999)->seconds();
    expect($unclaimed->issuedAt($family))->not->toBeNull();

    $this->travel(1)->seconds();
    expect($unclaimed->issuedAt($family))->toBeNull();
});

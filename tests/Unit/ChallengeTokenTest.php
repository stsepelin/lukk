<?php

declare(strict_types=1);

use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\Denylist;

function challenge(): ChallengeToken
{
    return app(ChallengeToken::class);
}

it('issues a challenge that consumes back to the subject', function () {
    $token = challenge()->issue('2fa', 42, 300);

    expect(challenge()->consume('2fa', $token))->toBe('42');
});

it('is single-use', function () {
    $token = challenge()->issue('2fa', 42, 300);

    expect(challenge()->consume('2fa', $token))->toBe('42');
    expect(challenge()->consume('2fa', $token))->toBeNull();
});

it('rejects a challenge presented as a different kind', function () {
    $token = challenge()->issue('2fa', 42, 300);

    expect(challenge()->consume('passkey', $token))->toBeNull();
});

it('rejects an expired challenge', function () {
    // Minted in the past so its exp is already behind the real clock the JWT lib uses.
    $token = $this->travel(-600)->seconds(fn () => challenge()->issue('2fa', 42, 300));

    expect(challenge()->consume('2fa', $token))->toBeNull();
});

it('rejects a garbage token', function () {
    expect(challenge()->consume('2fa', 'not-a-jwt'))->toBeNull();
});

it('rejects a challenge minted for a different audience', function () {
    $foreign = new ChallengeToken([
        'secret' => config('lukk.secret'),
        'algorithm' => config('lukk.algorithm'),
        'issuer' => config('lukk.issuer'),
        'audience' => 'https://evil.example.com',
        'leeway' => 0,
    ], app(Denylist::class));

    expect(challenge()->consume('2fa', $foreign->issue('2fa', 42, 300)))->toBeNull();
});

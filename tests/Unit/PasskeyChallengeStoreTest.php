<?php

declare(strict_types=1);

use Lukk\Passkeys\PasskeyChallengeStore;

uses()->group('passkeys');

function challengeStore(): PasskeyChallengeStore
{
    return app(PasskeyChallengeStore::class);
}

it('generates a base64url challenge of at least 16 bytes', function () {
    $challenge = challengeStore()->generate();

    expect($challenge)->toBeString();
    expect(strlen((string) base64_decode(strtr($challenge, '-_', '+/'))))->toBeGreaterThanOrEqual(16);
});

it('stores and pulls a user registration challenge once (single-use)', function () {
    challengeStore()->putForUser(7, 'CHALLENGE');

    expect(challengeStore()->pullForUser(7))->toBe('CHALLENGE');
    expect(challengeStore()->pullForUser(7))->toBeNull();
});

it('stores a login challenge under an opaque ceremony id (single-use)', function () {
    $id = challengeStore()->putForCeremony('CHALLENGE');

    expect($id)->toBeString()->not->toBe('');
    expect(challengeStore()->pullForCeremony($id))->toBe('CHALLENGE');
    expect(challengeStore()->pullForCeremony($id))->toBeNull();
});

it('returns null pulling an empty or unknown ceremony id', function () {
    expect(challengeStore()->pullForCeremony(''))->toBeNull();
    expect(challengeStore()->pullForCeremony('unknown'))->toBeNull();
});

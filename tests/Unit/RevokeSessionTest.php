<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Lukk\Contracts\Denylist;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\User;

uses()->group('refresh');

// No `lukk` key is guaranteed at runtime: `mergeConfigDeep` early-returns when the application's
// config is CACHED, which is the production norm, so an app that ran `config:cache` on an older
// version gets no backfill for a key added since. The denylist TTL is the worst place for that to
// land — two missing reads add to 0, and `Cache::put()` with a non-positive TTL FORGETS the key
// instead of writing it, so the revoke would denylist NOTHING and every access token of the family
// it just ended would keep working for the rest of its life.
it('still denylists the family when access_ttl and leeway are missing from the config', function () {
    $user = User::factory()->create();
    $pair = start()($user->id);
    $family = (string) RefreshToken::where('token_hash', hash('sha256', $pair->refreshToken))->value('family_id');

    // A cached config that predates both keys, not merely one holding odd values.
    config()->set('lukk', Arr::except(config('lukk'), ['access_ttl', 'leeway']));

    revokeSession()($family);

    expect(app(Denylist::class)->has('fid', $family))->toBeTrue()
        ->and(RefreshToken::where('family_id', $family)->whereNull('revoked_at')->exists())->toBeFalse();
});

<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Lukk\Actions\RevokeOtherSessions;
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

// The same read, on the higher-stakes operation. `DELETE /auth/sessions` is the "sign me out
// everywhere" button: denylisting nothing there answers 204 while every access token it claimed to
// kill keeps working for the rest of its life. The guarded read once reached `RevokeSession` alone.
it('still denylists every family when logout-all runs with access_ttl and leeway missing', function () {
    $user = User::factory()->create();
    $families = collect([start()($user->id), start()($user->id)])
        ->map(fn ($pair) => (string) RefreshToken::where('token_hash', hash('sha256', $pair->refreshToken))->value('family_id'));

    config()->set('lukk', Arr::except(config('lukk'), ['access_ttl', 'leeway']));

    revokeAll()($user->id);

    $families->each(fn (string $family) => expect(app(Denylist::class)->has('fid', $family))->toBeTrue());
    expect(RefreshToken::where('user_id', $user->id)->whereNull('revoked_at')->exists())->toBeFalse();
});

it('still denylists the other families when logout-others runs with access_ttl and leeway null', function () {
    // Null, not absent: the merge backfills on `array_key_exists`, so a per-guard
    // `'access_ttl' => env('LUKK_ADMIN_ACCESS_TTL')` with the variable unset survives it intact —
    // the shape that reaches a running application without anyone having cached a stale config.
    $user = User::factory()->create();
    $current = start()($user->id);
    $other = start()($user->id);
    $family = fn ($pair) => (string) RefreshToken::where('token_hash', hash('sha256', $pair->refreshToken))->value('family_id');

    config()->set('lukk.access_ttl', null);
    config()->set('lukk.leeway', null);

    app(RevokeOtherSessions::class)($user->id, $family($current));

    expect(app(Denylist::class)->has('fid', $family($other)))->toBeTrue()
        ->and(app(Denylist::class)->has('fid', $family($current)))->toBeFalse();
});

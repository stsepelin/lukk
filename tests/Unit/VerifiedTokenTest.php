<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Support\Abilities;
use Lukk\Support\VerifiedToken;
use Lukk\Tests\Fixtures\User;

uses()->group('abilities');

function token(string $guard, string $abilities, int $userId = 1, string $class = User::class): VerifiedToken
{
    return new VerifiedToken(
        guard: $guard,
        userId: $userId,
        userClass: $class,
        familyId: 'fam',
        abilities: Abilities::fromScope($abilities),
        claims: (object) ['sub' => (string) $userId, 'scope' => $abilities],
    );
}

it('returns the token for the ACTIVE guard when a user matches more than one', function () {
    // Two guards sharing a provider: same class, same id, so class+id no longer separates them.
    $request = Request::create('/');
    VerifiedToken::put($request, token('admin', 'admin.all'));
    VerifiedToken::put($request, token('api', 'orders.read'));

    $user = new User;
    $user->id = 1;

    expect(VerifiedToken::forUser($request, $user)?->abilities->all())->toBe(['orders.read']);
});

it('grants nothing when two guards match and neither is the active one', function () {
    // Handing back whichever iterated first would answer an authorization question with a token
    // minted for a different audience. There is no right answer here, so there is no answer.
    $request = Request::create('/');
    VerifiedToken::put($request, token('admin', 'admin.all'));
    VerifiedToken::put($request, token('partner', 'partner.read'));

    $user = new User;
    $user->id = 1;

    expect(VerifiedToken::forUser($request, $user))->toBeNull();
});

it('uses a single match even when the active guard is not named on the request', function () {
    // The ordinary case: one guard authenticated, and nothing pinned the active guard to its name.
    $request = Request::create('/');
    VerifiedToken::put($request, token('partner', 'partner.read'));

    $user = new User;
    $user->id = 1;

    expect(VerifiedToken::forUser($request, $user)?->abilities->all())->toBe(['partner.read']);
});

it('never matches a different id or a different model class', function () {
    $request = Request::create('/');
    VerifiedToken::put($request, token('api', 'orders.read', userId: 7));

    $other = new User;
    $other->id = 8;
    expect(VerifiedToken::forUser($request, $other))->toBeNull();

    $request2 = Request::create('/');
    VerifiedToken::put($request2, token('api', 'orders.read', userId: 7, class: 'App\\Models\\Admin'));

    $seven = new User;
    $seven->id = 7;
    expect(VerifiedToken::forUser($request2, $seven))->toBeNull();
});

it('resolves current() by guard, by active guard, or by being the only one', function () {
    $request = Request::create('/');
    expect(VerifiedToken::current($request))->toBeNull();

    VerifiedToken::put($request, token('partner', 'partner.read'));
    expect(VerifiedToken::current($request, 'partner')?->guard)->toBe('partner')
        ->and(VerifiedToken::current($request, 'nope'))->toBeNull()
        ->and(VerifiedToken::current($request)?->guard)->toBe('partner');

    // Two tokens, neither on the active guard: ambiguous, so nothing. The ability middleware then
    // denies — fail closed, per RequireAbility's deny-by-default contract.
    VerifiedToken::put($request, token('admin', 'admin.all'));
    expect(VerifiedToken::current($request))->toBeNull();
});

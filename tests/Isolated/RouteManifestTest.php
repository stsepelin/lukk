<?php

declare(strict_types=1);

use Illuminate\Support\Facades\RateLimiter;
use Lukk\Http\Middleware\ForceJsonRequest;
use Lukk\Http\Middleware\RefuseForgeableCookieGrant;
use Lukk\Http\Middleware\RequirePinnedAbility;
use Lukk\Tests\MultiGuardTestCase;

uses(MultiGuardTestCase::class)->group('multi-guard');

/*
 * The route manifest, written out: every route lukk mounts with every feature on and one extra guard,
 * and the exact middleware each carries, in order.
 *
 * The flows are tested elsewhere, and they cannot see most of this. A route that loses its throttle
 * still answers 200; one that loses `signed` still verifies a correctly signed link; one that loses
 * `lukk.confirm` still works for a caller who happens to have confirmed. Measured on 2026-11-14: eleven
 * middleware entries here could be deleted one at a time with the whole suite green — among them the
 * throttles on the two-factor challenge and on passkey login. So this table is the test: a change to
 * what guards a route has to be made twice, once on purpose.
 */

/** @return array<string, list<string>> */
function mountedRoutes(): array
{
    return collect(app('router')->getRoutes())
        ->mapWithKeys(fn ($route) => [
            implode('|', array_diff($route->methods(), ['HEAD'])).' '.$route->uri() => $route->gatherMiddleware(),
        ])
        ->all();
}

/**
 * @param  list<string>  $group
 * @param  array<string, list<string>>  $routes
 * @return array<string, list<string>>
 */
function under(string $prefix, array $group, array $routes): array
{
    return collect($routes)->mapWithKeys(function (array $middleware, string $route) use ($prefix, $group) {
        [$method, $uri] = explode(' ', $route, 2);

        return [$method.' '.$prefix.'/'.$uri => [...$group, ...$middleware]];
    })->all();
}

it('mounts exactly these routes, each behind exactly this middleware', function () {
    $grant = RefuseForgeableCookieGrant::class;
    $sessions = RequirePinnedAbility::class.':lukk.sessions';
    $account = RequirePinnedAbility::class.':lukk.account';
    $erasure = RequirePinnedAbility::class.':!always,lukk.account.delete';

    $admin = under('admin/auth', ['api', ForceJsonRequest::class, 'lukk.set-guard:admin'], [
        'GET jwks' => [],
        'POST login' => [$grant, 'throttle:lukk-admin-login'],
        'POST refresh' => [$grant, 'throttle:lukk-admin-refresh'],
        'POST two-factor-challenge' => [$grant, 'throttle:lukk-admin-2fa'],
        'POST logout' => [],
        'POST session/claim' => ['auth:admin', 'throttle:lukk-admin-claim'],
        'DELETE sessions' => ['auth:admin', $sessions],
        'DELETE sessions/others' => ['auth:admin', $sessions],
        'POST confirm-password' => ['auth:admin', $account, 'throttle:lukk-admin-confirm'],
    ]);

    $default = under('auth', ['api', ForceJsonRequest::class, 'lukk.set-guard:api'], [
        'GET jwks' => [],
        'POST register' => [$grant, 'throttle:lukk-register'],
        'POST login' => [$grant, 'throttle:lukk-login'],
        'POST refresh' => [$grant, 'throttle:lukk-refresh'],
        'POST logout' => [],
        'POST session/claim' => ['auth:api', 'throttle:lukk-claim'],
        'DELETE sessions' => ['auth:api', $sessions],
        'DELETE sessions/others' => ['auth:api', $sessions],
        'POST confirm-password' => ['auth:api', $account, 'throttle:lukk-confirm'],
        'GET account/export' => ['auth:api', 'lukk.confirm', $erasure, 'throttle:lukk-confirm'],
        'DELETE account' => ['auth:api', 'lukk.confirm', $erasure],
        'POST password' => ['auth:api', $account, 'throttle:lukk-confirm'],
        'POST two-factor-challenge' => [$grant, 'throttle:lukk-2fa'],
        'POST two-factor' => ['auth:api', 'lukk.confirm'],
        'DELETE two-factor' => ['auth:api', 'lukk.confirm'],
        'POST two-factor/confirm' => ['auth:api', 'lukk.confirm', 'throttle:lukk-2fa'],
        'GET two-factor/recovery-codes' => ['auth:api', $account],
        'POST two-factor/recovery-codes' => ['auth:api', 'lukk.confirm'],
        'POST passkeys/login-options' => ['throttle:lukk-passkeys'],
        'POST passkeys/login' => [$grant, 'throttle:lukk-passkeys'],
        'POST confirm-passkey' => ['auth:api', $account, 'throttle:lukk-confirm'],
        'POST confirm-passkey/options' => ['auth:api', $account, 'throttle:lukk-passkeys'],
        'GET passkeys' => ['auth:api', $account],
        'POST passkeys/registration-options' => ['auth:api', 'lukk.confirm'],
        'POST passkeys' => ['auth:api', 'lukk.confirm'],
        'DELETE passkeys/{credentialId}' => ['auth:api', 'lukk.confirm'],
        'POST email/verification-notification' => ['auth:api', 'throttle:lukk-email-verification'],
        'POST forgot-password' => ['throttle:lukk-password-reset'],
        'POST reset-password' => ['throttle:lukk-password-reset'],
    ]);

    // Outside the JSON-forcing group and behind no guard: the signature is the authority.
    $link = ['GET auth/email/verify/{id}/{hash}' => ['api', 'signed', 'throttle:lukk-email-verification']];

    expect(mountedRoutes())->toBe([...$admin, ...$default, ...$link]);
});

it('names only rate limiters that exist', function () {
    // `throttle:lukk-typo` is not an error to Laravel: a name with no limiter behind it is read as a
    // number of attempts, and a route can carry it for years.
    $named = collect(mountedRoutes())->flatten()
        ->filter(fn (string $middleware) => str_starts_with($middleware, 'throttle:'))
        ->map(fn (string $middleware) => substr($middleware, strlen('throttle:')))
        ->unique()->values();

    expect($named)->not->toBeEmpty();

    $named->each(fn (string $name) => expect(RateLimiter::limiter($name))->not->toBeNull("no rate limiter named [{$name}]"));
});

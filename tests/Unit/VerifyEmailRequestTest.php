<?php

declare(strict_types=1);

use Illuminate\Routing\Route;
use Illuminate\Support\Facades\DB;
use Lukk\Http\Requests\VerifyEmailRequest;
use Lukk\Tests\Fixtures\User;

/** A verification request whose route carries `{id}`. */
function verifyRequestFor(int|string $id): VerifyEmailRequest
{
    $request = VerifyEmailRequest::create('/auth/email/verify/'.$id.'/hash');
    $route = (new Route('GET', 'auth/email/verify/{id}/{hash}', []))->bind($request);
    $route->setParameter('id', $id);
    $request->setRouteResolver(fn () => $route);

    return $request;
}

it('looks the addressed user up once, however often it is asked', function () {
    // `authorize()` and the controller both ask; a second query per click is waste on a public link.
    $user = User::factory()->create();
    $request = verifyRequestFor($user->getKey());

    DB::enableQueryLog();
    $request->verifiable();
    $request->verifiable();

    expect(DB::getQueryLog())->toHaveCount(1);
});

it('addresses users through the configured provider, and finds nobody through an unconfigured one', function () {
    // A provider name `auth.providers` lacks resolves to no provider at all: no user, not a 500.
    $user = User::factory()->create();
    config(['lukk.user_provider' => 'missing']);

    expect(verifyRequestFor($user->getKey())->verifiable())->toBeNull();
});

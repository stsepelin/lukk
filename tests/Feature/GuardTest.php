<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Lukk\Contracts\Denylist;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\User;

beforeEach(function () {
    Route::middleware('auth:api')->get('/_protected', fn (Request $r) => ['id' => $r->user()->getAuthIdentifier()]);
});

it('authenticates a request carrying a valid bearer token', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    $this->withToken($pair->accessToken)->getJson('/_protected')
        ->assertOk()
        ->assertExactJson(['id' => $user->id]);
});

it('rejects a request with no bearer token', function () {
    $this->getJson('/_protected')->assertUnauthorized();
});

it('rejects a garbage / unsigned token', function () {
    $this->withToken('not-a-jwt')->getJson('/_protected')->assertUnauthorized();
});

it('rejects malformed Authorization headers', function (string $header) {
    $this->withHeaders(['Authorization' => $header])->getJson('/_protected')->assertUnauthorized();
})->with([
    'scheme only' => 'Bearer',
    'empty token' => 'Bearer ',
    'wrong scheme' => 'Token abcdef',
    'two-segment jwt' => 'Bearer aaa.bbb',
    'junk jwt' => 'Bearer not.a.jwt',
]);

it('rejects a token whose subject no longer exists', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    $user->delete();

    $this->withToken($pair->accessToken)->getJson('/_protected')->assertUnauthorized();
});

it('rejects the next request once the family is denylisted', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    // The access token works...
    $this->withToken($pair->accessToken)->getJson('/_protected')->assertOk();

    // ...until its family is denylisted, then it dies on the very next request.
    app(Denylist::class)->revokeFamily(RefreshToken::query()->value('family_id'), 900);

    // Each production request gets a fresh guard; reset the test app's memoized
    // guard/user so the second call re-runs verification instead of reusing the
    // user resolved above.
    $this->app['auth']->forgetGuards();

    $this->withToken($pair->accessToken)->getJson('/_protected')->assertUnauthorized();
});

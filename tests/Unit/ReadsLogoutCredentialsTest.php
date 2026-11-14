<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Http\Controllers\Concerns\ReadsLogoutCredentials;
use Lukk\Support\RefreshCookie;

it('reads a logout that carries no Content-Type at all', function () {
    // A body-less logout — a BFF's, a `sendBeacon` — has no Content-Type header. Test requests always get
    // one, so this builds the request by hand: without the cast, `explode(';', null)` is a TypeError under
    // strict_types, and the endpoint answered 500 where it should answer 204.
    $request = Request::create('/auth/logout', 'POST');
    $request->headers->remove('Content-Type');
    expect($request->headers->get('Content-Type'))->toBeNull();

    $reader = new class
    {
        use ReadsLogoutCredentials;

        /** @return array{tokens: array<int, string>, cookie: bool} */
        public function read(Request $request): array
        {
            return $this->logoutCredentials($request);
        }
    };

    expect($reader->read($request))->toBe(['tokens' => [], 'cookie' => false]);
});

it('reads each token once, and takes an empty cookie for none', function (string $cookie, array $body, array $expected) {
    // Cookie mode: in body mode the cookie is not read at all (`CookieModeLoginCsrfTest`).
    config(['lukk.cookie_mode' => true]);
    $request = Request::create('/auth/logout', 'POST', cookies: [RefreshCookie::name() => $cookie], server: ['CONTENT_TYPE' => 'application/json'], content: (string) json_encode($body));

    $reader = new class
    {
        use ReadsLogoutCredentials;

        /** @return array{tokens: array<int, string>, cookie: bool} */
        public function read(Request $request): array
        {
            return $this->logoutCredentials($request);
        }
    };

    expect($reader->read($request))->toBe($expected);
})->with([
    // A client that sends its token both ways names one session, and one lookup is metered for it.
    'the same token in the body and the cookie' => ['tok', ['refresh_token' => 'tok'], ['tokens' => ['tok'], 'cookie' => true]],
    'different tokens' => ['cookie-tok', ['refresh_token' => 'body-tok'], ['tokens' => ['body-tok', 'cookie-tok'], 'cookie' => true]],
    // An empty cookie is no credential: nothing to look up, and nothing to clear on its word.
    'an empty cookie' => ['', [], ['tokens' => [], 'cookie' => false]],
]);

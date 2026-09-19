<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Lukk\Http\Controllers\Concerns\ReadsLogoutCredentials;

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

<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;
use Lukk\Actions\SendEmailVerification;
use Lukk\Http\Controllers\EmailVerificationNotificationController;
use Lukk\Http\Middleware\RequireVerifiedEmail;

/** A request authenticated as a user model that does not implement MustVerifyEmail. */
function requestAsPlainUser(): Request
{
    $request = Request::create('/');
    $request->setUserResolver(fn () => new GenericUser(['id' => 1]));

    return $request;
}

it('lets a user with no email verification through the verified-email gate', function () {
    $response = (new RequireVerifiedEmail)->handle(requestAsPlainUser(), fn () => response('passed'));

    expect($response->getContent())->toBe('passed');
});

it('sends nothing to a user with no email verification, and still answers 202', function () {
    $send = Mockery::mock(SendEmailVerification::class);
    $send->shouldNotReceive('__invoke');

    $response = (new EmailVerificationNotificationController)(requestAsPlainUser(), $send);

    expect($response->getStatusCode())->toBe(202);
});

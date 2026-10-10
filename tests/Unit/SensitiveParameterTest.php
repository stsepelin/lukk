<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Lukk\Actions\AttemptLogin;
use Lukk\Actions\ChallengeTwoFactor;
use Lukk\Actions\ChangePassword;
use Lukk\Actions\ConfirmPassword;
use Lukk\Actions\ConfirmTwoFactor;
use Lukk\Actions\EndSession;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Actions\VerifyTwoFactorChallenge;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\TokenIssuer;
use Lukk\Contracts\TokenVerifier;
use Lukk\Contracts\TwoFactorAuthenticatable;
use Lukk\Contracts\TwoFactorProvider;
use Lukk\Http\Controllers\AuthenticatedSessionController;
use Lukk\Support\HashablePassword;
use Lukk\Tests\Fixtures\User;
use Lukk\Tokens\Jwt\FirebaseTokenIssuer;
use Lukk\Tokens\Jwt\FirebaseTokenVerifier;
use Lukk\TwoFactor\Google2FaTotpProvider;

/*
 * A raw secret passed as an argument lands in every stack trace that crosses the call: the exception
 * handler logs it, an error tracker ships it off the box, and a debug page renders it. PHP 8.2's
 * `#[\SensitiveParameter]` replaces the value with a `SensitiveParameterValue` in the trace, which is
 * what Laravel's own password broker and hasher do.
 */

it('keeps a presented refresh token out of the trace of a rotation that throws', function () {
    // Traces carry arguments only where zend.exception_ignore_args is off — the PHP default, and what
    // official images run without a php.ini. CI's php.ini turns it on, which would leave nothing to
    // check, so the test asks for arguments itself.
    $ignoreArgs = ini_set('zend.exception_ignore_args', '0');
    $pair = start()(1);
    Schema::drop('refresh_tokens');

    try {
        rotate()($pair->refreshToken);
        $this->fail('The rotation should have thrown.');
    } catch (Throwable $e) {
        $frame = collect($e->getTrace())->first(fn (array $frame) => ($frame['class'] ?? null) === RotateRefreshToken::class
            && $frame['function'] === '__invoke');

        expect($frame['args'][0])->toBeInstanceOf(SensitiveParameterValue::class)
            // Nor does it surface in any other frame: the hash is computed inside, so the raw value has no other path.
            ->and(collect($e->getTrace())->flatMap(fn (array $f) => $f['args'] ?? [])->contains($pair->refreshToken))->toBeFalse();
    } finally {
        ini_set('zend.exception_ignore_args', (string) $ignoreArgs);
    }
});

it('marks every parameter that carries a raw secret as sensitive', function (string $class, string $method, string $parameter) {
    $reflected = collect((new ReflectionMethod($class, $method))->getParameters())->firstOrFail(fn ($p) => $p->getName() === $parameter);

    expect($reflected->getAttributes(SensitiveParameter::class))->not->toBeEmpty();
})->with([
    [RotateRefreshToken::class, '__invoke', 'presentedSecret'],
    [EndSession::class, '__invoke', 'bearer'],
    [EndSession::class, '__invoke', 'refreshTokens'],
    [EndSession::class, 'endBearerSession', 'bearer'],
    [TokenIssuer::class, 'hash', 'secret'],
    [FirebaseTokenIssuer::class, 'hash', 'secret'],
    [TokenVerifier::class, 'verify', 'jwt'],
    [FirebaseTokenVerifier::class, 'verify', 'jwt'],
    [ChallengeToken::class, 'verify', 'token'],
    [ChallengeToken::class, 'familyOf', 'token'],
    [ChallengeToken::class, 'firstFactorOf', 'token'],
    [ChallengeToken::class, 'passwordFingerprintOf', 'token'],
    [ChallengeToken::class, 'consume', 'token'],
    [ChallengeToken::class, 'decode', 'token'],
    [ChallengeToken::class, 'headerType', 'token'],
    [ChallengeToken::class, 'headerCrit', 'token'],
    [ChallengeToken::class, 'header', 'token'],
    [ChangePassword::class, '__invoke', 'current'],
    [ChangePassword::class, '__invoke', 'password'],
    [ConfirmPassword::class, '__invoke', 'password'],
    [AttemptLogin::class, 'rehash', 'password'],
    [HashablePassword::class, 'verifiesOnlyInPart', 'password'],
    [VerifyTwoFactorChallenge::class, '__invoke', 'challengeToken'],
    [VerifyTwoFactorChallenge::class, '__invoke', 'code'],
    [VerifyTwoFactorChallenge::class, '__invoke', 'recoveryCode'],
    [ChallengeTwoFactor::class, '__invoke', 'code'],
    [ChallengeTwoFactor::class, '__invoke', 'recoveryCode'],
    [ConfirmTwoFactor::class, '__invoke', 'code'],
    [TwoFactorProvider::class, 'verify', 'secret'],
    [TwoFactorProvider::class, 'verify', 'code'],
    [TwoFactorProvider::class, 'otpauthUri', 'secret'],
    [Google2FaTotpProvider::class, 'verify', 'secret'],
    [Google2FaTotpProvider::class, 'verify', 'code'],
    [Google2FaTotpProvider::class, 'otpauthUri', 'secret'],
    [TwoFactorAuthenticatable::class, 'useRecoveryCode', 'code'],
    [User::class, 'useRecoveryCode', 'code'],
    [AuthenticatedSessionController::class, 'authenticateBearer', 'bearer'],
]);

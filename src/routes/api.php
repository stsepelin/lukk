<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lukk\Http\Controllers\AuthenticatedSessionController;
use Lukk\Http\Controllers\ConfirmablePasskeyController;
use Lukk\Http\Controllers\ConfirmablePasswordController;
use Lukk\Http\Controllers\ConfirmedTwoFactorAuthenticationController;
use Lukk\Http\Controllers\JwksController;
use Lukk\Http\Controllers\OtherSessionsController;
use Lukk\Http\Controllers\PasskeyAuthenticatedSessionController;
use Lukk\Http\Controllers\PasskeyController;
use Lukk\Http\Controllers\PasskeyLoginOptionsController;
use Lukk\Http\Controllers\PasskeyRegistrationOptionsController;
use Lukk\Http\Controllers\RecoveryCodeController;
use Lukk\Http\Controllers\SessionController;
use Lukk\Http\Controllers\TokenController;
use Lukk\Http\Controllers\TwoFactorAuthenticationController;
use Lukk\Http\Controllers\TwoFactorChallengedSessionController;

Route::prefix((string) config('lukk.path', 'auth'))
    ->middleware('api')
    ->group(function () {
        $guard = 'auth:'.config('lukk.guard', 'api');
        $confirmed = [$guard, 'lukk.confirm'];

        // Public key set (RFC 7517) — populated only under an asymmetric algorithm.
        Route::get('jwks', JwksController::class);

        // Sessions
        Route::post('login', [AuthenticatedSessionController::class, 'store'])->middleware('throttle:lukk-login');
        Route::post('refresh', [TokenController::class, 'store'])->middleware('throttle:lukk-refresh');
        Route::post('logout', [AuthenticatedSessionController::class, 'destroy'])->middleware($guard);
        Route::delete('sessions', [SessionController::class, 'destroy'])->middleware($guard);
        Route::delete('sessions/others', [OtherSessionsController::class, 'destroy'])->middleware($guard);
        Route::post('confirm-password', [ConfirmablePasswordController::class, 'store'])->middleware($guard);

        if (config('lukk.features.two_factor')) {
            Route::post('two-factor-challenge', [TwoFactorChallengedSessionController::class, 'store'])->middleware('throttle:lukk-2fa');
            Route::post('two-factor', [TwoFactorAuthenticationController::class, 'store'])->middleware($confirmed);
            Route::delete('two-factor', [TwoFactorAuthenticationController::class, 'destroy'])->middleware($confirmed);
            Route::post('two-factor/confirm', [ConfirmedTwoFactorAuthenticationController::class, 'store'])->middleware($confirmed);
            Route::get('two-factor/recovery-codes', [RecoveryCodeController::class, 'index'])->middleware($guard);
            Route::post('two-factor/recovery-codes', [RecoveryCodeController::class, 'store'])->middleware($confirmed);
        }

        if (config('lukk.features.passkeys')) {
            Route::post('passkeys/login-options', PasskeyLoginOptionsController::class)->middleware('throttle:lukk-passkeys');
            Route::post('passkeys/login', [PasskeyAuthenticatedSessionController::class, 'store'])->middleware('throttle:lukk-passkeys');
            Route::post('confirm-passkey', [ConfirmablePasskeyController::class, 'store'])->middleware($guard);
            Route::get('passkeys', [PasskeyController::class, 'index'])->middleware($guard);
            Route::post('passkeys/registration-options', PasskeyRegistrationOptionsController::class)->middleware($confirmed);
            Route::post('passkeys', [PasskeyController::class, 'store'])->middleware($confirmed);
            Route::delete('passkeys/{credentialId}', [PasskeyController::class, 'destroy'])->middleware($confirmed);
        }
    });

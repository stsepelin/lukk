<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lukk\Http\Controllers\AccountController;
use Lukk\Http\Controllers\AuthenticatedSessionController;
use Lukk\Http\Controllers\ConfirmablePasskeyController;
use Lukk\Http\Controllers\ConfirmablePasswordController;
use Lukk\Http\Controllers\ConfirmedTwoFactorAuthenticationController;
use Lukk\Http\Controllers\EmailVerificationNotificationController;
use Lukk\Http\Controllers\JwksController;
use Lukk\Http\Controllers\NewPasswordController;
use Lukk\Http\Controllers\OtherSessionsController;
use Lukk\Http\Controllers\PasskeyAuthenticatedSessionController;
use Lukk\Http\Controllers\PasskeyController;
use Lukk\Http\Controllers\PasskeyLoginOptionsController;
use Lukk\Http\Controllers\PasskeyRegistrationOptionsController;
use Lukk\Http\Controllers\PasswordController;
use Lukk\Http\Controllers\PasswordResetLinkController;
use Lukk\Http\Controllers\RecoveryCodeController;
use Lukk\Http\Controllers\RegisteredUserController;
use Lukk\Http\Controllers\SessionController;
use Lukk\Http\Controllers\TokenController;
use Lukk\Http\Controllers\TwoFactorAuthenticationController;
use Lukk\Http\Controllers\TwoFactorChallengedSessionController;
use Lukk\Http\Controllers\VerifyEmailController;
use Lukk\Http\Middleware\ForceJsonRequest;
use Lukk\Http\Middleware\RequirePinnedAbility;
use Lukk\Lukk;
use Lukk\Support\Abilities;

/**
 * The session routes every guard gets, defined ONCE.
 *
 * They used to be written out in both the extra-guard loop and the default-guard block, and the two
 * copies drifted: `RequirePinnedAbility` was added to the default block only, so a token pinned to
 * a narrow grant could still log an ADMIN account out everywhere — the gate absent from exactly the
 * mount a multi-guard install cares about. One definition makes that class of omission impossible.
 */
$sessionRoutes = function (string $guard, string $throttle = ''): void {
    Route::post('logout', [AuthenticatedSessionController::class, 'destroy'])->middleware($guard);

    // Gated on `lukk.sessions`: these revoke OTHER sessions, so a token pinned to a narrow grant —
    // a personal access token, a capped impersonation session — must not reach them. `logout` and
    // `refresh` are deliberately NOT gated: they act on the calling session alone, and a pinned
    // token has to be able to end and renew itself.
    $pinned = RequirePinnedAbility::class.':';
    Route::delete('sessions', [SessionController::class, 'destroy'])->middleware([$guard, $pinned.Abilities::SESSIONS]);
    Route::delete('sessions/others', [OtherSessionsController::class, 'destroy'])->middleware([$guard, $pinned.Abilities::SESSIONS]);

    // Throttled like login: it re-verifies the SAME password, so leaving it unmetered made the sudo
    // gate an unlimited password oracle for anyone already holding an access token.
    //
    // Gated for a pinned token because step-up is the gateway to everything that takes an account
    // over permanently — enrolling a passkey, disabling two-factor, regenerating recovery codes. All
    // of it needs the password, so a pinned token could never do it silently; but "a machine token
    // must not log the account out everywhere" and "a machine token may enrol a permanent
    // authenticator" cannot both be the rule, and this is which one lukk picked.
    Route::post('confirm-password', [ConfirmablePasswordController::class, 'store'])
        ->middleware([$guard, $pinned.Abilities::ACCOUNT, 'throttle:lukk-'.$throttle.'confirm']);
};

// Additional guards (multi-audience). Mounted FIRST so a subdomain-scoped guard takes precedence
// over the host-agnostic default guard sharing the same path. Each gets the CORE session routes
// wired to its own `auth:{name}` + crypto identity (features stay on the default guard for now).
foreach ((array) config('lukk.guards', []) as $guardName => $override) {
    $cfg = Lukk::guardConfig($guardName);

    Route::domain($cfg['domain'] ?? null)
        ->prefix((string) ($cfg['path'] ?? 'auth'))
        ->middleware(['api', ForceJsonRequest::class, 'lukk.set-guard:'.$guardName])
        ->group(function () use ($guardName, $sessionRoutes) {
            $guard = 'auth:'.$guardName;

            Route::get('jwks', JwksController::class);
            Route::post('login', [AuthenticatedSessionController::class, 'store'])->middleware('throttle:lukk-'.$guardName.'-login');
            Route::post('refresh', [TokenController::class, 'store'])->middleware('throttle:lukk-'.$guardName.'-refresh');

            // The redemption half of the two-factor challenge, mounted wherever `login` is.
            // `login` can answer `{"two_factor": true, "challenge_token": …}` on ANY guard whose
            // resolved config enables the feature — so without this the account was told to complete
            // a challenge it had no endpoint to complete: enrolled, challenged, and bricked. The
            // MANAGEMENT routes (enrol, confirm, disable, recovery codes) stay on the default guard;
            // they need step-up, which is a separate mount, and their absence locks nobody out.
            if (Lukk::guardConfig($guardName)['features']['two_factor'] ?? false) {
                Route::post('two-factor-challenge', [TwoFactorChallengedSessionController::class, 'store'])
                    ->middleware('throttle:lukk-'.$guardName.'-2fa');
            }

            $sessionRoutes($guard, $guardName.'-');
        });
}

// `ForceJsonRequest` renders these routes' errors as JSON regardless of host config. This is the
// DEFAULT guard — it carries every feature; `lukk.set-guard` resets the active guard each request.
Route::domain(config('lukk.domain'))
    ->prefix((string) config('lukk.path', 'auth'))
    ->middleware(['api', ForceJsonRequest::class, 'lukk.set-guard:'.config('lukk.guard', 'api')])
    ->group(function () use ($sessionRoutes) {
        $guard = 'auth:'.config('lukk.guard', 'api');
        $confirmed = [$guard, 'lukk.confirm'];

        // Public key set (RFC 7517) — populated only under an asymmetric algorithm.
        Route::get('jwks', JwksController::class);

        if (config('lukk.features.registration')) {
            // Public: create an account and (unless verification blocks it) start a session.
            Route::post('register', [RegisteredUserController::class, 'store'])->middleware('throttle:lukk-register');
        }

        Route::post('login', [AuthenticatedSessionController::class, 'store'])->middleware('throttle:lukk-login');
        Route::post('refresh', [TokenController::class, 'store'])->middleware('throttle:lukk-refresh');
        $sessionRoutes($guard);

        if (config('lukk.features.account_deletion')) {
            // Step-up confirmed AND gated on its own ability, which are two different controls doing
            // two different jobs.
            //
            // Step-up stops a stolen access token: erasure is irreversible, so authentication alone
            // must not be enough. It is no longer the only thing standing between a machine token
            // and this route — confirmations are now bound to the session that earned them — but it
            // still is not sufficient on its own, because a pin carrying `lukk.account` can earn its
            // own confirmation.
            //
            // Hence `lukk.account.delete`, deliberately not covered by `lukk.account`: that ability
            // already meant "manage my credentials", and folding erasure into it would have handed
            // every already-issued token carrying it the power to destroy the account, silently, on
            // upgrade. It would also invert the ordering — such a token cannot revoke one other
            // session, but could delete everything.
            // `ALWAYS`: `features.gate_auth_routes = false` must not reach this gate. That flag
            // buys back pre-0.6 reach for tokens issued before abilities existed; this route did not
            // exist then, so switching it off would not restore an old behaviour but hand a narrow
            // machine token an irreversible new one.
            $erasure = RequirePinnedAbility::class.':'.RequirePinnedAbility::ALWAYS.','.Abilities::ACCOUNT_DELETE;

            // Metered on the step-up bucket, deliberately shared rather than given its own.
            //
            // The export is the widest read lukk offers — identifier, every session's timing, every
            // passkey's name — and it rode only the broad `api` group limiter while every sibling
            // sensitive route (confirm-password, change-password, recovery codes) was metered. It is
            // a sudo-gated account operation, which is exactly what `lukk-confirm` already meters, so
            // sharing the bucket also stops an attacker who has one confirmation from spending the
            // window on bulk reads. A separate limiter would need new config keys for no new
            // behaviour.
            Route::get('account/export', [AccountController::class, 'export'])
                ->middleware([...$confirmed, $erasure, 'throttle:lukk-confirm']);
            Route::delete('account', [AccountController::class, 'destroy'])->middleware([...$confirmed, $erasure]);
        }

        if (config('lukk.features.change_password')) {
            // Shares the confirm budget deliberately: it re-verifies the same secret, and two
            // independent allowances for guessing one password is just a larger allowance.
            //
            // Gated for a pinned token on the same reasoning as step-up: it rotates the account
            // credential AND revokes every other session, so it reaches past what pinning a grant
            // is meant to allow.
            Route::post('password', [PasswordController::class, 'update'])
                ->middleware([$guard, RequirePinnedAbility::class.':'.Abilities::ACCOUNT, 'throttle:lukk-confirm']);
        }

        if (config('lukk.features.two_factor')) {
            Route::post('two-factor-challenge', [TwoFactorChallengedSessionController::class, 'store'])->middleware('throttle:lukk-2fa');
            Route::post('two-factor', [TwoFactorAuthenticationController::class, 'store'])->middleware($confirmed);
            Route::delete('two-factor', [TwoFactorAuthenticationController::class, 'destroy'])->middleware($confirmed);
            Route::post('two-factor/confirm', [ConfirmedTwoFactorAuthenticationController::class, 'store'])->middleware($confirmed);
            // Gated for a pinned token like the rest of `lukk.account`: it reports how many recovery
            // codes remain, which is reconnaissance for the same attack the write side protects.
            Route::get('two-factor/recovery-codes', [RecoveryCodeController::class, 'index'])
                ->middleware([$guard, RequirePinnedAbility::class.':'.Abilities::ACCOUNT]);
            Route::post('two-factor/recovery-codes', [RecoveryCodeController::class, 'store'])->middleware($confirmed);
        }

        if (config('lukk.features.passkeys')) {
            Route::post('passkeys/login-options', PasskeyLoginOptionsController::class)->middleware('throttle:lukk-passkeys');
            Route::post('passkeys/login', [PasskeyAuthenticatedSessionController::class, 'store'])->middleware('throttle:lukk-passkeys');
            // Shares the confirm budget. A passkey assertion is a signature, not a guessable secret,
            // so this is DoS/CPU metering rather than brute-force defence — which is also why it is
            // not gated by the confirm lockout below.
            // Gated for a pinned token exactly like `confirm-password`: it is the OTHER way to reach
            // step-up, so leaving it open would make the password gate decorative.
            Route::post('confirm-passkey', [ConfirmablePasskeyController::class, 'store'])
                ->middleware([$guard, RequirePinnedAbility::class.':'.Abilities::ACCOUNT, 'throttle:lukk-confirm']);
            // Same: it enumerates the account's second factors — credential ids, the human-chosen
            // device names, last-use timestamps. Target selection for a social-engineering step.
            Route::get('passkeys', [PasskeyController::class, 'index'])
                ->middleware([$guard, RequirePinnedAbility::class.':'.Abilities::ACCOUNT]);
            Route::post('passkeys/registration-options', PasskeyRegistrationOptionsController::class)->middleware($confirmed);
            Route::post('passkeys', [PasskeyController::class, 'store'])->middleware($confirmed);
            Route::delete('passkeys/{credentialId}', [PasskeyController::class, 'destroy'])->middleware($confirmed);
        }

        if (config('lukk.features.email_verification')) {
            Route::post('email/verification-notification', EmailVerificationNotificationController::class)
                ->middleware([$guard, 'throttle:lukk-email-verification']);
        }

        if (config('lukk.features.password_reset')) {
            // Public (no auth): a logged-out user requests + completes a reset.
            Route::post('forgot-password', PasswordResetLinkController::class)->middleware('throttle:lukk-password-reset');
            Route::post('reset-password', NewPasswordController::class)->middleware('throttle:lukk-password-reset');
        }
    });

// The verification link is clicked straight from an email, so it sits OUTSIDE the JSON-forcing
// group: the `signed` URL (not `auth`) is the authority, and the controller content-negotiates a
// browser redirect vs a 204. Gated on the feature like the routes above.
if (config('lukk.features.email_verification')) {
    Route::domain(config('lukk.domain'))
        ->prefix((string) config('lukk.path', 'auth'))
        ->middleware(['api'])
        ->group(function () {
            Route::get('email/verify/{id}/{hash}', VerifyEmailController::class)
                ->middleware(['signed', 'throttle:lukk-email-verification'])
                ->name('lukk.verification.verify');
        });
}

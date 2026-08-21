<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Contracts\Auth\UserProvider;
use Lukk\Actions\FinishPasskeyLogin;
use Lukk\Actions\StartSession;
use Lukk\Contracts\LoginResponse;
use Lukk\Http\Controllers\Concerns\DeterminesSessionOutcome;
use Lukk\Http\Requests\PasskeyAssertionRequest;

/**
 * Completes a passwordless passkey login: `store` verifies the assertion against
 * the negotiated ceremony and issues a token pair (`amr: ["webauthn"]`).
 */
class PasskeyAuthenticatedSessionController
{
    use DeterminesSessionOutcome;

    public function __construct(
        private readonly FinishPasskeyLogin $finishLogin,
        private readonly StartSession $start,
        private readonly UserProvider $users,
    ) {}

    public function store(PasskeyAssertionRequest $request): LoginResponse
    {
        $userId = ($this->finishLogin)((string) $request->input('ceremony_id'), $request->array('credential'));

        // Resolve the user rather than minting a session straight off the credential row. The
        // password path runs these gates and this one skipped both: `block_unverified_login` was
        // not enforced (reachable in any app that nulls `email_verified_at` on an email change —
        // the user still has a passkey and walks past the block that refuses their password), and
        // a user deleted since registering their passkey still got a refresh-token row.
        $user = $this->users->retrieveById($userId);

        abort_if($user === null, 401, 'Unauthenticated.');
        abort_if($this->emailUnverified($user), 403, 'Your email address is not verified.');

        return app(LoginResponse::class, ['pair' => ($this->start)($user->getAuthIdentifier(), ['amr' => ['webauthn']])]);
    }
}

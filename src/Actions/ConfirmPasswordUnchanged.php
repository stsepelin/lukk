<?php

declare(strict_types=1);

namespace Lukk\Actions;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Validation\ValidationException;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Lukk;
use Lukk\Support\PasswordFingerprint;
use Lukk\Support\TokenPair;

/**
 * Take back a session that a password sign-in has just started, if the password it was checked against
 * has been replaced since.
 *
 * Password change and reset write the new hash, THEN read and revoke the account's sessions. A sign-in
 * that checked the OLD password and committed its session after that read survived both — exactly the
 * sign-in a reset exists to shut out when an account is being recovered. So a sign-in does the mirror
 * image: it starts the session, THEN re-reads the password. Each side commits before it reads, so one
 * of them sees the other: either the change's read finds this session, or this re-read finds the new
 * hash.
 *
 * That needs three things to stay true, and the documentation says so to consumers:
 *  - the re-read is authoritative — the primary database, not a replica or a cache (forced below for an
 *    Eloquent provider; a custom provider has to guarantee it);
 *  - nothing wraps the sign-in, the change or the reset in a transaction — neither lukk nor the app (a
 *    transaction-per-request middleware on these routes reopens the race, and on InnoDB turns the
 *    re-read into a read of the snapshot the check already took);
 *  - the check happens AFTER the session is written: checked before, the change could land in the gap.
 */
class ConfirmPasswordUnchanged
{
    public function __construct(
        private readonly UserProvider $users,
        private readonly RefreshTokenRepository $tokens,
        private readonly RevokeSession $revoke,
    ) {}

    /**
     * The fingerprint a sign-in's session is granted on: the password the check read.
     *
     * With `Lukk::authenticateUsing` lukk did not read it — the callback authenticated however it does
     * (SSO, LDAP) and may return a model that never loaded the password column, or a stale instance.
     * Taken from that model, every such sign-in read as "password changed". There the baseline is the
     * STORED password, read right after the callback: a change after that point is still caught.
     */
    public function baseline(Authenticatable $user): ?string
    {
        if (Lukk::$authenticateUsing === null) {
            return PasswordFingerprint::of($user);
        }

        $stored = $this->stored($user->getAuthIdentifier());

        return $stored === null ? null : PasswordFingerprint::of($stored);
    }

    /**
     * @param  string|null  $fingerprint  from `baseline()`; null (a challenge that carries none) is never
     *                                    taken as unchanged
     */
    public function __invoke(int|string $userId, ?string $fingerprint, TokenPair $pair, string $field, string $message): void
    {
        $current = $this->stored($userId);

        if ($fingerprint !== null && $current !== null && PasswordFingerprint::matches($fingerprint, $current)) {
            return;
        }

        // Revoked, not merely withheld: the session row is already committed, and a change that read the
        // sessions before it did would not have seen it.
        $record = $this->tokens->findByHash(hash('sha256', $pair->refreshToken));

        if ($record !== null) {
            ($this->revoke)($record->familyId);
        }

        throw ValidationException::withMessages([$field => [$message]]);
    }

    /**
     * The user as stored NOW, read from the primary. Laravel reads through the write connection while a
     * transaction is open on it, so a read replica lagging behind the password write cannot answer "old".
     */
    private function stored(int|string $userId): ?Authenticatable
    {
        if ($this->users instanceof EloquentUserProvider) {
            $provider = $this->users;

            return $provider->createModel()->getConnection()->transaction(fn () => $provider->retrieveById($userId));
        }

        return $this->users->retrieveById($userId);
    }
}

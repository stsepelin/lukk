<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Hashing\Argon2IdHasher;
use Illuminate\Hashing\ArgonHasher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Hash;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\WebAuthnCeremony;
use Lukk\Lukk;
use Lukk\Support\VerifiedPasskey;

/**
 * How strongly an ACCOUNT can authenticate, and whether one passkey step-up meets that bar.
 *
 * NIST SP 800-63B-4 §4.1.2.1: binding an authenticator requires authentication at "the maximum AAL
 * currently available in the subscriber account". lukk's step-up token is what binds and removes
 * authenticators (passkey enrolment, `DELETE /auth/two-factor`), so the same bar applies to it.
 *
 * AAL2 is within an account's reach when it has a password (§2.2.1: a password alongside any
 * physical authenticator), or a passkey that is multi-factor on its own (§2.2.1, a multi-factor
 * authenticator; WebAuthn L3 §6.2.3). A TOTP does NOT raise it: an OTP authenticator is "something
 * you have" (§3.1.4), the same category as a single-factor passkey (§3.1.6), and §2.2.1 requires a
 * password or biometric comparison for two single-factor authenticators to reach AAL2.
 */
class PasskeyAssurance
{
    public function __construct(
        private readonly WebAuthnCeremony $ceremony,
        private readonly PasskeyRepository $passkeys,
    ) {}

    /** Can this account authenticate at AAL2 at all? */
    public function canReachMultiFactor(Authenticatable $user): bool
    {
        return $this->hasUsablePassword($user) || $this->hasMultiFactorCredential($user);
    }

    /**
     * Whether the stored password is one that could ever be confirmed.
     *
     * An import or an SSO account often carries a placeholder (`!`, `*`, a non-hash) rather than a
     * NULL. Counted as a password, it raised the step-up bar to AAL2 on an account with no way to
     * reach it — single-factor passkeys refused and the password path impossible, so no step-up at all.
     *
     * Counting a WORKING password as absent is the worse error — it lowers the account to AAL1 — so a
     * value is absent only when lukk can prove nothing verifies it: the stock provider, over the
     * application's own hasher, whose driver is one of the framework's `password_verify()` hashers,
     * and a value `password_verify()` itself could never accept. Anything else counts.
     */
    private function hasUsablePassword(Authenticatable $user): bool
    {
        // `(string)` normalises the two "no password" states the framework short-circuits on.
        $stored = (string) $user->getAuthPassword();

        if ($stored === '') {
            return false;
        }

        if ((Hash::info($stored)['algoName'] ?? null) !== 'unknown') {
            return true;
        }

        // The current guard's provider — the one `ConfirmPassword` checks against. The EXACT class: a
        // subclass may verify its own way. Null (a provider name nothing configures) proves nothing.
        $provider = app('auth')->createUserProvider(Lukk::userProviderName(Lukk::currentGuard()));

        if (! $provider instanceof EloquentUserProvider
            || $provider::class !== EloquentUserProvider::class
            // Constructed with a hasher of its own, the stock class checks however that hasher does.
            || $provider->getHasher() !== app('hash')
            || ! in_array(get_debug_type(app('hash')->driver()), [BcryptHasher::class, ArgonHasher::class, Argon2IdHasher::class], true)) {
            return true;
        }

        return $this->passwordVerifyCouldAccept($stored);
    }

    /**
     * Could `password_verify()` accept SOME password against this value?
     *
     * It falls back to `crypt()`, so with `hashing.bcrypt.verify` off — Laravel's documented setting
     * for importing hashes — a `$1$`, `$5$`, `$6$` or DES value verifies although `Hash::info()` calls it
     * `unknown`. `crypt()` refuses a value it cannot parse with a `*`-prefixed string, and otherwise
     * returns a result of the value's own length, which `password_verify()` compares in full.
     *
     * `crypt()` honours the work factor a value names, so one naming more than the defaults — a bcrypt
     * cost above 12, `rounds=` above 5000, any extended-DES count (up to 2^24) — counts without being
     * run: probing `$2b$31$…` takes hours.
     */
    private function passwordVerifyCouldAccept(string $stored): bool
    {
        if (str_starts_with($stored, '_')
            || (preg_match('/^\$2[abxy]?\$(\d+)\$/', $stored, $cost) === 1 && (int) $cost[1] > 12)
            || (preg_match('/^\$[56]\$rounds=(\d+)\$/', $stored, $rounds) === 1 && (int) $rounds[1] > 5000)) {
            return true;
        }

        $probe = crypt('', $stored);

        return ! str_starts_with($probe, '*') && strlen($probe) === strlen($stored);
    }

    /** Whether any of the account's passkeys has shown user verification, so it alone reaches AAL2. */
    public function hasMultiFactorCredential(Authenticatable $user): bool
    {
        foreach ($this->passkeys->credentialIdsFor($user->getAuthIdentifier()) as $credentialId) {
            $record = $this->passkeys->findByCredentialId($credentialId);

            if ($record !== null && $this->ceremony->isMultiFactor($record)) {
                return true;
            }
        }

        return false;
    }

    /** Does this verified step-up meet the account's own highest available level? */
    public function permitsStepUp(Authenticatable $user, VerifiedPasskey $passkey): bool
    {
        return $passkey->multiFactor || ! $this->canReachMultiFactor($user);
    }

    /** What a step-up ceremony should ask the authenticator for (WebAuthn L3 §5.8.6). */
    public function requiredUserVerification(Authenticatable $user): string
    {
        return $this->canReachMultiFactor($user) ? 'required' : 'preferred';
    }

    /** @return list<string> */
    public function credentialIdsFor(Authenticatable $user): array
    {
        return array_values($this->passkeys->credentialIdsFor($user->getAuthIdentifier()));
    }
}

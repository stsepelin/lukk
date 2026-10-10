<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Console\Concerns\ReadsStringInput;
use Lukk\Contracts\LockoutRepository;
use Lukk\Lukk;

/**
 * Lift an account lockout (NIST SP 800-63B-4 §3.2.2). The operator-facing half of the release story:
 * a locked-out user can't authenticate at all, so without this someone has to touch the database.
 */
class ReleaseLockoutCommand extends Command
{
    use ReadsStringInput;

    protected $signature = 'lukk:release
        {subject : The identifier that was locked (or the user id, for a two-factor or confirm lock)}
        {--purpose=login : Which authenticator to release — login, two_factor or confirm}
        {--guard= : The guard the lock belongs to; defaults to lukk\'s configured guard}';

    protected $description = 'Release an account lockout';

    public function __construct(private readonly AuthFactory $auth)
    {
        parent::__construct();
    }

    public function handle(LockoutRepository $lockouts): int
    {
        $purpose = $this->stringOption('purpose');

        if (! in_array($purpose, ['login', 'two_factor', 'confirm'], true)) {
            $this->components->error('--purpose must be "login", "two_factor" or "confirm".');

            return self::FAILURE;
        }

        // Locks are stamped with the guard that recorded them, so releasing has to name the same
        // one — defaulting to null would silently no-op on a single-guard app.
        $guard = $this->stringOption('guard') !== '' ? $this->stringOption('guard') : Lukk::currentGuard();

        // The operator pastes whatever the support ticket says — an address for `login`, a user id
        // for the others — so the command has to derive the same subject the failure path recorded.
        // `two_factor` and `confirm` key on the USER ID verbatim: lower-casing those would break a
        // ULID (uppercase Crockford base32) wherever comparison is binary (PostgreSQL, SQLite).
        // A `login` lock counts against the account and against the identifier's fold, and before 0.7 a
        // non-account was keyed by the identifier in plain text. With `release_after` at 0 this command is
        // the only thing that ever releases any of them, so all are released.
        $subjects = $purpose === 'login'
            ? [$this->loginSubject($this->stringArgument('subject'), $guard), LoginRateLimiter::lockoutSubject(null, $this->stringArgument('subject')), LoginRateLimiter::legacyLockoutSubject($this->stringArgument('subject'))]
            : [$this->stringArgument('subject')];

        // Which of them hold a lock, asked before clearing: the output must say whether a LOCK was
        // released or only a failure count cleared — a counter below the cap, or a lock `release_after`
        // already lifted. `release()` fires `AccountReleased` itself, for a held lock only, so every
        // path that lifts one (success, reset, this command, the repository API) reports through one
        // place; an expiry lifts it without an event. A lock taken between this read and the release
        // is still released and announced — only the wording here could lag it.
        $held = count(array_filter($subjects, fn (string $subject) => $lockouts->locked($purpose, $subject, $guard)));
        $cleared = array_sum(array_map(fn (string $subject) => $lockouts->release($purpose, $subject, $guard), $subjects));

        if ($cleared === 0) {
            $this->components->warn(sprintf('No %s lock found for [%s] on guard [%s].', $purpose, $this->stringArgument('subject'), $guard));

            return self::FAILURE;
        }

        $this->components->info($held > 0
            ? sprintf('Released the %s lock on [%s].', $purpose, $this->stringArgument('subject'))
            : sprintf('No %s lock was held for [%s]; cleared its failure count.', $purpose, $this->stringArgument('subject')));

        return self::SUCCESS;
    }

    /**
     * The `login` subject for a pasted identifier: the resolved user's id, or the normalized
     * identifier when it names no account (a lock recorded against an address an attacker probed).
     */
    private function loginSubject(string $input, string $guard): string
    {
        $field = Lukk::usernameField();
        // The provider sign-in used for this guard, or the lookup reads another table and reports
        // "no lock found" for a lock that exists. Null for a provider name `auth.providers` lacks.
        $provider = $this->auth->createUserProvider(Lukk::userProviderName($guard));

        // Two lookups: as pasted, then normalized. The realistic operator flow is to paste the
        // address the way the user wrote it (`  Victim@Y.com `), and on any engine whose comparison
        // is binary — PostgreSQL, SQLite — only the normalized form matches the stored row. Falling
        // straight through to the `idn:` bucket would report "no lock found" for a lock that exists.
        // (`stringArgument()` has already trimmed `$input`; the `trim` keeps this method honest on its own.)
        $user = $provider?->retrieveByCredentials([$field => trim($input)]) // @pest-mutate-ignore: UnwrapTrim
            ?? $provider?->retrieveByCredentials([$field => LoginRateLimiter::normalize($input)]);

        return LoginRateLimiter::lockoutSubject($user, $input);
    }
}

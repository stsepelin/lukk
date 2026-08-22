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
 * Lift an account lockout (NIST SP 800-63B §5.2.2). The operator-facing half of the release story:
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
        $subject = $purpose === 'login'
            ? $this->loginSubject($this->stringArgument('subject'), $guard)
            : $this->stringArgument('subject');

        // `release()` fires AccountReleased itself, so every path (success, reset, console, expiry)
        // reports through one place rather than only this one.
        if ($lockouts->release($purpose, $subject, $guard) === 0) {
            $this->components->warn(sprintf('No %s lock found for [%s] on guard [%s].', $purpose, $this->stringArgument('subject'), $guard));

            return self::FAILURE;
        }

        $this->components->info(sprintf('Released the %s lock on [%s].', $purpose, $this->stringArgument('subject')));

        return self::SUCCESS;
    }

    /**
     * The `login` subject for a pasted identifier: the resolved user's id, or the normalized
     * identifier when it names no account (a lock recorded against an address an attacker probed).
     */
    private function loginSubject(string $input, string $guard): string
    {
        $field = (string) config('lukk.username', 'email');
        $provider = $this->auth->createUserProvider((string) config("auth.guards.{$guard}.provider"));

        // Two lookups: as pasted, then normalized. The realistic operator flow is to paste the
        // address the way the user wrote it (`  Victim@Y.com `), and on any engine whose comparison
        // is binary — PostgreSQL, SQLite — only the normalized form matches the stored row. Falling
        // straight through to the `idn:` bucket would report "no lock found" for a lock that exists.
        $user = $provider?->retrieveByCredentials([$field => trim($input)])
            ?? $provider?->retrieveByCredentials([$field => LoginRateLimiter::normalize($input)]);

        return LoginRateLimiter::lockoutSubject($user, $input);
    }
}

<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Lukk\Contracts\LockoutRepository;
use Lukk\Lukk;

/**
 * Lift an account lockout (NIST SP 800-63B §5.2.2). The operator-facing half of the release story:
 * a locked-out user can't authenticate at all, so without this someone has to touch the database.
 */
class ReleaseLockoutCommand extends Command
{
    protected $signature = 'lukk:release
        {subject : The identifier that was locked (or the user id, for a two-factor lock)}
        {--purpose=login : Which authenticator to release — login or two_factor}
        {--guard= : The guard the lock belongs to; defaults to lukk\'s configured guard}';

    protected $description = 'Release an account lockout';

    public function handle(LockoutRepository $lockouts): int
    {
        $purpose = (string) $this->option('purpose');

        if (! in_array($purpose, ['login', 'two_factor'], true)) {
            $this->components->error('--purpose must be "login" or "two_factor".');

            return self::FAILURE;
        }

        // Recording normalizes (trim/lower/transliterate); releasing has to match, or the obvious
        // operator flow — paste the address out of the support ticket — silently does nothing.
        $subject = Str::transliterate(Str::lower(trim((string) $this->argument('subject'))));
        // Locks are stamped with the guard that recorded them, so releasing has to name the same
        // one — defaulting to null would silently no-op on a single-guard app.
        $guard = ((string) ($this->option('guard') ?? '')) !== '' ? (string) $this->option('guard') : Lukk::currentGuard();

        // `release()` fires AccountReleased itself, so every path (success, reset, console, expiry)
        // reports through one place rather than only this one.
        if ($lockouts->release($purpose, $subject, $guard) === 0) {
            $this->components->warn(sprintf('No %s lock found for [%s] on guard [%s].', $purpose, $subject, $guard));

            return self::FAILURE;
        }

        $this->components->info(sprintf('Released the %s lock on [%s].', $purpose, $subject));

        return self::SUCCESS;
    }
}

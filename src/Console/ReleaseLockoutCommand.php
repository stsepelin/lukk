<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Lukk\Contracts\LockoutRepository;
use Lukk\Events\AccountReleased;
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

        $subject = (string) $this->argument('subject');
        // Locks are stamped with the guard that recorded them, so releasing has to name the same
        // one — defaulting to null would silently no-op on a single-guard app.
        $guard = $this->option('guard') !== null ? (string) $this->option('guard') : Lukk::currentGuard();

        $lockouts->release($purpose, $subject, $guard);
        event(new AccountReleased($purpose, $subject, $guard));

        $this->components->info(sprintf('Released the %s lock on [%s].', $purpose, $subject));

        return self::SUCCESS;
    }
}

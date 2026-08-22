<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Contracts\RefreshTokenRepository;

class PruneTokensCommand extends Command
{
    protected $signature = 'lukk:prune {--lockout-days=30 : Age at which a spent lockout counter is dropped}';

    protected $description = 'Delete expired and revoked refresh tokens, and spent lockout counters.';

    public function handle(RefreshTokenRepository $repository, LockoutRepository $lockouts, PasskeyRepository $passkeys): int
    {
        $count = $repository->pruneExpired();

        $this->info("Pruned {$count} refresh token(s).");

        // A failed login writes a counter for any identifier, real or not, and one below the cap
        // never expires on its own — so without this the table grows without bound.
        $locks = $lockouts->prune((int) $this->option('lockout-days'));

        $this->info("Pruned {$locks} lockout counter(s).");

        // Passkeys belonging to users who no longer exist. Nothing else ever removes these: they
        // have no expiry, and erasure only reaches an account deleted through lukk's own route — a
        // row deleted directly, or by a cascade elsewhere, left the credential id, the human-chosen
        // device name and a last-used timestamp behind permanently.
        $orphans = $passkeys->pruneOrphaned();

        $this->info("Pruned {$orphans} orphaned passkey(s).");

        return self::SUCCESS;
    }
}

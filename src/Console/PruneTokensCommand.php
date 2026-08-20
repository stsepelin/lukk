<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Lukk\Contracts\LockoutRepository;
use Lukk\Contracts\RefreshTokenRepository;

class PruneTokensCommand extends Command
{
    protected $signature = 'lukk:prune {--lockout-days=30 : Age at which a spent lockout counter is dropped}';

    protected $description = 'Delete expired and revoked refresh tokens, and spent lockout counters.';

    public function handle(RefreshTokenRepository $repository, LockoutRepository $lockouts): int
    {
        $count = $repository->pruneExpired();

        $this->info("Pruned {$count} refresh token(s).");

        // A failed login writes a counter for any identifier, real or not, and one below the cap
        // never expires on its own — so without this the table grows without bound.
        $locks = $lockouts->prune((int) $this->option('lockout-days'));

        $this->info("Pruned {$locks} lockout counter(s).");

        return self::SUCCESS;
    }
}

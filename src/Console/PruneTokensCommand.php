<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Lukk\Contracts\RefreshTokenRepository;

class PruneTokensCommand extends Command
{
    protected $signature = 'lukk:prune';

    protected $description = 'Delete expired and revoked refresh tokens.';

    public function handle(RefreshTokenRepository $repository): int
    {
        $count = $repository->pruneExpired();

        $this->info("Pruned {$count} refresh token(s).");

        return self::SUCCESS;
    }
}

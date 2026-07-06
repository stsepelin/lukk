<?php

declare(strict_types=1);

namespace Lukk\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Lukk\Actions\RevokeAllSessions;
use Lukk\Actions\StartSession;
use Lukk\Lukk;
use Lukk\Support\TokenPair;

/**
 * Add to your User model (Sanctum HasApiTokens analog) for ergonomic session
 * management.
 */
trait HasRefreshTokens
{
    public function refreshTokens(): HasMany
    {
        $relation = $this->hasMany(Lukk::refreshTokenModel(), 'user_id');

        // Under multi-guard, a model's sessions are only those for its own guard.
        return Lukk::isMultiGuard() ? $relation->where('guard', $this->lukkGuard()) : $relation;
    }

    public function startSession(): TokenPair
    {
        return Lukk::onGuard($this->lukkGuard(), fn () => app(StartSession::class)($this->getAuthIdentifier()));
    }

    public function revokeAllSessions(): void
    {
        Lukk::onGuard($this->lukkGuard(), fn () => app(RevokeAllSessions::class)($this->getAuthIdentifier()));
    }

    /**
     * The lukk guard this model authenticates under. Defaults to the configured default guard;
     * override on a second model (e.g. `Admin`) to return its guard name so its sessions are
     * minted with that guard's crypto identity and scoped to its own refresh-token family.
     */
    public function lukkGuard(): string
    {
        return (string) config('lukk.guard', 'api');
    }
}

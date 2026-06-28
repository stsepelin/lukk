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
        return $this->hasMany(Lukk::refreshTokenModel(), 'user_id');
    }

    public function startSession(): TokenPair
    {
        return app(StartSession::class)($this->getAuthIdentifier());
    }

    public function revokeAllSessions(): void
    {
        app(RevokeAllSessions::class)($this->getAuthIdentifier());
    }
}

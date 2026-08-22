<?php

declare(strict_types=1);

namespace Lukk\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property int|string $user_id
 * @property ?string $guard
 * @property string $family_id
 * @property string $token_hash
 * @property ?string $previous_id
 * @property ?string $scope
 * @property ?Carbon $rotated_at
 * @property ?Carbon $revoked_at
 * @property Carbon $expires_at
 */
class RefreshToken extends Model
{
    use HasUlids;

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    /**
     * lukk never serializes this model, but an integrator's "active sessions" screen doing
     * `$user->refreshTokens()->get()` would — and that would publish the token hash and, since
     * 0.6, the family's pinned entitlement. `$hidden` only affects `toArray`/`toJson`, so nothing
     * inside lukk changes; it just turns a foot-gun into a non-event.
     */
    protected $hidden = ['token_hash', 'scope'];

    protected function casts(): array
    {
        return [
            'rotated_at' => 'datetime',
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}

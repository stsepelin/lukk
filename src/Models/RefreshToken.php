<?php

declare(strict_types=1);

namespace Lukk\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $id
 * @property int|string $user_id
 * @property string $family_id
 * @property string $token_hash
 * @property ?string $previous_id
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

    protected function casts(): array
    {
        return [
            'rotated_at' => 'datetime',
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}

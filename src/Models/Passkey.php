<?php

declare(strict_types=1);

namespace Lukk\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $credential_id
 * @property int|string $user_id
 * @property ?string $name
 * @property string $public_key
 * @property int $sign_count
 * @property ?array $transports
 * @property ?string $aaguid
 * @property ?Carbon $last_used_at
 */
class Passkey extends Model
{
    protected $primaryKey = 'credential_id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'transports' => 'array',
            'sign_count' => 'integer',
            'last_used_at' => 'datetime',
        ];
    }
}

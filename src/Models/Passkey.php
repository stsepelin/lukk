<?php

declare(strict_types=1);

namespace Lukk\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property string $credential_id
 * @property int|string $user_id
 * @property ?string $guard
 * @property ?string $name
 * @property string $public_key
 * @property int $sign_count
 * @property ?array<int, string> $transports
 * @property ?string $aaguid
 * @property ?Carbon $last_used_at
 * @property ?Carbon $created_at
 */
class Passkey extends Model
{
    protected $primaryKey = 'credential_id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    /**
     * Kept out of `toArray`/`toJson`, like `RefreshToken` keeps its `token_hash`.
     *
     * `public_key` is the credential's COSE key, encrypted at rest — lukk's own `summariesForUser()`
     * allowlists columns and never returns it, but an integrator serialising `$user->passkeys`
     * directly published it, along with `aaguid`, which fingerprints the authenticator's make and
     * model. Neither is a secret the holder can authenticate with, so this is hardening rather than
     * a fix — but the sibling model already carried it and this one did not.
     */
    protected $hidden = ['public_key', 'aaguid'];

    protected function casts(): array
    {
        return [
            'transports' => 'array',
            'sign_count' => 'integer',
            'last_used_at' => 'datetime',
        ];
    }
}

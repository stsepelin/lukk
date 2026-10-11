<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Models\RefreshToken;

/** A `useRefreshTokenModel` subclass on its own connection, as a shared auth database would be. */
class OtherConnectionRefreshToken extends RefreshToken
{
    protected $connection = 'lukk_other';

    protected $table = 'refresh_tokens';
}

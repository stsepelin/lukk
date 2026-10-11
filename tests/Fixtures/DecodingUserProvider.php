<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Auth\EloquentUserProvider;

/** An `EloquentUserProvider` subclass that decodes its own identifier format (`u_<id>`) before the lookup. */
class DecodingUserProvider extends EloquentUserProvider
{
    public function retrieveById($identifier)
    {
        return is_string($identifier) && str_starts_with($identifier, 'u_')
            ? parent::retrieveById(substr($identifier, 2))
            : null;
    }
}

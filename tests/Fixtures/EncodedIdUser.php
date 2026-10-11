<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/** An incrementing integer key presented as `u_<id>`; `DecodingUserProvider` reads it back. */
class EncodedIdUser extends User
{
    public function getAuthIdentifier()
    {
        return 'u_'.$this->getKey();
    }
}

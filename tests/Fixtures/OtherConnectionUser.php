<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/**
 * A user provider model on a DIFFERENT connection than lukk's own tables.
 *
 * An ordinary deployment — identities in a shared directory database, application tables local —
 * and the one shape the erasure transaction cannot cover, since SQL has no cross-connection
 * transaction without two-phase commit.
 */
class OtherConnectionUser extends User
{
    protected $connection = 'directory';
}

<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/**
 * An admin provider model bound to a DIFFERENT database connection than the passkeys table.
 *
 * A perfectly ordinary deployment (identities in a shared directory database, application tables
 * local) and the one shape `pruneOrphaned`'s subquery cannot express — SQL has no cross-connection
 * subquery, so the bare table name would silently resolve against the passkeys connection.
 */
class OtherConnectionAdmin extends Admin
{
    protected $connection = 'other';

    /** A name that exists ONLY on that connection, so reaching for it on the wrong one throws. */
    protected $table = 'directory_admins';
}

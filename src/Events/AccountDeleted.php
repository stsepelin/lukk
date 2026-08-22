<?php

declare(strict_types=1);

namespace Lukk\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Fired AFTER the erasure has committed.
 *
 * Deliberately carries identifiers rather than the user model: the row is gone, and handing a
 * listener a deleted Eloquent instance invites someone to `save()` it back. Anything needing the
 * model itself belongs in {@see AccountDeleting}.
 *
 * This is the right place for work that must not be rolled back and must not hold a transaction
 * open — telling a downstream processor to erase its copy, writing an audit record, sending the
 * confirmation an operator will be asked for when the subject queries the erasure later.
 */
class AccountDeleted
{
    use Dispatchable;

    public function __construct(
        public readonly int|string $userId,
        /**
         * The identifier the account authenticated with (`config('lukk.username')`, usually an email).
         *
         * Captured before deletion because it is the only key some artifacts have — lockout counters
         * are stored against it, not against `user_id`. Note that this event therefore CARRIES
         * personal data: keep it out of logs, and prefer a queued listener that erases rather than
         * one that records.
         */
        public readonly ?string $identifier,
        public readonly string $guard,
    ) {}
}

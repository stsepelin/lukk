<?php

declare(strict_types=1);

namespace Lukk\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Fired BEFORE anything is erased, inside the transaction that erases it.
 *
 * This is where an application erases or anonymizes its OWN domain data — lukk owns only the auth
 * side. Being inside the transaction is the point: if your listener throws, no ROW is deleted, and
 * the subject still has an account rather than a half-erased one. It also means your listener must
 * not do slow or non-transactional work (an HTTP call to a downstream processor belongs in
 * {@see AccountDeleted}, which fires after the commit).
 *
 * The user model is still fully intact here, so this is your last chance to read anything off it.
 *
 * ## Three things the rollback does NOT cover
 *
 * **Listen SYNCHRONOUSLY.** A `ShouldQueue` listener is pushed at dispatch time (Laravel's
 * `after_commit` is off by default), so its work is already on the wire when the transaction rolls
 * back: your domain data is erased and the account it belonged to still exists. That is the exact
 * half-erased outcome the transaction is here to prevent. If you need a queue, use
 * {@see AccountDeleted} — it fires after the commit, when the erasure is a fact.
 *
 * **Sessions are already gone.** Every session is revoked and denylisted *before* this transaction
 * opens, deliberately: a failure later still leaves the account unreachable rather than half-erased
 * and still usable. A listener that throws therefore turns "delete my account" into "log me out of
 * every device, permanently" — the rows come back, the sessions do not.
 *
 * **This event carries the whole model**, so queueing it serializes the subject's email, password
 * hash and encrypted two-factor secret into `jobs` — and into `failed_jobs`, which nothing prunes.
 * That residue outlives the erasure that triggered it. {@see AccountDeleted} carries identifiers
 * only, for this reason.
 */
class AccountDeleting
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        /** The lukk guard the request authenticated on. */
        public readonly string $guard,
    ) {}
}

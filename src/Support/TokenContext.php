<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * What is being minted, handed to `Lukk::abilitiesUsing` as its second argument.
 *
 * It exists so that callback can answer more than "what may this user do". A single object rather
 * than a growing parameter list is deliberate: adding a field here is backwards-compatible, whereas
 * a fourth positional argument would break every closure already written against three.
 *
 * The obvious need today is the **guard**. A multi-guard install serves different audiences — an
 * `admin` guard and a `customer` guard — from one user table often enough, and `['*']` for a
 * customer token is not the same grant as `['*']` for an admin one. The `familyId` identifies the
 * session, so a callback can narrow a grant per device or look up a session-specific policy.
 */
class TokenContext
{
    public function __construct(
        /** The lukk guard the token is being minted for (`config('lukk.guard')` unless multi-guard). */
        public readonly string $guard,
        /** The subject the token authenticates — the `sub` claim. */
        public readonly int|string $userId,
        /** The refresh-token family, stable across every rotation of one session — the `fid` claim. */
        public readonly string $familyId,
        /**
         * Whether this session's abilities are PINNED — its own grant, fixed for its lifetime,
         * rather than derived per mint from `Lukk::abilitiesUsing`. True for a personal access token
         * or a capped impersonation session. Stamped as the `pin` claim so a gate can tell the two
         * apart from the token alone, with no database read.
         *
         * Always **false** as seen by an `abilitiesUsing` callback: a pinned grant is used verbatim
         * and never asks the callback anything, so the callback only ever runs on the derived path.
         * Don't branch on it there.
         */
        public readonly bool $pinned = false,
    ) {}
}

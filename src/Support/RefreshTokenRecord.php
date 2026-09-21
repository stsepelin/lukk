<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * Storage-agnostic snapshot of a refresh-token row, handed to the rotation
 * policy. Timestamps are unix seconds so the policy does no date-library work.
 */
class RefreshTokenRecord
{
    public function __construct(
        public readonly string $id,
        public readonly int|string $userId,
        public readonly string $familyId,
        public readonly ?int $rotatedAt,
        public readonly ?int $revokedAt,
        public readonly int $expiresAt,
        /** The family's own scope claim, or null to derive it per mint. */
        public readonly ?string $scope = null,
        /**
         * When this ROW was created — meaningful to a data subject reading their own export, and the
         * FALLBACK signal for `claim_seconds` when `$original` is unknown.
         */
        public readonly ?int $createdAt = null,
        /**
         * Whether this row is the family's ORIGINAL — the one `StartSession` inserted, with no
         * predecessor. `claim_seconds` revokes a late first use only for the credential the sign-in
         * itself handed out, so this is the question it actually asks.
         *
         * **Tri-state, and `null` (unknown) is the default on purpose.** A repository written before
         * this field cannot answer, and `claim_seconds` then falls back to comparing `$createdAt`
         * with the session's issue time — the behaviour such a repository already had. Defaulting to
         * `true` would instead hand every SUCCESSOR row to the revocation path, which logs out
         * sessions in active use.
         */
        public readonly ?bool $original = null,
        /**
         * How the SESSION was authenticated (RFC 8176 `amr`), JSON-encoded — stamped once at sign-in
         * and carried forward by every rotation, because it describes the authentication EVENT and a
         * refresh does not repeat it. Null on a repository or a schema that does not carry it, in
         * which case the claim is simply absent, as it was before.
         */
        public readonly ?string $amr = null,
    ) {}
}

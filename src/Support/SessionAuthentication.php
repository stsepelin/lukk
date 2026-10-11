<?php

declare(strict_types=1);

namespace Lukk\Support;

use Lukk\Actions\StartSession;

/**
 * How, and WHEN, a session was authenticated — the family's record, written once at sign-in and carried
 * by every rotation, because a refresh repeats neither.
 *
 * Stored in the existing `amr` column (`RefreshTokenRepository::persist()`'s `$amr` argument, and
 * `RefreshTokenRecord::$amr`), so it needed no migration. The string is opaque to a repository: store
 * it and hand it back unchanged. Two shapes are read:
 *
 *  - `{"amr":["pwd","otp","mfa"],"auth_time":1760000000}` — what lukk writes; either key may be absent.
 *  - `["pwd","otp","mfa"]` — the bare RFC 8176 list written before the time was stored (and what a
 *    custom repository may still hold). Its sign-in time is UNKNOWN.
 *
 * The time used to be derived on rotation as `expires_at − refresh_ttl`. Lowering `refresh_ttl` moved
 * every older sign-in forward, so a multi-factor sign-in from weeks ago could read as hours old and vouch
 * for a password step-up (NIST SP 800-63B-4 §2.2.3 lets an AAL2 session reauthenticate with one factor
 * only while it IS one). An unknown time is now no time: the claim is omitted and the allowance fails
 * closed until the next multi-factor sign-in.
 */
class SessionAuthentication
{
    /** The encoded record's bound: the `amr` list's own, plus room for the time and the keys. */
    public const MAX_LENGTH = StartSession::MAX_AMR_LENGTH + 64;

    /** @param  list<string>|null  $methods */
    public function __construct(
        public readonly ?array $methods,
        public readonly ?int $authTime,
    ) {}

    public function encode(): ?string
    {
        $record = array_filter(['amr' => $this->methods, 'auth_time' => $this->authTime], fn ($value) => $value !== null);

        // Never more than `MAX_LENGTH`: `methods` arrives validated by `StartSession::encodeAmr()`.
        return $record === [] ? null : (string) json_encode($record); // @pest-mutate-ignore: RemoveStringCast
    }

    /**
     * The stored record, re-validated on the way OUT — the column is written through a swap seam, so the
     * read cannot assume lukk's own encoder ran. Anything unrecognised reads as nothing known.
     */
    public static function decode(?string $stored): self
    {
        if ($stored === null || strlen($stored) > self::MAX_LENGTH) {
            return new self(null, null);
        }

        $decoded = json_decode($stored, true);

        // The legacy bare list: the methods, and no time.
        if (is_array($decoded) && array_is_list($decoded)) {
            return new self(StartSession::decodeAmr($stored), null);
        }

        // A scalar would read as nothing below as well (`??` answers an offset of one as unset); this only
        // states the type.
        if (! is_array($decoded)) {
            return new self(null, null); // @pest-mutate-ignore: RemoveEarlyReturn
        }

        $time = $decoded['auth_time'] ?? null;

        return new self(
            StartSession::encodeAmr($decoded['amr'] ?? null) === null ? null : $decoded['amr'],
            is_int($time) && $time >= 0 ? $time : null,
        );
    }
}

<?php

declare(strict_types=1);

namespace Lukk\Support;

/**
 * The characters an account identifier may not carry, on every public route that writes or looks one up.
 *
 * The login throttle keys on the identifier's FOLD (`LoginRateLimiter::normalize()`), and with the lockout
 * off — the default — its IP-independent account bucket is the only cap on a distributed guesser (NIST
 * SP 800-63B-4 §3.2.2). A spelling the DATABASE resolves to an account while the fold keys it apart is a
 * fresh bucket, so every such spelling bought another `account_max_attempts` guesses:
 *
 *  - pdo_pgsql passes a bound string as a C string, so it ends at the first NUL: `victim@x.com\0<n>`
 *    looked up the victim, and each `<n>` keyed its own bucket — and a registration stored a different
 *    (truncated) value than the one it validated.
 *  - MySQL's `utf8mb4_unicode_ci` gives default-ignorable code points no weight (U+200B, U+00AD, U+034F)
 *    and pads trailing whitespace, so those matched the victim while `Str::transliterate` kept them.
 *
 * Refused: every control character (C0, C1 — NUL among them), every format character (`\p{Cf}`: zero-width
 * space, word joiner, soft hyphen, bidi controls), enclosing marks (`\p{Me}`), U+034F COMBINING GRAPHEME
 * JOINER, and any whitespace other than the ASCII space (U+00A0, U+3000, tab, line breaks). NOT refused:
 * combining marks in general (`\p{Mn}`) — Devanagari, Thai, Arabic and Hebrew need them — which the fold
 * strips instead, precomposed accented letters, and three code points of the refused classes that real
 * spelling needs: U+200C ZERO WIDTH NON-JOINER and U+200D ZERO WIDTH JOINER (RFC 5892 CONTEXTJ — Persian
 * writes `می‌خواهم` with a ZWNJ; emoji ZWJ sequences such as 👩‍💻) and U+20E3 COMBINING ENCLOSING KEYCAP
 * (keycap emoji, 1️⃣). MySQL's collation ignores those three as it does the rest, so the database may
 * resolve such a spelling to the plain one — and the fold strips them, so it keys the same bucket.
 *
 * The fold strips the whole set (and `\p{Mn}`) too, so a custom request class that skips this rule still
 * gets one bucket per account rather than one per spelling; only NUL truncation needs the refusal.
 */
class Identifier
{
    /**
     * The refused set, as a pattern. `\s` is Unicode-aware under `/u` in PCRE as PHP builds it; the
     * lookahead carves ZWNJ, ZWJ and the keycap out of `\p{Cf}` / `\p{Me}` (PCRE has no class subtraction).
     */
    public const INVISIBLE = '/(?![\x{200C}\x{200D}\x{20E3}])[\p{Cc}\p{Cf}\p{Me}\x{034F}]|[^\S ]/u';

    /** The validation rule, for a rule array (`not_regex` cannot go in a `|`-joined rule string). */
    public static function rule(): string
    {
        return 'not_regex:'.self::INVISIBLE;
    }
}

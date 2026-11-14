<?php

declare(strict_types=1);

namespace Lukk\Support;

use DateTimeImmutable;
use DateTimeInterface;

/**
 * The instant a stored local time names, when the clock showed that time twice.
 *
 * Laravel writes a timestamp as a zone-less string in `app.timezone` and parses it back the same way.
 * Where clocks are set back, one hour of wall time happens twice a year, and a string from it names two
 * instants; PHP picks one (the first occurrence in some zones, the second in others), so a `rotated_at`
 * written in the other reads back an hour off. The rotation grace window is 30 seconds wide:
 *
 *  - read an hour EARLY (the Americas), every concurrent refresh in that hour — two tabs, an SSR render —
 *    looked like a replay long past grace, and the family was revoked with a `RefreshTokenReused` alarm;
 *  - read an hour LATE (Europe, Australia), a replay up to an hour old was still "inside grace" and
 *    minted a sibling: reuse detection (RFC 9700 §4.14.2) was off for the hour.
 *
 * Nothing in the string says which occurrence was meant, but a rotation cannot have happened in the
 * future. So of the instants the string could name, this takes the LATEST ONE NOT AFTER NOW. That is
 * exact whenever the reader is less than the repeat away from the write — the whole of the grace window
 * — and it never calls a legitimate concurrent refresh reuse. What remains: a token rotated in the first
 * occurrence and replayed within `grace` of exactly one repeat later — or in the few seconds of skew
 * before it, below — is answered as inside grace. That is seconds once a year instead of an hour, and is
 * recorded under Known limitations; closing it needs the column stored in UTC, which is a schema
 * migration for every install.
 *
 * "Not after now" allows for the reader's clock running a few seconds BEHIND the writer's
 * (`SKEW_SECONDS`). Without that, a second host handling the concurrent refresh one second "before" the
 * rotation it was racing threw the true instant away as being in the future and took the one a full
 * repeat earlier: an hour past grace, the family revoked — the very false alarm this class exists to
 * prevent, for the zones PHP happens to read correctly.
 *
 * A zone with no such transition nearby — UTC, the recommended `app.timezone` — has one candidate and
 * gets it back unchanged.
 */
class RepeatedHour
{
    /** How far ahead of the reader's clock a rotation may be and still have happened: clock skew between hosts. */
    private const SKEW_SECONDS = 5;

    public static function resolve(DateTimeInterface $read, int $now): int
    {
        $timestamp = $read->getTimestamp();
        $zone = $read->getTimezone();
        $wall = $read->format('Y-m-d H:i:s');
        $candidates = [$timestamp];

        // A day either side: the repeat is at most a couple of hours, and the first entry is the offset in
        // force at the start of the range rather than a transition.
        // (The exact width decides nothing: a repeat is hours at most, a day is slack on both sides.)
        $transitions = $zone->getTransitions($timestamp - 86400, $timestamp + 86400) ?: []; // @pest-mutate-ignore: DecrementInteger,IncrementInteger

        foreach ($transitions as $index => $transition) {
            // How far the clock was set BACK at this transition; forward (or the leading entry) repeats nothing.
            $repeat = ($transitions[$index - 1]['offset'] ?? $transition['offset']) - $transition['offset'];

            // (A repeat of zero would only offer `$timestamp` again, which is already a candidate; no zone repeats one second.)
            foreach ($repeat > 0 ? [$timestamp - $repeat, $timestamp + $repeat] : [] as $other) { // @pest-mutate-ignore: GreaterToGreaterOrEqual,DecrementInteger,IncrementInteger
                if ((new DateTimeImmutable('@'.$other))->setTimezone($zone)->format('Y-m-d H:i:s') === $wall) {
                    $candidates[] = $other;
                }
            }
        }

        $past = array_filter($candidates, fn (int $candidate) => $candidate <= $now + self::SKEW_SECONDS);

        // All of them well ahead of the clock: nothing to choose by, so as read.
        return $past === [] ? $timestamp : max($past);
    }
}

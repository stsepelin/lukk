<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Lukk\Events\RefreshTokenReused;
use Lukk\Exceptions\InvalidRefreshToken;
use Lukk\Support\RepeatedHour;

/*
 * `rotated_at` is stored as a zone-less local string. In the hour a clock change repeats, that string
 * names two instants and PHP reads back only one of them — see `RepeatedHour`.
 *
 *   America/New_York, 2026-11-01: 01:00–02:00 happens twice, first at -04:00 then at -05:00 (06:00 UTC).
 *   Europe/Tallinn,   2026-10-25: 03:00–04:00 happens twice, first at +03:00 then at +02:00 (01:00 UTC).
 */

uses()->group('refresh');

afterEach(fn () => date_default_timezone_set('UTC'));

function utc(string $time): int
{
    return Carbon::parse($time, 'UTC')->getTimestamp();
}

/** A stored local string, as Eloquent hands it back in that zone. */
function stored(string $wall, string $zone): DateTimeImmutable
{
    return new DateTimeImmutable($wall, new DateTimeZone($zone));
}

it('reads a time from a repeated hour as its latest occurrence that is not in the future', function (string $zone, string $wall, string $now, string $expected) {
    expect(RepeatedHour::resolve(stored($wall, $zone), utc($now)))->toBe(utc($expected));
})->with([
    // PHP reads New York's repeated hour as the FIRST occurrence (05:30 UTC).
    'written in the second occurrence, read seconds later' => ['America/New_York', '2026-11-01 01:30:00', '2026-11-01 06:30:02', '2026-11-01 06:30:00'],
    'written in the first occurrence, read seconds later' => ['America/New_York', '2026-11-01 01:30:00', '2026-11-01 05:30:02', '2026-11-01 05:30:00'],
    'read at the very instant of the second occurrence' => ['America/New_York', '2026-11-01 01:30:00', '2026-11-01 06:30:00', '2026-11-01 06:30:00'],
    // A reader whose clock is a few seconds behind the writer's still reads the rotation it is racing.
    'read by a clock five seconds behind the second occurrence' => ['America/New_York', '2026-11-01 01:30:00', '2026-11-01 06:29:55', '2026-11-01 06:30:00'],
    'read six seconds before the second occurrence: not skew' => ['America/New_York', '2026-11-01 01:30:00', '2026-11-01 06:29:54', '2026-11-01 05:30:00'],
    'the other direction, a second behind' => ['Europe/Tallinn', '2026-10-25 03:30:05', '2026-10-25 01:30:04', '2026-10-25 01:30:05'],
    // PHP reads Tallinn's as the SECOND occurrence (01:30 UTC), so the first is the one recovered.
    'the other direction: written in the first, read in it' => ['Europe/Tallinn', '2026-10-25 03:30:00', '2026-10-25 00:30:02', '2026-10-25 00:30:00'],
    'the other direction: written in the second' => ['Europe/Tallinn', '2026-10-25 03:30:00', '2026-10-25 01:30:02', '2026-10-25 01:30:00'],
    'a half-hour repeat (Lord Howe)' => ['Australia/Lord_Howe', '2026-04-05 01:45:00', '2026-04-04 14:45:10', '2026-04-04 14:45:00'],
    'an ordinary hour in a zone that has repeats' => ['America/New_York', '2026-11-01 03:30:00', '2026-11-01 09:00:00', '2026-11-01 08:30:00'],
    'the hour a clock is set FORWARD over repeats nothing' => ['America/New_York', '2026-03-08 03:30:00', '2026-03-08 09:00:00', '2026-03-08 07:30:00'],
    'UTC has one reading' => ['UTC', '2026-11-01 01:30:00', '2026-11-01 09:00:00', '2026-11-01 01:30:00'],
    'every reading ahead of the clock: as read' => ['America/New_York', '2026-11-01 01:30:00', '2026-11-01 05:00:00', '2026-11-01 05:30:00'],
]);

/** Start a session, rotate it, and say the rotation was stored at this wall-clock time in the app's zone. */
function rotatedAtWallTime(string $zone, string $wall): string
{
    config(['app.timezone' => $zone]);
    date_default_timezone_set($zone);

    $pair = start()(1);
    rotate()($pair->refreshToken);
    DB::table('refresh_tokens')->whereNotNull('rotated_at')->update(['rotated_at' => $wall]);

    return $pair->refreshToken;
}

it('does not call a concurrent refresh in the repeated hour reuse', function () {
    // Rotated at 01:59:50 in the SECOND occurrence (06:59:50 UTC), replayed fifteen seconds later by a
    // second tab. Read back as the first occurrence, that was an hour and fifteen seconds past grace: the
    // family was revoked and the theft alarm raised, for every multi-tab user in that hour.
    Event::fake([RefreshTokenReused::class]);
    $token = rotatedAtWallTime('America/New_York', '2026-11-01 01:59:50');

    $this->travelTo(Carbon::createFromTimestamp(utc('2026-11-01 07:00:05'), 'America/New_York'));

    expect(rotate()($token)->refreshToken)->not->toBe($token)
        ->and(DB::table('refresh_tokens')->whereNotNull('revoked_at')->count())->toBe(0);
    Event::assertNotDispatched(RefreshTokenReused::class);
});

it('still revokes the family for a replay long after a rotation in the repeated hour', function () {
    // The other half. Rotated at 03:59:50 in Tallinn's FIRST occurrence (00:59:50 UTC) and replayed forty
    // minutes later: read back as the second occurrence, the rotation appeared to lie in the future, so the
    // replay was "inside grace" and minted a sibling — reuse detection was off for the hour.
    Event::fake([RefreshTokenReused::class]);
    $token = rotatedAtWallTime('Europe/Tallinn', '2026-10-25 03:59:50');

    $this->travelTo(Carbon::createFromTimestamp(utc('2026-10-25 01:40:00'), 'Europe/Tallinn'));

    expect(fn () => rotate()($token))->toThrow(InvalidRefreshToken::class);
    Event::assertDispatched(RefreshTokenReused::class);
});

it('does not revoke the family when the host handling a concurrent refresh runs a second behind', function () {
    // Two app hosts, the usual NTP-sized disagreement: the rotation was stored at 03:30:05 in the second
    // occurrence, and the sibling request is handled by a host that believes it is 03:30:04. Read as
    // "in the future, so it must have been the first occurrence", it was an hour past grace.
    Event::fake([RefreshTokenReused::class]);
    $token = rotatedAtWallTime('Europe/Tallinn', '2026-10-25 03:30:05');

    $this->travelTo(Carbon::createFromTimestamp(utc('2026-10-25 01:30:04'), 'Europe/Tallinn'));

    expect(rotate()($token)->refreshToken)->not->toBe($token)
        ->and(DB::table('refresh_tokens')->whereNotNull('revoked_at')->count())->toBe(0);
    Event::assertNotDispatched(RefreshTokenReused::class);
});

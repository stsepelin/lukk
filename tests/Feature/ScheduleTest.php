<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Lukk\Lukk;

afterEach(function () {
    Lukk::$runsScheduledPruning = true;
});

function schedulesPrune(): bool
{
    return collect(app(Schedule::class)->events())
        ->contains(fn ($event) => str_contains((string) $event->command, 'lukk:prune'));
}

it('schedules lukk:prune daily by default', function () {
    expect(schedulesPrune())->toBeTrue();
});

it('does not schedule pruning once disabled', function () {
    Lukk::disableScheduling();

    expect(schedulesPrune())->toBeFalse();
});

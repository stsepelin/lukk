<?php

declare(strict_types=1);

namespace Lukk\Console\Concerns;

/**
 * Read console input as a string, without pretending `mixed` is one.
 *
 * `option()` and `argument()` return `array|bool|string|null` — an option declared as an array, or a
 * flag, or an absent value. Casting that straight to `string` is a FATAL on the array case. These
 * narrow instead: anything that isn't a scalar becomes the empty string, which every caller here
 * already treats as "not supplied".
 *
 * A boolean flag still yields `"1"`, because `is_scalar(true)` is true — this does NOT protect
 * against reading a flag as a string, and no shipped command does.
 */
trait ReadsStringInput
{
    protected function stringOption(string $name): string
    {
        $value = $this->option($name);

        return is_scalar($value) ? trim((string) $value) : '';
    }

    protected function stringArgument(string $name): string
    {
        $value = $this->argument($name);

        return is_scalar($value) ? trim((string) $value) : '';
    }
}

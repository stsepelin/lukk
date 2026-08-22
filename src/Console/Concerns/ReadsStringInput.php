<?php

declare(strict_types=1);

namespace Lukk\Console\Concerns;

/**
 * Read console input as a string, without pretending `mixed` is one.
 *
 * `option()` and `argument()` return `array|bool|string|null` — an option declared as an array, or a
 * flag, or an absent value. Casting that straight to `string` is a fatal on the array case, and
 * silently yields `"1"` on the flag case. These narrow instead: anything that isn't a scalar becomes
 * the empty string, which every caller here already treats as "not supplied".
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

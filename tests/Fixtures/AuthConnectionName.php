<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/** A pure enum naming a connection by its case, as Laravel's `enum_value()` reads one. */
enum AuthConnectionName
{
    case lukk_other;
}

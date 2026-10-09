<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/** A connection named by an enum, which Laravel accepts wherever it takes a connection name. */
enum AuthConnection: string
{
    case Other = 'lukk_other';
}

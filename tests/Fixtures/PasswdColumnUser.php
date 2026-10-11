<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/** A user whose password lives in a column not called `password` (`getAuthPasswordName()`). */
class PasswdColumnUser extends User
{
    protected $table = 'users';

    protected $authPasswordName = 'passwd';
}

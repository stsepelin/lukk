<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Closure;
use Lukk\Models\RefreshToken;

/**
 * A `useRefreshTokenModel` subclass with model-event listeners, as an application auditing its sessions
 * would register in `booted()`. Each test sets `$onEvent`, which is called for every Eloquent model event
 * on the model; returning false from a `-ing` event cancels the write, as Eloquent defines.
 */
class ObservedRefreshToken extends RefreshToken
{
    protected $table = 'refresh_tokens';

    public static ?Closure $onEvent = null;

    protected static function booted(): void
    {
        foreach (['saving', 'creating', 'created', 'saved'] as $event) {
            static::registerModelEvent($event, fn (self $model) => self::$onEvent === null ? null : (self::$onEvent)($event, $model));
        }
    }
}

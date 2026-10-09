<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Illuminate\Cache\ArrayStore;
use Illuminate\Contracts\Cache\Store;

/** A cache store with no lock support (memcached without the extension, a custom store). */
class LocklessStore implements Store
{
    private ArrayStore $inner;

    public function __construct()
    {
        $this->inner = new ArrayStore;
    }

    public function get($key): mixed
    {
        return $this->inner->get($key);
    }

    public function many(array $keys): array
    {
        return $this->inner->many($keys);
    }

    public function put($key, $value, $seconds): bool
    {
        return $this->inner->put($key, $value, $seconds);
    }

    public function putMany(array $values, $seconds): bool
    {
        return $this->inner->putMany($values, $seconds);
    }

    public function increment($key, $value = 1): int|bool
    {
        return $this->inner->increment($key, $value);
    }

    public function decrement($key, $value = 1): int|bool
    {
        return $this->inner->decrement($key, $value);
    }

    public function forever($key, $value): bool
    {
        return $this->inner->forever($key, $value);
    }

    public function forget($key): bool
    {
        return $this->inner->forget($key);
    }

    public function flush(): bool
    {
        return $this->inner->flush();
    }

    public function touch($key, $seconds)
    {
        return $this->inner->touch($key, $seconds);
    }

    public function getPrefix(): string
    {
        return '';
    }
}

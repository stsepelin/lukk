<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

/**
 * The authenticated user on a route that only mounts behind `auth:{guard}`.
 *
 * `Request::user()` is nullable because a request need not be authenticated at all — but every
 * caller of this lives behind the guard, so null is unreachable there. Narrowed once here rather
 * than with a runtime guard at each call site: a branch that can never be taken is dead code, and
 * the 100% coverage gate would rightly reject it.
 *
 * `assert()` rather than a thrown exception for the same reason — it is compiled out in production
 * (`zend.assertions=-1`) and fails loudly in development if the assumption ever stops holding. If
 * it is disabled and the assumption breaks anyway, the declared return type turns it into a
 * TypeError, which is still loud.
 */
trait ResolvesAuthenticatedUser
{
    private function authenticated(Request $request): Authenticatable
    {
        $user = $request->user();

        assert($user !== null);

        return $user;
    }
}

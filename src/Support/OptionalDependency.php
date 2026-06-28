<?php

declare(strict_types=1);

namespace Lukk\Support;

use RuntimeException;

/**
 * Guards a feature-gated optional dependency. The 2FA/passkey libraries are
 * `suggest`ed (not required) so a lean install stays lean — enabling the feature
 * without the library should fail with an actionable message, not an opaque
 * "Class not found".
 */
class OptionalDependency
{
    public static function ensure(string $class, string $package, string $feature): void
    {
        if (! class_exists($class)) {
            throw new RuntimeException(sprintf(
                'The lukk "%s" feature requires the "%s" package. Install it with: composer require %s',
                $feature,
                $package,
                $package,
            ));
        }
    }
}

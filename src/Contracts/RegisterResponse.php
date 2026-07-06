<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Illuminate\Contracts\Support\Responsable;

/**
 * Returned by registration: the same token pair a login yields (auto-login), or — when
 * `email_verification.block_unverified_login` is on — a no-session "verify first" shape.
 * Rebind to reshape the body/cookies.
 */
interface RegisterResponse extends Responsable {}

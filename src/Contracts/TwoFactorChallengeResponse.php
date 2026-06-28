<?php

declare(strict_types=1);

namespace Lukk\Contracts;

use Illuminate\Contracts\Support\Responsable;

/**
 * Returned by login when the user has confirmed 2FA — instead of the token pair,
 * a challenge the client exchanges (with a code) at /auth/two-factor-challenge.
 * Rebind to reshape.
 */
interface TwoFactorChallengeResponse extends Responsable {}

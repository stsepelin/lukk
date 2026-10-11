<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Http\Requests\RegisterRequest;

/** A rebound registration request whose rules know nothing of bcrypt, NUL bytes or types. */
class LooseRegisterRequest extends RegisterRequest
{
    public function rules(): array
    {
        return ['name' => ['required'], 'email' => ['required', 'email'], 'password' => ['required', 'confirmed', 'min:8']];
    }
}

<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

/** A rebound registration request that words its own failures, and names its own attributes. */
class WordedRegisterRequest extends LooseRegisterRequest
{
    public function messages(): array
    {
        return ['password.min' => 'Your :attribute is too short.'];
    }

    public function attributes(): array
    {
        return ['password' => 'passphrase'];
    }
}

<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Http\Requests\RegisterRequest;

/** A rebound registration request that keeps lukk's rules and tightens the password's. */
class StricterRegisterRequest extends RegisterRequest
{
    public function rules(): array
    {
        $rules = parent::rules();
        $rules['password'][] = 'min:12';

        return $rules;
    }
}

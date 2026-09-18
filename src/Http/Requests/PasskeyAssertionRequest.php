<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * A WebAuthn assertion: the ceremony id plus the serialized credential. Shared by
 * passkey login and passkey step-up confirmation (the library validates the
 * assertion itself; this only guards the request shape).
 */
class PasskeyAssertionRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, array<int, string>>
     */
    public function rules(): array
    {
        return [
            'ceremony_id' => ['required', 'string'],
            'credential' => ['required', 'array'],
            // One rung deeper than `array`: `FinishPasskeyLogin` casts this to string, and an array or
            // object there raised an ErrorException — a 500 on an UNAUTHENTICATED route, against this
            // package's own rule that malformed input renders 422. WebAuthn L3 §5.1 types `id` as a
            // DOMString, so nothing legitimate is lost.
            'credential.id' => ['required', 'string'],
        ];
    }
}

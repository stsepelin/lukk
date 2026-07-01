<?php

declare(strict_types=1);

namespace Lukk\Http\Requests;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;

/**
 * Stateless email-verification request. The `signed` middleware validates the link
 * signature (untampered + unexpired); this resolves the user from the route `{id}`
 * and confirms `{hash}` matches sha1(email). It is a stateless variant of Laravel's
 * EmailVerificationRequest — no session or bearer, because the signature is the
 * authority and the link is clicked straight from an email.
 */
class VerifyEmailRequest extends FormRequest
{
    private ?Authenticatable $resolved = null;

    private bool $lookedUp = false;

    public function authorize(): bool
    {
        $user = $this->verifiable();

        return $user instanceof MustVerifyEmail
            && hash_equals((string) $this->route('hash'), sha1($user->getEmailForVerification()));
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [];
    }

    /** The user addressed by the signed link, or null when the `{id}` doesn't resolve. */
    public function verifiable(): ?Authenticatable
    {
        if (! $this->lookedUp) {
            $this->lookedUp = true;
            $this->resolved = Auth::createUserProvider(config('lukk.user_provider'))
                ?->retrieveById($this->route('id'));
        }

        return $this->resolved;
    }
}

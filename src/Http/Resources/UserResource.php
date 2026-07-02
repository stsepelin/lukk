<?php

declare(strict_types=1);

namespace Lukk\Http\Resources;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * Optional base user resource emitting the fields lukk-js reads — the identifier and a
 * derived `email_verified` boolean — so the client's `useLukkAuth().user` / `verified`
 * "just work". Extend it and override `fields()` to add your own; a bare model or your own
 * resource works too. lukk does not own your user endpoint — this is a convenience.
 */
class UserResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $user = $this->resource;

        return [
            'id' => $user->getAuthIdentifier(),
            // Derived boolean (OIDC-canonical email_verified); null when the model doesn't verify email.
            'email_verified' => $user instanceof MustVerifyEmail ? $user->hasVerifiedEmail() : null,
            ...$this->fields($request),
        ];
    }

    /**
     * Override to add your app's fields (e.g. `$this->name`, `$this->roles`).
     *
     * @return array<string, mixed>
     */
    protected function fields(Request $request): array
    {
        return [];
    }
}

<?php

declare(strict_types=1);

namespace Lukk\Http\Resources;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Lukk\Lukk;
use Lukk\Support\VerifiedToken;

/**
 * Optional base user resource emitting the fields lukk-js reads — the identifier, a
 * derived `email_verified` boolean, and the token's `abilities` — so the client's
 * `useLukkAuth().user` / `verified` / `can()` "just work". Extend it and override `fields()` to add
 * your own; a bare model or your own resource works too. lukk does not own your user endpoint —
 * this is a convenience.
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
            ...$this->abilities($request, $user),
            ...$this->fields($request),
        ];
    }

    /**
     * The current token's abilities — the only way a client in BFF mode can learn them, since it
     * never sees the access token that carries the `scope` claim.
     *
     * **Absent, not empty, when abilities are not in play.** The two mean different things to a
     * client: `[]` is "in use, and this token was granted nothing" (hide the UI), while an absent
     * key is "this server does not use abilities" (show it). Emitting `[]` unconditionally would
     * blank the UI of every install that upgraded without opting in.
     *
     * Only emitted for the token's OWN subject. A resource wrapping some *other* user — a user list,
     * an admin screen — would otherwise carry an `abilities` key describing the reader's token,
     * which reads as a claim about the wrong person.
     *
     * @return array<string, mixed>
     */
    protected function abilities(Request $request, object $user): array
    {
        $token = VerifiedToken::forUser($request, $user);

        if ($token === null) {
            return [];
        }

        // The global flag OR this token's own claim. A session pinned by `StartSession` carries a
        // real grant whether or not the install set the flag, and omitting the key then told the
        // client "this server doesn't use abilities" — so it rendered the full privileged UI for a
        // token the API will refuse. (A grant pinned to NOTHING carries no claim and so is still
        // invisible here; that residue is exactly what the flag exists to cover.)
        // `pin` closes the last gap: a grant pinned to NOTHING carries no `scope` claim, so before
        // this the most restricted token the API can issue reported no `abilities` key at all — and
        // the client read that as "this server doesn't use abilities" and rendered the full UI.
        $inUse = Lukk::usesAbilities() || isset($token->claims->scope) || isset($token->claims->pin);

        if (! $inUse) {
            return [];
        }

        // `token_pinned` too, because `abilities` alone is the wrong predictor for lukk's own gated
        // routes: those apply only to a pinned token, so a client gating "sign out other devices" on
        // `can('lukk.sessions')` would hide it from every ordinary user — whose derived grant never
        // contains it and who is never gated anyway. It describes the reader's own token, so it
        // discloses nothing they don't already hold.
        return [
            'abilities' => $token->abilities->all(),
            'token_pinned' => isset($token->claims->pin),
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

<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lukk\Actions\FinishPasskeyRegistration;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Events\PasskeyDeleted;
use Lukk\Http\Concerns\PreventsCaching;
use Lukk\Http\Controllers\Concerns\EndsOtherSessions;
use Lukk\Http\Controllers\Concerns\ResolvesAuthenticatedUser;
use Lukk\Http\Requests\PasskeyRegistrationRequest;

/**
 * The user's passkey credentials: `index` lists them, `store` registers a new
 * one (verifying the attestation), `destroy` removes one. Registration and
 * deletion sit behind step-up confirmation. The matching ceremony options are
 * negotiated by PasskeyRegistrationOptionsController.
 */
class PasskeyController
{
    use EndsOtherSessions;
    use PreventsCaching;
    use ResolvesAuthenticatedUser;

    public function __construct(
        private readonly FinishPasskeyRegistration $finishRegistration,
        private readonly PasskeyRepository $passkeys,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $passkeys = array_map(fn (array $passkey) => [
            'id' => $passkey['credential_id'],
            'name' => $passkey['name'],
            'last_used_at' => $passkey['last_used_at'],
        ], $this->passkeys->summariesForUser($this->authenticated($request)->getAuthIdentifier()));

        return $this->noStore(response()->json(['passkeys' => $passkeys]));
    }

    public function store(PasskeyRegistrationRequest $request): Response
    {
        ($this->finishRegistration)($this->authenticated($request), $request->array('credential'), $request->input('name'));

        return response()->noContent();
    }

    public function destroy(Request $request, string $credentialId): Response
    {
        $user = $this->authenticated($request);

        // Only an id spelled exactly as it is stored. The database compares more loosely than that:
        // MySQL's default collation folds case and pads trailing spaces, and pdo_pgsql ends a bound string
        // at a NUL, so `ABCDEF`, `AbCdEf ` and `AbCdEf\0x` each deleted the credential `AbCdEf` — and
        // `PasskeyDeleted`, the "an authenticator was removed" notice (NIST SP 800-63B-4 §4.2), then named
        // a credential that never existed. Compared against the ids the repository itself lists, so a
        // custom store with another id alphabet is held to its own spelling and nothing else.
        $owned = in_array($credentialId, $this->passkeys->credentialIdsFor($user->getAuthIdentifier()), true);

        // And only when a credential was actually removed — it may have gone since the line above.
        if ($owned && $this->passkeys->delete($user->getAuthIdentifier(), $credentialId)) {
            // The sweep first: a listener that throws (a removal notice that cannot be sent) must not leave
            // the removed device signed in — and a retry could not finish it, the credential being gone.
            $this->endOtherSessions($request, $user);
            event(new PasskeyDeleted($user, $credentialId));
        }

        return response()->noContent();
    }
}

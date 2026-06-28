<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Lukk\Actions\FinishPasskeyRegistration;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Http\Concerns\PreventsCaching;

/**
 * The user's passkey credentials: `index` lists them, `store` registers a new
 * one (verifying the attestation), `destroy` removes one. Registration and
 * deletion sit behind step-up confirmation. The matching ceremony options are
 * negotiated by PasskeyRegistrationOptionsController.
 */
class PasskeyController
{
    use PreventsCaching;

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
        ], $this->passkeys->summariesForUser($request->user()->getAuthIdentifier()));

        return $this->noStore(response()->json(['passkeys' => $passkeys]));
    }

    public function store(Request $request): Response
    {
        $request->validate(['credential' => ['required', 'array'], 'name' => ['nullable', 'string', 'max:255']]);

        ($this->finishRegistration)($request->user(), $request->array('credential'), $request->input('name'));

        return response()->noContent();
    }

    public function destroy(Request $request, string $credentialId): Response
    {
        $this->passkeys->delete($request->user()->getAuthIdentifier(), $credentialId);

        return response()->noContent();
    }
}

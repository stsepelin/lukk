<?php

declare(strict_types=1);

namespace Lukk\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Lukk\Actions\DeleteAccount;
use Lukk\Actions\ExportAccount;
use Lukk\Http\Concerns\PreventsCaching;

/**
 * The authenticated user's own account: export it (Art. 15 / 20) or erase it (Art. 17).
 *
 * Behind step-up confirmation, not merely authentication. Erasure is irreversible and a stolen
 * access token alone must not be enough to destroy an account — the same reasoning that puts
 * `confirm-password` in front of changing a password or removing a second factor.
 *
 * Step-up alone still does NOT close this to machine tokens, which is why both routes carry the
 * separate `lukk.account.delete` gate. A confirmation is bound to the refresh-token FAMILY that
 * earned it, so a pinned token can no longer present one the human's session earned — but a pin
 * carrying `lukk.account` can earn its own, and `lukk.account` is deliberately not enough here.
 *
 * `destroy()` returns a flat 204 and `export()` a plain JSON body — neither is a Response contract,
 * because there is nothing for a consumer to swap and nothing branches on the request.
 */
class AccountController
{
    use PreventsCaching;

    /**
     * The personal data lukk holds — the AUTH slice only.
     *
     * lukk knows about sessions, passkeys and whether two-factor is on. It knows nothing about the
     * data a subject actually cares about, so serving this alone as an Art. 15 response would
     * under-disclose. Append your own domain data before you hand it over.
     *
     * Behind step-up for the same reason erasure is: it discloses everything lukk knows about
     * someone, and a stolen access token should not be enough to pull that out.
     */
    public function export(Request $request, ExportAccount $export): JsonResponse
    {
        return $this->noStore(new JsonResponse($export($request->user())));
    }

    public function destroy(Request $request, DeleteAccount $delete): JsonResponse
    {
        $delete($request->user());

        return $this->noStore(new JsonResponse(null, 204));
    }
}

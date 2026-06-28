<?php

declare(strict_types=1);

namespace Lukk\Passkeys;

use Illuminate\Support\Facades\Crypt;
use Lukk\Contracts\PasskeyRepository;
use Lukk\Models\Passkey;
use Lukk\Support\NewPasskey;
use Lukk\Support\PasskeyRecord;

/**
 * Default storage: the passkeys table. The COSE public key is
 * encrypted at rest; the credential id is the primary key (globally unique).
 */
class DatabasePasskeyRepository implements PasskeyRepository
{
    public function store(int|string $userId, NewPasskey $passkey, ?string $name = null): void
    {
        Passkey::query()->create([
            'credential_id' => $passkey->credentialId,
            'user_id' => $userId,
            'name' => $name,
            'public_key' => Crypt::encryptString($passkey->publicKey),
            'sign_count' => $passkey->signCount,
            'transports' => $passkey->transports,
            'aaguid' => $passkey->aaguid,
        ]);
    }

    public function findByCredentialId(string $credentialId): ?PasskeyRecord
    {
        $row = Passkey::query()->find($credentialId);

        return $row === null ? null : $this->toRecord($row);
    }

    public function credentialIdsFor(int|string $userId): array
    {
        return Passkey::query()->where('user_id', $userId)->pluck('credential_id')->all();
    }

    public function updateSignCount(string $credentialId, int $signCount): void
    {
        Passkey::query()->whereKey($credentialId)->update([
            'sign_count' => $signCount,
            'last_used_at' => now(),
        ]);
    }

    public function summariesForUser(int|string $userId): array
    {
        return Passkey::query()->where('user_id', $userId)
            ->get(['credential_id', 'name', 'last_used_at'])
            ->map(fn (Passkey $row) => [
                'credential_id' => $row->credential_id,
                'name' => $row->name,
                'last_used_at' => $row->last_used_at?->getTimestamp(),
            ])->all();
    }

    public function delete(int|string $userId, string $credentialId): bool
    {
        return (bool) Passkey::query()->where('user_id', $userId)->whereKey($credentialId)->delete();
    }

    private function toRecord(Passkey $row): PasskeyRecord
    {
        return new PasskeyRecord(
            credentialId: $row->credential_id,
            userId: $row->user_id,
            publicKey: Crypt::decryptString($row->public_key),
            signCount: (int) $row->sign_count,
            transports: $row->transports ?? [],
            aaguid: $row->aaguid,
            name: $row->name,
            lastUsedAt: $row->last_used_at?->getTimestamp(),
        );
    }
}

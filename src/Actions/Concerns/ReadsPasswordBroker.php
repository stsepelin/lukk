<?php

declare(strict_types=1);

namespace Lukk\Actions\Concerns;

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

use function Illuminate\Support\enum_value;

/**
 * Where the configured password broker keeps its pending reset rows — for erasure, which deletes them,
 * and the data-subject export, which must disclose what erasure deletes. One copy, so the two can never
 * reach different tables.
 *
 * Using classes hold `private readonly ?string $passwordBroker` (`lukk.password_reset.broker`; null is
 * the default broker).
 */
trait ReadsPasswordBroker
{
    /**
     * Deliberately NOT memoized.
     *
     * A static cache looked free — schema state, on a rare path — but it is answered once per
     * PROCESS: a worker that started before a migration keeps saying "no such table" and silently
     * skips erasing those rows, which is the one failure mode this method exists to prevent. It also
     * leaks between tests in a shared process. Two cheap queries on an irreversible operation is not
     * a cost worth that.
     */
    private function resetTableExists(): bool
    {
        // On the broker's OWN connection (`auth.passwords.*.connection`, which the framework's broker
        // honours): checked on the default one, a table living elsewhere read as missing and the row —
        // a plaintext email address — survived the erasure.
        return Schema::connection($this->brokerConnection())
            ->hasTable($this->passwordResetTable());
    }

    /**
     * The table the configured broker actually writes to.
     *
     * Not hardcoded `password_reset_tokens`: a broker may name its own (`lukk.password_reset.broker`
     * pointing at one with `'table' => 'lukk_password_resets'` is exactly the setup the sibling
     * regression test uses), and guarding on the wrong name would skip a sweep that had work to do.
     */
    private function passwordResetTable(): string
    {
        // The cast only states the type: a table name from config is a string.
        return (string) (config("auth.passwords.{$this->brokerName()}.table") ?? 'password_reset_tokens'); // @pest-mutate-ignore: RemoveStringCast
    }

    /**
     * The broker's connection, as the framework reads it. An enum is a valid name in config; `(string)`
     * on one threw before anything was erased, and only later 12.x releases unwrap one inside
     * `DB::connection()` — so it is unwrapped here, with the framework's own helper, for both callers.
     * Null (or '') is the default connection.
     */
    private function brokerConnection(): ?string
    {
        $connection = enum_value(config("auth.passwords.{$this->brokerName()}.connection"));

        return is_string($connection) ? $connection : null;
    }

    private function brokerName(): string
    {
        // The cast only states the type: a broker name only reaches a config key, where null and '' read the same.
        return $this->passwordBroker ?? (string) config('auth.defaults.passwords'); // @pest-mutate-ignore: RemoveStringCast
    }

    /**
     * When the user's pending reset was requested, or null when there is none to read.
     *
     * Read the way the framework's `DatabaseTokenRepository` writes it: keyed on
     * `getEmailForPasswordReset()`, `created_at` beside the hashed token — which is never read. Guarded on
     * the table like the erasure sweep, so a cache-driven broker or an unmigrated install answers null.
     */
    private function pendingResetRequestedAt(mixed $user): ?string
    {
        if (! $user instanceof CanResetPassword || ! $this->resetTableExists()) {
            return null;
        }

        $requested = DB::connection($this->brokerConnection())->table($this->passwordResetTable())
            ->where('email', $user->getEmailForPasswordReset())
            ->value('created_at');

        return $requested === null ? null : Carbon::parse($requested)->toIso8601String();
    }
}

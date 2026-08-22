<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Lukk\Actions\RevokeSession;
use Lukk\Actions\RotateRefreshToken;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\RefreshTokenRepository;
use Lukk\Contracts\TokenIssuer;
use Lukk\Lukk;
use Lukk\Models\RefreshToken;
use Lukk\Refresh\DatabaseRefreshTokenRepository;
use Lukk\Support\RefreshTokenRecord;
use Lukk\Tests\Fixtures\User;

uses()->group('abilities', 'refresh');

afterEach(fn () => Lukk::$refreshTokenModel = null);

it('resolves the pre-transaction read on the primary, never a replica', function () {
    // `Connection::getReadPdo()` returns the write PDO only while `transactions > 0`. The grant is
    // resolved BEFORE the transaction opens, so on a read/write split that one read — and only that
    // one — lands on a replica, while the locked read inside the transaction hits the primary.
    // `sticky` doesn't cover it: a refresh has written nothing on the connection yet. The row being
    // looked up was inserted milliseconds ago by the previous rotation, which is exactly the window
    // replication lag covers, and a miss mints the successor with no grant at all.
    //
    // Runs on its own connection, deliberately: the suite wraps each test in a transaction, and
    // inside one `getReadPdo()` returns the write PDO regardless — so a test on the default
    // connection would pass whether or not the fix is present.
    $primary = tempnam(sys_get_temp_dir(), 'lukk-primary').'.sqlite';
    $replica = tempnam(sys_get_temp_dir(), 'lukk-replica').'.sqlite';
    touch($primary);
    touch($replica);

    config(['database.connections.lukk_split' => [
        'driver' => 'sqlite',
        'read' => ['database' => $replica],   // a replica that has not caught up
        'write' => ['database' => $primary],
        'prefix' => '',
        'foreign_key_constraints' => false,
    ]]);

    $schema = function (string $connection) {
        Schema::connection($connection)->create('refresh_tokens', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->unsignedBigInteger('user_id')->index();
            $table->string('family_id')->index();
            $table->string('previous_id')->nullable();
            $table->string('token_hash')->unique();
            $table->text('scope')->nullable();
            $table->timestamp('rotated_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    };

    // The row exists on the primary only — exactly the state replication lag produces.
    config(['database.connections.lukk_primary_only' => ['driver' => 'sqlite', 'database' => $primary, 'prefix' => '']]);
    config(['database.connections.lukk_replica_only' => ['driver' => 'sqlite', 'database' => $replica, 'prefix' => '']]);
    $schema('lukk_primary_only');
    $schema('lukk_replica_only');

    DB::connection('lukk_primary_only')->table('refresh_tokens')->insert([
        'id' => 'row-1', 'user_id' => 1, 'family_id' => 'fam', 'previous_id' => null,
        'token_hash' => 'the-hash', 'scope' => 'ci.deploy',
        'rotated_at' => null, 'revoked_at' => null,
        'expires_at' => now()->addDay(), 'created_at' => now(), 'updated_at' => now(),
    ]);

    Lukk::useRefreshTokenModel(SplitConnectionRefreshToken::class);
    $repository = new DatabaseRefreshTokenRepository;

    expect(DB::connection('lukk_split')->transactionLevel())->toBe(0, 'the split must not be inside a transaction, or the read PDO is bypassed anyway')
        ->and(DB::connection('lukk_replica_only')->table('refresh_tokens')->count())->toBe(0, 'the replica really is behind');

    $record = $repository->findByHash('the-hash');

    expect($record)->not->toBeNull('the pre-read must go to the primary, not the lagging replica')
        ->and($record->scope)->toBe('ci.deploy');

    Lukk::$refreshTokenModel = null;
    @unlink($primary);
    @unlink($replica);
});

it('refuses to mint when the pre-read disagrees with the locked read', function () {
    // "I couldn't read the row" must never collapse into "no abilities argument": the issuer reads a
    // null grant as "abilities not in use", which leaves a decorative `tokenClaimsUsing` scope
    // standing as the signed grant. Unreachable in practice — `token_hash` is unique and both reads
    // use the primary — so this pins the fail-closed behaviour if it ever becomes reachable.
    $pair = User::factory()->create()->startSession();

    $blind = new class(app(RefreshTokenRepository::class)) implements RefreshTokenRepository
    {
        public function __construct(private RefreshTokenRepository $inner) {}

        public function findByHash(string $hash): ?RefreshTokenRecord
        {
            return null;   // a replica that hasn't caught up
        }

        public function transaction(Closure $callback): mixed
        {
            return $this->inner->transaction($callback);
        }

        public function familyIsPinned(string $familyId): bool
        {
            return $this->inner->familyIsPinned($familyId);
        }

        public function findByHashForUpdate(string $hash): ?RefreshTokenRecord
        {
            return $this->inner->findByHashForUpdate($hash);
        }

        public function persist(int|string $userId, string $familyId, ?string $previousId, string $tokenHash, int $expiresAt, ?string $scope = null): void
        {
            $this->inner->persist($userId, $familyId, $previousId, $tokenHash, $expiresAt, $scope);
        }

        public function markRotated(string $id): void
        {
            $this->inner->markRotated($id);
        }

        public function countLiveTokens(string $familyId): int
        {
            return $this->inner->countLiveTokens($familyId);
        }

        public function revokeFamily(string $familyId): void
        {
            $this->inner->revokeFamily($familyId);
        }

        public function revokeUserFamilies(int|string $userId, ?callable $before = null): array
        {
            return $this->inner->revokeUserFamilies($userId, $before);
        }

        public function revokeUserFamiliesExcept(int|string $userId, string $exceptFamilyId, ?callable $before = null): array
        {
            return $this->inner->revokeUserFamiliesExcept($userId, $exceptFamilyId, $before);
        }

        public function pruneExpired(): int
        {
            return $this->inner->pruneExpired();
        }
    };

    $rotate = new RotateRefreshToken(
        $blind,
        app(TokenIssuer::class),
        app(RevokeSession::class),
        app(Denylist::class),
        Lukk::guardConfig(),
        Lukk::currentGuard(),
    );

    expect(fn () => $rotate($pair->refreshToken))
        ->toThrow(RuntimeException::class, 'disagreed with the locked read');
});

class SplitConnectionRefreshToken extends RefreshToken
{
    protected $connection = 'lukk_split';

    protected $table = 'refresh_tokens';
}

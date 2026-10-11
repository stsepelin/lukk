<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Lukk\Auth\JwtGuard;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\TokenVerifier;
use Lukk\Models\RefreshToken;
use Lukk\Tests\Fixtures\DecodingUserProvider;
use Lukk\Tests\Fixtures\EncodedIdUser;
use Lukk\Tests\Fixtures\PrefixedUlidUser;
use Lukk\Tests\Fixtures\PublicIdUser;
use Lukk\Tests\Fixtures\StringKeyUser;
use Lukk\Tests\Fixtures\UlidUser;
use Lukk\Tests\Fixtures\User;
use Lukk\Tests\Fixtures\UuidUser;

beforeEach(function () {
    Route::middleware('auth:api')->get('/_protected', fn (Request $r) => ['id' => $r->user()->getAuthIdentifier()]);
});

it('authenticates a request carrying a valid bearer token', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    $this->withToken($pair->accessToken)->getJson('/_protected')
        ->assertOk()
        ->assertExactJson(['id' => $user->id]);
});

it('rejects a request with no bearer token', function () {
    $this->getJson('/_protected')->assertUnauthorized();
});

it('rejects a garbage / unsigned token', function () {
    $this->withToken('not-a-jwt')->getJson('/_protected')->assertUnauthorized();
});

it('rejects malformed Authorization headers', function (string $header) {
    $this->withHeaders(['Authorization' => $header])->getJson('/_protected')->assertUnauthorized();
})->with([
    'scheme only' => 'Bearer',
    'empty token' => 'Bearer ',
    'wrong scheme' => 'Token abcdef',
    'two-segment jwt' => 'Bearer aaa.bbb',
    'junk jwt' => 'Bearer not.a.jwt',
]);

it('rejects a token whose subject no longer exists', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    $user->delete();

    $this->withToken($pair->accessToken)->getJson('/_protected')->assertUnauthorized();
});

it('rejects the next request once the family is denylisted', function () {
    $user = User::factory()->create();
    $pair = $user->startSession();

    // The access token works...
    $this->withToken($pair->accessToken)->getJson('/_protected')->assertOk();

    // ...until its family is denylisted, then it dies on the very next request.
    app(Denylist::class)->revokeFamily(RefreshToken::query()->value('family_id'), 900);

    // Each production request gets a fresh guard; reset the test app's memoized
    // guard/user so the second call re-runs verification instead of reusing the
    // user resolved above.
    app('auth')->forgetGuards();

    $this->withToken($pair->accessToken)->getJson('/_protected')->assertUnauthorized();
});

it('refuses a subject an integer key could never hold, without asking the database', function (mixed $sub) {
    // A co-issuer's `sub` reaches `retrieveById()`, and on PostgreSQL a non-integer — or one past bigint —
    // compared with an integer key is SQLSTATE 22P02/22003: a 500 instead of a 401
    // (tests/Concurrency/CoIssuerTokenTest.php). Refused before the lookup.
    $cfg = Lukk\Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => $sub, 'jti' => 'co-sub',
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);
    $queries = [];
    DB::listen(function ($query) use (&$queries) {
        $queries[] = $query->sql;
    });

    $this->withToken($token)->getJson('/_protected')->assertUnauthorized();

    expect(implode(' ', $queries))->not->toContain('from "users"');
})->with([
    'a word' => ['admin'],
    'past the integer range' => ['99999999999999999999'],
    'a fraction' => ['1.5'],
    'zero-padded' => ['01'],
    'signed' => ['+1'],
    'spaced' => [' 1'],
    'a trailing newline' => ["1\n"],
    'empty' => [''],
]);

it('resolves an integer subject, as a string or — from a rebound verifier — as an int', function () {
    $user = User::factory()->create();
    $verifierFor = fn (mixed $sub) => new class($sub) implements TokenVerifier
    {
        public function __construct(private mixed $sub) {}

        public function verify(string $token): ?object
        {
            return (object) ['sub' => $this->sub, 'jti' => 'j', 'exp' => time() + 60];
        }
    };

    foreach ([(string) $user->id, $user->id] as $sub) {
        $guard = new JwtGuard($verifierFor($sub), app('auth')->createUserProvider('users'));

        expect($guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer x']))?->getKey())->toBe($user->id);
    }
});

function coSubjectToken(string $sub): string
{
    $cfg = Lukk\Lukk::guardConfig();

    return JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => $sub, 'jti' => 'co-'.bin2hex(random_bytes(4)),
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);
}

it('resolves a UUID auth identifier on a model whose integer primary key is not the identifier', function () {
    // `retrieveById()` looks up `getAuthIdentifierName()`, and lukk mints `sub` from
    // `getAuthIdentifier()`: the integer key type says nothing about the column the subject is
    // compared with. Stock provider, real lookup.
    Schema::create('public_id_users', function (Blueprint $table) {
        $table->id();
        $table->uuid('public_id')->unique();
    });
    $user = PublicIdUser::query()->create(['public_id' => $uuid = (string) Str::uuid()]);
    expect($user->getKeyType())->toBe('int')->and($user->getIncrementing())->toBeTrue();

    $guard = new JwtGuard(verifier(), new EloquentUserProvider(app('hash'), PublicIdUser::class));

    expect($guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer '.coSubjectToken($uuid)]))?->getKey())
        ->toBe($user->getKey());
});

it('resolves a string subject on a non-incrementing model that kept the default int key type', function () {
    // `$incrementing = false` without `$keyType = 'string'` is the common way to write a string key;
    // Eloquent never casts such a key, so the leftover 'int' is no statement about the column.
    Schema::create('string_key_users', function (Blueprint $table) {
        $table->string('id')->primary();
    });
    $user = StringKeyUser::query()->create(['id' => 'usr_42']);
    expect($user->getKeyType())->toBe('int')->and($user->getIncrementing())->toBeFalse();

    $guard = new JwtGuard(verifier(), new EloquentUserProvider(app('hash'), StringKeyUser::class));

    expect($guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer '.coSubjectToken('usr_42')]))?->getKey())
        ->toBe('usr_42');
});

function guardFor(UserProvider $users, mixed $sub = '42'): ?Authenticatable
{
    $verifier = new class($sub) implements TokenVerifier
    {
        public function __construct(private mixed $sub) {}

        public function verify(string $token): ?object
        {
            return (object) ['sub' => $this->sub, 'jti' => 'j', 'exp' => time() + 60];
        }
    };

    return (new JwtGuard($verifier, $users))(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer x']));
}

it('refuses a subject carrying a NUL, whatever the provider', function () {
    // pdo_pgsql passes a bound string as a C string, so `alice\0x` looked up `alice` — another account.
    $users = Mockery::mock(UserProvider::class);
    $users->shouldNotReceive('retrieveById');

    expect(guardFor($users, "alice\0x"))->toBeNull()
        ->and(guardFor(new EloquentUserProvider(app('hash'), User::class), "1\0"))->toBeNull();
});

it('refuses a subject that is neither a string nor an integer for an Eloquent provider', function (mixed $sub) {
    $user = User::factory()->create();
    $queries = 0;
    DB::listen(function ($query) use (&$queries) {
        $queries += str_contains($query->sql, 'from "users"') ? 1 : 0;
    });

    expect(guardFor(new EloquentUserProvider(app('hash'), User::class), $sub))->toBeNull()
        ->and($queries)->toBe(0)
        ->and(guardFor(new EloquentUserProvider(app('hash'), User::class), $user->id)?->getKey())->toBe($user->id);
})->with([
    'a float' => [1.0],
    'an array' => [[1]],
    'a boolean' => [true],
]);

/** Counts the lookups the guard ran on the default connection. */
function lookupsDuring(Closure $call): array
{
    $lookups = 0;
    DB::listen(function ($query) use (&$lookups) {
        $lookups += str_starts_with($query->sql, 'select') ? 1 : 0;
    });

    return [$call(), $lookups];
}

it('refuses a subject a HasUuids or HasUlids key cannot hold, with no query', function (string $model, string $table, string $bad) {
    Schema::create($table, fn (Blueprint $t) => $table === 'uuid_users' ? $t->uuid('id')->primary() : $t->ulid('id')->primary());
    $user = $model::query()->create();
    $users = new EloquentUserProvider(app('hash'), $model);

    expect(lookupsDuring(fn () => guardFor($users, $bad)))->toBe([null, 0])
        ->and(lookupsDuring(fn () => guardFor($users, 7)))->toBe([null, 0])
        ->and(guardFor($users, (string) $user->getKey())?->getKey())->toBe($user->getKey());
})->with([
    'HasUuids' => [UuidUser::class, 'uuid_users', 'admin'],
    'HasUuids, a ULID' => [UuidUser::class, 'uuid_users', '01ARZ3NDEKTSV4RRFFQ69G5FAV'],
    'HasUlids' => [UlidUser::class, 'ulid_users', 'admin'],
    'HasUlids, a UUID' => [UlidUser::class, 'ulid_users', 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'],
]);

it('asks the model what a valid unique id is, so its own id format resolves', function () {
    // `HasUlids` with an overridden `newUniqueId()`/`isValidUniqueId()` (`usr_<ulid>`): `Str::isUlid`
    // refused every real user. The model's own check is also what Laravel's route-model binding accepts.
    Schema::create('prefixed_ulid_users', fn (Blueprint $t) => $t->string('id')->primary());
    $user = PrefixedUlidUser::query()->create();
    $users = new EloquentUserProvider(app('hash'), PrefixedUlidUser::class);

    expect($user->getKey())->toStartWith('usr_')
        ->and(guardFor($users, $user->getKey())?->getKey())->toBe($user->getKey())
        ->and(lookupsDuring(fn () => guardFor($users, (string) Str::ulid())))->toBe([null, 0]);
});

it('leaves an EloquentUserProvider subclass unchecked: it may decode its own identifiers', function () {
    // The model presents its integer key as `u_5` and the provider subclass reads it back. Judged by the
    // model's key, every token lukk minted for it was refused.
    $user = EncodedIdUser::query()->create(['email' => 'encoded@y.com']);
    $users = new DecodingUserProvider(app('hash'), EncodedIdUser::class);

    expect($user->getAuthIdentifier())->toBe('u_'.$user->id)
        ->and(guardFor($users, $user->getAuthIdentifier())?->getKey())->toBe($user->id)
        ->and(lookupsDuring(fn () => guardFor($users, 'admin'))[1])->toBe(0)
        ->and(lookupsDuring(fn () => guardFor($users, 'u_admin'))[1])->toBe(1);
});

it('leaves to the provider every shape it cannot be certain of', function (Closure $model, mixed $sub) {
    // Nothing is refused here: one lookup runs, and whatever the column makes of the subject is the
    // provider's answer (on PostgreSQL a refused parameter is a reported 500 — CoIssuerTokenTest).
    expect(lookupsDuring(fn () => guardFor(new EloquentUserProvider(app('hash'), $model()), $sub))[1])->toBe(1);
})->with([
    'an identifier that is not the key' => [function () {
        Schema::create('public_id_users', function (Blueprint $table) {
            $table->id();
            $table->uuid('public_id');
        });

        return PublicIdUser::class;
    }, 'admin'],
    'a key that does not increment' => [function () {
        Schema::create('string_key_users', fn (Blueprint $table) => $table->string('id')->primary());

        return StringKeyUser::class;
    }, 'admin'],
    'an incrementing key of another type' => [fn () => get_class(new class extends User
    {
        protected $keyType = 'string';
    }), 'admin'],
    'a uuid trait generating another column' => [fn () => get_class(new class extends UuidUser
    {
        protected $table = 'users';

        public function uniqueIds()
        {
            return ['public_id'];
        }
    }), '5'],
    'a ulid trait generating another column' => [fn () => get_class(new class extends UlidUser
    {
        protected $table = 'users';

        public function uniqueIds()
        {
            return ['public_id'];
        }
    }), '5'],
    'a negative integer on the stock key' => [fn () => User::class, '-5'],
    'an int on the stock key' => [fn () => User::class, 5],
    'zero on the stock key' => [fn () => User::class, '0'],
]);

it('treats an `integer` key type as the int it is', function () {
    $model = get_class(new class extends User
    {
        protected $keyType = 'integer';
    });

    expect(lookupsDuring(fn () => guardFor(new EloquentUserProvider(app('hash'), $model), 'admin')))->toBe([null, 0]);
});

it('does not interpret a failing lookup: the provider\'s error is reported', function () {
    // A refusal the subject passed the check for is the APPLICATION's — a scope with a mistyped binding, a
    // mistyped `$with` relation — and hiding it as "no user" was a 401 for everybody.
    $pdo = new PDOException('SQLSTATE[22P02]: refused');
    $pdo->errorInfo = ['22P02', 7, 'refused'];
    $users = Mockery::mock(UserProvider::class);
    $users->allows('retrieveById')->andThrow(new QueryException('testing', 'select 1', [], $pdo));

    expect(fn () => guardFor($users))->toThrow(QueryException::class);
});

it('leaves a provider that is not Eloquent to answer any subject itself', function () {
    // There is no model to ask for a key type, so nothing is refused before the provider's own lookup.
    $user = User::factory()->create();
    $users = Mockery::mock(UserProvider::class);
    $users->allows('retrieveById')->with('admin')->andReturn($user);
    $verifier = new class implements TokenVerifier
    {
        public function verify(string $jwt): ?object
        {
            return (object) ['sub' => 'admin', 'jti' => 'j', 'exp' => time() + 60];
        }
    };

    $guard = new JwtGuard($verifier, $users);

    expect($guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer x'])))->toBe($user);
});

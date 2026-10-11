<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Lukk\Auth\JwtGuard;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\TokenVerifier;
use Lukk\Models\RefreshToken;
use Lukk\Support\SubjectColumn;
use Lukk\Tests\Fixtures\PublicIdUser;
use Lukk\Tests\Fixtures\StringKeyUser;
use Lukk\Tests\Fixtures\User;

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

it('decides by the column, whatever key type the model declares', function (string $keyType) {
    // `users.id` is an integer column: a model declaring a string key does not make 'admin' a value it can
    // hold, and the provider is never asked.
    $guard = new JwtGuard(verifier(), new class(app('hash'), User::class, $keyType) extends EloquentUserProvider
    {
        public function __construct($hasher, $model, private string $keyType)
        {
            parent::__construct($hasher, $model);
        }

        public function createModel()
        {
            return parent::createModel()->setKeyType($this->keyType);
        }

        public function retrieveById($identifier)
        {
            return new User;
        }
    });

    expect($guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer '.coSubjectToken('admin')])))->toBeNull();
})->with(['string', 'int']);

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

it('finds the column however the model names its table', function (Closure $model) {
    $class = $model();
    $user = $class::query()->create(['email' => 'shape@y.com']);
    $lookups = 0;
    DB::listen(function ($query) use (&$lookups) {
        $lookups += str_contains($query->sql, 'where "id" = ?') ? 1 : 0;
    });

    // Refused from the column's type — no lookup at all — and a real user still resolves.
    expect(guardFor(new EloquentUserProvider(app('hash'), $class), 'admin'))->toBeNull()
        ->and($lookups)->toBe(0)
        ->and(guardFor(new EloquentUserProvider(app('hash'), $class), (string) $user->getKey())?->getKey())->toBe($user->getKey());
})->with([
    'schema-qualified' => [fn () => get_class(new class extends User
    {
        protected $table = 'main.users';
    })],
    'aliased' => [fn () => get_class(new class extends User
    {
        protected $table = 'users as u';
    })],
    'on a prefixed connection' => [function () {
        config(['database.connections.prefixed' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => 'app_']]);
        Schema::connection('prefixed')->create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email');
        });

        return get_class(new class extends User
        {
            protected $connection = 'prefixed';
        });
    }],
]);

it('keeps the type of each connection, table and column apart', function () {
    // Same column name on another table, same table on another connection, another column of the same
    // table: each is its own type, and a cached one must not answer for another.
    config(['database.connections.idle' => ['driver' => 'sqlite', 'database' => ':memory:']]);
    Schema::connection('idle')->create('users', function (Blueprint $table) {
        $table->string('id')->primary();
    });
    Schema::create('handles', function (Blueprint $table) {
        $table->string('id')->primary();
    });
    DB::connection('idle')->table('users')->insert(['id' => 'usr_1']);
    DB::table('handles')->insert(['id' => 'h_1']);
    $user = User::factory()->create(['email' => 'apart@y.com']);
    $byEmail = get_class(new class extends User
    {
        public function getAuthIdentifierName()
        {
            return 'email';
        }
    });
    $otherConnection = get_class(new class extends StringKeyUser
    {
        protected $connection = 'idle';

        protected $table = 'users';
    });
    $otherTable = get_class(new class extends StringKeyUser
    {
        protected $table = 'handles';
    });

    expect(guardFor(new EloquentUserProvider(app('hash'), User::class), 'admin'))->toBeNull()
        ->and(guardFor(new EloquentUserProvider(app('hash'), $byEmail), 'apart@y.com')?->getKey())->toBe($user->id)
        ->and(guardFor(new EloquentUserProvider(app('hash'), $otherConnection), 'usr_1')?->getKey())->toBe('usr_1')
        ->and(guardFor(new EloquentUserProvider(app('hash'), $otherTable), 'h_1')?->getKey())->toBe('h_1');
});

it('reads each column once per process, until flushed', function () {
    $reads = 0;
    DB::listen(function ($query) use (&$reads) {
        $reads += str_contains($query->sql, 'pragma_table_xinfo') ? 1 : 0;
    });
    $users = new EloquentUserProvider(app('hash'), User::class);

    guardFor($users, 'admin');
    guardFor($users, 'admin');
    expect($reads)->toBe(1);

    SubjectColumn::flush();
    guardFor($users, 'admin');
    expect($reads)->toBe(2);
});

it('checks nothing, and leaves the subject to the provider, when the column cannot be read', function (Closure $model) {
    // Never a 500 because of the check itself: an unreadable catalog, or no column by that name, falls back
    // to the provider's own answer — here SQLite's, which compares anything with anything.
    $class = $model();
    $user = User::factory()->create();
    $lookups = 0;
    DB::listen(function ($query) use (&$lookups) {
        $lookups += str_contains($query->sql, 'from "users"') ? 1 : 0;
    });

    expect(guardFor(new EloquentUserProvider(app('hash'), $class), 'admin'))->toBeNull()
        ->and($lookups)->toBe(1)
        ->and(guardFor(new EloquentUserProvider(app('hash'), $class), (string) $user->id))->not->toBeNull();
})->with([
    'the catalog read fails' => [function () {
        DB::connection()->beforeExecuting(function (string $sql) {
            if (str_contains($sql, 'pragma_table_xinfo')) {
                throw new RuntimeException('catalog unavailable');
            }
        });

        return User::class;
    }],
    'no column by that name' => [fn () => get_class(new class extends User
    {
        public function getAuthIdentifierName()
        {
            return 'ID';
        }
    })],
]);

it('reads the column in a savepoint inside a transaction, and in none outside one', function () {
    // On PostgreSQL a failed catalog read would abort a caller's transaction (CoIssuerTokenTest pins it);
    // outside one, a transaction of its own would cost a BEGIN and COMMIT for nothing.
    config(['database.connections.idle' => ['driver' => 'sqlite', 'database' => ':memory:']]);
    Schema::connection('idle')->create('users', function (Blueprint $table) {
        $table->id();
        $table->string('email');
    });
    $model = get_class(new class extends User
    {
        protected $connection = 'idle';
    });
    $began = 0;
    Event::listen(TransactionBeginning::class, function () use (&$began) {
        $began++;
    });

    guardFor(new EloquentUserProvider(app('hash'), $model), 'admin');
    expect($began)->toBe(0);

    SubjectColumn::flush();
    DB::connection('idle')->beginTransaction();
    guardFor(new EloquentUserProvider(app('hash'), $model), 'admin');
    DB::connection('idle')->rollBack();
    expect($began)->toBe(2);
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

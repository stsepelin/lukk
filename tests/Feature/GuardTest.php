<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\SoftDeletes;
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

it('leaves a model whose key is not an integer to its provider', function (string $keyType) {
    // Only an integer key has a column type lukk can know; a string key (a UUID, a ULID, a username) is
    // passed through as before — an unknown one is a 401 from the lookup.
    $model = new class extends User
    {
        protected $table = 'users';
    };
    $model->setKeyType($keyType);
    $guard = new JwtGuard(verifier(), new class(app('hash'), $model::class, $keyType) extends EloquentUserProvider
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
            return $identifier === 'admin' ? new User : null;
        }
    });
    $cfg = Lukk\Lukk::guardConfig();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => 'admin', 'jti' => 'co-'.$keyType,
        'iat' => time(), 'nbf' => time(), 'exp' => time() + 600,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => 'at+jwt']);

    $resolved = $guard(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]));

    expect($resolved === null)->toBe($keyType !== 'string');
})->with(['string', 'int', 'integer']);

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

/** A lookup failing as PostgreSQL fails it for a value the column's type refuses. */
function refusedLookup(string $sqlState, ?string $connection = null, string $sql = 'select * from "users" where "id" = ? limit 1', array $bindings = ['42']): QueryException
{
    $pdo = new PDOException("SQLSTATE[{$sqlState}]: refused");
    $pdo->errorInfo = [$sqlState, 7, 'refused'];

    return new QueryException($connection ?? DB::getDefaultConnection(), $sql, $bindings, $pdo);
}

/** An Eloquent provider whose lookup first writes a row (to see what a savepoint undoes), then fails. */
function failingEloquentProvider(string $sqlState, ?Closure $failure = null): EloquentUserProvider
{
    return new class(app('hash'), User::class, $failure ?? fn () => refusedLookup($sqlState)) extends EloquentUserProvider
    {
        public function __construct($hasher, $model, private Closure $failure)
        {
            parent::__construct($hasher, $model);
        }

        public function retrieveById($identifier)
        {
            DB::table('users')->insert(['email' => 'written-by-the-lookup@y.com']);

            throw ($this->failure)();
        }
    };
}

function guardFor(UserProvider $users, string $sub = '42'): ?Authenticatable
{
    return (new JwtGuard(verifier(), $users))(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer '.coSubjectToken($sub)]));
}

it('answers a lookup the column type refuses as no user, not a 500', function (string $sqlState) {
    // PostgreSQL types the parameter against the column: 22P02 (not a number) or 22003 (out of range).
    // The key-type check cannot see every integer column — a Snowflake key, an integer identifier that is
    // not the key, a 32-bit key — so the refusal itself is read as "no such user"
    // (tests/Concurrency/CoIssuerTokenTest.php pins the real engine).
    expect(guardFor(failingEloquentProvider($sqlState)))->toBeNull();
})->with(['22P02', '22003']);

it('answers no user only for the lookup of the subject itself', function (Closure $sql, array $bindings, bool $swallowed) {
    // A 22P02 from another statement inside `retrieveById()` — an eager-loaded `$with` relation with a
    // mistyped key, a global scope, a `retrieved` listener — is a broken application, not a subject naming
    // no user. Read as one it was a 401 for every user and an outage nobody was told about. Only the very
    // SQL the stock provider issues for the subject counts.
    $guard = fn () => guardFor(failingEloquentProvider('22P02', fn () => refusedLookup('22P02', sql: $sql(), bindings: $bindings)));

    $swallowed ? expect($guard())->toBeNull() : expect($guard)->toThrow(QueryException::class);
})->with([
    'the stock lookup' => [fn () => User::query()->where('id', '42')->limit(1)->toSql(), ['42'], true],
    'the stock lookup, the subject bound as an int' => [fn () => User::query()->where('id', 42)->limit(1)->toSql(), [42], true],
    'the same table, an eager load binding the subject' => [fn () => User::query()->whereIn('id', ['42'])->toSql(), ['42'], false],
    'the lookup without the limit first() adds' => [fn () => User::query()->where('id', '42')->toSql(), ['42'], false],
    'the stock lookup, another value bound' => [fn () => User::query()->where('id', 'acme')->limit(1)->toSql(), ['acme'], false],
    'the stock lookup, a binding that is no scalar' => [fn () => User::query()->where('id', '42')->limit(1)->toSql(), [['42']], false],
]);

/**
 * PostgreSQL's refusal, on sqlite: every select on the connection fails as 22P02, with the SQL and bindings
 * the stock provider REALLY built — so the guard is tested against what Laravel generates, not a guess.
 */
function refuseSelectsOn(string $connection): void
{
    DB::connection($connection)->beforeExecuting(function (string $sql, array $bindings) use ($connection) {
        if (str_starts_with($sql, 'select')) {
            throw refusedLookup('22P02', $connection, $sql, $bindings);
        }
    });
}

it('recognises the stock lookup whatever shape the model and provider give it', function (Closure $provider, string $connection) {
    $users = $provider();
    refuseSelectsOn($connection);

    expect(guardFor($users))->toBeNull();
})->with([
    'a schema-qualified table' => [fn () => new EloquentUserProvider(app('hash'), get_class(new class extends User
    {
        protected $table = 'main.users';
    })), 'testing'],
    'an aliased table' => [fn () => new EloquentUserProvider(app('hash'), get_class(new class extends User
    {
        protected $table = 'users as u';
    })), 'testing'],
    'a schema-qualified table on a prefixed connection' => [function () {
        config(['database.connections.prefixed' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => 'app_']]);

        return new EloquentUserProvider(app('hash'), get_class(new class extends User
        {
            protected $connection = 'prefixed';

            protected $table = 'main.users';
        }));
    }, 'prefixed'],
    'soft deletes' => [fn () => new EloquentUserProvider(app('hash'), get_class(new class extends User
    {
        use SoftDeletes;
    })), 'testing'],
    'a global scope' => [fn () => new EloquentUserProvider(app('hash'), get_class(new class extends User
    {
        protected static function booted(): void
        {
            self::addGlobalScope('active', fn ($query) => $query->where('active', true));
        }
    })), 'testing'],
    'a withQuery() callback' => [fn () => (new EloquentUserProvider(app('hash'), User::class))
        ->withQuery(fn ($query) => $query->where('tenant', 'acme')), 'testing'],
]);

it('reports a refusal from a provider whose lookup is not the stock one', function () {
    // There is no rebuilding a subclass's own query, so its refusal is rethrown — the 500, reported —
    // rather than guessed at.
    refuseSelectsOn('testing');
    $provider = new class(app('hash'), User::class) extends EloquentUserProvider
    {
        public function retrieveById($identifier)
        {
            return $this->createModel()->newQuery()->where('email', $identifier)->first();
        }
    };

    expect(fn () => guardFor($provider))->toThrow(QueryException::class);
});

it('recognises the lookup on a prefixed connection, and of a subject that is not a string', function () {
    // The table a lookup reads carries the connection's prefix; and `sub` from a rebound verifier may be
    // an int, bound as one — compared as strings on both sides.
    config(['database.connections.prefixed' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => 'app_']]);
    $model = new class extends User
    {
        protected $connection = 'prefixed';
    };
    $provider = new class(app('hash'), $model::class) extends EloquentUserProvider
    {
        public function retrieveById($identifier)
        {
            throw refusedLookup('22P02', 'prefixed', 'select * from "app_users" where "id" = ? limit 1', [(string) $identifier]);
        }
    };
    $intSubject = new class implements TokenVerifier
    {
        public function verify(string $token): ?object
        {
            return (object) ['sub' => 42, 'jti' => 'j', 'exp' => time() + 60];
        }
    };

    expect(guardFor($provider))->toBeNull()
        ->and((new JwtGuard($intSubject, $provider))(Request::create('/', server: ['HTTP_AUTHORIZATION' => 'Bearer x'])))->toBeNull();
});

it('reads a refusal on a connection its savepoint did not cover by that connection\'s own state', function () {
    // The savepoint is taken on the MODEL's connection. A lookup that ran on another one is covered only if
    // that one holds no transaction to abort.
    config(['database.connections.idle' => ['driver' => 'sqlite', 'database' => ':memory:']]);

    expect(guardFor(failingEloquentProvider('22P02', fn () => refusedLookup('22P02', 'idle'))))->toBeNull();

    DB::connection('idle')->beginTransaction();

    try {
        expect(fn () => guardFor(failingEloquentProvider('22P02', fn () => refusedLookup('22P02', 'idle'))))->toThrow(QueryException::class);
    } finally {
        DB::connection('idle')->rollBack();
    }
});

it('lets any other database failure through', function () {
    expect(fn () => guardFor(failingEloquentProvider('08006')))->toThrow(QueryException::class);
});

it('fails only its own lookup inside the caller\'s transaction', function () {
    // On PostgreSQL a failed statement aborts the transaction it runs in, and COMMIT then silently
    // rolls back. Inside one, the lookup gets a savepoint of its own — which is what undoes its write here.
    // (The suite's RefreshDatabase already holds a transaction open, so levels are counted from it.)
    $outer = DB::transactionLevel();

    DB::transaction(function () use ($outer) {
        DB::table('users')->insert(['email' => 'the-caller@y.com']);

        expect(guardFor(failingEloquentProvider('22P02')))->toBeNull()
            ->and(DB::transactionLevel())->toBe($outer + 1);
    });

    expect(DB::table('users')->pluck('email')->all())->toBe(['the-caller@y.com']);
});

it('opens no transaction of its own for a lookup outside one', function () {
    // The savepoint is for an APPLICATION's transaction only: wrapping every request's lookup in one would
    // cost each authenticated request a BEGIN and COMMIT round trip for nothing.
    config(['database.connections.idle' => ['driver' => 'sqlite', 'database' => ':memory:']]);
    Schema::connection('idle')->create('users', function (Blueprint $table) {
        $table->id();
        $table->string('email');
    });
    $model = new class extends User
    {
        protected $connection = 'idle';
    };
    $user = $model::query()->create(['email' => 'idle@y.com']);
    $began = 0;
    Event::listen(TransactionBeginning::class, function () use (&$began) {
        $began++;
    });

    expect(guardFor(new EloquentUserProvider(app('hash'), $model::class), (string) $user->getKey())?->getKey())->toBe($user->getKey())
        ->and($began)->toBe(0);
});

it('does not swallow a refused lookup it could not isolate inside a transaction', function () {
    // A provider that is not Eloquent names no connection lukk could take a savepoint on; swallowing its
    // failure would leave a PostgreSQL transaction aborted behind a 401. Outside a transaction it is a 401.
    // The suite's RefreshDatabase holds the default connection in a transaction; a second connection
    // holds none.
    config(['database.connections.idle' => ['driver' => 'sqlite', 'database' => ':memory:']]);
    $idle = Mockery::mock(UserProvider::class);
    $idle->allows('retrieveById')->andThrow(refusedLookup('22P02', 'idle'));
    $busy = Mockery::mock(UserProvider::class);
    $busy->allows('retrieveById')->andThrow(refusedLookup('22P02'));

    expect(DB::connection('idle')->transactionLevel())->toBe(0)
        ->and(guardFor($idle))->toBeNull()
        ->and(DB::transactionLevel())->toBeGreaterThan(0)
        ->and(fn () => guardFor($busy))->toThrow(QueryException::class);
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

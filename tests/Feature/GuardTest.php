<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Lukk\Auth\JwtGuard;
use Lukk\Contracts\Denylist;
use Lukk\Contracts\TokenVerifier;
use Lukk\Models\RefreshToken;
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

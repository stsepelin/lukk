<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Lukk\Auth\ChallengeToken;
use Lukk\Contracts\Denylist;
use Lukk\Lukk;

function challenge(): ChallengeToken
{
    return app(ChallengeToken::class);
}

/**
 * A challenge minted the way a co-issuer sharing this guard's secret mints one: no `gid`, no `fid`,
 * and `$claims` laid over a valid baseline. A claim set to null is left out entirely.
 *
 * @param  array<string, mixed>  $claims
 */
function coIssuedChallenge(array $claims = []): string
{
    $cfg = Lukk::guardConfig();
    $now = time();
    $payload = array_filter([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '42', 'jti' => (string) Str::uuid(),
        'iat' => $now, 'nbf' => $now, 'exp' => $now + 300,
        ...$claims,
    ], fn ($value) => $value !== null);

    return JWT::encode($payload, $cfg['secret'], $cfg['algorithm'], head: ['typ' => '2fa+challenge']);
}

/**
 * Run `$probe` until it starts and finishes inside one wall-clock second. The JWT library reads the
 * real clock, and a boundary that is exact to the second would otherwise flip on a tick mid-probe.
 */
function withinOneSecond(Closure $probe): mixed
{
    do {
        $second = time();
        $result = $probe();
    } while (time() !== $second);

    return $result;
}

/** The real denylist, remembering how long each spent challenge was marked for. */
class RecordingDenylist implements Denylist
{
    /** @var list<int> */
    public array $ttls = [];

    public function __construct(private readonly Denylist $inner) {}

    public function revokeJti(string $jti, int $ttlSeconds): void
    {
        $this->ttls[] = $ttlSeconds;
        $this->inner->revokeJti($jti, $ttlSeconds);
    }

    public function revokeFamily(string $familyId, int $ttlSeconds): void
    {
        $this->inner->revokeFamily($familyId, $ttlSeconds);
    }

    public function has(string $type, string $id): bool
    {
        return $this->inner->has($type, $id);
    }

    public function hasAny(array $types): bool
    {
        return $this->inner->hasAny($types);
    }
}

it('issues a challenge that consumes back to the subject', function () {
    $token = challenge()->issue('2fa', 42, 300);

    expect(challenge()->consume('2fa', $token))->toBe('42');
});

it('is single-use', function () {
    $token = challenge()->issue('2fa', 42, 300);

    expect(challenge()->consume('2fa', $token))->toBe('42');
    expect(challenge()->consume('2fa', $token))->toBeNull();
});

it('rejects a challenge declaring critical headers it does not understand', function () {
    // RFC 7515 §4.1.11: a JWS whose `crit` names extensions the recipient does not support MUST be
    // rejected. lukk emits none, so anything carrying `crit` came from a co-issuer expressing a
    // restriction — and silently ignoring a restriction is the inversion `crit` exists to prevent.
    $cfg = Lukk::guardConfig();
    $now = time();
    $token = JWT::encode([
        'iss' => $cfg['issuer'], 'aud' => $cfg['audience'], 'sub' => '42', 'jti' => 'crit-challenge',
        'iat' => $now, 'nbf' => $now, 'exp' => $now + 300,
    ], $cfg['secret'], $cfg['algorithm'], head: ['typ' => '2fa+challenge', 'crit' => ['exp-nonsense']]);

    expect(challenge()->consume('2fa', $token))->toBeNull();
});

it('rejects a challenge presented as a different kind', function () {
    $token = challenge()->issue('2fa', 42, 300);

    expect(challenge()->consume('passkey', $token))->toBeNull();
});

it('rejects an expired challenge', function () {
    // Minted in the past so its exp is already behind the real clock the JWT lib uses.
    $token = $this->travel(-600)->seconds(fn () => challenge()->issue('2fa', 42, 300));

    expect(challenge()->consume('2fa', $token))->toBeNull();
});

it('rejects a garbage token', function () {
    expect(challenge()->consume('2fa', 'not-a-jwt'))->toBeNull();
});

it('rejects a challenge minted for a different audience', function () {
    $foreign = new ChallengeToken([
        'secret' => config('lukk.secret'),
        'algorithm' => config('lukk.algorithm'),
        'issuer' => config('lukk.issuer'),
        'audience' => 'https://evil.example.com',
        'leeway' => 0,
    ], app(Denylist::class));

    expect(challenge()->consume('2fa', $foreign->issue('2fa', 42, 300)))->toBeNull();
});

it('redeems a challenge from a co-issuer that predates the gid and fid claims', function () {
    // The positive control for every hand-minted refusal below, and the co-issuer half of both
    // bindings: an absent `gid` or `fid` is `null === null`, which admits the token rather than
    // stranding a topology this class exists to support.
    $token = coIssuedChallenge();

    expect(challenge()->familyOf('2fa', $token))->toBeNull()
        ->and(challenge()->consume('2fa', $token))->toBe('42');
});

it('refuses a challenge minted on another guard that shares its crypto identity', function () {
    // One instance, so issuer, audience and secret are identical — the minimal multi-guard shape,
    // where `gid` is the ONLY thing standing between "admins.1 cleared the first factor" and a
    // session as users.1.
    $shared = challenge();
    $token = $shared->issue('2fa', 42, 300);

    expect(Lukk::onGuard('admin', fn () => $shared->consume('2fa', $token)))->toBeNull()
        ->and($shared->consume('2fa', $token))->toBe('42');
});

it('binds a step-up to the session that earned it, and an empty family to nothing', function () {
    // `RequireConfirmation` compares the bound family STRICTLY against the presenting token's own.
    // An empty string stamped as `fid` would be a binding to a family no session has, rather than
    // the explicit "unbound" that null is.
    expect(challenge()->familyOf('reauth', challenge()->issue('reauth', 42, 300, 'fam-1')))->toBe('fam-1')
        ->and(challenge()->familyOf('reauth', challenge()->issue('reauth', 42, 300, '')))->toBeNull();
});

it('refuses a challenge whose claims are not the types they are read as', function (array $claims) {
    // RFC 8725 §3.11: validate claim types before use. Every one of these reaches a cast or a strict
    // comparison further down, and a co-issuer — the topology this class exists to support — can mint
    // any of them. A missing `exp` is a challenge that never expires, against "short TTL".
    expect(challenge()->consume('2fa', coIssuedChallenge($claims)))->toBeNull();
})->with([
    'a non-string sub' => [['sub' => 42]],
    'a non-string fid' => [['fid' => ['fam-1']]],
    'a numeric-string exp' => [['exp' => (string) (time() + 300)]],
    'no exp at all' => [['exp' => null]],
    'a non-string jti' => [['jti' => 7]],
    'no jti at all' => [['jti' => null]],
]);

it('refuses a challenge with an empty jti, which could never be marked spent', function () {
    // The denylist treats an empty id as "nothing to look up", so a challenge carrying `jti: ""`
    // would redeem, write a marker nothing ever reads, and redeem again.
    $token = coIssuedChallenge(['jti' => '']);

    expect(challenge()->consume('2fa', $token))->toBeNull()
        ->and(challenge()->consume('2fa', $token))->toBeNull();
});

it('fails closed on an audience that is only empty strings', function () {
    // `LUKK_ADMIN_AUDIENCE=` reaches config as `''`. Stamped and compared as-is, `'' === ''` holds
    // and the challenge is bound to nothing — the same hole as an absent audience, one step removed.
    $blank = new ChallengeToken(['audience' => ''] + Lukk::guardConfig(), app(Denylist::class));

    expect($blank->consume('2fa', $blank->issue('2fa', 42, 300)))->toBeNull();
});

it('redeems a challenge on a guard whose audience is a single string', function () {
    // `'audience' => env('LUKK_ADMIN_AUDIENCE')` is the documented per-guard shape, and it is a
    // string, not a list.
    $admin = new ChallengeToken(['audience' => 'https://admin.example.com'] + Lukk::guardConfig(), app(Denylist::class));

    expect($admin->consume('2fa', $admin->issue('2fa', 42, 300)))->toBe('42');
});

it('signs a challenge with the configured asymmetric algorithm', function () {
    // An RS256 deployment has no `secret`: signing a challenge as HS256 there would either fail to
    // mint or produce a token the pinned verification key refuses — every second factor broken.
    $pair = rsaKeypair();
    $rs256 = new ChallengeToken([
        'algorithm' => 'RS256',
        'secret' => null,
        'keys' => ['active' => 'k1', 'private' => $pair['private'], 'passphrase' => null, 'public' => ['k1' => $pair['public']]],
    ] + Lukk::guardConfig(), app(Denylist::class));

    $token = $rs256->issue('2fa', 42, 300);
    $header = json_decode((string) base64_decode(strtr(explode('.', $token)[0], '-_', '+/')), true);

    expect($header)->toMatchArray(['alg' => 'RS256', 'kid' => 'k1', 'typ' => '2fa+challenge'])
        ->and($rs256->consume('2fa', $token))->toBe('42');
});

it('takes an algorithm that arrives as a non-string, as a published config can hand it over', function () {
    // `JWT::encode()` types `$alg` as `string`, so under `strict_types` a `Stringable` reaching it
    // uncast is a TypeError — a 500 on every login that asks for a second factor. `KeyRing` and the
    // access-token issuer cast the same key; this pins that the challenge mint agrees with them.
    $cfg = ['algorithm' => new class
    {
        public function __toString(): string
        {
            return 'HS256';
        }
    }] + Lukk::guardConfig();
    $tokens = new ChallengeToken($cfg, app(Denylist::class));

    expect($tokens->consume('2fa', $tokens->issue('2fa', 42, 300)))->toBe('42');
});

it('defaults an absent leeway to five seconds, and honours a configured one of zero', function () {
    // The decode leeway is the window a challenge still redeems in past `exp`, so its default is a
    // security boundary rather than a tolerance: five seconds, the same as the access tokens.
    $expiredBy = fn (ChallengeToken $tokens, int $seconds) => withinOneSecond(
        fn () => $tokens->verify('2fa', $this->travel(-(60 + $seconds))->seconds(fn () => $tokens->issue('2fa', 42, 60))),
    );
    $unset = new ChallengeToken(Arr::except(Lukk::guardConfig(), 'leeway'), app(Denylist::class));
    $none = new ChallengeToken(['leeway' => 0] + Lukk::guardConfig(), app(Denylist::class));

    expect($expiredBy($unset, 4))->toBe('42')
        ->and($expiredBy($unset, 5))->toBeNull()
        ->and($expiredBy($none, 1))->toBeNull();
});

it('marks a spent challenge for exactly as long as it could still decode', function () {
    // The token decodes for `leeway` seconds past `exp`, so a marker that lapses at `exp` leaves a
    // replay window of exactly that length; one far longer than the token only bloats the store.
    $this->freezeSecond();

    $spent = function (array $config): int {
        $denylist = new RecordingDenylist(app(Denylist::class));
        $tokens = new ChallengeToken($config, $denylist);
        $tokens->consume('2fa', $tokens->issue('2fa', 42, 300));

        return $denylist->ttls[0];
    };

    expect($spent(['leeway' => 30] + Lukk::guardConfig()))->toBe(330)
        ->and($spent(Arr::except(Lukk::guardConfig(), 'leeway')))->toBe(305);
});

it('refuses a replay inside the leeway after exp', function () {
    // The attack the leeway term in the marker's TTL exists for: redeem a challenge just after its
    // `exp`, then present it again while it still decodes.
    $this->freezeSecond();
    $token = $this->travel(-298)->seconds(fn () => challenge()->issue('2fa', 42, 300));

    expect(challenge()->consume('2fa', $token))->toBe('42');

    $this->travel(3)->seconds();

    expect(challenge()->consume('2fa', $token))->toBeNull();
});

it('still marks a challenge spent when it is redeemed on the last second of its leeway', function () {
    // Nothing is left of the window, but a cache reads a zero TTL as "forget" (Laravel) or refuses it
    // outright (Redis `SETEX`), so the marker is floored at one second rather than vanishing — or
    // throwing after the second factor has already verified.
    $this->freezeSecond();
    $denylist = new RecordingDenylist(app(Denylist::class));
    $tokens = new ChallengeToken(['leeway' => 5] + Lukk::guardConfig(), $denylist);
    $token = $tokens->issue('2fa', 42, 60);

    $this->travel(65)->seconds();

    expect($tokens->consume('2fa', $token))->toBe('42')
        ->and($denylist->ttls)->toBe([1])
        ->and($tokens->consume('2fa', $token))->toBeNull();
});

it('burns a challenge whose leeway reached config as an un-cast environment string', function () {
    // A config published before `leeway` was cast hands `LUKK_LEEWAY=2.5` over as the string "2.5".
    // Uncast, the marker's TTL becomes a float and `Denylist::revokeJti(int)` throws — AFTER the
    // second factor verified, leaving the challenge unburned for another try.
    $tokens = new ChallengeToken(['leeway' => '2.5'] + Lukk::guardConfig(), app(Denylist::class));
    $token = $tokens->issue('2fa', 42, 300);

    expect($tokens->consume('2fa', $token))->toBe('42')
        ->and($tokens->consume('2fa', $token))->toBeNull();
});

it('carries the password fingerprint it was issued with, and only a string one', function () {
    $token = challenge()->issue('2fa', 7, 300, passwordFingerprint: 'fp-123');
    expect(challenge()->passwordFingerprintOf('2fa', $token))->toBe('fp-123')
        ->and(challenge()->passwordFingerprintOf('2fa', challenge()->issue('2fa', 7, 300)))->toBeNull()
        ->and(challenge()->passwordFingerprintOf('2fa', 'garbage'))->toBeNull();

    // RFC 8725 §3.11, as for `sub` and `fid`: a co-issuer's non-string claim is an invalid challenge, not a 500.
    foreach ([['x'], 42, true] as $bad) {
        $forged = coIssuedChallenge(['pwf' => $bad]);
        expect(challenge()->verify('2fa', $forged))->toBeNull()
            ->and(challenge()->passwordFingerprintOf('2fa', $forged))->toBeNull();
    }
});

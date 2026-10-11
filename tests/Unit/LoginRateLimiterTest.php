<?php

declare(strict_types=1);

use Illuminate\Auth\GenericUser;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Lukk\Auth\LoginRateLimiter;
use Lukk\Tests\Fixtures\User;

it('reports the wait of whichever bucket blocks longer', function () {
    // The IP bucket and the per-account bucket fill at different times; the caller has to wait out
    // the later one, or the retry it was told to make is refused again.
    $this->freezeSecond();
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5);
    $request = Request::create('/auth/login', 'POST', ['email' => 'ada@example.test'], server: ['REMOTE_ADDR' => '203.0.113.9']);

    app(RateLimiter::class)->hit($limiter->key($request), 60);
    $this->travel(30)->seconds();
    app(RateLimiter::class)->hit($limiter->accountKey($request), 60);

    expect($limiter->availableIn($request))->toBe(60);
});

/** A login request for `$identifier` from `$ip`. */
function loginRequest(string $identifier = 'ada@example.test', string $ip = '203.0.113.9'): Request
{
    return Request::create('/auth/login', 'POST', ['email' => $identifier], server: ['REMOTE_ADDR' => $ip]);
}

it('composes both bucket keys from the guard, the identifier and — for the IP bucket — the caller', function () {
    // Spelled out because the two buckets must stay distinct and guard-scoped: collapse them and a
    // flood on one guard locks a colliding account out of another, or the account cap becomes the
    // IP cap.
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5, 'email', 'admin');
    $request = loginRequest();

    $digest = hash('sha256', 'ada@example.test');

    expect($limiter->key($request))->toBe('admin|'.$digest.'|'.Lukk\Lukk::rateLimitKey($request))
        ->and($limiter->accountKey($request))->toBe('acct|admin|'.$digest);
});

it('does not let two identifiers that HTML-entity-fold together share a bucket', function () {
    // These keys go to `Illuminate\Cache\RateLimiter` directly, so they never get the md5 that
    // `ThrottleRequests` applies — only `cleanRateLimiterKey`, which is `htmlentities()` plus an
    // entity-shortening regex, and that is a many-to-one fold: `a&b@x.com` and `aab@x.com` are both
    // valid addresses and both cleaned to `aab@x.com`. Sharing the bucket would be a nuisance; what
    // made it a hole is `clear()`, which cleans the key the same way — so signing in successfully as
    // the look-alike reset the VICTIM's per-account counter, the IP-independent backstop that exists
    // so a distributed attacker cannot get `max_attempts` guesses per IP against one account.
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5, 'email', 'web');
    $clean = fn (string $key) => preg_replace('/&([a-z])[a-z]+;/i', '$1', htmlentities($key));

    $victim = $clean($limiter->accountKey(loginRequest('aab@x.com')));
    $lookalike = $clean($limiter->accountKey(loginRequest('a&b@x.com')));

    expect($lookalike)->not->toBe($victim);
});

it('clears only the per-address bucket on a successful sign-in', function () {
    // It used to clear the account bucket too. That bucket is keyed on the identifier fold, which a
    // look-alike account shares, so its owner could sign in to reset the victim's IP-independent count
    // between bursts. It now only decays; a real user loses nothing short of `account_max_attempts`
    // failures in one window.
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5);
    $request = loginRequest();
    $limiter->increment($request);

    $limiter->clear($request);

    expect(app(RateLimiter::class)->attempts($limiter->key($request)))->toBe(0)
        ->and(app(RateLimiter::class)->attempts($limiter->accountKey($request)))->toBe(1);
});

it('normalizes an identifier before it becomes a bucket', function () {
    // Trimmed, lower-cased and transliterated, so `  Ada@Example.test ` shares one bucket with the
    // address the user actually typed at their last attempt.
    expect(LoginRateLimiter::normalize('  Ada@Example.test '))->toBe('ada@example.test');
});

it('hashes an identifier longer than 190 characters, and keeps one that is not', function () {
    // Cache keys are bounded; the boundary itself is pinned so a long address cannot slip past it
    // and blow the key length.
    $at190 = str_repeat('a', 184).'@x.com';
    $at191 = str_repeat('a', 185).'@x.com';

    expect(strlen($at190))->toBe(190)
        ->and(LoginRateLimiter::normalize($at190))->toBe($at190)
        ->and(LoginRateLimiter::normalize($at191))->toBe('sha256:'.hash('sha256', $at191));
});

it('keys a request with no identifier at all, rather than raising a TypeError', function () {
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 5, 'email', 'admin');

    expect($limiter->accountKey(Request::create('/auth/login', 'POST')))->toBe('acct|admin|'.hash('sha256', ''));
});

it('derives no legacy subject from an identifier that is blank', function () {
    // `idn:` alone would name one bucket for every blank caller — the shape the repository's
    // empty-subject refusal exists to stop — and erasure would delete it on behalf of anyone.
    expect(LoginRateLimiter::legacyLockoutSubject('   '))->toBe('')
        ->and(LoginRateLimiter::legacyLockoutSubject(' Ada@Example.test '))->toBe('idn:ada@example.test')
        ->and(LoginRateLimiter::lockoutSubject(null, '   '))->toBe('');
});

it('names an account\'s own counters from its identifier, a numeric one included', function () {
    config(['lukk.username' => 'phone']);

    expect(LoginRateLimiter::subjectsOf(new GenericUser(['id' => 5, 'phone' => 5551234])))
        ->toBe([LoginRateLimiter::lockoutSubject(null, '5551234'), 'id:5'])
        ->and(LoginRateLimiter::subjectsOf(new GenericUser(['id' => 5])))->toBe(['id:5']);

    config(['lukk.username' => 'email']);
    $user = User::factory()->make(['id' => 9, 'email' => 'Ada@Example.test']);
    expect(LoginRateLimiter::subjectsOf($user))->toBe([LoginRateLimiter::lockoutSubject(null, 'ada@example.test'), 'id:9']);
});

it('counts an identifier that names no account once per attempt, not twice', function () {
    // For a non-account the account subject IS the fold, so the two must not both be counted.
    expect(LoginRateLimiter::lockoutSubjects(null, 'Ghost@Y.com'))->toBe([LoginRateLimiter::lockoutSubject(null, 'ghost@y.com')]);
});

it('folds every spelling the database resolves to one account onto one key', function (string $respelled) {
    // The fold must never be FINER than the database's equality, or each spelling is another bucket of
    // guesses. MySQL's `utf8mb4_unicode_ci` gives default-ignorable and combining code points no primary
    // weight and pads trailing whitespace; `Str::transliterate` turned U+200B and U+3000 into spaces and
    // U+034F into `?`, so they keyed apart. Stripped and trimmed before the fold, they key together.
    expect(LoginRateLimiter::normalize($respelled))->toBe('victim@example.com');
})->with([
    'zero-width space' => ["victim\u{200B}@example.com"],
    'combining grapheme joiner' => ["victim\u{034F}@example.com"],
    'variation selector' => ["victim\u{FE0F}@example.com"],
    'enclosing mark' => ["victim\u{20DD}@example.com"],
    // Accepted by `Identifier` (spelling needs them), so the fold is what keeps them on one bucket.
    'zero-width joiner' => ["victim\u{200D}@example.com"],
    'zero-width non-joiner' => ["victim\u{200C}@example.com"],
    'combining enclosing keycap' => ["victim\u{20E3}@example.com"],
    'combining accent' => ["vi\u{0301}ctim@example.com"],
    'trailing ideographic space' => ["victim@example.com\u{3000}"],
    'leading no-break space' => ["\u{00A0}victim@example.com"],
    'C1 control' => ["victim@example.com\u{0085}"],
    'ASCII whitespace and case, as before' => ["  Victim@Example.com\t"],
]);

it('folds invalid UTF-8 as it always did rather than to nothing', function () {
    // The Unicode-aware passes answer null on invalid UTF-8; an identifier that slipped past validation
    // (a custom request) must still get a key of its own, not the shared empty one.
    expect(LoginRateLimiter::normalize("ad\xFFa@example.com"))->not->toBe('')
        // …and still trimmed, as every identifier was before the Unicode passes.
        ->and(LoginRateLimiter::normalize("  ad\xFFa@example.com\t"))->toBe(LoginRateLimiter::normalize("ad\xFFa@example.com"));
});

it('keys a blank identifier on the caller alone, and never on the shared empty account', function () {
    $this->freezeSecond();
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 1, 'email', 'api');
    $blank = loginRequest('   ');

    $limiter->increment($blank);
    $this->travel(30)->seconds();

    // The bucket every blank-identifier caller used to share, filled — and with the LATER window.
    app(RateLimiter::class)->hit('acct|api|'.hash('sha256', ''), 60);
    app(RateLimiter::class)->hit('acct|api|'.hash('sha256', ''), 60);

    expect($limiter->key($blank))->toBe('api|'.Lukk\Lukk::rateLimitKey($blank))
        ->and($limiter->tooManyAttempts($blank))->toBeFalse()
        ->and($limiter->availableIn($blank))->toBe(30)
        ->and(app(RateLimiter::class)->attempts('acct|api|'.hash('sha256', '')))->toBe(2);
});

it('reports no wait for a blank identifier that has failed nothing', function () {
    $limiter = new LoginRateLimiter(app(RateLimiter::class), 5, 60, 1, 'email', 'api');

    expect($limiter->availableIn(loginRequest('')))->toBe(0);
});

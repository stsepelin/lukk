<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Lukk\Exceptions\RetryableValidationException;
use Lukk\Tests\Fixtures\User;

/*
 * RFC 9110 §10.2.3. The route-level throttles have always answered with `Retry-After`; the 429s and 423s
 * lukk's own actions throw named the wait only inside a translated sentence, so a client that backs off
 * on the header backed off for one and not the other — on the same endpoint.
 */

beforeEach(fn () => $this->freezeSecond());

it('names the wait in a header when the login failure throttle refuses', function () {
    config(['lukk.rate_limits.login.max_attempts' => 2, 'lukk.rate_limits.login.decay_seconds' => 90]);
    User::factory()->create(['email' => 'victim@y.com']);

    foreach (range(1, 2) as $ignored) {
        app('auth')->forgetGuards();
        $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'bad'])->assertStatus(422)->assertHeaderMissing('Retry-After');
    }

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'bad'])
        ->assertStatus(429)
        ->assertHeader('Retry-After', '90')
        // Still the application's ordinary validation shape: the header is added, nothing is replaced.
        ->assertJsonValidationErrorFor('email');
});

it('names the wait on a lock that releases by itself, and none on one that does not', function (int $releaseAfter, ?string $header, string $message) {
    config([
        'lukk.features.lockout' => true, 'lukk.lockout.max_attempts' => 1, 'lukk.lockout.release_after' => $releaseAfter,
        'lukk.rate_limits.login.max_attempts' => 500, 'lukk.rate_limits.login.account_max_attempts' => 500,
    ]);
    User::factory()->create(['email' => 'victim@y.com']);

    app('auth')->forgetGuards();
    $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'bad'])->assertStatus(422);
    app('auth')->forgetGuards();
    $response = $this->postJson('/auth/login', ['email' => 'victim@y.com', 'password' => 'bad'])->assertStatus(423);

    expect($response->headers->get('Retry-After'))->toBe($header)
        ->and($response->json('errors.email'))->toBe([$message]);
})->with([
    'auto-release in five minutes' => [300, '300', 'Too many login attempts. Please try again in 300 seconds.'],
    // "Contact support": there is no moment to come back at, and inventing one would be a lie.
    'manual release only' => [0, null, 'This account is locked. Contact support to restore access.'],
]);

it('never tells a client to retry in zero seconds', function () {
    expect(RetryableValidationException::withMessages(['x' => ['y']])->retryAfter(0)->retryAfter)->toBe(1)
        ->and(RetryableValidationException::withMessages(['x' => ['y']])->retryAfter(-5)->retryAfter)->toBe(1)
        ->and(RetryableValidationException::withMessages(['x' => ['y']])->retryAfter(2)->retryAfter)->toBe(2)
        ->and(RetryableValidationException::withMessages(['x' => ['y']])->retryAfter)->toBe(1);
});

it('leaves a Retry-After the application already set', function () {
    app('router')->aliasMiddleware('probe.retry-after', SetsItsOwnRetryAfter::class);
    Route::post('/probe/retry', fn () => throw RetryableValidationException::withMessages(['x' => ['y']])->retryAfter(30)->status(429))
        ->middleware(['lukk.force-json', 'probe.retry-after']);
    Route::post('/probe/plain', fn () => throw RetryableValidationException::withMessages(['x' => ['y']])->retryAfter(30)->status(429))
        ->middleware('lukk.force-json');

    $this->post('/probe/retry')->assertStatus(429)->assertHeader('Retry-After', '7');
    $this->post('/probe/plain')->assertStatus(429)->assertHeader('Retry-After', '30');
});

class SetsItsOwnRetryAfter
{
    public function handle($request, Closure $next)
    {
        return tap($next($request), fn ($response) => $response->headers->set('Retry-After', '7'));
    }
}

<?php

declare(strict_types=1);

use Lukk\Support\RefreshCookie;
use Lukk\Tests\Fixtures\User;

/*
 * Login CSRF (OWASP CSRF cheat sheet; ASVS 5.0 V3). `SameSite=Strict` stops the refresh cookie being SENT
 * cross-site, not being SET: RFC 6265bis §5.7 stores a SameSite cookie from the response to a cross-site
 * top-level navigation. So a page on any site could auto-submit a form to `/auth/login` with the
 * ATTACKER's credentials (or to `/auth/refresh` with the attacker's token) and plant the attacker's
 * session in the victim's browser; the victim's SPA then refreshes into the attacker's account and
 * whatever they enter lands there. In cookie mode the routes that set the cookie now accept only a
 * request a form cannot produce — the rule `/logout` already applies.
 */

beforeEach(fn () => config(['lukk.cookie_mode' => true]));

$crossSiteForm = ['Sec-Fetch-Site' => 'cross-site', 'Origin' => 'https://evil.example'];

it('refuses a cross-site form login, and sets no cookie', function () use ($crossSiteForm) {
    User::factory()->create(['email' => 'attacker@y.com']);

    $this->withHeaders($crossSiteForm)
        ->post('/auth/login', ['email' => 'attacker@y.com', 'password' => 'password'])
        ->assertStatus(415)
        ->assertCookieMissing(RefreshCookie::name());
});

it('refuses a cross-site form refresh carrying the attacker\'s own token', function () use ($crossSiteForm) {
    $attacker = User::factory()->create()->startSession()->refreshToken;

    $this->withHeaders($crossSiteForm)
        ->post('/auth/refresh', ['refresh_token' => $attacker])
        ->assertStatus(415)
        ->assertCookieMissing(RefreshCookie::name());
});

it('refuses a form without fetch metadata, which is what an old browser sends', function () {
    User::factory()->create(['email' => 'old@y.com']);

    $this->post('/auth/login', ['email' => 'old@y.com', 'password' => 'password'])->assertStatus(415);
});

it('still signs in a JSON request, which a cross-origin page cannot send without a preflight', function () {
    User::factory()->create(['email' => 'spa@y.com']);

    $this->withHeaders(['Sec-Fetch-Site' => 'same-site'])
        ->postJson('/auth/login', ['email' => 'spa@y.com', 'password' => 'password'])
        ->assertOk()
        ->assertCookie(RefreshCookie::name());
});

it('still signs in a same-origin form, which only the app itself can send', function () {
    User::factory()->create(['email' => 'form@y.com']);

    $this->withHeaders(['Sec-Fetch-Site' => 'same-origin'])
        ->post('/auth/login', ['email' => 'form@y.com', 'password' => 'password'])
        ->assertOk();
});

it('does not take a safelisted text/plain body for JSON', function () {
    // `isJson()` matches `text/plain; x=/json`, which is CORS-safelisted and needs no preflight.
    User::factory()->create(['email' => 'plain@y.com']);

    $this->call('POST', '/auth/login', [], [], [], ['CONTENT_TYPE' => 'text/plain; x=/json', 'HTTP_SEC_FETCH_SITE' => 'cross-site'],
        json_encode(['email' => 'plain@y.com', 'password' => 'password']))
        ->assertStatus(415);
});

it('leaves body mode alone, where no cookie is set', function () use ($crossSiteForm) {
    // The tokens come back in a response the attacker's page cannot read; nothing is planted.
    config(['lukk.cookie_mode' => false]);
    User::factory()->create(['email' => 'body@y.com']);

    $this->withHeaders($crossSiteForm)
        ->post('/auth/login', ['email' => 'body@y.com', 'password' => 'password'])
        ->assertOk();
});

it('does not take a refresh cookie in body mode, where no CSRF guard stands in front of it', function () use ($crossSiteForm) {
    // A cookie left over from cookie mode (or planted by a sibling subdomain) would otherwise be
    // consumed by any cross-site form: the attacker cannot read the response, but the victim's next
    // refresh presents a rotated token, and past grace that revokes the whole family.
    config(['lukk.cookie_mode' => false]);
    $victim = User::factory()->create()->startSession()->refreshToken;

    $this->withHeaders($crossSiteForm)
        ->withUnencryptedCookie(RefreshCookie::name(), $victim)
        ->post('/auth/refresh')
        ->assertUnauthorized();

    expectNoThrow(fn () => rotate()($victim));
});

it('guards every route that sets the cookie', function (string $route) use ($crossSiteForm) {
    config(['lukk.features.registration' => true]);

    $this->withHeaders($crossSiteForm)->post($route, [])->assertStatus(415);
})->with(['/auth/login', '/auth/refresh', '/auth/register', '/auth/two-factor-challenge', '/auth/passkeys/login']);

it('says why it refused', function () use ($crossSiteForm) {
    $this->withHeaders($crossSiteForm)->post('/auth/login', [])->assertStatus(415)->assertExactJson(['message' => 'This request must be sent as JSON.']);
});

it('treats a cached config without cookie_mode as body mode', function () use ($crossSiteForm) {
    $lukk = config('lukk');
    unset($lukk['cookie_mode']);
    config(['lukk' => $lukk]);
    User::factory()->create(['email' => 'stale@y.com']);

    $this->withHeaders($crossSiteForm)->post('/auth/login', ['email' => 'stale@y.com', 'password' => 'password'])->assertOk();
});

it('reads no refresh cookie on a cached config without cookie_mode, which is body mode', function () use ($crossSiteForm) {
    $lukk = config('lukk');
    unset($lukk['cookie_mode']);
    config(['lukk' => $lukk]);
    $victim = User::factory()->create()->startSession()->refreshToken;

    $this->withHeaders($crossSiteForm)->withUnencryptedCookie(RefreshCookie::name(), $victim)->post('/auth/refresh')->assertUnauthorized();
});

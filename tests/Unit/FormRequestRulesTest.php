<?php

declare(strict_types=1);

use Illuminate\Validation\Rules\Password;
use Lukk\Http\Requests\ChangePasswordRequest;
use Lukk\Http\Requests\ConfirmPasswordRequest;
use Lukk\Http\Requests\ForgotPasswordRequest;
use Lukk\Http\Requests\LoginRequest;
use Lukk\Http\Requests\PasskeyAssertionRequest;
use Lukk\Http\Requests\PasskeyRegistrationRequest;
use Lukk\Http\Requests\TwoFactorChallengeRequest;

// Each rule pinned on its own (see `failedRulesFor`). A null field that should be allowed is pinned
// by failing NOTHING, which is what `nullable` buys: without it, `string` rejects the null.

it('applies each change-password rule on its own', function (string $field, array $overrides, string $rule) {
    $data = array_merge([
        'current_password' => 'old-password-123',
        'password' => 'new-password-123',
        'password_confirmation' => 'new-password-123',
    ], $overrides);

    expect(failedRulesFor((new ChangePasswordRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'current required' => ['current_password', ['current_password' => null], 'Required'],
    'current a string' => ['current_password', ['current_password' => ['x']], 'String'],
    'current bounded' => ['current_password', ['current_password' => str_repeat('a', 256)], 'Max'],
    'new required' => ['password', ['password' => null], 'Required'],
    'new confirmed' => ['password', ['password_confirmation' => 'other-password-123'], 'Confirmed'],
    'new differs from current' => ['password', ['current_password' => 'new-password-123'], 'Different'],
    'new bounded' => ['password', ['password' => str_repeat('a', 256), 'password_confirmation' => str_repeat('a', 256)], 'Max'],
    'new without a NUL byte' => ['password', ['password' => "new-pass\0word-123", 'password_confirmation' => "new-pass\0word-123"], 'NotRegex'],
    'new meets the defaults' => ['password', ['password' => 'short', 'password_confirmation' => 'short'], Password::class],
]);

it('applies each step-up confirm-password rule on its own', function (string $field, array $data, string $rule) {
    // This route used to take a bare `Request` and cast `$request->input('password')` — the only
    // endpoint in the package doing so. `{"password":["x"]}` raised "Array to string conversion",
    // which `HandleExceptions` promotes to an ErrorException and renders as a 500, on an
    // ability-gated but reachable security route. `PasskeyAssertionRequest` documents the same bug.
    expect(failedRulesFor((new ConfirmPasswordRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'required' => ['password', [], 'Required'],
    'a string' => ['password', ['password' => ['x']], 'String'],
    'bounded' => ['password', ['password' => str_repeat('a', 256)], 'Max'],
]);

it('applies each two-factor challenge rule on its own', function (string $field, array $data, string $rule) {
    expect(failedRulesFor((new TwoFactorChallengeRequest)->rules(), ['challenge_token' => 'ct', ...$data], $field))->toHaveKey($rule);
})->with([
    'challenge required' => ['challenge_token', ['challenge_token' => null], 'Required'],
    'challenge a string' => ['challenge_token', ['challenge_token' => ['x']], 'String'],
    'code a string' => ['code', ['code' => ['x']], 'String'],
    'code excludes a recovery code' => ['code', ['code' => '123456', 'recovery_code' => 'r'], 'Prohibits'],
    'recovery code a string' => ['recovery_code', ['recovery_code' => ['x']], 'String'],
    'recovery code excludes a code' => ['recovery_code', ['code' => '123456', 'recovery_code' => 'r'], 'Prohibits'],
]);

it('lets either two-factor credential be null', function (string $field) {
    $data = ['challenge_token' => 'ct', 'code' => null, 'recovery_code' => null];

    expect(failedRulesFor((new TwoFactorChallengeRequest)->rules(), $data, $field))->toBe([]);
})->with(['code', 'recovery_code']);

it('applies each passkey registration rule on its own', function (string $field, array $data, string $rule) {
    expect(failedRulesFor((new PasskeyRegistrationRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'credential required' => ['credential', [], 'Required'],
    'credential an array' => ['credential', ['credential' => 'x'], 'Array'],
    'name a string' => ['name', ['credential' => ['id' => 'x'], 'name' => ['x']], 'String'],
    'name bounded' => ['name', ['credential' => ['id' => 'x'], 'name' => str_repeat('a', 256)], 'Max'],
]);

it('lets a passkey be registered without a name', function () {
    expect(failedRulesFor((new PasskeyRegistrationRequest)->rules(), ['credential' => ['id' => 'x'], 'name' => null], 'name'))->toBe([]);
});

it('applies each passkey assertion rule on its own', function (string $field, array $data, string $rule) {
    $data = array_merge(['ceremony_id' => 'c', 'credential' => ['id' => 'x']], $data);

    expect(failedRulesFor((new PasskeyAssertionRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'ceremony required' => ['ceremony_id', ['ceremony_id' => null], 'Required'],
    'ceremony a string' => ['ceremony_id', ['ceremony_id' => ['x']], 'String'],
    'credential required' => ['credential', ['credential' => null], 'Required'],
    'credential an array' => ['credential', ['credential' => 'x'], 'Array'],
    'credential id required' => ['credential.id', ['credential' => ['type' => 'public-key']], 'Required'],
    'credential id a string' => ['credential.id', ['credential' => ['id' => ['x']]], 'String'],
]);

it('applies each forgot-password rule on its own', function (array $data, string $rule) {
    expect(failedRulesFor((new ForgotPasswordRequest)->rules(), $data, 'email'))->toHaveKey($rule);
})->with([
    'required' => [[], 'Required'],
    'a string' => [['email' => ['x']], 'String'],
    'well-formed' => [['email' => 'not-an-email'], 'Email'],
    'bounded' => [['email' => str_repeat('a', 250).'@x.com'], 'Max'],
    // On its own: `email` happens to refuse a NUL as well, but the broker's lookup must not depend on
    // which email validator mode the app configures — pdo_pgsql would look up the truncated prefix.
    'without an invisible character' => [['email' => "ada@example.test\0x"], 'NotRegex'],
]);

it('applies each sign-in rule on its own', function (array $data, string $field, string $rule) {
    expect(failedRulesFor((new LoginRequest)->rules(), $data, $field))->toHaveKey($rule);
})->with([
    'identifier a string' => [['email' => ['x'], 'password' => 'secret-123456'], 'email', 'String'],
    'identifier bounded' => [['email' => str_repeat('a', 256), 'password' => 'secret-123456'], 'email', 'Max'],
    'password a string' => [['email' => 'ada@example.test', 'password' => ['x']], 'password', 'String'],
    'password bounded' => [['email' => 'ada@example.test', 'password' => str_repeat('a', 256)], 'password', 'Max'],
    // Pinned here, on its own, because the equalizer's try/catch masks it end to end: delete this
    // rule alone and the whole suite stayed green. `password_hash` raises `ValueError` on a NUL byte
    // where `password_verify` only returns false, so hashing one on the no-usable-password branch
    // answered 500 while a real account answered 422 — a deterministic, single-request account
    // oracle that also escaped the failure limiter. `ChangePasswordRequest` carried the rule already.
    'password without a NUL byte' => [['email' => 'ada@example.test', 'password' => "a\0b"], 'password', 'NotRegex'],
]);

// The throttle keys on the identifier's FOLD, so a spelling the DATABASE resolves to an account while the
// fold keys it apart is a fresh bucket of guesses. pdo_pgsql ends a bound string at NUL; MySQL's
// `utf8mb4_unicode_ci` ignores default-ignorable code points and pads trailing U+3000. Refused here, so
// no such spelling reaches the lookup (tests/Concurrency/IdentifierRespellingTest.php pins both engines).
it('refuses an identifier carrying a character no one types into one', function (string $identifier) {
    expect(failedRulesFor((new LoginRequest)->rules(), ['email' => $identifier, 'password' => 'secret-123456'], 'email'))
        ->toHaveKey('NotRegex');
})->with([
    'NUL' => ["victim@example.com\0x1"],
    'C0 control' => ["victim\x01@example.com"],
    'C1 control (NEL)' => ["victim@example.com\u{0085}"],
    'zero-width space' => ["victim\u{200B}@example.com"],
    'soft hyphen' => ["vic\u{00AD}tim@example.com"],
    'combining grapheme joiner' => ["victim\u{034F}@example.com"],
    'enclosing mark' => ["victim\u{20DD}@example.com"],
    'ideographic space' => ["victim@example.com\u{3000}"],
    'no-break space' => ["victim\u{00A0}@example.com"],
    'tab' => ["victim\t@example.com"],
]);

it('accepts the identifiers people actually have', function (string $identifier) {
    expect(failedRulesFor((new LoginRequest)->rules(), ['email' => $identifier, 'password' => 'secret-123456'], 'email'))
        ->toBe([]);
})->with([
    'ASCII' => ['ada@example.test'],
    'precomposed accents' => ['jérôme.müller@exämple.test'],
    'Devanagari (combining vowel signs and virama)' => ['हिन्दी@उदाहरण.भारत'],
    'Thai (combining marks)' => ['ผู้ใช้@ตัวอย่าง.ไทย'],
    'CJK' => ['用户@例子.广告'],
    'a username with an ASCII space' => ['Ada Lovelace'],
    'apostrophe' => ["o'brien@example.ie"],
    // U+200C/U+200D are format characters (`\p{Cf}`) that spelling needs — RFC 5892 lists them as
    // CONTEXTJ, valid in an IDN label: Persian writes `می‌خواهم` with a ZWNJ, an emoji ZWJ sequence
    // joins its parts with a ZWJ, and a keycap emoji ends in U+20E3 (`\p{Me}`). The fold strips all
    // three, so each still keys the account's bucket (LoginRateLimiterTest).
    'Persian with a zero-width non-joiner' => ["\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}"],
    'an emoji ZWJ sequence' => ["dev\u{1F469}\u{200D}\u{1F4BB}"],
    'a keycap emoji' => ["room1\u{FE0F}\u{20E3}"],
]);

it('leaves a missing sign-in field to the credential check, not to validation', function (string $field) {
    // `sometimes`: an absent field is refused as a wrong credential — 422 with the same body as any
    // other failed sign-in — rather than telling a prober which half they got wrong.
    expect(failedRulesFor((new LoginRequest)->rules(), [], $field))->toBe([]);
})->with(['email', 'password']);

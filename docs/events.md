# Events & Maintenance

- [Security Events](#security-events)
- [Constant-Time Login](#constant-time-login)
- [Non-Cacheable Responses](#non-cacheable-responses)
- [Pruning Expired Tokens](#pruning-expired-tokens)
- [Testing](#testing)

<a name="security-events"></a>
## Security Events

### RefreshTokenReused

When a refresh token that should no longer be usable is presented, Lukk force-revokes the entire token family and dispatches `Lukk\Events\RefreshTokenReused`. This is a token-theft signal — listen for it to log or alert:

```php
use Illuminate\Support\Facades\Event;
use Lukk\Events\RefreshTokenReused;

Event::listen(function (RefreshTokenReused $event) {
    Log::warning('Refresh token reuse detected', [
        'family' => $event->familyId,
        'reason' => $event->reason,
    ]);
});
```

The `reason` is one of:

| Reason | Meaning |
|---|---|
| `reuse` | A consumed token was replayed after the grace window — a successor already exists. |
| `revoked` | An already-revoked token was replayed. |

### PasskeyCloneDetected

When [passkeys](passkeys.md) are enabled, a regressing signature counter on an assertion dispatches `Lukk\Events\PasskeyCloneDetected`, indicating a possible credential clone. A zero counter is never flagged (synced passkeys always report `0`).

<a name="constant-time-login"></a>
## Constant-Time Login

Login is constant-time by design: an unknown email runs the same hashing work as a wrong password, so an attacker cannot enumerate accounts through timing or response differences. This behavior is part of the package's security contract — see the [security checklist](architecture.md#security-checklist).

<a name="non-cacheable-responses"></a>
## Non-Cacheable Responses

Every token-bearing response is sent with `Cache-Control: no-store, private`, so tokens are never cached by proxies, the browser, or an intermediary BFF.

<a name="pruning-expired-tokens"></a>
## Pruning Expired Tokens

Expired and revoked refresh-token rows accumulate over time. The `lukk:prune` command deletes them:

```bash
php artisan lukk:prune
```

The package schedules this command to run **daily by default**. To take over scheduling, opt out from a service provider's `boot` method and register your own cadence:

```php
use Illuminate\Support\Facades\Schedule;
use Lukk\Lukk;

public function boot(): void
{
    Lukk::disableScheduling();

    Schedule::command('lukk:prune')->hourly();
}
```

<a name="testing"></a>
## Testing

To authenticate a user in your own tests, use `Lukk::actingAs()` (the Sanctum-style helper):

```php
use Lukk\Lukk;

Lukk::actingAs($user);

$this->getJson('/api/me')->assertOk();
```

It accepts an optional guard name as the second argument (default `api`).

### Running the Package's Test Suite

```bash
composer install
vendor/bin/pest                       # whole suite
vendor/bin/pest tests/Unit            # isolated class/logic tests
vendor/bin/pest --group=passkeys      # one domain (passkeys, two-factor, refresh, confirmation)
```

Tests are split into `tests/Unit` (a class or action exercised directly) and `tests/Feature` (behavior through an HTTP route), with command tests under `tests/Feature/Console`. Testbench provides the application context, with an in-memory SQLite database and the array cache driver. The suite covers rotation, the grace window, reuse detection, the denylist, JWT algorithm pinning, the guard, both output modes, the login throttle, step-up confirmation, two-factor, passkeys, and the contract-swap seams.

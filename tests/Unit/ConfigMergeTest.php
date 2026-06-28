<?php

declare(strict_types=1);

use Illuminate\Contracts\Foundation\CachesConfiguration;
use Lukk\LukkServiceProvider;

// Simulates a config published before newer nested keys existed. mergeConfigFrom
// only merges the first dimension, so without the deep merge these keys would be
// absent at runtime (and resolve to null/0 — e.g. a rate limit of 0).
it('backfills missing nested config keys from the package defaults', function () {
    $defaults = [
        'algorithm' => 'HS256',
        'audience' => ['https://api.example.com'],
        'rate_limits' => ['login' => ['max_attempts' => 5, 'decay_seconds' => 60, 'ip_max_attempts' => 30]],
        'two_factor' => ['window' => 1, 'recovery_codes' => 8, 'challenge_ttl' => 300],
        'passkeys' => ['challenge_ttl' => 120, 'user_verification' => 'preferred', 'origins' => []],
        'features' => ['rotation' => true, 'two_factor' => false, 'passkeys' => false],
    ];

    $published = [
        'audience' => ['https://my.example.com'],
        'rate_limits' => ['login' => ['max_attempts' => 7, 'decay_seconds' => 90]],   // no ip_max_attempts
        'two_factor' => ['window' => 2],                                               // no recovery_codes / challenge_ttl
        'passkeys' => ['challenge_ttl' => 300, 'origins' => ['https://app.example.com']], // no user_verification
        'features' => ['rotation' => true, 'two_factor' => true],                       // no passkeys flag
    ];

    $merged = LukkServiceProvider::mergeConfig($defaults, $published);

    // Missing nested keys are backfilled from defaults...
    expect($merged['algorithm'])->toBe('HS256')
        ->and($merged['rate_limits']['login']['ip_max_attempts'])->toBe(30)
        ->and($merged['two_factor']['recovery_codes'])->toBe(8)
        ->and($merged['two_factor']['challenge_ttl'])->toBe(300)
        ->and($merged['passkeys']['user_verification'])->toBe('preferred')
        ->and($merged['features']['passkeys'])->toBeFalse();

    // ...published values win where present...
    expect($merged['rate_limits']['login']['max_attempts'])->toBe(7)
        ->and($merged['two_factor']['window'])->toBe(2)
        ->and($merged['passkeys']['challenge_ttl'])->toBe(300)
        ->and($merged['features']['two_factor'])->toBeTrue();

    // ...and list values are replaced wholesale, never merged element-wise.
    expect($merged['audience'])->toBe(['https://my.example.com'])
        ->and($merged['passkeys']['origins'])->toBe(['https://app.example.com']);
});

// The deep merge mirrors mergeConfigFrom's own guard: when the app's config is
// cached, nothing is merged (the cache is already the final, complete config).
it('skips the deep merge when the application configuration is cached', function () {
    $app = new class implements CachesConfiguration
    {
        public function configurationIsCached()
        {
            return true;
        }

        public function getCachedConfigPath()
        {
            return '';
        }

        public function getCachedServicesPath()
        {
            return '';
        }
    };

    $provider = new LukkServiceProvider($app);
    $merge = new ReflectionMethod($provider, 'mergeConfigDeep');
    $merge->setAccessible(true);

    // If it did not return early it would access $app['config']; the fake app is
    // not array-accessible, so that would throw and fail this test.
    $merge->invoke($provider, 'unused', 'lukk');

    expect($app->configurationIsCached())->toBeTrue();
});

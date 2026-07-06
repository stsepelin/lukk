<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;

class GenerateSecretCommand extends Command
{
    protected $signature = 'lukk:secret
        {--guard= : Generate the secret for a specific guard (writes LUKK_<GUARD>_SECRET)}
        {--show : Display the generated secret instead of writing it to the .env file}
        {--f|force : Overwrite an existing secret without confirmation}';

    protected $description = 'Generate the HMAC signing secret for Lukk access tokens.';

    public function handle(): int
    {
        // 256-bit key, hex-encoded — firebase/php-jwt v7 enforces a >=256-bit HMAC secret.
        $key = bin2hex(random_bytes(32));

        if ($this->option('show')) {
            $this->line('<comment>'.$key.'</comment>');

            return self::SUCCESS;
        }

        [$envVar, $configKey] = $this->target();

        if (! $this->setSecretInEnvironmentFile($key, $envVar, $configKey)) {
            return self::FAILURE;
        }

        $this->laravel['config'][$configKey] = $key;

        $this->components->info('Lukk signing secret set successfully.');

        return self::SUCCESS;
    }

    /**
     * The .env variable and config key to write — the default guard's `LUKK_SECRET`/`lukk.secret`,
     * or a per-guard `LUKK_<GUARD>_SECRET`/`lukk.guards.<guard>.secret` when `--guard` is given.
     *
     * @return array{0:string,1:string}
     */
    protected function target(): array
    {
        $guard = (string) ($this->option('guard') ?? '');

        if ($guard === '') {
            return ['LUKK_SECRET', 'lukk.secret'];
        }

        $envVar = 'LUKK_'.strtoupper(str_replace('-', '_', $guard)).'_SECRET';

        return [$envVar, "lukk.guards.{$guard}.secret"];
    }

    protected function setSecretInEnvironmentFile(string $key, string $envVar, string $configKey): bool
    {
        $current = (string) ($this->laravel['config'][$configKey] ?? '');

        if ($current !== '' && ! $this->option('force')
            && ! $this->confirm('A Lukk secret already exists. Overwrite it?')) {
            return false;
        }

        $path = $this->laravel->environmentFilePath();

        if (! is_file($path)) {
            $this->components->error('No .env file found. Create one before running lukk:secret.');

            return false;
        }

        $contents = file_get_contents($path);

        if (preg_match("/^{$envVar}=/m", $contents) === 1) {
            $contents = preg_replace("/^{$envVar}=.*$/m", "{$envVar}={$key}", $contents);
        } else {
            $contents = rtrim($contents, "\n")."\n\n{$envVar}={$key}\n";
        }

        file_put_contents($path, $contents);

        return true;
    }
}

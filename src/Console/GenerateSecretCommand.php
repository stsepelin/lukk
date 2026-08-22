<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Lukk\Console\Concerns\ReadsStringInput;

class GenerateSecretCommand extends Command
{
    use ReadsStringInput;

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

        $this->laravel->make('config')->set($configKey, $key);

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
        $guard = $this->stringOption('guard');

        if ($guard === '') {
            return ['LUKK_SECRET', 'lukk.secret'];
        }

        $envVar = 'LUKK_'.strtoupper(str_replace('-', '_', $guard)).'_SECRET';

        return [$envVar, "lukk.guards.{$guard}.secret"];
    }

    protected function setSecretInEnvironmentFile(string $key, string $envVar, string $configKey): bool
    {
        $current = (string) ($this->laravel->make('config')->get($configKey) ?? '');

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

        // Unreachable in a booted Laravel app — `HandleExceptions` promotes the E_WARNING on the
        // line above into an ErrorException before this runs — but `file_get_contents` is still
        // `string|false` to a type checker, and every call below needs a string.
        // @codeCoverageIgnoreStart
        if ($contents === false) {
            $this->components->error("Could not read [{$path}].");

            return false;
        }
        // @codeCoverageIgnoreEnd

        if (preg_match("/^{$envVar}=/m", $contents) === 1) {
            $contents = preg_replace("/^{$envVar}=.*$/m", "{$envVar}={$key}", $contents);
        } else {
            $contents = rtrim($contents, "\n")."\n\n{$envVar}={$key}\n";
        }

        file_put_contents($path, $contents);

        return true;
    }
}

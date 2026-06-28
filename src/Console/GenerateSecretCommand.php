<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;

class GenerateSecretCommand extends Command
{
    protected $signature = 'lukk:secret
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

        if (! $this->setSecretInEnvironmentFile($key)) {
            return self::FAILURE;
        }

        $this->laravel['config']['lukk.secret'] = $key;

        $this->components->info('Lukk signing secret set successfully.');

        return self::SUCCESS;
    }

    protected function setSecretInEnvironmentFile(string $key): bool
    {
        $current = (string) ($this->laravel['config']['lukk.secret'] ?? '');

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

        if (preg_match('/^LUKK_SECRET=/m', $contents) === 1) {
            $contents = preg_replace('/^LUKK_SECRET=.*$/m', 'LUKK_SECRET='.$key, $contents);
        } else {
            $contents = rtrim($contents, "\n")."\n\nLUKK_SECRET=".$key."\n";
        }

        file_put_contents($path, $contents);

        return true;
    }
}

<?php

declare(strict_types=1);

namespace Lukk\Console;

use Illuminate\Console\Command;
use Lukk\Console\Concerns\ReadsStringInput;

/**
 * Generate an asymmetric signing keypair for RS256/ES256 — the sibling to
 * `lukk:secret` (which generates the HS256 secret). It prints the PEMs and the
 * env to set rather than touching the filesystem, so you control where the
 * (private) key lands.
 */
class GenerateKeysCommand extends Command
{
    use ReadsStringInput;

    protected $signature = 'lukk:keygen
        {--algorithm=RS256 : RS256 (RSA-2048) or ES256 (EC P-256)}
        {--kid= : Key id to label the key (default: a random id)}';

    protected $description = 'Generate an RS256/ES256 signing keypair for Lukk access tokens.';

    public function handle(): int
    {
        $algorithm = strtoupper($this->stringOption('algorithm'));

        $spec = match ($algorithm) {
            'RS256' => ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA],
            'ES256' => ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'],
            default => null,
        };

        if ($spec === null) {
            $this->components->error("Unsupported algorithm [{$algorithm}]. Use RS256 or ES256.");

            return self::FAILURE;
        }

        $resource = openssl_pkey_new($spec);

        if ($resource === false || ! openssl_pkey_export($resource, $private)) {
            $this->components->error('Could not generate a keypair — check that the OpenSSL extension and its configuration are available.'); // @codeCoverageIgnore

            return self::FAILURE; // @codeCoverageIgnore
        }

        $details = openssl_pkey_get_details($resource);

        // `false` on a key openssl cannot introspect. Indexing it would fatal on the line that is
        // supposed to be HANDING the operator their new key.
        // @codeCoverageIgnoreStart
        if ($details === false || ! isset($details['key'])) {
            $this->components->error('Could not read the generated key.');

            return self::FAILURE;
        }
        // @codeCoverageIgnoreEnd

        $public = (string) $details['key'];
        $kid = $this->stringOption('kid') !== '' ? $this->stringOption('kid') : 'k'.bin2hex(random_bytes(4));

        $this->components->info("Generated an {$algorithm} keypair (kid: {$kid}).");
        $this->newLine();
        $this->line($private);
        $this->line($public);
        $this->newLine();
        $this->line('Store the keys, then set in your .env:');
        $this->line("LUKK_ALGORITHM={$algorithm}");
        $this->line("LUKK_ACTIVE_KID={$kid}");
        $this->line('LUKK_PRIVATE_KEY=@/path/to/private.pem   # or paste the PEM inline');
        $this->line('LUKK_PUBLIC_KEY=@/path/to/public.pem');

        return self::SUCCESS;
    }
}

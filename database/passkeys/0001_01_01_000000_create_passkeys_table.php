<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('passkeys', function (Blueprint $table) {
            $table->string('credential_id')->primary(); // base64url — globally unique
            $table->foreignId('user_id')->index();

            // The guard this credential belongs to (multi-guard isolation). Null on the default
            // guard; an extra guard (e.g. `admin`) stamps its name, so its credentials can't be
            // asserted, listed, erased or pruned by another guard even when user ids collide
            // (`users.id == admins.id` is the ordinary case across separate provider tables).
            // Unused under a single guard. `credential_id` stays GLOBALLY unique — WebAuthn requires
            // it, and a credential can only ever belong to one account anyway.
            $table->string('guard')->nullable();
            $table->string('name')->nullable();
            $table->text('public_key');                  // encrypted COSE key
            $table->unsignedBigInteger('sign_count')->default(0);
            $table->json('transports')->nullable();
            $table->string('aaguid')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('passkeys');
    }
};

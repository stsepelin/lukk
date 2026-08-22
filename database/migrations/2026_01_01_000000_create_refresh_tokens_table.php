<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('refresh_tokens', function (Blueprint $table) {
            $table->ulid('id')->primary();

            // Change to ulid()/uuid() here if your users use non-integer keys.
            $table->unsignedBigInteger('user_id')->index();

            // The guard a family belongs to (multi-guard isolation). Null on the default guard;
            // an extra guard (e.g. `admin`) stamps its name so its families can't be seen, rotated,
            // or revoked by another guard even when user ids collide. Unused under a single guard.
            $table->string('guard')->nullable();

            $table->uuid('family_id')->index();          // stable across a rotation chain
            $table->char('token_hash', 64)->unique();    // sha256(opaque secret)
            $table->ulid('previous_id')->nullable();     // audit chain pointer
            // The token's OWN abilities, when it has any. NULL is the normal case and means
            // "derive from Lukk::abilitiesUsing on every mint", which keeps a revoked ability
            // taking effect within access_ttl. A value pins the grant for this family's lifetime —
            // which is what a personal access token or an impersonation cap needs, and what a
            // callback keyed on the subject cannot express.
            $table->text('scope')->nullable();
            $table->timestamp('rotated_at')->nullable(); // set when consumed to mint a successor
            $table->timestamp('revoked_at')->nullable()->index(); // hard kill (logout / reuse cascade); indexed for prune
            $table->timestamp('expires_at')->index();    // absolute family ceiling
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('refresh_tokens');
    }
};

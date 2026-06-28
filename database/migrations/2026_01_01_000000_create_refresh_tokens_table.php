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

            $table->uuid('family_id')->index();          // stable across a rotation chain
            $table->char('token_hash', 64)->unique();    // sha256(opaque secret)
            $table->ulid('previous_id')->nullable();     // audit chain pointer
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

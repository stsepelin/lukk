<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('lukk_lockouts', function (Blueprint $table) {
            $table->ulid('id')->primary();

            // NIST SP 800-63B §5.2.2 caps CONSECUTIVE failures, which a decaying cache window can't
            // express — a counter that expires isn't consecutive, and one that lives in the cache
            // doesn't survive a flush. Hence a table.
            $table->string('purpose');            // which authenticator: login | two_factor
            $table->string('subject');            // the normalized identifier, or the user id for 2FA
            $table->string('guard')->nullable();  // multi-guard isolation, mirroring refresh_tokens

            $table->unsignedInteger('attempts')->default(0);
            $table->timestamp('locked_at')->nullable()->index(); // indexed for pruning released rows
            $table->timestamps();

            // One counter per authenticator per account per guard.
            $table->unique(['purpose', 'subject', 'guard']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('lukk_lockouts');
    }
};

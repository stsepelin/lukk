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
            $table->string('purpose', 32);  // which authenticator: login | two_factor | confirm
            $table->string('subject');      // the normalized identifier, or the user id for 2FA

            // NOT NULL with a '' sentinel, unlike refresh_tokens: NULLs compare as DISTINCT in a
            // unique index on MySQL, Postgres AND SQLite, so a nullable guard here would silently
            // stop deduping and let one account hold several counters. Narrowed alongside `purpose`
            // to keep the three-column index clear of InnoDB's 3072-byte ceiling on utf8mb4.
            $table->string('guard', 64)->default('');

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

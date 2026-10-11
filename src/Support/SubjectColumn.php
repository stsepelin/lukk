<?php

declare(strict_types=1);

namespace Lukk\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Throwable;

/**
 * Whether a token's `sub` is a value the user model's identifier COLUMN can hold at all — decided from the
 * column's real type, read from the schema once per process.
 *
 * A co-issuer sharing the secret (the verify-only topology) can put anything in `sub`, and PostgreSQL types
 * the lookup's parameter against the column: `"admin"` against an integer column, `"3000000000"` against a
 * 32-bit one, a non-UUID against `uuid`, is SQLSTATE 22P02/22003 — a 500 on every authenticated route for
 * that token, where a `sub` naming no user is a 401. Refused BEFORE the lookup, so no failing statement is
 * ever run (and none can abort a caller's transaction), and a failure the application causes itself — a
 * scope with a mistyped binding, a mistyped `$with` relation — stays the 500 it is.
 *
 * The model's declarations are not the answer: `$keyType` defaults to `'int'` on string keys, a Snowflake
 * key is an integer that does not increment, and the auth identifier may be another column altogether. The
 * schema is. MySQL and SQLite coerce instead of refusing; the same refusal there is merely consistent.
 *
 * Integer types take a canonical integer within the type's range (unsigned variants on MySQL), `uuid` a UUID
 * as PostgreSQL reads one, `numeric`/`decimal` a number; any other type is not checked. When the column
 * cannot be read (no such table or column, a catalog error) nothing is checked: the provider answers, as it
 * always did. The result — including "not found" — is kept for the process, which is what makes this one
 * catalog query per worker rather than one per request (Octane-safe: the schema does not change under a
 * running worker); `flush()` is for tests.
 */
class SubjectColumn
{
    /** @var array<string, array{type_name: string, type: string}|null> */
    private static array $columns = [];

    public static function flush(): void
    {
        self::$columns = [];
    }

    public static function admits(Model&Authenticatable $model, int|string $sub): bool
    {
        $column = self::describe($model);

        return $column === null || self::fits($column['type_name'], $column['type'], (string) $sub);
    }

    /** Whether `$sub` is a value of this column type (`type_name` and full `type` as Laravel's `getColumns()` reports them). */
    public static function fits(string $typeName, string $type, string $sub): bool
    {
        $bits = match (strtolower($typeName)) {
            'tinyint' => 8,
            'int2', 'smallint' => 16,
            'mediumint' => 24,
            'int4', 'int' => 32,
            // SQLite reports every integer column as `integer`, which it stores in 64 bits; on PostgreSQL
            // and MySQL `type_name` is `int4`/`int`, never `integer`.
            'int8', 'bigint', 'integer' => 64,
            default => null,
        };

        if ($bits !== null) {
            return self::integerWithin($sub, $bits, str_contains(strtolower($type), 'unsigned'));
        }

        return match (strtolower($typeName)) {
            // PostgreSQL's input forms: either case, optional braces, a hyphen after any group of four.
            'uuid' => preg_match('/^(\{)?(?:[0-9a-f]{4}-?){7}[0-9a-f]{4}(?(1)\})\z/i', $sub) === 1,
            'numeric', 'decimal' => is_numeric($sub),
            default => true,
        };
    }

    private static function integerWithin(string $sub, int $bits, bool $unsigned): bool
    {
        if (preg_match('/^(?:0|-?[1-9][0-9]*)\z/', $sub) !== 1) {
            return false;
        }

        if ($unsigned) {
            // 2^64 − 1 is past PHP's int, so the unsigned bound is compared as a canonical digit string.
            $max = $bits === 64 ? '18446744073709551615' : (string) ((1 << $bits) - 1);

            return $sub[0] !== '-' && (strlen($sub) < strlen($max) || (strlen($sub) === strlen($max) && strcmp($sub, $max) <= 0));
        }

        $max = $bits === 64 ? PHP_INT_MAX : (1 << ($bits - 1)) - 1;

        return filter_var($sub, FILTER_VALIDATE_INT, ['options' => ['min_range' => -$max - 1, 'max_range' => $max]]) !== false;
    }

    /** @return array{type_name: string, type: string}|null */
    private static function describe(Model&Authenticatable $model): ?array
    {
        $connection = $model->getConnection();
        // `users as u` names the table `users`; `public.users` keeps its schema, which `getColumns()` reads,
        // adding the connection's prefix to the table part itself.
        // A pattern this simple cannot fail on a string, so the cast only states the type.
        $table = (string) preg_replace('/\s+as\s+\S+$/i', '', $model->getTable()); // @pest-mutate-ignore: RemoveStringCast
        $name = $model->getAuthIdentifierName();
        $key = implode("\0", [$connection->getName(), $table, $name]);

        if (! array_key_exists($key, self::$columns)) {
            self::$columns[$key] = self::read($connection, $table, $name);
        }

        return self::$columns[$key];
    }

    /** @return array{type_name: string, type: string}|null */
    private static function read(Connection $connection, string $table, string $name): ?array
    {
        $columns = fn (): array => $connection->getSchemaBuilder()->getColumns($table);

        try {
            // Inside a caller's transaction, in a savepoint of its own: on PostgreSQL a failed statement
            // aborts the whole transaction, and its COMMIT then silently rolls back.
            $all = $connection->transactionLevel() > 0 ? $connection->transaction($columns) : $columns();
        } catch (Throwable) {
            return null;
        }

        foreach ($all as $column) {
            if ($column['name'] === $name) {
                return ['type_name' => $column['type_name'], 'type' => $column['type']];
            }
        }

        return null;
    }
}

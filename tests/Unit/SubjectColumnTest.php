<?php

declare(strict_types=1);

use Lukk\Support\SubjectColumn;

/*
 * The `type_name` / `type` pairs are what Laravel's `Schema::getColumns()` reports on each engine
 * (PostgreSQL `int8`/`bigint`, MySQL `bigint`/`bigint unsigned`, SQLite `integer`/`integer`).
 */

it('takes a canonical integer within the column type\'s range', function (string $typeName, string $type, string $sub, bool $fits) {
    expect(SubjectColumn::fits($typeName, $type, $sub))->toBe($fits);
})->with([
    // PostgreSQL
    'int2 max' => ['int2', 'smallint', '32767', true],
    'int2 past max' => ['int2', 'smallint', '32768', false],
    'int2 min' => ['int2', 'smallint', '-32768', true],
    'int2 past min' => ['int2', 'smallint', '-32769', false],
    'int4 max' => ['int4', 'integer', '2147483647', true],
    'int4 past max' => ['int4', 'integer', '2147483648', false],
    'int4 min' => ['int4', 'integer', '-2147483648', true],
    'int4 past min' => ['int4', 'integer', '-2147483649', false],
    'int8 max' => ['int8', 'bigint', '9223372036854775807', true],
    'int8 past max' => ['int8', 'bigint', '9223372036854775808', false],
    'int8 min' => ['int8', 'bigint', '-9223372036854775808', true],
    'int8 past min' => ['int8', 'bigint', '-9223372036854775809', false],
    'a word' => ['int8', 'bigint', 'admin', false],
    'a fraction' => ['int8', 'bigint', '1.5', false],
    'zero-padded' => ['int8', 'bigint', '01', false],
    'signed with a plus' => ['int8', 'bigint', '+1', false],
    'spaced' => ['int8', 'bigint', ' 1', false],
    'empty' => ['int8', 'bigint', '', false],
    'trailing newline' => ['int8', 'bigint', "1\n", false],
    'unsigned, trailing newline' => ['bigint', 'bigint unsigned', "1\n", false],
    'zero' => ['int8', 'bigint', '0', true],
    'upper-case type name' => ['INT4', 'INTEGER', '2147483648', false],
    // MySQL
    'tinyint max' => ['tinyint', 'tinyint', '127', true],
    'tinyint past max' => ['tinyint', 'tinyint', '128', false],
    'tinyint min' => ['tinyint', 'tinyint', '-128', true],
    'tinyint past min' => ['tinyint', 'tinyint', '-129', false],
    'tinyint unsigned max' => ['tinyint', 'tinyint unsigned', '255', true],
    'tinyint unsigned past max' => ['tinyint', 'tinyint unsigned', '256', false],
    'tinyint unsigned negative' => ['tinyint', 'tinyint unsigned', '-1', false],
    'smallint unsigned max' => ['smallint', 'smallint unsigned', '65535', true],
    'smallint unsigned past max' => ['smallint', 'smallint unsigned', '65536', false],
    'mediumint max' => ['mediumint', 'mediumint', '8388607', true],
    'mediumint past max' => ['mediumint', 'mediumint', '8388608', false],
    'mediumint min' => ['mediumint', 'mediumint', '-8388608', true],
    'mediumint unsigned max' => ['mediumint', 'mediumint unsigned', '16777215', true],
    'mediumint unsigned past max' => ['mediumint', 'mediumint unsigned', '16777216', false],
    'int max' => ['int', 'int', '2147483647', true],
    'int past max' => ['int', 'int', '2147483648', false],
    'int unsigned max' => ['int', 'int unsigned', '4294967295', true],
    'int unsigned past max' => ['int', 'int unsigned', '4294967296', false],
    'bigint unsigned max' => ['bigint', 'bigint unsigned', '18446744073709551615', true],
    'bigint unsigned past max, same length' => ['bigint', 'BIGINT UNSIGNED', '18446744073709551616', false],
    'bigint unsigned, upper-case type' => ['bigint', 'BIGINT UNSIGNED', '18446744073709551615', true],
    'bigint unsigned, longer' => ['bigint', 'bigint unsigned', '100000000000000000000', false],
    'bigint unsigned, shorter' => ['bigint', 'bigint unsigned', '9223372036854775808', true],
    'bigint unsigned zero' => ['bigint', 'bigint unsigned', '0', true],
    'bigint unsigned word' => ['bigint', 'bigint unsigned', 'admin', false],
    'bigint signed past max' => ['bigint', 'bigint', '9223372036854775808', false],
    // SQLite
    'integer, 64-bit' => ['integer', 'integer', '9223372036854775807', true],
    'integer past 64-bit' => ['integer', 'integer', '9223372036854775808', false],
    'integer, a word' => ['integer', 'integer', 'admin', false],
]);

it('takes a UUID in any form PostgreSQL reads, for a uuid column', function (string $sub, bool $fits) {
    expect(SubjectColumn::fits('uuid', 'uuid', $sub))->toBe($fits)
        ->and(SubjectColumn::fits('UUID', 'UUID', $sub))->toBe($fits);
})->with([
    'canonical' => ['a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', true],
    'upper case' => ['A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11', true],
    'braced' => ['{a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11}', true],
    'no hyphens' => ['a0eebc999c0b4ef8bb6d6bb9bd380a11', true],
    'hyphen after every four' => ['a0ee-bc99-9c0b-4ef8-bb6d-6bb9-bd38-0a11', true],
    'an open brace only' => ['{a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', false],
    'a close brace only' => ['a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11}', false],
    'one digit short' => ['a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a1', false],
    'one digit long' => ['a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a111', false],
    'not hex' => ['g0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', false],
    'a word' => ['admin', false],
    'trailing newline' => ["a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11\n", false],
]);

it('takes a number for a numeric or decimal column', function (string $typeName, string $sub, bool $fits) {
    expect(SubjectColumn::fits($typeName, $typeName, $sub))->toBe($fits);
})->with([
    'numeric, a fraction' => ['numeric', '1.5', true],
    'numeric, a word' => ['numeric', 'admin', false],
    'decimal, an integer' => ['decimal', '42', true],
    'decimal, a word' => ['decimal', 'admin', false],
    'upper-case type name' => ['NUMERIC', 'admin', false],
]);

it('checks no other column type', function (string $typeName) {
    expect(SubjectColumn::fits($typeName, $typeName, "anything at all \u{2603}"))->toBeTrue();
})->with(['varchar', 'text', 'bpchar', 'char', 'citext', 'float8', 'jsonb']);

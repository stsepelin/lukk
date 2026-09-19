<?php

declare(strict_types=1);

namespace Lukk\Tests\Fixtures;

use Lukk\Contracts\LockoutRepository;

/** Holds nothing; records the subject lists the export and erasure paths ask about. */
class RecordingLockoutRepository implements LockoutRepository
{
    /** @var array<int, string> */
    public array $summarised = [];

    /** @var array<int, string> */
    public array $forgotten = [];

    public function locked(string $purpose, string $subject, ?string $guard): bool
    {
        return false;
    }

    public function recordFailure(string $purpose, string $subject, ?string $guard): int
    {
        return 0;
    }

    public function maxAttempts(): int
    {
        return 100;
    }

    public function release(string $purpose, string $subject, ?string $guard): int
    {
        return 0;
    }

    public function availableIn(string $purpose, string $subject, ?string $guard): ?int
    {
        return null;
    }

    public function prune(int $staleAfterDays): int
    {
        return 0;
    }

    public function forget(array $subjects, ?string $guard): int
    {
        $this->forgotten = $subjects;

        return 0;
    }

    public function summariesForSubjects(array $subjects, ?string $guard): array
    {
        $this->summarised = $subjects;

        return [];
    }
}

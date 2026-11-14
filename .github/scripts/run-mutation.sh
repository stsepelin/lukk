#!/usr/bin/env bash
#
# One mutation run, held to the two things the score alone does not say.
#
# Usage: .github/scripts/run-mutation.sh [pest arguments, e.g. --everything --path=src/Lukk.php]
#
# - `--min=99` is the floor, here so the nightly shards and the pull-request job cannot drift apart.
# - A TIMEOUT fails the run. The plugin scores a mutant that ran out of time as caught, but a timeout
#   only says the tests did not finish: with the budget `patch-pest-mutate.php` sets (ten times the
#   suite plus a minute) one that still runs out is a mutation that hangs or a suite that got ten times
#   slower, and either deserves a look rather than a point.

set -euo pipefail

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# No memory limit: per-test coverage for the whole suite does not fit in PHP's stock 512M.
XDEBUG_MODE=coverage php -d memory_limit=-1 vendor/bin/pest --mutate --parallel --covered-only --min=99 "$@" 2>&1 | tee "$log"

# The summary reads `Mutations: 2 timeout, 310 tested`; colour codes sit between the words. Stripped into
# a file first, and matched without `-q`: under `pipefail`, a `grep -q` that exits on its match can kill
# the `sed` feeding it, and the pipeline's failure then reads as "no timeout".
plain="$(mktemp)"
trap 'rm -f "$log" "$plain"' EXIT
sed $'s/\x1b\\[[0-9;]*m//g' "$log" > "$plain"

# No summary at all means the wording moved, and this check with it: say so instead of passing.
if ! grep -E 'Mutations:.* [0-9]+ tested' "$plain" > /dev/null; then
    echo "::error::No 'Mutations: … tested' summary in the output — run-mutation.sh can no longer tell whether a mutant timed out. Update it for this plugin version."
    exit 1
fi

if grep -E 'Mutations:.* [0-9]+ timeout' "$plain" > /dev/null; then
    echo "::error::Mutants timed out — listed above as TIMEOUT. A timeout is not a kill: run each with --id=<id> and see what it does."
    exit 1
fi

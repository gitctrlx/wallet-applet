#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 QuantX
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Runs both vector generators and fails on any byte difference between them, or between their
# output and the committed spec/vectors/*.json (spec/protocol.md §18). Needs JDK 25 and Bun.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
java_out="$root/tests/build/vectors/java"
ts_out="$root/tests/build/vectors/ts"

rm -rf "$java_out" "$ts_out"
"$root/gradlew" -p "$root" --quiet :tests:generateVectors
(cd "$root/spec/vectors/gen/ts" && bun install --frozen-lockfile --silent && bun generate.ts "$ts_out")
diff -r "$java_out" "$ts_out"

committed="$(cd "$root/spec/vectors" && ls -1 ./*.json 2>/dev/null | sed 's|^\./||' || true)"
generated="$(cd "$java_out" && ls -1 ./*.json | sed 's|^\./||' | grep -vx selftest.json || true)"
diff <(echo "$committed") <(echo "$generated")
for f in $generated; do
  cmp "$java_out/$f" "$root/spec/vectors/$f"
done
echo "vectors: generators agree ($(echo "$generated" | grep -c . || true) protocol files, selftest included)"

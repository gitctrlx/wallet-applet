// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// TypeScript generator (noble) of the files of spec/protocol.md §18. Usage: `bun generate.ts <outDir>`.
// Each implementation stage adds the files it owns to FILES; selftest.json is the harness's own
// agreement check and is never committed. Output is canonical: JSON.stringify(value, null, 2) + "\n".
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { selftest } from './selftest.ts';

const FILES: Record<string, () => unknown> = { 'selftest.json': selftest };

const out = process.argv[2];
if (!out) throw new Error('usage: bun generate.ts <outDir>');
mkdirSync(out, { recursive: true });
for (const [name, build] of Object.entries(FILES)) {
  writeFileSync(join(out, name), `${JSON.stringify(build(), null, 2)}\n`, 'ascii');
}

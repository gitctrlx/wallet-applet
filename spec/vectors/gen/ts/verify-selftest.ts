// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// verify-selftest.ts: builds a verify.ts input file out of the committed vector cases
// (spec/vectors/{ecdsa,bip340,ed25519}.json) so the standalone verifier's own plumbing is
// exercised end to end. Ed25519 entries use the §12.3 message expansion: each case's committed
// privateKey signs the expanded message, matching the shape a real applet session emits.
// Usage: bun verify-selftest.ts <vectorDir> <outFile>
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { det } from './lib.ts';

const dir = process.argv[2];
const out = process.argv[3];
const load = (name: string) => JSON.parse(readFileSync(join(dir, name), 'utf8'));

const expandMessage = (seed: Uint8Array, length: number): Uint8Array => {
  const blocks: Uint8Array[] = [];
  for (let i = 0, have = 0; have < length; i++, have += 64) {
    const ctr = new Uint8Array([i >>> 24, i >>> 16, i >>> 8, i].map((v) => v & 0xff));
    blocks.push(sha512(concatBytes(seed, ctr)));
  }
  return concatBytes(...blocks).subarray(0, length);
};

const ecdsaDoc = load('ecdsa.json');
const ecdsa = ecdsaDoc.cases.flatMap((c: Record<string, string>) =>
  ['signature', 'lowS', 'highS'].map((variant) => ({
    publicKey: c.publicKey,
    digest: c.digest,
    signature: c[variant],
  })),
);

const bip340Doc = load('bip340.json');
const bip340 = [
  ...bip340Doc.official
    .filter((r: Record<string, unknown>) => r.valid === true && r.publicKey !== '')
    .map((r: Record<string, string>) => ({
      outputKey: r.publicKey,
      message: r.message,
      signature: r.signature,
    })),
  ...bip340Doc.cases.map((c: Record<string, string>) => ({
    outputKey: c.outputKey,
    message: c.message,
    signature: c.signature,
  })),
];

const edDoc = load('ed25519.json');
const edEntries = edDoc.cases.map((c: Record<string, string>) => {
  const seed = det(`verify/selftest/${c.name}`);
  const message = expandMessage(seed, hexToBytes(c.message).length);
  return {
    publicKey: c.publicKey,
    messageSeed: bytesToHex(seed),
    messageLength: message.length,
    signature: bytesToHex(ed25519.sign(message, hexToBytes(c.privateKey))),
  };
});

writeFileSync(out, JSON.stringify({ ecdsa, bip340, ed25519: edEntries }, null, 2) + '\n');
console.log(`wrote ${out}: ${ecdsa.length} ecdsa, ${bip340.length} bip340, ${edEntries.length} ed25519`);

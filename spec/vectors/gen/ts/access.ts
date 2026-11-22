// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// access.json: the access-code rules of spec/protocol.md §7.1 — 6–64 characters of printable
// ASCII hashed with Argon2id (m = 65536 KiB, t = 3, p = 4, T = 32, version 0x13) over the
// per-card salt "qntx-card/v1/access" ‖ ID(A), and the codes a host MUST reject before hashing.
// Mirrors gen/java/.../AccessDoc.java.
import { argon2id } from '@noble/hashes/argon2.js';
import { bytesToHex, concatBytes, sha256, utf8ToBytes } from './lib.ts';
import { CARD1, CARD2, compressedKey } from './cards.ts';

const LABEL = utf8ToBytes('qntx-card/v1/access');
const M = 65536;
const T = 3;
const P = 4;
const TAG = 32;

/** null when code satisfies §7.1, else the reason a host rejects it. */
const invalidReason = (code: string): string | null => {
  if (code.length < 6 || code.length > 64) return 'length';
  for (const c of code) {
    if (c < ' ' || c > '~') return 'character';
  }
  return null;
};

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

const valid = (name: string, code: string, cardId: Uint8Array): object => {
  if (invalidReason(code) !== null) throw new Error(`valid case rejected by §7.1 rules: ${name}`);
  const salt = concatBytes(LABEL, cardId);
  const accessHash = argon2id(utf8(code), salt, {
    m: M,
    t: T,
    p: P,
    dkLen: TAG,
    version: 0x13,
  });
  return {
    name,
    code,
    codeHex: bytesToHex(utf8(code)),
    cardId: bytesToHex(cardId),
    salt: bytesToHex(salt),
    accessHash: bytesToHex(accessHash),
  };
};

const rejected = (name: string, code: string, reason: string): object => {
  const actual = invalidReason(code);
  if (actual !== reason) {
    throw new Error(`rejected case ${name} expected ${reason}, got ${actual}`);
  }
  return { name, codeHex: bytesToHex(utf8(code)), reason };
};

export function accessDoc(): unknown {
  const card1 = sha256(compressedKey(CARD1)).subarray(0, 16);
  const card2 = sha256(compressedKey(CARD2)).subarray(0, 16);
  const printable = String.fromCharCode(...Array.from({ length: 64 }, (_, i) => 0x20 + i));
  const validCases = [
    valid('six-digits-card1', '123456', card1),
    valid('six-digits-card2', '123456', card2),
    valid('printable-64-card1', printable, card1),
  ];
  const rejectedCases = [
    rejected('five-chars', '12345', 'length'),
    rejected('sixty-five-chars', 'a'.repeat(65), 'length'),
    rejected('non-ascii', '12345é', 'character'),
    rejected('control-tab', '12345\t6', 'character'),
    rejected('del', '123456\x7f', 'character'),
  ];
  return {
    params: { saltLabel: bytesToHex(LABEL), m: M, t: T, p: P, T: TAG, version: 0x13 },
    valid: validCases,
    rejected: rejectedCases,
  };
}

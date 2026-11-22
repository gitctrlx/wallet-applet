// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// verify.ts: the standalone noble-only verifier for signature entries an implementation under
// test emits (spec/protocol.md §18). Input file shape:
//   {
//     "ecdsa":   [ { "publicKey"(33B compressed hex), "digest"(32B), "signature"(64B r‖s) } ],
//     "bip340":  [ { "outputKey"(32B), "message"(hex, any length), "signature"(64B) } ],
//     "ed25519": [ { "publicKey"(32B), "messageSeed"(32B), "messageLength", "signature"(64B) } ]
//   }
// The ed25519 message is SHA-512(seed‖u32(0))‖SHA-512(seed‖u32(1))‖… truncated to messageLength,
// u32 big-endian — the §12.3 expansion the applet and host agree on. ECDSA verifies with
// lowS:false + prehash:false so either malleability twin passes (§1/§12.1). Success prints
// "ecdsa N ok, bip340 N ok, ed25519 N ok"; any failing entry is printed and the exit code is 1.
import { readFileSync } from 'node:fs';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes } from '@noble/hashes/utils.js';

interface EcdsaEntry { publicKey: string; digest: string; signature: string }
interface Bip340Entry { outputKey: string; message: string; signature: string }
interface Ed25519Entry {
  publicKey: string;
  messageSeed: string;
  messageLength: number;
  signature: string;
}
interface VerifyDoc {
  ecdsa?: EcdsaEntry[];
  bip340?: Bip340Entry[];
  ed25519?: Ed25519Entry[];
}

/** The §12.3 message expansion: SHA-512(seed‖u32be(i)) blocks, truncated to length. */
const expandMessage = (seed: Uint8Array, length: number): Uint8Array => {
  const blocks: Uint8Array[] = [];
  for (let i = 0, have = 0; have < length; i++, have += 64) {
    const ctr = new Uint8Array(4);
    ctr[0] = (i >>> 24) & 0xff;
    ctr[1] = (i >>> 16) & 0xff;
    ctr[2] = (i >>> 8) & 0xff;
    ctr[3] = i & 0xff;
    blocks.push(sha512(concatBytes(seed, ctr)));
  }
  return concatBytes(...blocks).subarray(0, length);
};

const fail = (kind: string, index: number, entry: unknown, why: string) => {
  console.error(`${kind}[${index}] FAIL: ${why}`, JSON.stringify(entry));
  process.exitCode = 1;
};

const verifyEcdsa = (e: EcdsaEntry, i: number) => {
  try {
    const pub = secp256k1.Point.fromBytes(hexToBytes(e.publicKey)).toBytes(false);
    if (!secp256k1.verify(hexToBytes(e.signature), hexToBytes(e.digest), pub,
        { lowS: false, prehash: false })) {
      fail('ecdsa', i, e, 'signature does not verify');
    }
  } catch (err) {
    fail('ecdsa', i, e, `verify threw: ${(err as Error).message}`);
  }
};

const verifyBip340 = (e: Bip340Entry, i: number) => {
  try {
    if (!schnorr.verify(hexToBytes(e.signature), hexToBytes(e.message),
        hexToBytes(e.outputKey))) {
      fail('bip340', i, e, 'signature does not verify');
    }
  } catch (err) {
    fail('bip340', i, e, `verify threw: ${(err as Error).message}`);
  }
};

const verifyEd25519 = (e: Ed25519Entry, i: number) => {
  try {
    const message = expandMessage(hexToBytes(e.messageSeed), e.messageLength);
    if (!ed25519.verify(hexToBytes(e.signature), message, hexToBytes(e.publicKey))) {
      fail('ed25519', i, e, 'signature does not verify');
    }
  } catch (err) {
    fail('ed25519', i, e, `verify threw: ${(err as Error).message}`);
  }
};

const doc = JSON.parse(readFileSync(process.argv[2], 'utf8')) as VerifyDoc;
const ecdsa = doc.ecdsa ?? [];
const bip340 = doc.bip340 ?? [];
const ed = doc.ed25519 ?? [];
ecdsa.forEach(verifyEcdsa);
bip340.forEach(verifyBip340);
ed.forEach(verifyEd25519);
if (!process.exitCode) {
  console.log(`ecdsa ${ecdsa.length} ok, bip340 ${bip340.length} ok, ed25519 ${ed.length} ok`);
}

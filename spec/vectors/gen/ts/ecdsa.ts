// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// ecdsa.json: secp256k1 ECDSA signing vectors of spec/protocol.md §12.1 over the secp256k1
// templates of derivation.json. Signatures are RFC 6979 deterministic (no low-s normalisation);
// each case also carries the low-s and high-s variants with the SEC 1 §4.1.6 recovery id of every
// variant, recovered independently with noble's Signature.recoverPublicKey. The invalid entries
// are asserted to fail §1 verification (r, s outside [1, n−1], wrong digest, wrong key).
// Mirrors gen/java/.../EcdsaDoc.java.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';
import {
  N,
  bytesToHex,
  compress,
  det,
  publicKey,
  scalarBytes,
  sign,
  verify,
} from './lib.ts';
import { TEMPLATE_SEED, bip32Derive, wire } from './derivation.ts';

const TEMPLATES: [string, string][] = [
  ['evm', "m/44'/60'/0'/0/0"],
  ['tron', "m/44'/195'/0'/0/0"],
  ['btc-bip84-account', "m/84'/0'/0'"],
  ['btc-bip84', "m/84'/0'/0'/0/0"],
  ['depth-10', "m/0/1'/2/3'/4/5'/6/7'/8/9'"],
];

/** r ‖ min(s, n−s) or r ‖ max(s, n−s) of the r ‖ s signature. */
const flipS = (rs: Uint8Array, high: boolean): Uint8Array => {
  const s = bytesToNumberBE(rs.subarray(32, 64));
  const complement = N - s;
  const v = (s >= complement) === high ? s : complement;
  const out = rs.slice();
  out.set(scalarBytes(v), 32);
  return out;
};

/**
 * The SEC 1 §4.1.6 recovery id (0–3) of r ‖ s for publicKey65: candidate R points are
 * x = r + (i ≫ 1)·n with y parity i & 1; the key is r⁻¹·(s·R − e·G).
 */
const recoveryId = (publicKey65: Uint8Array, digest: Uint8Array, rs: Uint8Array): number => {
  const want = secp256k1.Point.fromBytes(publicKey65);
  const sig = secp256k1.Signature.fromBytes(rs, 'compact');
  for (let i = 0; i < 4; i++) {
    try {
      const candidate = sig.addRecoveryBit(i).recoverPublicKey(digest);
      if (candidate.equals(want)) return i;
    } catch {
      // r + jn outside the field: not a candidate
    }
  }
  throw new Error(`no recovery id for ${bytesToHex(rs)}`);
};

const invalid = (
  name: string,
  publicKey33: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array,
  reason: string,
): object => {
  const pub65 = secp256k1.Point.fromBytes(publicKey33).toBytes(false);
  if (verify(pub65, digest, signature)) throw new Error(`invalid case verifies: ${name}`);
  return {
    name,
    publicKey: bytesToHex(publicKey33),
    digest: bytesToHex(digest),
    signature: bytesToHex(signature),
    reason,
  };
};

const withComponent = (rs: Uint8Array, half: number, component: Uint8Array): Uint8Array => {
  const out = rs.slice();
  out.set(component, 32 * half);
  return out;
};

export function ecdsaDoc(): unknown {
  const keys33: Uint8Array[] = [];
  const digests: Uint8Array[] = [];
  const signatures: Uint8Array[] = [];
  const cases = TEMPLATES.map(([name, path]) => {
    const node = bip32Derive(TEMPLATE_SEED, path);
    const d = bytesToNumberBE(node.privateKey);
    const pub65 = publicKey(d);
    const pub33 = compress(pub65);
    const digest = det(`ecdsa/${name}/digest`);
    const sig = sign(d, digest);
    const lowS = flipS(sig, false);
    const highS = flipS(sig, true);
    for (const [variant, s] of [
      ['signature', sig],
      ['lowS', lowS],
      ['highS', highS],
    ] as const) {
      if (!verify(pub65, digest, s)) throw new Error(`${name} ${variant} does not verify`);
    }
    keys33.push(pub33);
    digests.push(digest);
    signatures.push(lowS);
    return {
      name,
      path,
      wire: bytesToHex(wire(path)),
      privateKey: bytesToHex(node.privateKey),
      publicKey: bytesToHex(pub33),
      publicKeyUncompressed: bytesToHex(pub65),
      digest: bytesToHex(digest),
      signature: bytesToHex(sig),
      recoveryId: recoveryId(pub65, digest, sig),
      lowS: bytesToHex(lowS),
      lowSRecoveryId: recoveryId(pub65, digest, lowS),
      highS: bytesToHex(highS),
      highSRecoveryId: recoveryId(pub65, digest, highS),
    };
  });
  const evmKey = keys33[0];
  const evmDigest = digests[0];
  const evmSig = signatures[0];
  const wrongDigest = evmDigest.slice();
  wrongDigest[31] ^= 0x01;
  const invalidCases = [
    invalid('r-zero', evmKey, evmDigest, withComponent(evmSig, 0, new Uint8Array(32)),
        'r is outside [1, n-1]'),
    invalid('s-zero', evmKey, evmDigest, withComponent(evmSig, 1, new Uint8Array(32)),
        's is outside [1, n-1]'),
    invalid('r-is-n', evmKey, evmDigest, withComponent(evmSig, 0, scalarBytes(N)),
        'r is outside [1, n-1]'),
    invalid('s-is-n', evmKey, evmDigest, withComponent(evmSig, 1, scalarBytes(N)),
        's is outside [1, n-1]'),
    invalid('wrong-digest', evmKey, wrongDigest, evmSig,
        'the signature was made over a different digest'),
    invalid('wrong-key', keys33[1], evmDigest, evmSig,
        'the signature was made under a different key'),
  ];
  return { cases, invalid: invalidCases };
}

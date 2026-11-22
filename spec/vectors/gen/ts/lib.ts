// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// Shared primitives mirroring host/src/main/java/org/qntx/card/host/Crypto.java and
// gen/java/org/qntx/card/vectors/{Vec,Cards}.java byte for byte (noble oracle).
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { cbc, cmac, ecb } from '@noble/ciphers/aes.js';

export { bytesToHex, concatBytes, hexToBytes, sha256, sha512, utf8ToBytes };

export const N: bigint = secp256k1.Point.CURVE().n;

/** det(name) = SHA-256(ASCII("qntx-card/vectors/" + name)). */
export const det = (name: string): Uint8Array => sha256(utf8ToBytes(`qntx-card/vectors/${name}`));
/** First len bytes of det(name) ‖ det(name + "/1") ‖ det(name + "/2") ‖ … */
export const detLen = (name: string, len: number): Uint8Array => {
  const out = new Uint8Array(len);
  for (let i = 0, done = 0; done < len; i++) {
    const block = i === 0 ? det(name) : det(`${name}/${i}`);
    const take = Math.min(32, len - done);
    out.set(block.subarray(0, take), done);
    done += take;
  }
  return out;
};

/** det(name) asserted in [1, n−1] as required for private scalars. */
export const detScalar = (name: string): bigint => {
  const d = bytesToNumberBE(det(name));
  if (d <= 0n || d >= N) throw new Error(`det scalar out of range: ${name}`);
  return d;
};

export const scalarBytes = (v: bigint): Uint8Array => numberToBytesBE(v, 32);

export const hmacSha512 = (key: Uint8Array, ...parts: Uint8Array[]): Uint8Array =>
  hmac(sha512, key, concatBytes(...parts));

export const u16 = (v: number): Uint8Array => new Uint8Array([v >>> 8, v & 0xff]);
const u32 = (v: number): Uint8Array =>
  new Uint8Array([v >>> 24, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);

export const aesBlock = (key: Uint8Array, block: Uint8Array): Uint8Array =>
  ecb(key, { disablePadding: true }).encrypt(block);
export const aesCbc = (key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array =>
  cbc(key, iv, { disablePadding: true }).encrypt(data);
export const cmacOf = (key: Uint8Array, ...parts: Uint8Array[]): Uint8Array =>
  cmac(concatBytes(...parts), key);

/** One-step KDF of NIST SP 800-56C Rev. 2 §4.1 option 1; len <= 64. */
export const kdf = (z: Uint8Array, label: Uint8Array, ctx: Uint8Array, len: number): Uint8Array => {
  const out = new Uint8Array(len);
  for (let i = 1, done = 0; done < len; i++) {
    const block = sha256(concatBytes(u32(i), z, label, ctx));
    const take = Math.min(32, len - done);
    out.set(block.subarray(0, take), done);
    done += take;
  }
  return out;
};

/** Counter-mode KDF of NIST SP 800-108r1 §4.1 with PRF = CMAC, r = 8, 256-bit output. */
export const kdf108 = (key: Uint8Array, label: Uint8Array, ctx: Uint8Array): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 1; i <= 2; i++) {
    const block = cmacOf(key, new Uint8Array([i]), label, new Uint8Array(1), ctx, new Uint8Array([1, 0]));
    out.set(block, (i - 1) * 16);
  }
  return out;
};

/** ISO/IEC 9797-1 padding method 2: X ‖ 0x80 ‖ 0^k to a multiple of 16. */
export const m2pad = (plain: Uint8Array): Uint8Array => {
  const out = new Uint8Array((Math.floor(plain.length / 16) + 1) * 16);
  out.set(plain);
  out[plain.length] = 0x80;
  return out;
};

/** scalar · G uncompressed (65 bytes). */
export const publicKey = (d: bigint): Uint8Array => secp256k1.getPublicKey(scalarBytes(d), false);
/** SEC 1 §2.3.3 compression of a point (33 bytes). */
export const compress = (point65: Uint8Array): Uint8Array =>
  secp256k1.Point.fromBytes(point65).toBytes(true);
/** scalar · point as a 65-byte uncompressed encoding. */
export const multiply = (scalar: bigint, point65: Uint8Array): Uint8Array =>
  secp256k1.Point.fromBytes(point65).multiply(scalar).toBytes(false);

/**
 * ECDSA over the 32-byte hash with RFC 6979 nonces (SHA-256) and no low-s normalisation;
 * wire form r(32) ‖ s(32).
 */
export const sign = (d: bigint, hash32: Uint8Array): Uint8Array =>
  secp256k1.sign(hash32, scalarBytes(d), { lowS: false, prehash: false });

/** ECDSA verify of r ‖ s; false on malformed input or out-of-range scalars. */
export const verify = (publicKey65: Uint8Array, hash32: Uint8Array, rs: Uint8Array): boolean => {
  if (rs.length !== 64) return false;
  const r = bytesToNumberBE(rs.subarray(0, 32));
  const s = bytesToNumberBE(rs.subarray(32, 64));
  if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
  try {
    return secp256k1.verify(rs, hash32, publicKey65, { lowS: false, prehash: false });
  } catch {
    return false;
  }
};

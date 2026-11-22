// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// Agreement self-test of the two generators; inputs mirror gen/java/.../Selftest.java.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

const scalar = (d: bigint): Uint8Array => hexToBytes(d.toString(16).padStart(64, '0'));

export function selftest(): unknown {
  const messages = [utf8ToBytes(''), utf8ToBytes('abc'), new Uint8Array(200)];
  const hashes = messages.map((m) => ({
    input: bytesToHex(m),
    sha256: bytesToHex(sha256(m)),
    sha512: bytesToHex(sha512(m)),
  }));
  const key = utf8ToBytes('Jefe');
  const data = utf8ToBytes('what do ya want for nothing?');
  const n = secp256k1.Point.CURVE().n;
  const scalars = [1n, 2n, n - 1n, bytesToNumberBE(sha256(utf8ToBytes('qntx-card/selftest')))];
  const points = scalars.map((d) => ({
    d: bytesToHex(scalar(d)),
    compressed: bytesToHex(secp256k1.getPublicKey(scalar(d), true)),
    uncompressed: bytesToHex(secp256k1.getPublicKey(scalar(d), false)),
  }));
  return {
    description: 'Agreement self-test of the vector generators; not a protocol vector file',
    count: hashes.length + 1 + points.length,
    hashes,
    hmacSha512: [{ key: bytesToHex(key), data: bytesToHex(data), mac: bytesToHex(hmac(sha512, key, data)) }],
    secp256k1: points,
    flags: [true, false],
  };
}

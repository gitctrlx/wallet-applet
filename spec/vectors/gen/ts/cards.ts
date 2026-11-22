// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// The deterministic CA and card-identity material shared by cert.json and session.json;
// mirrors gen/java/.../Cards.java and host/.../Certificates.java + Ids.java.
import {
  bytesToHex,
  compress,
  concatBytes,
  detScalar,
  publicKey,
  sha256,
  sign,
  utf8ToBytes,
  verify,
} from './lib.ts';

/** CA private scalar det("cert/" + name). */
export const caPrivate = (name: string): bigint => detScalar(`cert/${name}`);

/** First det(name + "/" + i), i = 0, 1, … whose public key has the requested y parity. */
export const identityPrivate = (name: string, wantOddY: boolean): bigint => {
  for (let i = 0; ; i++) {
    const d = detScalar(`${name}/${i}`);
    if (((publicKey(d)[64] & 1) === 1) === wantOddY) return d;
  }
};

export const CA1 = caPrivate('ca1');
export const CA2 = caPrivate('ca2');
export const CARD1 = identityPrivate('cert/card1', false);
export const CARD2 = identityPrivate('cert/card2', true);

export const LABEL_CERT = utf8ToBytes('qntx-card/v1/cert');

/** cert = A(33) ‖ r(32) ‖ s(32), issued for the compressed identity key a under caPrivate. */
export const issue = (ca: bigint, a: Uint8Array): Uint8Array =>
  concatBytes(a, sign(ca, sha256(concatBytes(LABEL_CERT, a))));

/** Verify(anchor, "qntx-card/v1/cert" ‖ A, r ‖ s) of spec/protocol.md §5.2. */
export const verifyCert = (anchor: Uint8Array, cert: Uint8Array): boolean =>
  anchor.length === 65 &&
  cert.length === 97 &&
  verify(anchor, sha256(concatBytes(LABEL_CERT, cert.subarray(0, 33))), cert.subarray(33, 97));

/** ID(A) = SHA-256(A)[0..16). */
export const cardId = (a: Uint8Array): Uint8Array => sha256(a).subarray(0, 16);

/** "XXXX-XXXX", uppercase hex of ID(A)[0..4). */
export const shortId = (a: Uint8Array): string => {
  const h = bytesToHex(cardId(a).subarray(0, 4)).toUpperCase();
  return `${h.slice(0, 4)}-${h.slice(4)}`;
};

/** Compressed public key of a private scalar. */
export const compressedKey = (d: bigint): Uint8Array => compress(publicKey(d));

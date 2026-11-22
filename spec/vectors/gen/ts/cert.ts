// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// cert.json: the test CAs and card identities of spec/protocol.md §5 — certificates
// A(33) ‖ r(32) ‖ s(32) issued under ca1 and the verify cases of §5.2, including a high-s
// variant, a wrong anchor, a wrong key, a corrupted s and out-of-range scalars.
// Mirrors gen/java/.../CertDoc.java.
import { bytesToNumberBE } from '@noble/curves/utils.js';
import { bytesToHex, N, publicKey, scalarBytes, utf8ToBytes } from './lib.ts';
import { cardId, CARD1, CARD2, CA1, CA2, compressedKey, issue, shortId, verifyCert } from './cards.ts';

const identity = (name: string, d: bigint) => {
  const pub = publicKey(d);
  const a = compressedKey(d);
  return {
    name,
    private: bytesToHex(scalarBytes(d)),
    public: bytesToHex(pub),
    compressed: bytesToHex(a),
    id: bytesToHex(cardId(a)),
    short: shortId(a),
  };
};

const withScalar = (cert: Uint8Array, off: number, v: bigint): Uint8Array => {
  const out = cert.slice();
  out.set(scalarBytes(v), off);
  return out;
};

export function certDoc(): unknown {
  const a1 = compressedKey(CARD1);
  const a2 = compressedKey(CARD2);
  const cert1 = issue(CA1, a1);
  const cert2 = issue(CA1, a2);
  const ca1Public = publicKey(CA1);
  const ca2Public = publicKey(CA2);

  const highS = cert1.slice();
  highS.set(scalarBytes(N - bytesToNumberBE(cert1.subarray(65, 97))), 65);
  const wrongKey = cert2.slice();
  wrongKey.set(cert1.subarray(33, 97), 33);
  const sFlip = cert1.slice();
  sFlip[96] ^= 1;

  const verify = (
    name: string,
    anchor: Uint8Array,
    cert: Uint8Array,
    expected: boolean,
  ): object => {
    const valid = verifyCert(anchor, cert);
    if (valid !== expected) throw new Error(`verify case disagrees with its oracle: ${name}`);
    return { name, anchor: bytesToHex(anchor), cert: bytesToHex(cert), valid };
  };

  return {
    label: bytesToHex(utf8ToBytes('qntx-card/v1/cert')),
    cas: [
      { name: 'ca1', private: bytesToHex(scalarBytes(CA1)), public: bytesToHex(ca1Public) },
      { name: 'ca2', private: bytesToHex(scalarBytes(CA2)), public: bytesToHex(ca2Public) },
    ],
    identities: [identity('card1', CARD1), identity('card2', CARD2)],
    verify: [
      verify('card1-under-ca1', ca1Public, cert1, true),
      verify('card2-under-ca1', ca1Public, cert2, true),
      verify('card1-high-s', ca1Public, highS, true),
      verify('wrong-anchor', ca2Public, cert1, false),
      verify('wrong-key', ca1Public, wrongKey, false),
      verify('s-flip', ca1Public, sFlip, false),
      verify('r-zero', ca1Public, withScalar(cert1, 33, 0n), false),
      verify('s-zero', ca1Public, withScalar(cert1, 65, 0n), false),
      verify('r-n', ca1Public, withScalar(cert1, 33, N), false),
      verify('s-n', ca1Public, withScalar(cert1, 65, N), false),
    ],
  };
}

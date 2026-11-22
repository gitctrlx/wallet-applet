// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// session.json: one fully deterministic OPEN exchange (spec/protocol.md §8.1–8.2) — fixed
// host and card ephemerals, the certified identity of cert.json's card1 under ca1, the
// transcript hash TH, the shared secret Z, the RFC 6979 session signature and the four record
// keys — plus the response variants Open.response MUST reject (§8.1). Mirrors SessionDoc.java.
import {
  bytesToHex,
  concatBytes,
  detScalar,
  kdf,
  multiply,
  publicKey,
  scalarBytes,
  sha256,
  sign,
  utf8ToBytes,
} from './lib.ts';
import { CA1, CA2, CARD1, CARD2, compressedKey, issue } from './cards.ts';

const LABEL = utf8ToBytes('qntx-card/v1/session');
const KDF_LABEL = utf8ToBytes('qntx-card/v1/kdf-session');

/** 80 10 00 00 41 ‖ hostEph ‖ 00 (§8.1). */
const requestApdu = (hostEph: Uint8Array): Uint8Array =>
  concatBytes(new Uint8Array([0x80, 0x10, 0, 0, 65]), hostEph, new Uint8Array(1));

/** cardEph(65) ‖ sig(64) ‖ cert(97) ‖ 9000 (§8.1). */
const openResponse = (cardEph: Uint8Array, sig: Uint8Array, cert: Uint8Array): Uint8Array =>
  concatBytes(cardEph, sig, cert, new Uint8Array([0x90, 0]));

export function sessionDoc(): unknown {
  const caPublic = publicKey(CA1);
  const a = compressedKey(CARD1);
  const cert = issue(CA1, a);

  const hostPrivate = detScalar('session/host');
  const cardPrivate = detScalar('session/card');
  const hostEph = publicKey(hostPrivate);
  const cardEph = publicKey(cardPrivate);

  const th = sha256(concatBytes(LABEL, hostEph, cardEph, a));
  const z = multiply(cardPrivate, hostEph).subarray(1, 33);
  const sig = sign(CARD1, th);
  const keys = kdf(z, KDF_LABEL, th, 64);

  // each rejected response MUST make Open.response throw (§8.1 host checks)
  const a2 = compressedKey(CARD2);
  const cert2 = issue(CA1, a2);
  const certUnderCa2 = issue(CA2, a);
  const flippedEph = cardEph.slice();
  flippedEph[33] ^= 1;
  const rejected = [
    { name: 'other-certified-key', response: openResponse(cardEph, sign(CARD2, th), cert) },
    {
      name: 'other-cert-signature-over-this-A',
      response: openResponse(cardEph, sign(CARD2, th), cert2),
    },
    { name: 'cert-under-other-ca', response: openResponse(cardEph, sig, certUnderCa2) },
    { name: 'flipped-cardEph', response: openResponse(flippedEph, sig, cert) },
  ].map((r) => ({ name: r.name, response: bytesToHex(r.response) }));

  return {
    label: bytesToHex(LABEL),
    kdfLabel: bytesToHex(KDF_LABEL),
    ca: bytesToHex(caPublic),
    identity: { private: bytesToHex(scalarBytes(CARD1)), compressed: bytesToHex(a) },
    cert: bytesToHex(cert),
    hostPrivate: bytesToHex(scalarBytes(hostPrivate)),
    hostEph: bytesToHex(hostEph),
    cardPrivate: bytesToHex(scalarBytes(cardPrivate)),
    cardEph: bytesToHex(cardEph),
    th: bytesToHex(th),
    z: bytesToHex(z),
    sig: bytesToHex(sig),
    kce: bytesToHex(keys.subarray(0, 16)),
    kcm: bytesToHex(keys.subarray(16, 32)),
    kre: bytesToHex(keys.subarray(32, 48)),
    krm: bytesToHex(keys.subarray(48, 64)),
    request: bytesToHex(requestApdu(hostEph)),
    response: bytesToHex(openResponse(cardEph, sig, cert)),
    rejected,
  };
}

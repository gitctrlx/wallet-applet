// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// wrap.json: seed wrapping of spec/protocol.md §7.2 and §10.1 —
// K_enc ‖ K_mac = KDF108(wrapKey, "qntx-card/v1/wrap", accessHash), ct = CBC(K_enc, 0¹⁶, seed),
// tag = CMAC(K_mac, ct) and the fingerprint SHA-256("qntx-card/v1/fingerprint" ‖ seed).
// Mirrors gen/java/.../WrapDoc.java.
import { aesCbc, bytesToHex, cmacOf, concatBytes, det, detLen, kdf108, sha256, utf8ToBytes } from './lib.ts';
import { TEMPLATE_SEED } from './derivation.ts';

const WRAP_LABEL = utf8ToBytes('qntx-card/v1/wrap');
const FP_LABEL = utf8ToBytes('qntx-card/v1/fingerprint');
const ZERO_IV = new Uint8Array(16);

const wrap = (name: string, wrapKey: Uint8Array, accessHash: Uint8Array, seed: Uint8Array): object => {
  const keys = kdf108(wrapKey, WRAP_LABEL, accessHash);
  const kEnc = keys.subarray(0, 16);
  const kMac = keys.subarray(16, 32);
  const ct = aesCbc(kEnc, ZERO_IV, seed);
  return {
    name,
    wrapKey: bytesToHex(wrapKey),
    accessHash: bytesToHex(accessHash),
    seed: bytesToHex(seed),
    kEnc: bytesToHex(kEnc),
    kMac: bytesToHex(kMac),
    ct: bytesToHex(ct),
    tag: bytesToHex(cmacOf(kMac, ct)),
    fp: bytesToHex(sha256(concatBytes(FP_LABEL, seed))),
  };
};

export function wrapDoc(): unknown {
  return {
    wrapLabel: bytesToHex(WRAP_LABEL),
    fingerprintLabel: bytesToHex(FP_LABEL),
    cases: [
      wrap('wrap-1', detLen('wrap/1/wrapKey', 16), det('wrap/1/accessHash'), detLen('wrap/1/seed', 64)),
      wrap('wrap-2', detLen('wrap/2/wrapKey', 16), det('wrap/2/accessHash'), detLen('wrap/2/seed', 64)),
      wrap('wrap-3', detLen('wrap/3/wrapKey', 16), det('wrap/3/accessHash'), detLen('wrap/3/seed', 64)),
      wrap(
        'wrap-template-seed',
        detLen('wrap/template/wrapKey', 16),
        det('wrap/template/accessHash'),
        TEMPLATE_SEED,
      ),
    ],
  };
}

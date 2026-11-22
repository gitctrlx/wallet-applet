// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// kdf.json: the NIST SP 800-38B App. D.1 AES-CMAC examples (an independent oracle asserted
// against the published tags), the one-step KDF of SP 800-56C Rev. 2 §4.1 option 1 and the
// counter-mode KDF108 of SP 800-108r1 §4.1. Mirrors gen/java .../KdfDoc.java.
import { bytesToHex, det, detLen, hexToBytes, kdf, kdf108, cmacOf, utf8ToBytes } from './lib.ts';

const CMAC_KEY = '2b7e151628aed2a6abf7158809cf4f3c';
const CMAC_PARTS = [
  '6bc1bee22e409f96e93d7e117393172a',
  'ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411',
  'e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
];
const CMAC_TAGS = [
  'bb1d6929e95937287fa37d129b756746',
  '070a16b46b4d4144f79bdd9dd04a287c',
  'dfa66747de9ae63030ca32611497c827',
  '51f0bebf7e3b9d92fc49741779363cfe',
];

const SESSION_LABEL = utf8ToBytes('qntx-card/v1/kdf-session');
const TRANSFER_LABEL = utf8ToBytes('qntx-card/v1/kdf-transfer');
const WRAP_LABEL = utf8ToBytes('qntx-card/v1/wrap');

export function kdfDoc(): unknown {
  const key = hexToBytes(CMAC_KEY);
  const cmac = CMAC_TAGS.map((tag, i) => {
    const message = hexToBytes(CMAC_PARTS.slice(0, i).join(''));
    if (bytesToHex(cmacOf(key, message)) !== tag) {
      throw new Error(`CMAC mismatch, example ${i + 1}`);
    }
    return { key: CMAC_KEY, message: bytesToHex(message), tag };
  });

  const z = det('kdf/z');
  const ctx = det('kdf/ctx');
  const oneStep = [
    { z, label: SESSION_LABEL, ctx, len: 64 },
    { z: det('kdf/z-transfer'), label: TRANSFER_LABEL, ctx, len: 32 },
    { z, label: SESSION_LABEL, ctx, len: 33 },
    { z, label: SESSION_LABEL, ctx: new Uint8Array(0), len: 16 },
  ].map((c) => ({
    z: bytesToHex(c.z),
    label: bytesToHex(c.label),
    ctx: bytesToHex(c.ctx),
    len: c.len,
    out: bytesToHex(kdf(c.z, c.label, c.ctx, c.len)),
  }));

  const wrap = [0, 1].map((i) => {
    const key108 = detLen(`kdf108/key/${i}`, 16);
    return {
      key: bytesToHex(key108),
      label: bytesToHex(WRAP_LABEL),
      ctx: bytesToHex(ctx),
      out: bytesToHex(kdf108(key108, WRAP_LABEL, ctx)),
    };
  });

  return { cmac, kdf: oneStep, kdf108: wrap };
}

// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0

// record.json: command and response records of spec/protocol.md §8.3–8.4 under fixed keys —
// valid records (a full 16-byte padding block, the largest data, the shortest plaintext,
// counter 0xFFFF) and the rejected records of §8.3 steps 2–5 and the host-side checks of §8.4.
// Mirrors gen/java/.../RecordDoc.java.
import { aesBlock, aesCbc, bytesToHex, cmacOf, concatBytes, detLen, hexToBytes, m2pad, u16 } from './lib.ts';

const KCE = detLen('record/kce', 16);
const KCM = detLen('record/kcm', 16);
const KRE = detLen('record/kre', 16);
const KRM = detLen('record/krm', 16);

/** first ‖ 0^13 ‖ u16(ctr), the pre-encryption IV block (§8.3–8.4). */
const ivSeed = (first: number, ctr: number): Uint8Array =>
  concatBytes(new Uint8Array([first]), new Uint8Array(13), u16(ctr));

const tag = (key: Uint8Array, ctr: number, ct: Uint8Array): Uint8Array =>
  cmacOf(key, u16(ctr), ct).subarray(0, 8);

/** 80 12 00 00 Lc ‖ ct ‖ tag ‖ 00 with tag over u16(ctr) ‖ ct. */
const commandApdu = (ctr: number, ct: Uint8Array): Uint8Array =>
  concatBytes(
    new Uint8Array([0x80, 0x12, 0, 0, ct.length + 8]),
    ct,
    tag(KCM, ctr, ct),
    new Uint8Array(1),
  );

/** ct ‖ tag ‖ 90 00 with tag over u16(ctr) ‖ ct (§8.4). */
const responseRapdu = (ctr: number, ct: Uint8Array): Uint8Array =>
  concatBytes(ct, tag(KRM, ctr, ct), new Uint8Array([0x90, 0]));

const command = (
  name: string,
  ctr: number,
  ins: string,
  p1: string,
  p2: string,
  data: Uint8Array,
) => {
  const plain = concatBytes(hexToBytes(ins), hexToBytes(p1), hexToBytes(p2), data);
  const iv = aesBlock(KCE, ivSeed(0x01, ctr));
  return {
    name,
    ctr,
    ins,
    p1,
    p2,
    data: bytesToHex(data),
    iv: bytesToHex(iv),
    apdu: bytesToHex(commandApdu(ctr, aesCbc(KCE, iv, m2pad(plain)))),
  };
};

const response = (name: string, ctr: number, data: Uint8Array, sw: Uint8Array) => {
  const iv = aesBlock(KRE, ivSeed(0x02, ctr));
  const ct = aesCbc(KRE, iv, m2pad(concatBytes(data, sw)));
  return {
    name,
    ctr,
    data: bytesToHex(data),
    sw: bytesToHex(sw),
    iv: bytesToHex(iv),
    rapdu: bytesToHex(responseRapdu(ctr, ct)),
  };
};

const reject = (name: string, ctr: number, apdu: Uint8Array) => ({
  name,
  ctr,
  apdu: bytesToHex(apdu),
});
const rejectRapdu = (name: string, ctr: number, rapdu: Uint8Array) => ({
  name,
  ctr,
  rapdu: bytesToHex(rapdu),
});

export function recordDoc(): unknown {
  const commands = [
    command('status-ctr0', 0, '20', '00', '00', new Uint8Array(0)),
    command('data13-ctr1', 1, '99', '00', '00', detLen('record/data13', 13)),
    command('data236-ctr1234', 0x1234, '99', '00', '00', detLen('record/data236', 236)),
    command('two-byte-plain-ctr2-inner-6700', 2, '20', '00', '', new Uint8Array(0)),
    command('status-ctr-ffff', 0xffff, '20', '00', '00', new Uint8Array(0)),
  ];
  const responses = [
    response('status-blank', 0, hexToBytes('0100'), hexToBytes('9000')),
    response('empty-6a80', 3, new Uint8Array(0), hexToBytes('6a80')),
    response('data14-ctr4', 4, detLen('record/resp14', 14), hexToBytes('9000')),
    response('data237-ctr5', 5, detLen('record/resp237', 237), hexToBytes('9000')),
  ];

  // §8.3 steps 2–5: each of these earns outer 6982 and a teardown on the card
  const status0 = hexToBytes(commands[0].apdu);
  const tagFlipped = status0.slice();
  tagFlipped[5 + 16] ^= 1;
  // Lc = 23: 15 ct bytes + 8 tag — (Lc − 8) is not a multiple of 16 (§8.3 step 3)
  const truncated = new Uint8Array(5 + 23 + 1);
  truncated.set(status0.subarray(0, 5 + 15));
  truncated.set(status0.subarray(5 + 16, 5 + 16 + 8 + 1), 5 + 15);
  truncated[4] = 23;
  const lc16 = status0.slice(0, 5 + 16 + 1);
  lc16[4] = 16;
  const p1_01 = status0.slice();
  p1_01[2] = 1;
  const noPad = new Uint8Array(16); // a whole zero block: no 0x80 anywhere
  const longPad = new Uint8Array(32); // "20 00 00" ‖ 0x80 ‖ 0^28: 28 zeros after the 0x80
  longPad[0] = 0x20;
  longPad[3] = 0x80;
  const rejectedCommands = [
    reject('tag-flipped', 0, tagFlipped),
    reject('replay-ctr1-at-ctr0', 0, hexToBytes(commands[1].apdu)),
    reject('no-m2-padding', 0, commandApdu(0, aesCbc(KCE, aesBlock(KCE, ivSeed(0x01, 0)), noPad))),
    reject('overlong-padding', 0, commandApdu(0, aesCbc(KCE, aesBlock(KCE, ivSeed(0x01, 0)), longPad))),
    reject('truncated-ct', 0, truncated),
    reject('lc-16', 0, lc16),
    reject('p1-01', 0, p1_01),
  ];

  // host-side abandon cases of §8.4
  const rsp0 = hexToBytes(responses[0].rapdu);
  const rspTagFlipped = rsp0.slice();
  rspTagFlipped[16] ^= 1;
  const rspTruncated = rsp0.slice(0, rsp0.length - 1);
  const rejectedResponses = [
    rejectRapdu('tag-flipped', 0, rspTagFlipped),
    rejectRapdu(
      'bad-padding',
      1,
      responseRapdu(1, aesCbc(KRE, aesBlock(KRE, ivSeed(0x02, 1)), new Uint8Array(16))),
    ),
    rejectRapdu('truncated', 0, rspTruncated),
    rejectRapdu('wrong-counter', 1, rsp0),
  ];

  return {
    keys: {
      kce: bytesToHex(KCE),
      kcm: bytesToHex(KCM),
      kre: bytesToHex(KRE),
      krm: bytesToHex(KRM),
    },
    commands,
    responses,
    rejectedCommands,
    rejectedResponses,
  };
}

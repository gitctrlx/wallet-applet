// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.util.Arrays;
import java.util.List;

/**
 * {@code record.json}: command and response records of spec/protocol.md §8.3–8.4 under fixed keys —
 * valid records (a full 16-byte padding block, the largest data, the shortest plaintext, counter
 * {@code 0xFFFF}) and the rejected records of §8.3 steps 2–5 and the host-side checks of §8.4.
 */
final class RecordDoc {
    private static final byte[] KCE = Vec.det("record/kce", 16);
    private static final byte[] KCM = Vec.det("record/kcm", 16);
    private static final byte[] KRE = Vec.det("record/kre", 16);
    private static final byte[] KRM = Vec.det("record/krm", 16);

    private RecordDoc() {}

    static Object document() {
        List<Object> commands =
                List.of(
                        command("status-ctr0", 0, "20", "00", "00", new byte[0]),
                        command("data13-ctr1", 1, "99", "00", "00", Vec.det("record/data13", 13)),
                        command(
                                "data236-ctr1234",
                                0x1234,
                                "99",
                                "00",
                                "00",
                                Vec.det("record/data236", 236)),
                        command("two-byte-plain-ctr2-inner-6700", 2, "20", "00", "", new byte[0]),
                        command("status-ctr-ffff", 0xFFFF, "20", "00", "00", new byte[0]));
        List<Object> responses =
                List.of(
                        response("status-blank", 0, Vec.unhex("0100"), Vec.unhex("9000")),
                        response("empty-6a80", 3, new byte[0], Vec.unhex("6a80")),
                        response("data14-ctr4", 4, Vec.det("record/resp14", 14), Vec.unhex("9000")),
                        response(
                                "data237-ctr5",
                                5,
                                Vec.det("record/resp237", 237),
                                Vec.unhex("9000")));

        // §8.3 steps 2–5: each of these earns outer 6982 and a teardown on the card
        byte[] status0 = apduOf(commands.get(0));
        byte[] tagFlipped = status0.clone();
        tagFlipped[5 + 16] ^= 1;
        // Lc = 23: 15 ct bytes + 8 tag — (Lc − 8) is not a multiple of 16 (§8.3 step 3)
        byte[] truncated = new byte[5 + 23 + 1];
        System.arraycopy(status0, 0, truncated, 0, 5 + 15);
        System.arraycopy(status0, 5 + 16, truncated, 5 + 15, 8 + 1);
        truncated[4] = 23;
        byte[] lc16 = Arrays.copyOf(status0, 5 + 16 + 1);
        lc16[4] = 16;
        byte[] p1_01 = status0.clone();
        p1_01[2] = 1;
        byte[] noPad = new byte[16]; // a whole zero block: no 0x80 anywhere
        byte[] longPad = new byte[32]; // "20 00 00" ‖ 0x80 ‖ 0^28: 28 zeros after the 0x80
        longPad[0] = 0x20;
        longPad[3] = (byte) 0x80;
        List<Object> rejectedCommands =
                List.of(
                        reject("tag-flipped", 0, tagFlipped),
                        reject("replay-ctr1-at-ctr0", 0, apduOf(commands.get(1))),
                        reject("no-m2-padding", 0, commandApdu(0, ct(KCE, (byte) 0x01, 0, noPad))),
                        reject(
                                "overlong-padding",
                                0,
                                commandApdu(0, ct(KCE, (byte) 0x01, 0, longPad))),
                        reject("truncated-ct", 0, truncated),
                        reject("lc-16", 0, lc16),
                        reject("p1-01", 0, p1_01));

        // host-side abandon cases of §8.4
        byte[] rsp0 = rapduOf(responses.get(0));
        byte[] rspTagFlipped = rsp0.clone();
        rspTagFlipped[16] ^= 1;
        byte[] rspTruncated = Arrays.copyOf(rsp0, rsp0.length - 1);
        List<Object> rejectedResponses =
                List.of(
                        rejectRapdu("tag-flipped", 0, rspTagFlipped),
                        rejectRapdu(
                                "bad-padding",
                                1,
                                responseRapdu(1, ct(KRE, (byte) 0x02, 1, new byte[16]))),
                        rejectRapdu("truncated", 0, rspTruncated),
                        rejectRapdu("wrong-counter", 1, rsp0));

        return Vec.object(
                "keys",
                        Vec.object(
                                "kce", Vec.hex(KCE),
                                "kcm", Vec.hex(KCM),
                                "kre", Vec.hex(KRE),
                                "krm", Vec.hex(KRM)),
                "commands", commands,
                "responses", responses,
                "rejectedCommands", rejectedCommands,
                "rejectedResponses", rejectedResponses);
    }

    private static Object command(
            String name, int ctr, String ins, String p1, String p2, byte[] data) {
        byte[] plain = concat(Vec.unhex(ins), Vec.unhex(p1), Vec.unhex(p2), data);
        byte[] iv = Crypto.aesBlock(KCE, ivSeed((byte) 0x01, ctr));
        return Vec.object(
                "name", name,
                "ctr", ctr,
                "ins", ins,
                "p1", p1,
                "p2", p2,
                "data", Vec.hex(data),
                "iv", Vec.hex(iv),
                "apdu",
                        Vec.hex(
                                commandApdu(
                                        ctr, Crypto.aesCbc(KCE, iv, Crypto.m2pad(plain), true))));
    }

    private static Object response(String name, int ctr, byte[] data, byte[] sw) {
        byte[] iv = Crypto.aesBlock(KRE, ivSeed((byte) 0x02, ctr));
        byte[] ct = Crypto.aesCbc(KRE, iv, Crypto.m2pad(concat(data, sw)), true);
        return Vec.object(
                "name", name,
                "ctr", ctr,
                "data", Vec.hex(data),
                "sw", Vec.hex(sw),
                "iv", Vec.hex(iv),
                "rapdu", Vec.hex(responseRapdu(ctr, ct)));
    }

    /** {@code 80 12 00 00 Lc ‖ ct ‖ tag ‖ 00} with {@code tag} over {@code u16(ctr) ‖ ct}. */
    private static byte[] commandApdu(int ctr, byte[] ct) {
        byte[] tag = Arrays.copyOf(Crypto.cmac(KCM, Crypto.u16(ctr), ct), 8);
        byte[] apdu = new byte[5 + ct.length + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) (ct.length + 8);
        System.arraycopy(ct, 0, apdu, 5, ct.length);
        System.arraycopy(tag, 0, apdu, 5 + ct.length, 8);
        return apdu;
    }

    /** {@code ct ‖ tag ‖ 90 00} with {@code tag} over {@code u16(ctr) ‖ ct} (§8.4). */
    private static byte[] responseRapdu(int ctr, byte[] ct) {
        byte[] tag = Arrays.copyOf(Crypto.cmac(KRM, Crypto.u16(ctr), ct), 8);
        byte[] rapdu = new byte[ct.length + 8 + 2];
        System.arraycopy(ct, 0, rapdu, 0, ct.length);
        System.arraycopy(tag, 0, rapdu, ct.length, 8);
        rapdu[rapdu.length - 2] = (byte) 0x90;
        return rapdu;
    }

    private static byte[] ct(byte[] key, byte first, int ctr, byte[] blocks) {
        return Crypto.aesCbc(key, Crypto.aesBlock(key, ivSeed(first, ctr)), blocks, true);
    }

    /** {@code first ‖ 0¹³ ‖ u16(ctr)}, the pre-encryption IV block (§8.3–8.4). */
    private static byte[] ivSeed(byte first, int ctr) {
        byte[] seed = new byte[16];
        seed[0] = first;
        byte[] c = Crypto.u16(ctr);
        seed[14] = c[0];
        seed[15] = c[1];
        return seed;
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static byte[] apduOf(Object entry) {
        return Vec.unhex((String) ((java.util.Map<?, ?>) entry).get("apdu"));
    }

    private static byte[] rapduOf(Object entry) {
        return Vec.unhex((String) ((java.util.Map<?, ?>) entry).get("rapdu"));
    }

    private static Object reject(String name, int ctr, byte[] apdu) {
        return Vec.object("name", name, "ctr", ctr, "apdu", Vec.hex(apdu));
    }

    private static Object rejectRapdu(String name, int ctr, byte[] rapdu) {
        return Vec.object("name", name, "ctr", ctr, "rapdu", Vec.hex(rapdu));
    }
}

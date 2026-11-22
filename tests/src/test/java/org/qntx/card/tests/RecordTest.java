// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.qntx.card.Internals;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/** §8.3–§8.5 command records on the simulator: checking order, replay, teardown, fuzz. */
final class RecordTest {

    private static Card blankWith(Session[] out) throws Exception {
        Card card = Vecs.blankSelf();
        out[0] = Vecs.open(card);
        return card;
    }

    @Test
    void statusRecordsRoundTrip() throws Exception {
        Session[] s = new Session[1];
        Card card = blankWith(s);
        Response r = Vecs.roundtrip(card, s[0], 0x20, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(Vecs.unhex("0100"), r.data()); // BLANK, tries 0 (§9.3)
        assertEquals(0x9000, Vecs.roundtrip(card, s[0], 0x20, 0, 0, new byte[0]).sw());
        assertEquals(2, s[0].counter());
    }

    @Test
    void rejectedRecordsTearTheSessionDown() throws Exception {
        // each malformed record must answer 6982 and kill the session (§8.5)
        for (int variant = 0; variant < 5; variant++) {
            Session[] s = new Session[1];
            Card card = blankWith(s);
            byte[] apdu;
            switch (variant) {
                case 0 -> { // P1 != 0
                    apdu = s[0].wrap(0x20, 0, 0, new byte[0]);
                    apdu[2] = 0x01;
                }
                case 1 -> { // Lc < 24
                    apdu = new byte[21];
                    apdu[0] = (byte) 0x80;
                    apdu[1] = 0x12;
                    apdu[4] = 0x10;
                    Vecs.RND.nextBytes(Arrays.copyOfRange(apdu, 5, 21));
                }
                case 2 -> { // ct not a multiple of 16
                    apdu = new byte[28];
                    apdu[0] = (byte) 0x80;
                    apdu[1] = 0x12;
                    apdu[4] = 0x17;
                    Vecs.RND.nextBytes(Arrays.copyOfRange(apdu, 5, 28));
                }
                case 3 -> { // tag bit flipped
                    apdu = s[0].wrap(0x20, 0, 0, new byte[0]);
                    apdu[apdu.length - 2] ^= 1;
                }
                default -> { // replay: send a ctr-0 record twice
                    apdu = s[0].wrap(0x20, 0, 0, new byte[0]);
                    assertEquals(0x9000, Vecs.sw(card.transmit(apdu)));
                }
            }
            assertEquals(0x6982, Vecs.sw(card.transmit(apdu)), "variant " + variant);
            // the session is dead: even a well-formed record now gets 6985
            assertEquals(0x6985, Vecs.sw(card.transmit(apdu)), "after " + variant);
        }
        // P2 alone non-zero also gives 6982
        Session[] s2 = new Session[1];
        Card card2 = blankWith(s2);
        byte[] apdu = s2[0].wrap(0x20, 0, 0, new byte[0]);
        apdu[3] = 0x01;
        assertEquals(0x6982, Vecs.sw(card2.transmit(apdu)));
    }

    @Test
    void validTagButBadPaddingIs6982() throws Exception {
        // §8.3 step 5: a well-formed record whose plaintext is not M2 padding fails after
        // the tag check — needs the live session keys to encrypt the bad plaintext
        Session[] s = new Session[1];
        Card card = blankWith(s);
        byte[] kce = field(s[0], "kce");
        byte[] kcm = field(s[0], "kcm");
        byte[] seed = new byte[16];
        seed[0] = 0x01;
        byte[] iv = Crypto.aesBlock(kce, seed);
        // nonzero padding-free plaintext: decrypts to 0x41s with no 0x80 terminator, so
        // the in-place wipe of the decrypted span is observable in the APDU buffer
        byte[] junk = new byte[16];
        Arrays.fill(junk, (byte) 0x41);
        byte[] ct = Crypto.aesCbc(kce, iv, junk, true);
        byte[] tag = new byte[8];
        System.arraycopy(Crypto.cmac(kcm, Crypto.u16(0), ct), 0, tag, 0, 8);
        byte[] apdu = new byte[5 + ct.length + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) (ct.length + 8);
        System.arraycopy(ct, 0, apdu, 5, ct.length);
        System.arraycopy(tag, 0, apdu, 5 + ct.length, 8);
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        // §16.3 item 3: the decrypted span of the rejected record is wiped in place
        byte[] buf = card.apduBuffer();
        for (int i = 5; i < 5 + ct.length; i++) {
            assertEquals(0, buf[i], "decrypted span not wiped at " + i);
        }
        assertEquals(0x6985, Vecs.sw(card.transmit(apdu)));
    }

    @Test
    void responseTailLeavesNoInnerPlaintext() throws Exception {
        // §16.3 item 3: a 236-byte inner plaintext ends far past the 24-byte 6D00
        // response record; the gap that held decrypted plaintext must be zeroed
        Session[] s = new Session[1];
        Card card = blankWith(s);
        byte[] plain = new byte[236];
        plain[0] = 0x7F; // unknown inner INS -> 6D00
        byte[] apdu = record(s[0], plain);
        Response r = s[0].unwrap(card.transmit(apdu));
        assertEquals(0x6D00, r.sw());
        byte[] buf = card.apduBuffer();
        for (int i = 24; i < 5 + 240; i++) {
            assertEquals(0, buf[i], "plaintext residue at " + i);
        }
    }

    @Test
    void emptyInnerPlaintextIs6700() throws Exception {
        // M2 of the empty plaintext is 0x80 || 0^15 — unwrap yields plen 0 -> inner 6700
        Session[] s = new Session[1];
        Card card = blankWith(s);
        byte[] apdu = record(s[0], new byte[0]);
        Response r = s[0].unwrap(card.transmit(apdu));
        assertEquals(0x6700, r.sw());
    }

    @Test
    void misalignedCiphertextWithValidTagIs6982() throws Exception {
        // §8.3 step 3: Lc - 8 not a multiple of 16, with a valid tag over those bytes
        Session[] s = new Session[1];
        Card card = blankWith(s);
        byte[] kcm = field(s[0], "kcm");
        byte[] ct = new byte[31];
        Vecs.RND.nextBytes(ct);
        byte[] tag = new byte[8];
        System.arraycopy(Crypto.cmac(kcm, Crypto.u16(0), ct), 0, tag, 0, 8);
        byte[] apdu = new byte[5 + 31 + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) 39;
        System.arraycopy(ct, 0, apdu, 5, 31);
        System.arraycopy(tag, 0, apdu, 5 + 31, 8);
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertEquals(0x6985, Vecs.sw(card.transmit(apdu)));
    }

    @Test
    void alignedButTooShortRecordIs6982() throws Exception {
        // §8.3 step 3: the minimum record is 16 ciphertext bytes + 8 tag bytes —
        // an aligned 8-byte ciphertext with a valid tag is still rejected
        Session[] s = new Session[1];
        Card card = blankWith(s);
        byte[] kcm = field(s[0], "kcm");
        byte[] ct = new byte[8];
        Vecs.RND.nextBytes(ct);
        byte[] tag = new byte[8];
        System.arraycopy(Crypto.cmac(kcm, Crypto.u16(0), ct), 0, tag, 0, 8);
        byte[] apdu = new byte[5 + 8 + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) 16;
        System.arraycopy(ct, 0, apdu, 5, 8);
        System.arraycopy(tag, 0, apdu, 13, 8);
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertEquals(0x6985, Vecs.sw(card.transmit(apdu)));
    }

    private static byte[] record(Session s, byte[] plain) throws Exception {
        byte[] kce = field(s, "kce");
        byte[] kcm = field(s, "kcm");
        byte[] seed = new byte[16];
        seed[0] = 0x01;
        byte[] iv = Crypto.aesBlock(kce, seed);
        byte[] ct = Crypto.aesCbc(kce, iv, Crypto.m2pad(plain), true);
        byte[] tag = new byte[8];
        System.arraycopy(Crypto.cmac(kcm, Crypto.u16(0), ct), 0, tag, 0, 8);
        byte[] apdu = new byte[5 + ct.length + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) (ct.length + 8);
        System.arraycopy(ct, 0, apdu, 5, ct.length);
        System.arraycopy(tag, 0, apdu, 5 + ct.length, 8);
        return apdu;
    }

    @Test
    void counterExhaustionClosesBothSides() throws Exception {
        Session[] s = new Session[1];
        Card card = blankWith(s);
        // wind both counters to 0xFFFF: the card word via reflection, the host field likewise
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[4] = (byte) 0xFF;
        words[5] = (byte) 0xFF;
        Field ctr = Session.class.getDeclaredField("ctr");
        ctr.setAccessible(true);
        ctr.setInt(s[0], 0xFFFF);
        byte[] apdu = s[0].wrap(0x20, 0, 0, new byte[0]);
        byte[] rapdu = card.transmit(apdu);
        // the card answered the FFFF record then tore its own session down (§8.5)
        Response r = s[0].unwrap(rapdu);
        assertEquals(0x9000, r.sw());
        assertTrue(s[0].closed(), "host session must close after counter 0xFFFF");
        assertEquals(0x6985, Vecs.sw(card.transmit(apdu)));
    }

    @Test
    void shortInnerPlaintextIs6700() throws Exception {
        // §8.3 step 6: a two-byte inner plaintext answers 6700 inside the record
        Session[] s = new Session[1];
        Card card = blankWith(s);
        byte[] kce = field(s[0], "kce");
        byte[] kcm = field(s[0], "kcm");
        byte[] plain = {0x20, 0x00};
        byte[] seed = new byte[16];
        seed[0] = 0x01; // u16(0) at [14..16) stays zero
        byte[] iv = Crypto.aesBlock(kce, seed);
        byte[] ct = Crypto.aesCbc(kce, iv, Crypto.m2pad(plain), true);
        byte[] tag = new byte[8];
        System.arraycopy(Crypto.cmac(kcm, Crypto.u16(0), ct), 0, tag, 0, 8);
        byte[] apdu = new byte[5 + ct.length + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) (ct.length + 8);
        System.arraycopy(ct, 0, apdu, 5, ct.length);
        System.arraycopy(tag, 0, apdu, 5 + ct.length, 8);
        Response r = s[0].unwrap(card.transmit(apdu));
        assertEquals(0x6700, r.sw());
    }

    private static byte[] field(Object o, String name) {
        try {
            Field f = o.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return (byte[]) f.get(o);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void fuzzRandomRecordsFailClosed() throws Exception {
        Session[] s = new Session[1];
        Card card = blankWith(s);
        Vecs.RND.setSeed(20260317L);
        int torn = 0;
        for (int i = 0; i < 100; i++) {
            byte[] apdu = new byte[5 + Vecs.RND.nextInt(80) + 1];
            apdu[0] = (byte) 0x80;
            apdu[1] = 0x12;
            apdu[4] = (byte) (apdu.length - 6);
            Vecs.RND.nextBytes(Arrays.copyOfRange(apdu, 5, apdu.length - 1));
            int sw = Vecs.sw(card.transmit(apdu));
            assertTrue(sw == 0x6982 || sw == 0x6985, "unexpected SW " + Integer.toHexString(sw));
            if (sw == 0x6982) {
                torn++;
                break;
            }
        }
        assertTrue(torn > 0, "random garbage must fail the tag check");
        // after the tear every further record gets 6985 until a new OPEN
        assertEquals(0x6985, Vecs.sw(card.transmit(s[0].wrap(0x20, 0, 0, new byte[0]))));
    }
}

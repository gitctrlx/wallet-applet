// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;
import javacard.framework.Applet;
import javacard.security.AESKey;
import org.junit.jupiter.api.Test;
import org.qntx.card.Internals;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * §8.5/§16.2: every teardown path zeroes the session words, the four AES keys, both scratch arrays
 * and the transient EC scalar, and leaves no inner plaintext in the APDU buffer.
 */
final class TeardownTest {

    private static final String[] KEYS = {"kce", "kcm", "kre", "krm"};

    private static void assertDead(Card card) {
        Applet applet = card.applet(Spec.WALLET_AID);
        assertArrayEquals(new byte[8], Internals.words(applet), "session words not cleared");
        byte[] key = new byte[16];
        for (String name : KEYS) {
            AESKey k = Internals.sessionKey(applet, name);
            k.getKey(key, (short) 0);
            assertArrayEquals(new byte[16], key, name + " not wiped");
        }
        assertArrayEquals(new byte[130], Internals.pBytes(applet), "Mem.P not wiped");
        assertArrayEquals(new byte[256], Internals.wBytes(applet), "Mem.W not wiped");
        byte[] s = new byte[32];
        Internals.ephKey(applet).getS(s, (short) 0);
        assertArrayEquals(new byte[32], s, "ephemeral scalar not wiped");
    }

    @Test
    void deselectTearsDown() throws Exception {
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        card.transmit(Spec.SELECT); // re-SELECT deselects the applet
        assertDead(card);
        assertEquals(0x6985, Vecs.sw(card.transmit(new byte[] {(byte) 0x80, 0x12, 0, 0, 0x18})));
    }

    @Test
    void selectTearsAnOpenSessionDown() throws Exception {
        // the applet's own select() clears the same state the deselect path does
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        card.applet(Spec.WALLET_AID).select();
        assertDead(card);
    }

    @Test
    void pendingWordIsClearedByTeardown() throws Exception {
        // every session word holds a nonzero value before the tear, pending included
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[6] = 0x69;
        words[7] = 0x69;
        byte[] apdu = session.wrap(0x20, 0, 0, new byte[0]);
        apdu[apdu.length - 2] ^= 1; // bad tag
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertDead(card);
    }

    @Test
    void recordFailureTearsDown() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // advance ctr to 1 so every session word holds a nonzero value before the tear
        Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        byte[] apdu = session.wrap(0x20, 0, 0, new byte[0]);
        apdu[apdu.length - 2] ^= 1; // bad tag
        assertEquals(0x6982, Vecs.sw(card.transmit(apdu)));
        assertDead(card);
    }

    @Test
    void innerFaultTearsDown() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // corrupt the persistent fails word pair so STATUS faults with 6F00 inside the record
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[2] = 0x12;
        state[3] = 0x34;
        state[4] = 0x12;
        state[5] = 0x34; // f == complement instead of f == ~complement
        var r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x6F00, r.sw());
        assertDead(card);
        assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
    }

    @Test
    void outerFaultTearsAnOpenSessionDown() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // corrupt the life word: OPEN faults with 6F00 and process() tears the session
        byte[] state = Internals.stateArray(card.applet(Spec.WALLET_AID));
        state[0] = 0x12;
        state[1] = 0x34;
        assertEquals(0x6F00, Vecs.sw(card.transmit(Vecs.unhex("8010000000"))));
        assertDead(card);
        assertEquals(0x6985, Vecs.sw(card.transmit(session.wrap(0x20, 0, 0, new byte[0]))));
    }

    @Test
    void counterExhaustionTearsDown() throws Exception {
        // §8.5: the response carrying ctr = 0xFFFF tears the session down
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        byte[] words = Internals.words(card.applet(Spec.WALLET_AID));
        words[4] = (byte) 0xFF;
        words[5] = (byte) 0xFF;
        Field ctr = Session.class.getDeclaredField("ctr");
        ctr.setAccessible(true);
        ctr.setInt(session, 0xFFFF);
        byte[] rapdu = card.transmit(session.wrap(0x20, 0, 0, new byte[0]));
        assertEquals(0x9000, session.unwrap(rapdu).sw());
        assertDead(card);
    }

    @Test
    void openWipesTheEphemeralScalar() throws Exception {
        Card card = Vecs.blankSelf();
        Vecs.open(card);
        Applet applet = card.applet(Spec.WALLET_AID);
        byte[] s = new byte[32];
        Internals.ephKey(applet).getS(s, (short) 0);
        assertArrayEquals(new byte[32], s, "ephemeral scalar x must be wiped after OPEN");
        // and the shared scratch that held x, Z and the KDF output must be zero
        byte[] w = Internals.wBytes(applet);
        int zpt = Internals.sessionOffset("W_ZPT");
        int keys = Internals.sessionOffset("W_KEYS");
        int x = Internals.sessionOffset("W_X");
        for (int i = 0; i < 65; i++) {
            assertEquals(0, w[zpt + i], "W_ZPT not wiped");
        }
        for (int i = 0; i < 64; i++) {
            assertEquals(0, w[keys + i], "W_KEYS not wiped");
        }
        for (int i = 0; i < 32; i++) {
            assertEquals(0, w[x + i], "W_X not wiped");
        }
    }
}

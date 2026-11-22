// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;
import org.qntx.card.sim.TornException;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The nonce and tearing acceptance of architecture §14.5 G5: with the random generator fixed to a
 * constant the hedged nonce still never repeats (counter and card ID, §12.3), and tearing around
 * the T-EDCTR commit or the ECDSA verify-key write can never leave a half-advanced counter or a
 * half-updated key behind.
 *
 * <p>Counts: {@code qntx.nonce.count} signatures (default 1 000).
 */
final class NonceTest {

    private static final int COUNT = Integer.getInteger("qntx.nonce.count", 1_000);

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
        Rng.reset();
    }

    private javacard.framework.Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void verified() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    private void powerUp() throws Exception {
        card.powerCycle();
        card.transmit(Spec.SELECT);
        session = Vecs.open(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, p1, 0, data);
    }

    private long edCounter() {
        byte[] s = Internals.stateArray(applet());
        return ((s[State.OFF_EDCOUNTER] & 0xFFL) << 24)
                | ((s[State.OFF_EDCOUNTER + 1] & 0xFFL) << 16)
                | ((s[State.OFF_EDCOUNTER + 2] & 0xFFL) << 8)
                | (s[State.OFF_EDCOUNTER + 3] & 0xFFL);
    }

    /** One whole stream for {@code message}: begin, the stream in one finish chunk. */
    private Response[] sign(byte[] message) throws Exception {
        Response begin = inner(0x33, 0, Vecs.pathEdSolana());
        assertEquals(0x9000, begin.sw());
        byte[] stream =
                Ed25519.stream(
                        Wei25519Map.encode(begin.data()),
                        Wei25519Map.encode(Vecs.pkEdSolana()),
                        message);
        Response fin = inner(0x33, 2, stream);
        assertEquals(0x9000, fin.sw());
        return new Response[] {begin, fin};
    }

    @Test
    void aConstantGeneratorStillNeverRepeatsR() throws Exception {
        // §12.3's hedge: Zr fails fixed but r still varies with the committed counter and ID
        verified();
        byte[] constant = new byte[32];
        constant[31] = 1;
        Rng.fix(constant);
        byte[] message = new byte[32];
        Vecs.RND.nextBytes(message);
        byte[] encodedA = Wei25519Map.encode(Vecs.pkEdSolana());
        Set<String> seen = new HashSet<>();
        long before = edCounter();
        for (int i = 0; i < COUNT; i++) {
            Response[] rs = sign(message);
            String encR = java.util.HexFormat.of().formatHex(Wei25519Map.encode(rs[0].data()));
            assertTrue(seen.add(encR), "W(R) repeated at signature " + i);
            assertTrue(
                    Ed25519.verify(
                            encodedA,
                            message,
                            Ed25519.signature(Wei25519Map.encode(rs[0].data()), rs[1].data())),
                    "signature " + i);
        }
        assertEquals(COUNT, edCounter() - before, "edCounter advanced once per begin");
    }

    @Test
    void tEdctrTearsNeverAdvanceTheCounter() throws Exception {
        // each write index of begin's T-EDCTR torn in turn: the counter rolls back,
        // nothing was output, and the next begin uses old + 1 — no W(R) twice in the run
        byte[] constant = new byte[32];
        constant[31] = 7;
        byte[] message = new byte[] {1, 2, 3};
        byte[] encodedA = Wei25519Map.encode(Vecs.pkEdSolana());
        Set<String> seen = new HashSet<>();
        int writes;
        {
            verified();
            assertEquals(0x9000, inner(0x33, 0, Vecs.pathEdSolana()).sw());
            writes = card.writes();
        }
        for (int tear = 1; tear <= writes; tear++) {
            verified();
            Rng.fix(constant);
            long before = edCounter();
            card.tearAt(tear);
            assertThrows(
                    TornException.class,
                    () -> card.transmit(session.wrap(0x33, 0, 0, Vecs.pathEdSolana())));
            powerUp();
            assertEquals(before, edCounter(), "tear " + tear + ": counter rolled back");
            Response[] rs = sign(message);
            assertEquals(before + 1, edCounter(), "the next begin committed old + 1");
            String encR = java.util.HexFormat.of().formatHex(Wei25519Map.encode(rs[0].data()));
            assertTrue(seen.add(encR), "W(R) repeated after tear " + tear);
            assertTrue(
                    Ed25519.verify(
                            encodedA,
                            message,
                            Ed25519.signature(Wei25519Map.encode(rs[0].data()), rs[1].data())));
        }
    }

    @Test
    void ecdsaVerifyKeyWriteTearsCleanly() throws Exception {
        // the single setW is outside any transaction (§16.1 item 1): tearing it leaves
        // the life state untouched and the next signature still verifies
        byte[] data = new byte[32 + Vecs.pathSecpEvm().length];
        System.arraycopy(Vecs.digest(), 0, data, 0, 32);
        System.arraycopy(Vecs.pathSecpEvm(), 0, data, 32, Vecs.pathSecpEvm().length);
        verified();
        assertEquals(0x9000, inner(0x31, 0, data).sw());
        assertEquals(1, card.writes(), "one setW per SIGN_ECDSA");
        byte[] state = Internals.stateArray(applet()).clone();
        card.tearAt(1);
        assertThrows(TornException.class, () -> card.transmit(session.wrap(0x31, 0, 0, data)));
        powerUp();
        assertArrayEquals(state, Internals.stateArray(applet()), "persistent state unchanged");
        Response r = inner(0x31, 0, data);
        assertEquals(0x9000, r.sw());
        assertTrue(
                org.qntx.card.host.Ecdsa.verify(
                        org.qntx.card.host.Crypto.decompress(
                                org.qntx.card.host.Bip32.derive(Vecs.seed(), "m/44'/60'/0'/0/0")
                                        .publicKey()),
                        Vecs.digest(),
                        r.data()));
    }
}

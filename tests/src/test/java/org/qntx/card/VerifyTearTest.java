// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.Applet;
import javacard.framework.Util;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.TornException;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §9.5 VERIFY under power loss (architecture §14.4 W2): for every {@code f ∈ 0..9} and both codes,
 * and for the re-entry state {@code f = L}, tear at every persistent write and assert the
 * post-state invariants: a failure inside T-FAIL is uncounted, a committed T-FAIL is counted, a
 * torn T-OK keeps {@code f + 1}, a torn T-ERASE is all-old or all-erased, and the read-back gate
 * catches a skipped T-FAIL or a skipped commit.
 */
final class VerifyTearTest {

    private static final short OFF_CT = State.OFF_CT;
    private static final short OFF_TAG = State.OFF_TAG;
    private static final short OFF_FP = State.OFF_FP;

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void setFails(short f) {
        byte[] s = Internals.stateArray(applet());
        Util.setShort(s, State.OFF_FAILS, f);
        Util.setShort(s, (short) (State.OFF_FAILS + 2), (short) ~f);
    }

    private void setWaited(short w) {
        byte[] words = Internals.words(applet());
        Util.setShort(words, (short) 8, w);
    }

    private short fails() {
        return Util.getShort(Internals.stateArray(applet()), State.OFF_FAILS);
    }

    private boolean blank() {
        return Util.getShort(Internals.stateArray(applet()), State.OFF_LIFE) == Const.LIFE_BLANK;
    }

    /** A LOADED card with a fresh open session at failure count {@code f} and 15 waits. */
    private void loadedAt(short f) throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
        setFails(f);
        setWaited((short) Const.WAIT_UNITS);
    }

    private void powerUp() throws Exception {
        card.powerCycle();
        card.transmit(Spec.SELECT);
        session = Vecs.open(card);
    }

    private void tornVerify(byte[] code) {
        assertThrows(TornException.class, () -> card.transmit(session.wrap(0x22, 0, 0, code)));
    }

    private Response verify(byte[] code) throws Exception {
        return Vecs.roundtrip(card, session, 0x22, 0, 0, code);
    }

    private int verifyWrites(byte[] code) throws Exception {
        Card dry = Vecs.blankSelf();
        Session s = Vecs.loadWallet(dry);
        byte[] state = Internals.stateArray(dry.applet(Spec.WALLET_AID));
        // same f, same gate state as the card under test
        byte[] mine = Internals.stateArray(applet());
        Util.setShort(state, State.OFF_FAILS, Util.getShort(mine, State.OFF_FAILS));
        Util.setShort(
                state,
                (short) (State.OFF_FAILS + 2),
                Util.getShort(mine, (short) (State.OFF_FAILS + 2)));
        Util.setShort(
                Internals.words(dry.applet(Spec.WALLET_AID)), (short) 8, (short) Const.WAIT_UNITS);
        Vecs.roundtrip(dry, s, 0x22, 0, 0, code);
        return dry.writes();
    }

    private void assertLoadedyFieldsIntact() {
        byte[] s = Internals.stateArray(applet());
        boolean nonzero = false;
        for (int i = OFF_CT; i < OFF_CT + 64; i++) {
            nonzero |= s[i] != 0;
        }
        assertTrue(nonzero, "ct must still hold the ciphertext");
        nonzero = false;
        for (int i = OFF_TAG; i < OFF_TAG + 16; i++) {
            nonzero |= s[i] != 0;
        }
        assertTrue(nonzero, "tag must still hold the MAC");
        nonzero = false;
        for (int i = OFF_FP; i < OFF_FP + 32; i++) {
            nonzero |= s[i] != 0;
        }
        assertTrue(nonzero, "fp must still hold the fingerprint");
    }

    /**
     * Tears VERIFY at every write for one (f, code) pair; {@code expectErase} is the wrong code at
     * {@code f = 9}.
     */
    private void tearSweep(short f, byte[] code, boolean rightCode, boolean expectErase)
            throws Exception {
        loadedAt(f);
        int n = verifyWrites(code);
        for (int tear = 1; tear <= n; tear++) {
            loadedAt(f);
            Fault.countCalls();
            card.tearAt(tear);
            tornVerify(code);
            int matchCalls = Fault.calls("Wallet.match");
            Fault.reset();
            boolean inTFail = tear <= 2; // T-FAIL = writeFails: two setShort writes
            powerUp();
            if (inTFail) {
                assertEquals(f, fails(), "tear " + tear + ": uncommitted T-FAIL must not count");
                assertEquals(0, matchCalls, "no match call before the gate");
                assertTrue(!blank(), "still LOADED");
            } else {
                // the first post-T-FAIL write is torn: the failure is committed
                if (expectErase) {
                    if (blank()) {
                        assertAllErased();
                    } else {
                        assertEquals(Const.FAIL_LIMIT, fails(), "tear " + tear + ": f = L stays");
                        assertLoadedyFieldsIntact();
                    }
                } else if (rightCode) {
                    // T-OK torn: f + 1 stands
                    if (f + 1 < Const.FAIL_LIMIT) {
                        assertEquals((short) (f + 1), fails(), "tear " + tear);
                        assertTrue(!blank());
                    } else {
                        assertEquals(Const.FAIL_LIMIT, fails(), "tear " + tear);
                    }
                } else {
                    // unreachable for wrong code at f < 9 (no writes after T-FAIL)
                    throw new IllegalStateException("wrong code wrote past T-FAIL");
                }
            }
        }
    }

    private void assertAllErased() {
        byte[] s = Internals.stateArray(applet());
        assertEquals(0, fails());
        for (int i = State.OFF_ORIGIN; i <= State.OFF_OFFER + 1; i++) {
            assertEquals(0, s[i], "origin/offer not cleared");
        }
        for (int i = State.OFF_MEMBERS; i < State.OFF_CERT; i++) {
            assertEquals(0, s[i], "members/fp/ct/tag not cleared");
        }
    }

    @Test
    void wrongCodeTears() throws Exception {
        for (short f = 0; f < Const.FAIL_LIMIT; f++) {
            tearSweep(f, Vecs.accessHashWrong(), false, f == Const.FAIL_LIMIT - 1);
        }
    }

    @Test
    void rightCodeTears() throws Exception {
        for (short f = 0; f < Const.FAIL_LIMIT; f++) {
            tearSweep(f, Vecs.accessHash(), true, false);
        }
    }

    @Test
    void tornRightCodeThenVerifyResets() throws Exception {
        // tear the T-OK of a right-code VERIFY at f = 0: f = 1 stands, then the right code resets
        loadedAt((short) 0);
        card.tearAt(3);
        tornVerify(Vecs.accessHash());
        powerUp();
        assertEquals(1, fails());
        assertEquals(0x9000, verify(Vecs.accessHash()).sw());
        assertEquals(0, fails());
    }

    @Test
    void reentryAtLimitErasesWithoutMatch() throws Exception {
        loadedAt((short) Const.FAIL_LIMIT);
        Fault.countCalls();
        assertEquals(0x6983, verify(Vecs.accessHash()).sw());
        assertEquals(0, Fault.calls("Wallet.match"), "no comparison at f = L");
        assertTrue(blank(), "f = L re-entry erases");
        assertEquals(0, fails());
    }

    @Test
    void skippedTFailIsCaughtByTheGate() throws Exception {
        loadedAt((short) 0);
        Fault.countCalls();
        Fault.armSkip("Wallet.tFail", 1);
        Response r = verify(Vecs.accessHash());
        assertEquals(0x6F00, r.sw());
        assertEquals(0, Fault.calls("Wallet.match"), "gate fails before the comparison");
        assertTrue(blank(), "gate failure erases");
    }

    @Test
    void skippedTFailCommitIsCaughtByTheGate() throws Exception {
        loadedAt((short) 0);
        Fault.countCalls();
        Fault.armSkip("JCSystem.commitTransaction", 1);
        Response r = verify(Vecs.accessHash());
        assertEquals(0x6F00, r.sw());
        assertEquals(0, Fault.calls("Wallet.match"));
        assertTrue(blank());
        // the still-open transaction was aborted by gateFail before T-ERASE committed
        assertEquals(2, card.commits().size(), "aborted T-FAIL + committed T-ERASE");
    }

    @Test
    void statusReportsBlankAfterTear() throws Exception {
        loadedAt((short) 0);
        card.tearAt(1);
        tornVerify(Vecs.accessHash());
        powerUp();
        Response r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertArrayEquals(new byte[] {0x02, 0x0a}, r.data(), "untorn f = 0 stays LOADED");
    }
}

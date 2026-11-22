// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.Applet;
import javacard.framework.Util;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.TornException;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * §9.4/§9.6/§9.7 write transactions under power loss (architecture §14.4 W4): T-CREATE, T-CHANGE
 * and T-ERASE are single commits — tearing at any of their writes leaves the card exactly in the
 * pre-command state, never a mix of old and new fields.
 */
final class WalletTearTest {

    private Card card;
    private Session session;

    private Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void blank() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.open(card);
    }

    private void loadedVerified() throws Exception {
        blank();
        session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    private void powerUp() throws Exception {
        card.powerCycle();
        card.transmit(Spec.SELECT);
        session = Vecs.open(card);
    }

    private Response verify(byte[] code) throws Exception {
        return Vecs.roundtrip(card, session, 0x22, 0, 0, code);
    }

    private static byte[] createData() {
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        return data;
    }

    private boolean blankLife() {
        return Util.getShort(Internals.stateArray(applet()), State.OFF_LIFE) == Const.LIFE_BLANK;
    }

    @Test
    void createImportTearsAtomically() throws Exception {
        int n;
        {
            blank();
            assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, createData()).sw());
            n = card.writes();
        }
        for (int tear = 1; tear <= n; tear++) {
            blank();
            card.tearAt(tear);
            assertThrows(
                    TornException.class,
                    () -> card.transmit(session.wrap(0x21, 1, 0, createData())));
            powerUp();
            assertTrue(blankLife(), "tear " + tear + ": T-CREATE must not leave a mix");
            Response r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
            assertEquals(0x01, r.data()[0]);
            // a fresh CREATE still succeeds on the untouched card
            assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, createData()).sw());
        }
    }

    @Test
    void createGenerateTearsAtomically() throws Exception {
        byte[] data = new byte[64];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.entropy(), 0, data, 32, 32);
        int n;
        {
            blank();
            assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 0, 0, data).sw());
            n = card.writes();
        }
        for (int tear = 1; tear <= n; tear++) {
            blank();
            card.tearAt(tear);
            assertThrows(TornException.class, () -> card.transmit(session.wrap(0x21, 0, 0, data)));
            powerUp();
            assertTrue(blankLife(), "tear " + tear);
        }
    }

    @Test
    void changeTearsAtomically() throws Exception {
        int n;
        {
            loadedVerified();
            assertEquals(
                    0x9000, Vecs.roundtrip(card, session, 0x23, 0, 0, Vecs.accessHashNew()).sw());
            n = card.writes();
        }
        for (int tear = 1; tear <= n; tear++) {
            loadedVerified();
            card.tearAt(tear);
            assertThrows(
                    TornException.class,
                    () -> card.transmit(session.wrap(0x23, 0, 0, Vecs.accessHashNew())));
            powerUp();
            assertTrue(!blankLife(), "tear " + tear + ": still LOADED");
            // the old code still verifies — the rewrap never committed
            assertEquals(0x9000, verify(Vecs.accessHash()).sw(), "tear " + tear);
        }
    }

    @Test
    void eraseTearsAtomically() throws Exception {
        int n;
        {
            loadedVerified();
            assertEquals(0x9000, Vecs.roundtrip(card, session, 0x24, 0, 0, new byte[0]).sw());
            n = card.writes();
        }
        for (int tear = 1; tear <= n; tear++) {
            loadedVerified();
            card.tearAt(tear);
            assertThrows(
                    TornException.class,
                    () -> card.transmit(session.wrap(0x24, 0, 0, new byte[0])));
            powerUp();
            assertTrue(!blankLife(), "tear " + tear + ": still LOADED");
            assertEquals(0x9000, verify(Vecs.accessHash()).sw(), "tear " + tear);
        }
    }
}

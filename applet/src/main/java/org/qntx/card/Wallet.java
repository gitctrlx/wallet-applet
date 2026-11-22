// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISOException;

/** Inner wallet commands (§9.3 on); the core stage implements STATUS only. */
final class Wallet {
    private final State state;

    Wallet(State state) {
        this.state = state;
    }

    /**
     * STATUS (§9.3): {@code life(1) ‖ tries(1)} — {@code 0x01} BLANK, {@code 0x02} LOADED; {@code
     * tries = 0} in BLANK, {@code max(L − f, 0)} in LOADED. The {@code fails} complement is checked
     * in both states and a disagreement is a fault (§16.2 item 2). No side effect.
     */
    short status(byte[] out, short off) {
        short life = state.life();
        short f = state.fails();
        if (life == Const.LIFE_BLANK) {
            out[off] = 0x01;
            out[(short) (off + 1)] = 0;
            return 2;
        }
        if (life == Const.LIFE_LOADED) {
            out[off] = 0x02;
            short tries = (short) (Const.FAIL_LIMIT - f);
            out[(short) (off + 1)] = (byte) (tries < 0 ? 0 : tries);
            return 2;
        }
        // a life the §9.2 table would have denied is a detected fault: the gate
        // re-check must have been skipped (§16.2 item 4)
        ISOException.throwIt(Const.SW_FAULT);
        return 0;
    }
}

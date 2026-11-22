// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * The one persistent {@code byte[272]} holding every non-key field of protocol.md §4.2
 * (architecture.md §4 layout), so each named transaction touches a single array plus its key
 * objects. Writes happen only through {@link #write} and {@link #setLife}, only inside the
 * transaction the spec names, and always atomically.
 */
final class State {
    static final short OFF_LIFE = 0;
    static final short OFF_FAILS = 2;
    static final short OFF_ORIGIN = 6;
    static final short OFF_OFFER = 8;
    static final short OFF_EDCOUNTER = 10;
    static final short OFF_MEMBERS = 14;
    static final short OFF_FP = 63;
    static final short OFF_CT = 95;
    static final short OFF_TAG = 159;
    static final short OFF_CERT = 175;

    private final byte[] state = new byte[Const.STATE_LEN];

    State() {
        // §16.2 item 2: fails <- 0 writes the value and its complement
        Util.setShort(state, OFF_FAILS, (short) 0);
        Util.setShort(state, (short) (OFF_FAILS + 2), (short) -1);
        Util.setShort(state, OFF_OFFER, Const.OFFER_NONE);
        Util.setShort(state, OFF_LIFE, Const.LIFE_FACTORY);
    }

    /** The coded life value; a non-member read is a detected fault (§16.2 item 1). */
    short life() {
        short life = Util.getShort(state, OFF_LIFE);
        if (life != Const.LIFE_FACTORY && life != Const.LIFE_BLANK && life != Const.LIFE_LOADED) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        return life;
    }

    /** The failure count {@code f}; a complement mismatch is a detected fault (§16.2 item 2). */
    short fails() {
        short f = Util.getShort(state, OFF_FAILS);
        short c = Util.getShort(state, (short) (OFF_FAILS + 2));
        if ((short) (f ^ c) != -1) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        return f;
    }

    /** Atomic write of a coded life value; only inside the transaction that owns it. */
    void setLife(short life) {
        Util.setShort(state, OFF_LIFE, life);
    }

    /** Atomic copy into the array; only inside the transaction that owns the field. */
    void write(short off, byte[] src, short srcOff, short len) {
        Util.arrayCopy(src, srcOff, state, off, len);
    }

    /** The stored certificate at {@code cert(97)} (§5.2). */
    void cert(byte[] dst, short dstOff) {
        Util.arrayCopy(state, OFF_CERT, dst, dstOff, Const.CERT_LEN);
    }
}

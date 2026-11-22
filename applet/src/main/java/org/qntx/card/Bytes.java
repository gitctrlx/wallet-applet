// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.Util;

/** Constant-time compare, wiping and the M2 padding of spec/protocol.md §1. */
final class Bytes {
    private Bytes() {}

    /**
     * Constant-time equality of {@code len} bytes (§16.4): fixed loop bound, OR of XORs, no early
     * exit. Returns the coded result (§16.2 item 1).
     */
    static short equal(byte[] a, short aOff, byte[] b, short bOff, short len) {
        byte diff = 0;
        for (short i = 0; i < len; i++) {
            diff |= (byte) (a[(short) (aOff + i)] ^ b[(short) (bOff + i)]);
        }
        return diff == 0 ? Const.CHECK_OK : Const.CHECK_FAIL;
    }

    /** Zeroes transient memory or the APDU buffer; persistent arrays use atomic writes only. */
    static void wipe(byte[] arr, short off, short len) {
        Util.arrayFillNonAtomic(arr, off, len, (byte) 0);
    }

    /**
     * ISO/IEC 9797-1 padding method 2 in place (§1): {@code X ‖ 0x80 ‖ 0ᵏ} to the next multiple of
     * 16, always appending the 0x80 byte so a full block gets a whole padding block.
     */
    static short pad(byte[] buf, short off, short len) {
        short padded = (short) (((len >> 4) + 1) << 4);
        buf[(short) (off + len)] = (byte) 0x80;
        Util.arrayFillNonAtomic(buf, (short) (off + len + 1), (short) (padded - len - 1), (byte) 0);
        return padded;
    }

    /**
     * Removes M2 padding (§1 {@code unM2}); returns the unpadded length or -1 when the input is
     * empty, not a multiple of 16, its last non-zero byte is not 0x80, or more than 15 zero bytes
     * follow it. Fixed bound: one full scan finds the last non-zero byte.
     */
    static short unpad(byte[] buf, short off, short len) {
        if (len <= 0 || (short) (len & 0x0F) != 0) {
            return -1;
        }
        short marker = -1;
        for (short i = 0; i < len; i++) {
            if (buf[(short) (off + i)] != 0) {
                marker = i;
            }
        }
        if (marker < 0
                || buf[(short) (off + marker)] != (byte) 0x80
                || (short) (len - marker) > 16) {
            return -1;
        }
        return marker;
    }
}

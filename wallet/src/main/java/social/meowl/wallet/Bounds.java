/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import javacard.framework.ISOException;

/**
 * Overflow-safe boundary checks for byte-buffer offsets and lengths.
 *
 * <p>The remaining-capacity test is written as {@code needed > dst.length - offset} so the
 * subtraction runs on an already-validated non-negative quantity, side-stepping the 16-bit signed
 * wrap that {@code (short)(offset + needed) > dst.length} is prone to on JavaCard.
 */
final class Bounds {

    private Bounds() {}

    /**
     * Verifies that {@code buf[offset .. offset + length]} is a valid sub-range. Raises {@link
     * Constants#SW_WRONG_LENGTH} on any malformed input (null buffer, negative offset or length,
     * insufficient capacity). Used both as a destination-capacity check and a source-range check —
     * the two are arithmetically identical so a single helper backs both call sites.
     */
    static void requireCapacity(byte[] buf, short offset, short length) {
        if (buf == null
                || offset < 0
                || length < 0
                || offset > (short) buf.length
                || length > (short) (buf.length - offset)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }
}

/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

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
     * Verifies that {@code dst[offset .. offset + needed]} is a valid sub-range. Raises {@link
     * Constants#SW_WRONG_LENGTH} on any malformed input (null buffer, negative offset or length,
     * insufficient capacity).
     */
    static void requireCapacity(byte[] dst, short offset, short needed) {
        if (dst == null
                || offset < 0
                || needed < 0
                || offset > (short) dst.length
                || needed > (short) (dst.length - offset)) {
            ISOException.throwIt(Constants.Sw.WRONG_LENGTH);
        }
    }

    /**
     * Source-side counterpart of {@link #requireCapacity}; same semantics, different name for
     * call-site readability.
     */
    static void requireRange(byte[] src, short offset, short length) {
        if (src == null
                || offset < 0
                || length < 0
                || offset > (short) src.length
                || length > (short) (src.length - offset)) {
            ISOException.throwIt(Constants.Sw.WRONG_LENGTH);
        }
    }
}

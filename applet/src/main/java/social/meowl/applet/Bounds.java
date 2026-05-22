/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;

/**
 * Centralised, overflow-safe boundary checks for byte-buffer offsets and lengths.
 *
 * <p>Audit F-05 found that {@code ApduTlv.ensureCapacity} and {@code Authentikey.ensureCapacity}
 * were near-identical private implementations of the same predicate, with the additional caveat
 * that an arithmetic check of the form {@code (short)(offset + needed) > dst.length} silently wraps
 * under JC's 16-bit signed {@code short} when {@code offset + needed} exceeds {@code 0x7FFF}. Audit
 * F-04 demonstrated that the wrap was theoretically reachable on attacker-controlled inputs.
 *
 * <p>This class exposes a single, overflow-safe primitive whose check rearranges the inequality to
 * {@code needed > (dst.length - offset)} so the subtraction is always done on an already-validated
 * non-negative quantity. Every caller in the applet that previously rolled its own check is
 * migrated to call this class.
 */
final class Bounds {

    private Bounds() {}

    /**
     * Verifies that {@code dst[offset .. offset + needed]} is a valid sub-range of {@code dst}.
     * Raises {@link Constants#SW_WRONG_LENGTH} if any of the inputs is malformed (null buffer,
     * negative offset, negative length, or insufficient remaining capacity).
     *
     * <p>The remaining-capacity test is written as {@code needed > dst.length - offset} to side-
     * step the JC short overflow that {@code (short)(offset + needed) > dst.length} is prone to.
     *
     * @param dst destination buffer; must be non-null
     * @param offset starting offset in {@code dst}; must lie in {@code [0, dst.length]}
     * @param needed number of bytes to reserve starting at {@code offset}; must be {@code >= 0}
     */
    static void requireCapacity(byte[] dst, short offset, short needed) {
        if (dst == null
                || offset < 0
                || needed < 0
                || offset > (short) dst.length
                || needed > (short) (dst.length - offset)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }

    /**
     * Variant of {@link #requireCapacity(byte[], short, short)} for source-side validation. Same
     * semantics; provided as a separate name purely for call-site readability — a TLV writer
     * conceptually validates the destination cap with {@code requireCapacity} and the source range
     * with {@code requireRange}.
     */
    static void requireRange(byte[] src, short offset, short length) {
        if (src == null
                || offset < 0
                || length < 0
                || offset > (short) src.length
                || length > (short) (src.length - offset)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }
}

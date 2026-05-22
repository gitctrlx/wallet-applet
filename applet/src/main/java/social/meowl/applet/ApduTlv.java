/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Helpers for writing simple BER-TLV (single-byte tag, single-byte length) records into a
 * destination buffer.
 *
 * <p>Usage is intentionally restricted to the simplified form {@code [tag(1) | length(1) |
 * value(length)]} with {@code length ∈ [0, 255]} per {@code docs/specs/meap-1.md §TLV-encoding}.
 * This deliberately departs from strict BER-TLV (which mandates long-form {@code 0x81 LL} for
 * length ≥ 128); the meowl wire trades strict ISO compliance for parser simplicity, since every TLV
 * value is well below 256 bytes. Audit F-36 corrected an earlier {@code length ≤ 127} claim that
 * contradicted both the spec and the {@link #MAX_VALUE_LEN} constant.
 *
 * <p>Every method returns the offset immediately past the last byte written, so call sites can
 * chain writes without keeping a separate cursor variable. Misuse (oversized value, illegal offset,
 * source/destination overrun) raises {@link Constants#SW_WRONG_LENGTH} rather than a silent
 * buffer-corruption bug.
 */
public final class ApduTlv {

    /**
     * Maximum value length supported by the simplified single-byte length form.
     *
     * <p>The single-byte length encodes the inclusive range {@code [0, 255]} per MEAP-1
     * §TLV-encoding; previously this constant was {@code 0x7F} (audit M-1.06), which over-
     * restricted the cap below what the spec and the host parser accept. Today every value the
     * applet emits is well below 128 bytes (the largest is the 33-byte compressed authentikey), but
     * raising the cap to {@code 0xFF} aligns the three TLV touch-points (spec, applet,
     * tools/core/Tlv) so a future field with 128+ bytes is unblocked.
     */
    public static final short MAX_VALUE_LEN = (short) 0xFF;

    /** Fixed length of the value carried by {@link #putByte(byte[], short, byte, byte)}. */
    public static final short BYTE_VALUE_LEN = (short) 1;

    /** Fixed length of the value carried by {@link #putShort(byte[], short, byte, short)}. */
    public static final short SHORT_VALUE_LEN = (short) 2;

    private ApduTlv() {}

    /**
     * Writes a TLV record carrying a single byte value.
     *
     * @return the offset immediately after the written record
     */
    public static short putByte(byte[] dst, short offset, byte tag, byte value) {
        Bounds.requireCapacity(dst, offset, (short) (2 + BYTE_VALUE_LEN));
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) BYTE_VALUE_LEN;
        dst[(short) (offset + 2)] = value;
        return (short) (offset + 2 + BYTE_VALUE_LEN);
    }

    /**
     * Writes a TLV record carrying a 16-bit big-endian short value.
     *
     * @return the offset immediately after the written record
     */
    public static short putShort(byte[] dst, short offset, byte tag, short value) {
        Bounds.requireCapacity(dst, offset, (short) (2 + SHORT_VALUE_LEN));
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) SHORT_VALUE_LEN;
        Util.setShort(dst, (short) (offset + 2), value);
        return (short) (offset + 2 + SHORT_VALUE_LEN);
    }

    /**
     * Writes a TLV record carrying {@code length} bytes copied from {@code src} starting at {@code
     * srcOffset}.
     *
     * <p>Raises {@link Constants#SW_WRONG_LENGTH} if {@code length} exceeds {@link #MAX_VALUE_LEN},
     * if the source range is malformed, or if the destination cannot hold the record.
     *
     * @return the offset immediately after the written record
     */
    public static short putBytes(
            byte[] dst, short offset, byte tag, byte[] src, short srcOffset, short length) {
        if (length > MAX_VALUE_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        Bounds.requireRange(src, srcOffset, length);
        Bounds.requireCapacity(dst, offset, (short) (2 + length));
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) length;
        Util.arrayCopyNonAtomic(src, srcOffset, dst, (short) (offset + 2), length);
        return (short) (offset + 2 + length);
    }

    /**
     * Reserves a TLV header at {@code offset}, returning the offset where the caller should start
     * writing the value. After the caller has written {@code length} bytes the header is back-
     * patched via {@link #finishReserved(byte[], short, short)}.
     *
     * <p>This two-step API is the JavaCard equivalent of streaming TLV: the value is built directly
     * inside the destination buffer with no intermediate copy.
     *
     * @return the offset immediately after the reserved 2-byte header
     */
    public static short reserve(byte[] dst, short offset, byte tag) {
        Bounds.requireCapacity(dst, offset, (short) 2);
        dst[offset] = tag;
        // length placeholder; back-patched by finishReserved().
        dst[(short) (offset + 1)] = (byte) 0;
        return (short) (offset + 2);
    }

    /**
     * Completes a record previously opened with {@link #reserve(byte[], short, byte)}.
     *
     * @param headerOffset the offset returned by the original {@code reserve} call, minus 2 — i.e.
     *     the offset of the tag byte
     * @param valueLen the number of value bytes the caller wrote past the reserved header
     */
    public static void finishReserved(byte[] dst, short headerOffset, short valueLen) {
        if (valueLen < 0 || valueLen > MAX_VALUE_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        dst[(short) (headerOffset + 1)] = (byte) valueLen;
    }
}

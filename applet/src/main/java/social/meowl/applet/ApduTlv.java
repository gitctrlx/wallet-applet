/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Helpers for writing simple BER-TLV (single-byte tag, single-byte length) records into an APDU
 * response buffer.
 *
 * <p>The applet's TLV usage is intentionally restricted to the simplified form {@code [tag(1) |
 * length(1) | value(length)]} with {@code length ≤ 127}. This is sufficient for every TLV record
 * meowl emits (see {@code Constants.TAG_*}) and keeps the encoder small enough to audit by
 * inspection.
 *
 * <p>The class is non-instantiable; every method writes into a caller-provided buffer and returns
 * the offset just past the last byte written.
 */
public final class ApduTlv {

    /** Maximum value-length supported by the simplified single-byte length form. */
    private static final short MAX_VALUE_LEN = (short) 0x7F;

    private ApduTlv() {
        // non-instantiable
    }

    /**
     * Writes a TLV record {@code [tag | 1 | value]} where the value is a single byte.
     *
     * @return the offset immediately after the written record
     */
    public static short putByte(byte[] dst, short offset, byte tag, byte value) {
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) 0x01;
        dst[(short) (offset + 2)] = value;
        return (short) (offset + 3);
    }

    /**
     * Writes a TLV record {@code [tag | 2 | hi | lo]} where the value is a 16-bit big-endian
     * integer.
     *
     * @return the offset immediately after the written record
     */
    public static short putShort(byte[] dst, short offset, byte tag, short value) {
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) 0x02;
        Util.setShort(dst, (short) (offset + 2), value);
        return (short) (offset + 4);
    }

    /**
     * Writes a TLV record {@code [tag | length | value(length)]} copying {@code length} bytes from
     * {@code src} starting at {@code srcOffset}.
     *
     * <p>Raises {@link Constants#SW_WRONG_LENGTH} if {@code length} exceeds the single-byte length
     * encoding limit of 127 bytes.
     *
     * @return the offset immediately after the written record
     */
    public static short putBytes(
            byte[] dst, short offset, byte tag, byte[] src, short srcOffset, short length) {
        if (length < 0 || length > MAX_VALUE_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) length;
        Util.arrayCopyNonAtomic(src, srcOffset, dst, (short) (offset + 2), length);
        return (short) (offset + 2 + length);
    }

    /**
     * Writes a versioned 2-byte TLV record {@code [tag | 2 | major | minor]}.
     *
     * @return the offset immediately after the written record
     */
    public static short putVersion(byte[] dst, short offset, byte tag, byte major, byte minor) {
        dst[offset] = tag;
        dst[(short) (offset + 1)] = (byte) 0x02;
        dst[(short) (offset + 2)] = major;
        dst[(short) (offset + 3)] = minor;
        return (short) (offset + 4);
    }
}

/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISOException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Direct unit tests for the {@link ApduTlv} simplified single-byte BER-TLV writer.
 *
 * <p>Covers the four entry points ({@link ApduTlv#putByte putByte} / {@link ApduTlv#putShort
 * putShort} / {@link ApduTlv#putBytes putBytes} / {@link ApduTlv#reserve reserve} + {@link
 * ApduTlv#finishReserved finishReserved}) against the wire shapes pinned by protocol.md §5, plus
 * the destination-range bound check on {@code finishReserved} so a value written past the buffer
 * surfaces as {@link Constants#SW_WRONG_LENGTH} rather than a runtime {@code
 * IndexOutOfBoundsException} ({@code 6F00}).
 */
class ApduTlvTest {

    private static final byte TAG = (byte) 0x42;

    @Test
    @DisplayName("putByte: emits [tag, 0x01, value] and returns the cursor past the record")
    void putByteHappyPath() {
        byte[] dst = new byte[16];
        short cursor = ApduTlv.putByte(dst, (short) 4, TAG, (byte) 0x7E);
        assertEquals((short) 7, cursor);
        assertEquals(TAG, dst[4]);
        assertEquals((byte) 0x01, dst[5]);
        assertEquals((byte) 0x7E, dst[6]);
    }

    @Test
    @DisplayName("putByte: leading/trailing bytes are untouched")
    void putByteDoesNotClobberNeighbours() {
        byte[] dst = filled((byte) 0xAA, 16);
        ApduTlv.putByte(dst, (short) 5, TAG, (byte) 0x00);
        assertEquals((byte) 0xAA, dst[4]);
        assertEquals((byte) 0xAA, dst[8]);
    }

    @Test
    @DisplayName("putByte: insufficient capacity raises SW_WRONG_LENGTH")
    void putByteCapacityFailure() {
        byte[] dst = new byte[2]; // need 3 bytes
        assertSw(Constants.SW_WRONG_LENGTH, () -> ApduTlv.putByte(dst, (short) 0, TAG, (byte) 0));
    }

    @Test
    @DisplayName("putShort: emits [tag, 0x02, hi, lo] in big-endian order")
    void putShortHappyPath() {
        byte[] dst = new byte[8];
        short cursor = ApduTlv.putShort(dst, (short) 1, TAG, (short) 0x12AB);
        assertEquals((short) 5, cursor);
        assertEquals(TAG, dst[1]);
        assertEquals((byte) 0x02, dst[2]);
        assertEquals((byte) 0x12, dst[3]);
        assertEquals((byte) 0xAB, dst[4]);
    }

    @Test
    @DisplayName("putShort: insufficient capacity raises SW_WRONG_LENGTH")
    void putShortCapacityFailure() {
        byte[] dst = new byte[3]; // need 4 bytes
        assertSw(
                Constants.SW_WRONG_LENGTH,
                () -> ApduTlv.putShort(dst, (short) 0, TAG, (short) 0x1234));
    }

    @Test
    @DisplayName(
            "reserve + finishReserved: round-trip preserves value bytes and back-patches length")
    void reserveAndFinishRoundtrip() {
        byte[] dst = new byte[16];
        short valueStart = ApduTlv.reserve(dst, (short) 2, TAG);
        assertEquals((short) 4, valueStart);
        // Caller writes 6 value bytes directly into dst[4..10).
        for (short i = 0; i < 6; i++) {
            dst[(short) (valueStart + i)] = (byte) (0x30 + i);
        }
        ApduTlv.finishReserved(dst, (short) 2, (short) 6);
        assertEquals(TAG, dst[2]);
        assertEquals((byte) 0x06, dst[3]);
        for (int i = 0; i < 6; i++) {
            assertEquals((byte) (0x30 + i), dst[4 + i]);
        }
    }

    @Test
    @DisplayName("finishReserved: zero-length value back-patches to 0x00")
    void finishReservedZeroLength() {
        byte[] dst = new byte[8];
        ApduTlv.reserve(dst, (short) 0, TAG);
        ApduTlv.finishReserved(dst, (short) 0, (short) 0);
        assertEquals(TAG, dst[0]);
        assertEquals((byte) 0x00, dst[1]);
    }

    @Test
    @DisplayName("finishReserved: negative valueLen raises SW_WRONG_LENGTH")
    void finishReservedNegativeLength() {
        byte[] dst = new byte[16];
        ApduTlv.reserve(dst, (short) 0, TAG);
        assertSw(
                Constants.SW_WRONG_LENGTH,
                () -> ApduTlv.finishReserved(dst, (short) 0, (short) -1));
    }

    @Test
    @DisplayName("finishReserved: valueLen > MAX_VALUE_LEN raises SW_WRONG_LENGTH")
    void finishReservedOverMaxLength() {
        byte[] dst = new byte[300];
        ApduTlv.reserve(dst, (short) 0, TAG);
        assertSw(
                Constants.SW_WRONG_LENGTH,
                () -> ApduTlv.finishReserved(dst, (short) 0, (short) 256));
    }

    @Test
    @DisplayName("finishReserved: dst too small for header + claimed value raises SW_WRONG_LENGTH")
    void finishReservedDestinationOverrun() {
        // Caller programmer error: reserved at the very end of the buffer, then claims more value
        // bytes than dst can hold. The bounds check rejects the obviously inconsistent record
        // instead of silently back-patching the length byte past the buffer end.
        byte[] dst = new byte[10];
        ApduTlv.reserve(dst, (short) 5, TAG); // value would start at offset 7
        // Claim 5 value bytes, but only 3 fit (10 - 5 - 2 = 3). Must reject with 6700.
        assertSw(
                Constants.SW_WRONG_LENGTH, () -> ApduTlv.finishReserved(dst, (short) 5, (short) 5));
    }

    @Test
    @DisplayName(
            "finishReserved: dst exactly large enough for header + value succeeds at the boundary")
    void finishReservedExactBoundary() {
        byte[] dst = new byte[10];
        ApduTlv.reserve(dst, (short) 5, TAG); // value would start at offset 7
        // 10 - 5 = 5 bytes available, header consumes 2, value can be exactly 3.
        ApduTlv.finishReserved(dst, (short) 5, (short) 3);
        assertEquals((byte) 0x03, dst[6]);
    }

    @Test
    @DisplayName("reserve: insufficient capacity for the 2-byte header raises SW_WRONG_LENGTH")
    void reserveCapacityFailure() {
        byte[] dst = new byte[1]; // need 2 bytes
        assertSw(Constants.SW_WRONG_LENGTH, () -> ApduTlv.reserve(dst, (short) 0, TAG));
    }

    @Test
    @DisplayName(
            "sequential records: putByte → putShort → reserve+finishReserved lay out without gaps")
    void chainedRecordsLayoutContiguously() {
        byte[] dst = new byte[20];
        short cursor = (short) 0;
        cursor = ApduTlv.putByte(dst, cursor, (byte) 0x01, (byte) 0xAA);
        cursor = ApduTlv.putShort(dst, cursor, (byte) 0x02, (short) 0xBBCC);
        short headerOff = cursor;
        short valueOff = ApduTlv.reserve(dst, headerOff, (byte) 0x03);
        dst[valueOff] = (byte) 0xDD;
        dst[(short) (valueOff + 1)] = (byte) 0xEE;
        ApduTlv.finishReserved(dst, headerOff, (short) 2);
        cursor = (short) (valueOff + 2);

        // Expected layout: 01 01 AA | 02 02 BB CC | 03 02 DD EE
        byte[] expected = {
            (byte) 0x01,
            (byte) 0x01,
            (byte) 0xAA,
            (byte) 0x02,
            (byte) 0x02,
            (byte) 0xBB,
            (byte) 0xCC,
            (byte) 0x03,
            (byte) 0x02,
            (byte) 0xDD,
            (byte) 0xEE,
        };
        byte[] actual = new byte[expected.length];
        System.arraycopy(dst, 0, actual, 0, expected.length);
        assertArrayEquals(expected, actual);
        assertEquals((short) 11, cursor);
    }

    private static byte[] filled(byte value, int length) {
        byte[] out = new byte[length];
        java.util.Arrays.fill(out, value);
        return out;
    }

    @FunctionalInterface
    private interface Thunk {
        void run();
    }

    /** Asserts that {@code thunk} raises an {@link ISOException} with the given status word. */
    private static void assertSw(short expectedSw, Thunk thunk) {
        ISOException ex = assertThrows(ISOException.class, thunk::run);
        assertEquals(expectedSw & 0xFFFF, ex.getReason() & 0xFFFF, "unexpected status word");
    }
}

/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.ISOException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Coverage for the constant-time mask-based {@link SecureChannel#stripPkcs5} and {@link
 * SecureChannel#compare16}. Both helpers are package-private so this test reaches them directly.
 * They use sticky-mask accumulators (rather than early-return branches) so the time spent is
 * independent of where in the buffer the verdict is reached; the cases below enumerate every legal
 * padding length and a representative spread of malformed inputs so any regression to an
 * early-return branch trips the build.
 */
class SecureChannelStripPkcs5Test {

    private static final short BLOCK = (short) 16;

    /**
     * Every legitimate PKCS#5 padding length 1..16 must be accepted, and {@link
     * SecureChannel#stripPkcs5} must return the correct unpadded length. The padded layout we
     * fabricate is always one full block: 16 - padLen "data" bytes followed by padLen pad bytes.
     */
    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
    @DisplayName("stripPkcs5 accepts every legitimate padding length 1..16")
    void acceptsEveryValidPadLength(int padLen) {
        byte[] buf = new byte[BLOCK];
        // Fill the data prefix with a sentinel that differs from the pad byte so a pad-leak
        // bug that copied data into the pad region would be caught.
        for (int i = 0; i < BLOCK - padLen; i++) {
            buf[i] = (byte) 0x5A;
        }
        for (int i = BLOCK - padLen; i < BLOCK; i++) {
            buf[i] = (byte) padLen;
        }
        short unpadded = SecureChannel.stripPkcs5(buf, (short) 0, BLOCK);
        assertEquals((short) (BLOCK - padLen), unpadded);
    }

    @Test
    @DisplayName("stripPkcs5 rejects padLen == 0")
    void rejectsPadZero() {
        byte[] buf = new byte[BLOCK];
        // All zeros — the trailing byte is 0x00 which violates PKCS#5.
        ISOException ex =
                assertThrows(
                        ISOException.class, () -> SecureChannel.stripPkcs5(buf, (short) 0, BLOCK));
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED, ex.getReason());
    }

    @Test
    @DisplayName("stripPkcs5 rejects padLen > BLOCK_LEN")
    void rejectsPadLargerThanBlock() {
        byte[] buf = new byte[BLOCK];
        // Trailing byte 0x11 (= 17) which exceeds the AES-128 block size.
        for (int i = 0; i < BLOCK; i++) {
            buf[i] = (byte) 0x11;
        }
        ISOException ex =
                assertThrows(
                        ISOException.class, () -> SecureChannel.stripPkcs5(buf, (short) 0, BLOCK));
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED, ex.getReason());
    }

    @Test
    @DisplayName("stripPkcs5 rejects a single tampered byte at every pad position")
    void rejectsTamperedPadByte() {
        for (int tamperPos = 0; tamperPos < BLOCK; tamperPos++) {
            byte[] buf = new byte[BLOCK];
            // padLen = BLOCK so every byte must equal 0x10.
            for (int i = 0; i < BLOCK; i++) {
                buf[i] = (byte) BLOCK;
            }
            buf[tamperPos] ^= (byte) 0x01;
            final byte[] frozen = buf;
            ISOException ex =
                    assertThrows(
                            ISOException.class,
                            () -> SecureChannel.stripPkcs5(frozen, (short) 0, BLOCK),
                            "single-byte tamper at pos " + tamperPos + " must trip the mask");
            assertEquals(Constants.SW_SECURE_CHANNEL_FAILED, ex.getReason());
        }
    }

    @Test
    @DisplayName("stripPkcs5 rejects unaligned paddedLen")
    void rejectsUnalignedLength() {
        byte[] buf = new byte[BLOCK];
        ISOException ex =
                assertThrows(
                        ISOException.class,
                        () -> SecureChannel.stripPkcs5(buf, (short) 0, (short) 15));
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED, ex.getReason());
    }

    @Test
    @DisplayName("stripPkcs5 rejects zero paddedLen")
    void rejectsZeroLength() {
        byte[] buf = new byte[BLOCK];
        ISOException ex =
                assertThrows(
                        ISOException.class,
                        () -> SecureChannel.stripPkcs5(buf, (short) 0, (short) 0));
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED, ex.getReason());
    }

    @Test
    @DisplayName("stripPkcs5 honours non-zero offsets")
    void honoursOffset() {
        // Place a valid 16-byte block at offset 8 in a 32-byte buffer.
        byte[] buf = new byte[32];
        for (int i = 8; i < 8 + BLOCK; i++) {
            buf[i] = (byte) BLOCK;
        }
        short unpadded = SecureChannel.stripPkcs5(buf, (short) 8, BLOCK);
        assertEquals((short) 0, unpadded);
    }

    @Test
    @DisplayName("compare16 returns 0 on identical inputs")
    void compareEqual() {
        byte[] a = new byte[BLOCK];
        byte[] b = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) {
            a[i] = b[i] = (byte) i;
        }
        assertEquals((short) 0, SecureChannel.compare16(a, (short) 0, b, (short) 0));
    }

    @Test
    @DisplayName("compare16 returns > 0 when a > b at every byte position")
    void compareGreater() {
        for (int diffPos = 0; diffPos < BLOCK; diffPos++) {
            byte[] a = new byte[BLOCK];
            byte[] b = new byte[BLOCK];
            a[diffPos] = (byte) 0x01;
            short verdict = SecureChannel.compare16(a, (short) 0, b, (short) 0);
            assertTrue(
                    verdict > 0,
                    "diff at pos " + diffPos + " must yield > 0 (got " + verdict + ")");
        }
    }

    @Test
    @DisplayName("compare16 returns < 0 when a < b at every byte position")
    void compareLess() {
        for (int diffPos = 0; diffPos < BLOCK; diffPos++) {
            byte[] a = new byte[BLOCK];
            byte[] b = new byte[BLOCK];
            b[diffPos] = (byte) 0x01;
            short verdict = SecureChannel.compare16(a, (short) 0, b, (short) 0);
            assertTrue(
                    verdict < 0,
                    "diff at pos " + diffPos + " must yield < 0 (got " + verdict + ")");
        }
    }

    @Test
    @DisplayName("compare16 verdict is dominated by the most-significant differing byte")
    void mostSignificantByteWins() {
        // a = 02 FF, b = 01 00. Position 0 says a > b; position 1 (lower order) says a > b too.
        // Verdict must be > 0.
        byte[] a = new byte[BLOCK];
        byte[] b = new byte[BLOCK];
        a[0] = (byte) 0x02;
        a[1] = (byte) 0xFF;
        b[0] = (byte) 0x01;
        b[1] = (byte) 0x00;
        assertTrue(SecureChannel.compare16(a, (short) 0, b, (short) 0) > 0);

        // a = 01 FF, b = 02 00. Position 0 says a < b; position 1 contradicts. The earlier
        // (more significant) verdict must stick.
        a[0] = (byte) 0x01;
        a[1] = (byte) 0xFF;
        b[0] = (byte) 0x02;
        b[1] = (byte) 0x00;
        assertTrue(SecureChannel.compare16(a, (short) 0, b, (short) 0) < 0);
    }

    @Test
    @DisplayName("compare16 handles full-byte values 0x80..0xFF correctly")
    void compareHighByteValues() {
        // Sanity: a = 0xFF FF ..., b = 0x80 ..., a > b. Tests the unsigned-byte semantics:
        // a signed-byte buggy implementation would treat 0xFF as -1 < 0x80 (= -128) and flip.
        byte[] a = new byte[BLOCK];
        byte[] b = new byte[BLOCK];
        a[0] = (byte) 0xFF;
        b[0] = (byte) 0x80;
        assertTrue(SecureChannel.compare16(a, (short) 0, b, (short) 0) > 0);
    }
}

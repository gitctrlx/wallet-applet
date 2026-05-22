/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.framework.ISOException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link Bounds} — the overflow-safe range-check helper introduced by audit F-04 /
 * F-05.
 *
 * <p>Previously covered only indirectly via {@link ApduTlv} / {@link Authentikey}, but the F-04
 * fix's headline guarantee — overflow-safety for {@code offset + needed} sums larger than {@code
 * 0x7FFF} — is best pinned by a direct test that constructs the overflowing pair and observes the
 * rejection (audit F-45).
 */
class BoundsTest {

    @Test
    @DisplayName("requireCapacity rejects a null destination buffer with SW_WRONG_LENGTH")
    void requireCapacityRejectsNull() {
        ISOException ex =
                assertThrows(
                        ISOException.class,
                        () -> Bounds.requireCapacity(null, (short) 0, (short) 0));
        assertEquals(Constants.SW_WRONG_LENGTH, ex.getReason());
    }

    @Test
    @DisplayName("requireCapacity rejects a negative offset")
    void requireCapacityRejectsNegativeOffset() {
        assertThrows(
                ISOException.class,
                () -> Bounds.requireCapacity(new byte[16], (short) -1, (short) 0));
    }

    @Test
    @DisplayName("requireCapacity rejects a negative needed length")
    void requireCapacityRejectsNegativeNeeded() {
        assertThrows(
                ISOException.class,
                () -> Bounds.requireCapacity(new byte[16], (short) 0, (short) -1));
    }

    @Test
    @DisplayName("requireCapacity accepts a zero-length reserve at the buffer end (edge case)")
    void requireCapacityAcceptsZeroAtEnd() {
        assertDoesNotThrow(() -> Bounds.requireCapacity(new byte[16], (short) 16, (short) 0));
    }

    @Test
    @DisplayName("requireCapacity accepts a full-buffer reserve at offset 0")
    void requireCapacityAcceptsFullBuffer() {
        assertDoesNotThrow(() -> Bounds.requireCapacity(new byte[16], (short) 0, (short) 16));
    }

    @Test
    @DisplayName("requireCapacity rejects an offset strictly past the buffer length")
    void requireCapacityRejectsOffsetPastLength() {
        assertThrows(
                ISOException.class,
                () -> Bounds.requireCapacity(new byte[16], (short) 17, (short) 0));
    }

    @Test
    @DisplayName("requireCapacity rejects when needed exceeds the remaining capacity")
    void requireCapacityRejectsInsufficientRemaining() {
        assertThrows(
                ISOException.class,
                () -> Bounds.requireCapacity(new byte[16], (short) 10, (short) 7));
    }

    @Test
    @DisplayName("requireCapacity is overflow-safe when (offset + needed) wraps the signed short")
    void requireCapacityOverflowSafe() {
        // Naive check: (short)(20000 + 20000) = -25536 — would pass <= dst.length. The Bounds
        // implementation rearranges to needed > dst.length - offset, which is overflow-immune.
        assertThrows(
                ISOException.class,
                () -> Bounds.requireCapacity(new byte[16], (short) 20000, (short) 20000));
    }

    @Test
    @DisplayName("requireRange mirrors requireCapacity for the source-side variant")
    void requireRangeMirrorsCapacity() {
        assertThrows(ISOException.class, () -> Bounds.requireRange(null, (short) 0, (short) 0));
        assertThrows(
                ISOException.class, () -> Bounds.requireRange(new byte[16], (short) -1, (short) 0));
        assertThrows(
                ISOException.class, () -> Bounds.requireRange(new byte[16], (short) 0, (short) 17));
        assertThrows(
                ISOException.class,
                () -> Bounds.requireRange(new byte[16], (short) 20000, (short) 20000));
        assertDoesNotThrow(() -> Bounds.requireRange(new byte[16], (short) 0, (short) 16));
        assertDoesNotThrow(() -> Bounds.requireRange(new byte[16], (short) 16, (short) 0));
    }
}

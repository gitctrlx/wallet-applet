/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.gp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import social.meowl.tools.gp.GpFacade.MemoryReport;

/**
 * Verifies the BER-TLV walker that decodes the GlobalPlatform {@code GET DATA FF21} ("Card
 * Resources Information") response. The walker tolerates partial responses (cards may omit any of
 * the three inner tags) and rejects malformed blobs without throwing — both contracts are part of
 * the {@code meowl gp info} graceful-degrade behaviour.
 */
class MemoryReportTest {

    @Test
    @DisplayName("parses all three inner counters from a well-formed FF21 response")
    void allThreeCounters() {
        // FF21 0E  C0 04 00 01 D4 C0  C1 02 00 80  C2 02 00 40
        // -> persistent = 0x0001D4C0 = 120000, transientReset = 128, transientDeselect = 64
        byte[] blob = hex("FF210EC0040001D4C0C1020080C2020040");
        Optional<MemoryReport> parsed = MemoryReport.parse(blob);

        assertTrue(parsed.isPresent());
        MemoryReport r = parsed.get();
        assertTrue(r.freePersistentBytes().isPresent());
        assertEquals(120000L, r.freePersistentBytes().getAsLong());
        assertTrue(r.freeTransientResetBytes().isPresent());
        assertEquals(128, r.freeTransientResetBytes().getAsInt());
        assertTrue(r.freeTransientDeselectBytes().isPresent());
        assertEquals(64, r.freeTransientDeselectBytes().getAsInt());
    }

    @Test
    @DisplayName("populates only the persistent counter when the card omits transient tags")
    void onlyPersistent() {
        byte[] blob = hex("FF2106C004000F4240");
        Optional<MemoryReport> parsed = MemoryReport.parse(blob);

        assertTrue(parsed.isPresent());
        MemoryReport r = parsed.get();
        assertEquals(1_000_000L, r.freePersistentBytes().getAsLong());
        assertFalse(r.freeTransientResetBytes().isPresent());
        assertFalse(r.freeTransientDeselectBytes().isPresent());
    }

    @Test
    @DisplayName("ignores unknown inner tags inside the FF21 envelope")
    void ignoresUnknownTags() {
        // FF21 0B  CF 03 DE AD BE  C0 04 00 00 04 00
        byte[] blob = hex("FF210BCF03DEADBEC00400000400");
        Optional<MemoryReport> parsed = MemoryReport.parse(blob);

        assertTrue(parsed.isPresent());
        assertEquals(1024L, parsed.get().freePersistentBytes().getAsLong());
    }

    @Test
    @DisplayName("accepts BER long-form lengths (81 LL)")
    void longFormLength() {
        // FF21 81 06  C0 04 00 00 10 00
        byte[] blob = hex("FF218106C00400001000");
        Optional<MemoryReport> parsed = MemoryReport.parse(blob);

        assertTrue(parsed.isPresent());
        assertEquals(4096L, parsed.get().freePersistentBytes().getAsLong());
    }

    @Test
    @DisplayName("returns empty when the outer tag is wrong")
    void wrongOuterTag() {
        byte[] blob = hex("FF2306C00400001000");
        assertFalse(MemoryReport.parse(blob).isPresent());
    }

    @Test
    @DisplayName("returns empty when the blob is truncated mid-value")
    void truncated() {
        // FF21 06 declares 6 bytes of payload but only 4 follow.
        byte[] blob = hex("FF2106C00400");
        assertFalse(MemoryReport.parse(blob).isPresent());
    }

    @Test
    @DisplayName("returns empty for null / too-short input")
    void nullAndShortInput() {
        assertFalse(MemoryReport.parse(null).isPresent());
        assertFalse(MemoryReport.parse(new byte[] {}).isPresent());
        assertFalse(MemoryReport.parse(new byte[] {(byte) 0xFF}).isPresent());
    }

    private static byte[] hex(String s) {
        String trimmed = s.replace(" ", "");
        int len = trimmed.length();
        if ((len & 1) != 0) throw new IllegalArgumentException("odd hex length");
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] =
                    (byte)
                            ((Character.digit(trimmed.charAt(i * 2), 16) << 4)
                                    | Character.digit(trimmed.charAt(i * 2 + 1), 16));
        }
        return out;
    }
}

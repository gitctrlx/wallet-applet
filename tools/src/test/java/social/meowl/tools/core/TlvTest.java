/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SequencedMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Tests for the single-byte tag / single-byte length TLV codec. */
class TlvTest {

    @Nested
    @DisplayName("parse() / iterate()")
    class Parsing {

        @Test
        @DisplayName("decodes a single TLV entry")
        void single() {
            byte[] blob = {(byte) 0x01, 0x03, 0x0A, 0x0B, 0x0C};
            SequencedMap<Byte, byte[]> parsed = Tlv.parse(blob);
            assertEquals(1, parsed.size());
            assertArrayEquals(new byte[] {0x0A, 0x0B, 0x0C}, parsed.get((byte) 0x01));
        }

        @Test
        @DisplayName("decodes consecutive entries and preserves insertion order")
        void multiple() {
            byte[] blob = {0x01, 0x01, (byte) 0xAA, 0x02, 0x02, 0x11, 0x22, 0x05, 0x00};
            SequencedMap<Byte, byte[]> parsed = Tlv.parse(blob);
            assertEquals(3, parsed.size());
            // SequencedMap exposes ordered keys; verify they came out in wire order.
            var keys = parsed.sequencedKeySet().iterator();
            assertEquals((byte) 0x01, keys.next());
            assertEquals((byte) 0x02, keys.next());
            assertEquals((byte) 0x05, keys.next());
            assertArrayEquals(new byte[] {(byte) 0xAA}, parsed.get((byte) 0x01));
            assertArrayEquals(new byte[] {0x11, 0x22}, parsed.get((byte) 0x02));
            assertArrayEquals(new byte[0], parsed.get((byte) 0x05));
        }

        @Test
        @DisplayName("zero-length values are accepted")
        void zeroLength() {
            byte[] blob = {0x07, 0x00};
            assertArrayEquals(new byte[0], Tlv.parse(blob).get((byte) 0x07));
        }

        @Test
        @DisplayName("empty blob produces an empty map")
        void empty() {
            assertTrue(Tlv.parse(new byte[0]).isEmpty());
        }

        @Test
        @DisplayName("rejects truncated header (single trailing byte)")
        void truncatedHeader() {
            IllegalArgumentException ex =
                    assertThrows(
                            IllegalArgumentException.class, () -> Tlv.parse(new byte[] {0x01}));
            assertTrue(ex.getMessage().contains("Truncated"), ex::getMessage);
        }

        @Test
        @DisplayName("rejects length running past the end of the buffer")
        void overlongLength() {
            // Tag 0x01, length 0x05, but only 3 value bytes follow.
            byte[] blob = {0x01, 0x05, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC};
            IllegalArgumentException ex =
                    assertThrows(IllegalArgumentException.class, () -> Tlv.parse(blob));
            assertTrue(ex.getMessage().contains("declared length"), ex::getMessage);
        }

        @Test
        @DisplayName("0xFF length boundary is decodable")
        void maxLength() {
            byte[] value = new byte[0xFF];
            for (int i = 0; i < value.length; i++) value[i] = (byte) i;
            byte[] blob = new byte[2 + value.length];
            blob[0] = 0x09;
            blob[1] = (byte) 0xFF;
            System.arraycopy(value, 0, blob, 2, value.length);
            assertArrayEquals(value, Tlv.parse(blob).get((byte) 0x09));
        }
    }

    @Nested
    @DisplayName("encode() / encodeAll()")
    class Encoding {

        @Test
        @DisplayName("encode wraps tag/length around the value")
        void singleEntry() {
            byte[] encoded = Tlv.encode((byte) 0x42, new byte[] {0x01, 0x02});
            assertArrayEquals(new byte[] {0x42, 0x02, 0x01, 0x02}, encoded);
        }

        @Test
        @DisplayName("encode rejects values longer than 0xFF bytes")
        void overlongRejected() {
            byte[] tooLong = new byte[256];
            assertThrows(IllegalArgumentException.class, () -> Tlv.encode((byte) 0x01, tooLong));
        }

        @Test
        @DisplayName("encodeAll round-trips through parse()")
        void roundTrip() {
            Map<Byte, byte[]> entries = new LinkedHashMap<>();
            entries.put((byte) 0x01, new byte[] {0x01, 0x00});
            entries.put((byte) 0x02, new byte[] {(byte) 0xCA, (byte) 0xFE});
            entries.put((byte) 0x03, new byte[0]);

            byte[] blob = Tlv.encodeAll(entries);
            SequencedMap<Byte, byte[]> parsed = Tlv.parse(blob);
            assertEquals(3, parsed.size());
            assertArrayEquals(entries.get((byte) 0x01), parsed.get((byte) 0x01));
            assertArrayEquals(entries.get((byte) 0x02), parsed.get((byte) 0x02));
            assertArrayEquals(entries.get((byte) 0x03), parsed.get((byte) 0x03));
        }
    }

    @Test
    @DisplayName("Entry equality is structural and toString is deterministic")
    void entrySemantics() {
        Tlv.Entry a = new Tlv.Entry((byte) 0x05, new byte[] {0x11, 0x22});
        Tlv.Entry b = new Tlv.Entry((byte) 0x05, new byte[] {0x11, 0x22});
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals("Tlv(05, 1122)", a.toString());
    }
}

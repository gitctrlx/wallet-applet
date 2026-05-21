/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Round-trip and edge-case tests for {@link Hex}. */
class HexTest {

    @Nested
    @DisplayName("decode()")
    class Decode {

        @ParameterizedTest(name = "decode(\"{0}\") accepts {1}-byte payload")
        @CsvSource({
            "00, 1",
            "DEADBEEF, 4",
            "0xDEADBEEF, 4",
            "0XDEADBEEF, 4",
            "F06D656F776C01, 7",
        })
        @DisplayName("accepts uppercase, lowercase, and 0x-prefixed inputs")
        void roundTrip(String hex, int expectedLength) {
            byte[] bytes = Hex.decode(hex);
            assertEquals(expectedLength, bytes.length);
        }

        @Test
        @DisplayName("decodes the empty string to a zero-length array")
        void emptyString() {
            assertArrayEquals(new byte[0], Hex.decode(""));
            assertArrayEquals(new byte[0], Hex.decode("0x"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"0", "abc", "deadbeefF", "0xDEADBEEFF"})
        @DisplayName("rejects odd-length input with a descriptive message")
        void oddLengthRejected(String hex) {
            IllegalArgumentException ex =
                    assertThrows(IllegalArgumentException.class, () -> Hex.decode(hex));
            assertTrue(ex.getMessage().contains("odd length"), ex::getMessage);
        }

        @ParameterizedTest
        @ValueSource(strings = {"GG", "DEADBEGG", "AB-CD-EF", "ZZZZ"})
        @DisplayName("rejects non-hex characters in even-length input")
        void nonHexRejected(String hex) {
            IllegalArgumentException ex =
                    assertThrows(IllegalArgumentException.class, () -> Hex.decode(hex));
            assertTrue(ex.getMessage().contains("non-hex"), ex::getMessage);
        }

        @Test
        @DisplayName("null input throws NPE with the parameter name")
        void nullRejected() {
            NullPointerException ex =
                    assertThrows(NullPointerException.class, () -> Hex.decode(null));
            assertEquals("hex", ex.getMessage());
        }
    }

    @Nested
    @DisplayName("encode()")
    class Encode {

        @Test
        @DisplayName("returns uppercase hex with no separators")
        void roundTrip() {
            byte[] bytes = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
            assertEquals("DEADBEEF", Hex.encode(bytes));
        }

        @Test
        @DisplayName("encodes the empty array to the empty string")
        void empty() {
            assertEquals("", Hex.encode(new byte[0]));
        }

        @Test
        @DisplayName("decode(encode(x)) == x for arbitrary bytes")
        void roundTripIdentity() {
            byte[] bytes = new byte[256];
            for (int i = 0; i < 256; i++) bytes[i] = (byte) i;
            assertArrayEquals(bytes, Hex.decode(Hex.encode(bytes)));
        }

        @Test
        @DisplayName("encodeWithSeparator inserts the separator between bytes only")
        void encodeWithSeparator() {
            byte[] bytes = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
            assertEquals("DE:AD:BE:EF", Hex.encodeWithSeparator(bytes, ':'));
        }

        @Test
        @DisplayName("encodeByte / encodeShort produce fixed-width representations")
        void byteAndShort() {
            assertEquals("01", Hex.encodeByte((byte) 0x01));
            assertEquals("FF", Hex.encodeByte((byte) 0xFF));
            assertEquals("9000", Hex.encodeShort((short) 0x9000));
            assertEquals("0001", Hex.encodeShort((short) 0x0001));
        }
    }

    @Test
    @DisplayName("0x prefix is case-insensitive and stripped exactly once")
    void prefixHandling() {
        assertArrayEquals(new byte[] {0x42}, Hex.decode("0x42"));
        assertArrayEquals(new byte[] {0x42}, Hex.decode("0X42"));
        // A leading 0x followed by another 0x is interpreted as data, not a second prefix.
        byte[] decoded = Hex.decode("0x0042");
        assertNotNull(decoded);
        assertEquals(2, decoded.length);
    }
}

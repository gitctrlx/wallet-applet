/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

/** Tests for the host-side mirror of the applet status-word table. */
class MeowlSwTest {

    @ParameterizedTest
    @EnumSource(MeowlSw.class)
    @DisplayName("ofValue round-trips every catalogued SW")
    void ofValueRoundTrip(MeowlSw sw) {
        assertEquals(sw, MeowlSw.ofValue(sw.value()).orElseThrow());
    }

    @Test
    @DisplayName("isSuccess returns true only for 9000")
    void isSuccess() {
        assertTrue(MeowlSw.isSuccess(0x9000));
        assertFalse(MeowlSw.isSuccess(0x9001));
        assertFalse(MeowlSw.isSuccess(0x6982));
        assertFalse(MeowlSw.isSuccess(0x0000));
    }

    @Nested
    @DisplayName("describe()")
    class Describe {

        @ParameterizedTest(name = "describe(0x{0}) → contains \"{1}\"")
        @CsvSource({
            "9000, Success",
            "6700, Wrong length",
            "6982, Security status not satisfied",
            "6985, Condition of use",
            "6A86, Incorrect P1 or P2",
            "6D00, INS not supported",
            "6E00, CLA not supported",
            "6FB0, Lifecycle state forbids",
            "6FB1, Secure Channel required",
            "6FB2, Secure Channel cryptographic check failed",
            "6FE0, JavaCard feature not available",
            "6FE1, Internal sentinel",
        })
        @DisplayName("recognises every catalogued status word")
        void catalogued(String hex, String fragment) {
            int sw = Integer.parseInt(hex, 16);
            String text = MeowlSw.describe(sw);
            assertTrue(text.contains(fragment), text);
            assertTrue(text.contains(hex), text);
        }

        @Test
        @DisplayName("decodes the 6FAn reset-countdown family with remaining count")
        void resetCountdown() {
            assertTrue(
                    MeowlSw.describe(0x6FA3).contains("3 invocation(s) remaining"),
                    MeowlSw.describe(0x6FA3));
            assertTrue(
                    MeowlSw.describe(0x6FA0).contains("wipe complete"), MeowlSw.describe(0x6FA0));
        }

        @Test
        @DisplayName("decodes the 63Cn PIN-retries family with remaining count")
        void pinRetries() {
            assertTrue(MeowlSw.describe(0x63C2).contains("2 attempt(s) remaining"));
            assertTrue(MeowlSw.describe(0x63C0).contains("0 attempt(s) remaining"));
        }

        @Test
        @DisplayName("falls back to \"Unknown SW\" with the raw hex")
        void unknown() {
            String text = MeowlSw.describe(0x9999);
            assertTrue(text.contains("0x9999"));
            assertTrue(text.contains("Unknown"), text);
        }

        @Test
        @DisplayName("ignores high-order bits beyond 16")
        void highBitsIgnored() {
            // ResponseAPDU#getSW() is `int` in apdu4j; ensure we mask before lookup.
            assertEquals(MeowlSw.describe(0x9000), MeowlSw.describe(0x12349000));
        }
    }
}

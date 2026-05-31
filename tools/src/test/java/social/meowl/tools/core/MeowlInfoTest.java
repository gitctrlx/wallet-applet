/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Tests for the decoded {@code GET_INFO} model. */
class MeowlInfoTest {

    private static byte[] authentikey() {
        byte[] ak = new byte[33];
        ak[0] = 0x02;
        for (int i = 1; i < ak.length; i++) {
            ak[i] = (byte) i;
        }
        return ak;
    }

    private static Map<Byte, byte[]> fullTags() {
        Map<Byte, byte[]> tags = new LinkedHashMap<>();
        tags.put(MeowlInfo.TAG_PROTOCOL_VERSION, new byte[] {0x01, 0x00});
        tags.put(MeowlInfo.TAG_APPLET_VERSION, new byte[] {0x00, 0x01});
        tags.put(MeowlInfo.TAG_LIFECYCLE, new byte[] {0x03});
        tags.put(MeowlInfo.TAG_CAPABILITIES, new byte[] {0x01, (byte) 0xF7});
        tags.put(MeowlInfo.TAG_AUTHENTIKEY, authentikey());
        return tags;
    }

    @Nested
    @DisplayName("parse() of a well-formed response")
    class WellFormed {

        private final MeowlInfo info = MeowlInfo.parse(Tlv.encodeAll(fullTags()));

        @Test
        @DisplayName("decodes the two-byte versions")
        void versions() {
            assertEquals("1.0", info.protocolVersion().toString());
            assertEquals("0.1", info.appletVersion().toString());
        }

        @Test
        @DisplayName("resolves the lifecycle to a known state")
        void lifecycle() {
            assertEquals(3, info.lifecycleCode());
            assertEquals(MeowlLifecycle.SEEDED, info.lifecycle().orElseThrow());
            assertEquals("SEEDED", info.lifecycleName());
        }

        @Test
        @DisplayName("decodes the capability bitmask")
        void capabilities() {
            assertEquals(0x01F7, info.capabilityBits());
            assertTrue(info.capabilities().contains(MeowlCapability.SLIP10));
            assertFalse(info.capabilities().contains(MeowlCapability.SC_GCM));
        }

        @Test
        @DisplayName("returns a defensive copy of the authentikey")
        void authentikeyDefensiveCopy() {
            byte[] first = info.authentikey();
            first[0] = (byte) 0xFF;
            assertEquals(0x02, info.authentikey()[0] & 0xFF);
        }
    }

    @Test
    @DisplayName("renders UNKNOWN(0xNN) for an unrecognised lifecycle code")
    void unknownLifecycleName() {
        Map<Byte, byte[]> tags = fullTags();
        tags.put(MeowlInfo.TAG_LIFECYCLE, new byte[] {0x7F});
        MeowlInfo info = MeowlInfo.parse(Tlv.encodeAll(tags));
        assertTrue(info.lifecycle().isEmpty());
        assertEquals("UNKNOWN(0x7F)", info.lifecycleName());
    }

    @Nested
    @DisplayName("strict parsing")
    class Strict {

        @Test
        @DisplayName("rejects a response missing a required tag")
        void missingTag() {
            Map<Byte, byte[]> tags = fullTags();
            tags.remove(MeowlInfo.TAG_AUTHENTIKEY);
            IllegalArgumentException ex =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> MeowlInfo.parse(Tlv.encodeAll(tags)));
            assertTrue(ex.getMessage().contains("authentikey"), ex::getMessage);
        }

        @Test
        @DisplayName("rejects a mis-sized fixed-length tag")
        void wrongLength() {
            Map<Byte, byte[]> tags = fullTags();
            tags.put(MeowlInfo.TAG_LIFECYCLE, new byte[] {0x01, 0x02});
            IllegalArgumentException ex =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> MeowlInfo.parse(Tlv.encodeAll(tags)));
            assertTrue(ex.getMessage().contains("lifecycle"), ex::getMessage);
        }
    }
}

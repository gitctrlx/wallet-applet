/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests for the host-side mirror of the applet capability bitmask. */
class MeowlCapabilityTest {

    @Test
    @DisplayName("decode expands the 0x01F7 reference bitmask in ascending mask order")
    void decodeReferenceBitmask() {
        // 0x01F7 is the capability set documented in protocol.md §5 (every bit except SC_GCM).
        assertEquals(
                List.of(
                        MeowlCapability.ECDSA_K1,
                        MeowlCapability.SCHNORR_K1,
                        MeowlCapability.ED25519,
                        MeowlCapability.SC_CBC_HMAC,
                        MeowlCapability.PKI,
                        MeowlCapability.RESET_TO_FACTORY,
                        MeowlCapability.BIP32,
                        MeowlCapability.SLIP10),
                MeowlCapability.decode(0x01F7));
    }

    @Test
    @DisplayName("decode of zero yields no capabilities")
    void decodeZero() {
        assertTrue(MeowlCapability.decode(0).isEmpty());
    }

    @Test
    @DisplayName("decode of a single bit yields exactly that capability")
    void decodeSingleBit() {
        assertEquals(List.of(MeowlCapability.ED25519), MeowlCapability.decode(0x0004));
    }

    @Test
    @DisplayName("every capability occupies a distinct single bit")
    void masksAreDistinctSingleBits() {
        int union = 0;
        for (MeowlCapability cap : MeowlCapability.values()) {
            assertEquals(1, Integer.bitCount(cap.mask()), cap + " mask must be a single bit");
            assertEquals(0, union & cap.mask(), cap + " mask overlaps another capability");
            union |= cap.mask();
        }
    }

    @Test
    @DisplayName("unknownBits surfaces bits not mapped to a capability")
    void unknownBits() {
        assertEquals(0x0200, MeowlCapability.unknownBits(0x0200));
        assertEquals(0, MeowlCapability.unknownBits(0x01F7));
        assertEquals(0x0200, MeowlCapability.unknownBits(0x03F7));
    }
}

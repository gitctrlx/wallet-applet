/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Tests for the host-side mirror of the applet lifecycle states. */
class MeowlLifecycleTest {

    @ParameterizedTest
    @EnumSource(MeowlLifecycle.class)
    @DisplayName("ofCode round-trips every lifecycle state")
    void ofCodeRoundTrip(MeowlLifecycle state) {
        assertEquals(state, MeowlLifecycle.ofCode(state.code()).orElseThrow());
    }

    @Test
    @DisplayName("wire codes match the protocol.md §4 ordering")
    void wireCodes() {
        assertEquals(0, MeowlLifecycle.UNINITIALIZED.code());
        assertEquals(1, MeowlLifecycle.PERSONALIZED.code());
        assertEquals(2, MeowlLifecycle.SETUP_DONE.code());
        assertEquals(3, MeowlLifecycle.SEEDED.code());
    }

    @Test
    @DisplayName("ofCode returns empty for an unknown code")
    void unknownCode() {
        assertTrue(MeowlLifecycle.ofCode(99).isEmpty());
        assertTrue(MeowlLifecycle.ofCode(-1).isEmpty());
    }
}

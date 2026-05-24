/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the pure {@link LifecycleState#isLegalForward(byte, byte)} forward-progression
 * rule. The stateful {@code transitionToInTx} / {@code resetInTx} flow is covered end-to-end on
 * physical silicon by the personalisation and reset INS handlers exercised in {@link
 * MeowlAppletTest} and {@link PersonalisationTest}; there is no in-JVM unit-test path because
 * jcardsim's RSA backend rejects the prime modulus that the surrounding applet install loads.
 */
class LifecycleStateTest {

    @Nested
    @DisplayName("isLegalForward(): pure forward-progression rule")
    class IsLegalForward {

        @Test
        @DisplayName("each adjacent forward step is legal")
        void adjacentForwardLegal() {
            assertTrue(
                    LifecycleState.isLegalForward(
                            LifecycleState.UNINITIALIZED, LifecycleState.PERSONALIZED));
            assertTrue(
                    LifecycleState.isLegalForward(
                            LifecycleState.PERSONALIZED, LifecycleState.SETUP_DONE));
            assertTrue(
                    LifecycleState.isLegalForward(
                            LifecycleState.SETUP_DONE, LifecycleState.SEEDED));
        }

        @Test
        @DisplayName("self-transitions are illegal")
        void selfTransitionIllegal() {
            assertFalse(
                    LifecycleState.isLegalForward(
                            LifecycleState.UNINITIALIZED, LifecycleState.UNINITIALIZED));
            assertFalse(
                    LifecycleState.isLegalForward(LifecycleState.SEEDED, LifecycleState.SEEDED));
        }

        @Test
        @DisplayName("backward transitions are illegal")
        void backwardIllegal() {
            assertFalse(
                    LifecycleState.isLegalForward(
                            LifecycleState.SEEDED, LifecycleState.SETUP_DONE));
            assertFalse(
                    LifecycleState.isLegalForward(
                            LifecycleState.PERSONALIZED, LifecycleState.UNINITIALIZED));
        }

        @Test
        @DisplayName("skipping a state is illegal")
        void skippingIllegal() {
            assertFalse(
                    LifecycleState.isLegalForward(
                            LifecycleState.UNINITIALIZED, LifecycleState.SETUP_DONE));
            assertFalse(
                    LifecycleState.isLegalForward(
                            LifecycleState.UNINITIALIZED, LifecycleState.SEEDED));
        }

        @Test
        @DisplayName("transitions past SEEDED are illegal")
        void pastTerminalIllegal() {
            assertFalse(
                    LifecycleState.isLegalForward(
                            LifecycleState.SEEDED, (byte) (LifecycleState.SEEDED + 1)));
        }

        private static void assertTrue(boolean condition) {
            assertEquals(true, condition);
        }

        private static void assertFalse(boolean condition) {
            assertEquals(false, condition);
        }
    }
}

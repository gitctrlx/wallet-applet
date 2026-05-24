/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the {@link LifecycleState} finite state machine.
 *
 * <p>The pure {@link LifecycleState#isLegalForward(byte, byte)} decision function is exercised
 * directly. The stateful {@code transitionToInTx} / {@code resetInTx} flow is exercised inside a
 * {@link CardSimulator} so the JavaCard transaction machinery is engaged exactly as it would be on
 * real silicon. Every mutator demands a caller-held transaction; the tests open one explicitly per
 * call to match the production contract advertised by {@link LifecycleState}.
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

    @Nested
    @DisplayName("transitionToInTx() / resetInTx(): stateful behaviour under CardSimulator")
    class Stateful {

        private LifecycleState newInstance() {
            // We need the JavaCard transaction machinery active, so spin up a tiny applet that
            // simply exposes a fresh LifecycleState. Loading it through the simulator engages the
            // same code paths real silicon would take.
            CardSimulator simulator = new CardSimulator();
            AID aid = AIDUtil.create(new byte[] {(byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01});
            simulator.installApplet(aid, MeowlApplet.class);
            simulator.selectApplet(aid);
            return new LifecycleState();
        }

        /** Drives one {@code transitionToInTx} call inside a manual transaction. */
        private static void advance(LifecycleState s, byte target) {
            JCSystem.beginTransaction();
            try {
                s.transitionToInTx(target);
                JCSystem.commitTransaction();
            } catch (RuntimeException e) {
                JCSystem.abortTransaction();
                throw e;
            }
        }

        @Test
        @DisplayName("a fresh instance is UNINITIALIZED")
        void freshIsUninitialized() {
            assertEquals(LifecycleState.UNINITIALIZED, newInstance().current());
        }

        @Test
        @DisplayName("each legal forward step updates the state")
        void forwardUpdatesState() {
            LifecycleState s = newInstance();
            advance(s, LifecycleState.PERSONALIZED);
            assertEquals(LifecycleState.PERSONALIZED, s.current());
            advance(s, LifecycleState.SETUP_DONE);
            assertEquals(LifecycleState.SETUP_DONE, s.current());
            advance(s, LifecycleState.SEEDED);
            assertEquals(LifecycleState.SEEDED, s.current());
        }

        @Test
        @DisplayName("illegal transitions throw SW_LIFECYCLE_INVALID and leave state untouched")
        void illegalTransitionThrows() {
            LifecycleState s = newInstance();
            JCSystem.beginTransaction();
            try {
                ISOException ex =
                        assertThrows(
                                ISOException.class,
                                () -> s.transitionToInTx(LifecycleState.SEEDED));
                assertEquals(Constants.SW_LIFECYCLE_INVALID, ex.getReason());
            } finally {
                JCSystem.abortTransaction();
            }
            assertEquals(LifecycleState.UNINITIALIZED, s.current());
        }

        @Test
        @DisplayName("resetInTx() collapses any forward state back to UNINITIALIZED")
        void resetCollapses() {
            LifecycleState s = newInstance();
            advance(s, LifecycleState.PERSONALIZED);
            advance(s, LifecycleState.SETUP_DONE);
            advance(s, LifecycleState.SEEDED);
            JCSystem.beginTransaction();
            try {
                s.resetInTx();
                JCSystem.commitTransaction();
            } catch (RuntimeException e) {
                JCSystem.abortTransaction();
                throw e;
            }
            assertEquals(LifecycleState.UNINITIALIZED, s.current());
        }
    }
}

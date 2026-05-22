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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ResetToFactory} — the multi-step destructive-wipe trigger specified in
 * {@code docs/specs/meap-3.md}.
 *
 * <p>{@link MeowlAppletTest.ResetToFactory} already exercises the end-to-end APDU path; this file
 * pins the unit-level invariants directly against the {@link ResetToFactory} class:
 *
 * <ul>
 *   <li>countdown sequence and final wipe status word;
 *   <li>{@link ResetToFactory#rearm} restores the counter to {@link
 *       Constants#RESET_REQUIRED_INVOCATIONS};
 *   <li>the counter is rearmed <em>before</em> {@link WipeTrigger#wipe} runs so an exception out of
 *       {@code wipe()} cannot leave {@code remaining[0] = 0} and emit a spurious {@code 0x6FFF} on
 *       the next invocation.
 * </ul>
 *
 * <p>A {@link CardSimulator} is span up only to provide the JC transient-memory environment that
 * {@link ResetToFactory#ResetToFactory()} requires for its {@code CLEAR_ON_RESET} counter.
 */
class ResetToFactoryTest {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private ResetToFactory trigger;
    private CountingWipe wipe;

    private static final class CountingWipe implements WipeTrigger {
        int callCount;
        boolean shouldThrow;

        @Override
        public void wipe() {
            callCount++;
            if (shouldThrow) {
                throw new RuntimeException("simulated wipe failure");
            }
        }
    }

    @BeforeEach
    void setUp() {
        CardSimulator simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_BYTES);
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
        trigger = new ResetToFactory();
        wipe = new CountingWipe();
    }

    @Test
    @DisplayName("fresh trigger reports the configured countdown threshold")
    void freshArmedCounter() {
        assertEquals(Constants.RESET_REQUIRED_INVOCATIONS, trigger.remaining());
    }

    @Test
    @DisplayName("countdown sequence: every step throws SW_RESET_COUNTDOWN_BASE + remaining")
    void countdownSequence() {
        for (int expected = Constants.RESET_REQUIRED_INVOCATIONS - 1; expected > 0; expected--) {
            ISOException ex =
                    assertThrows(ISOException.class, () -> trigger.recordInvocation(wipe));
            assertEquals((short) (Constants.SW_RESET_COUNTDOWN_BASE + expected), ex.getReason());
            assertEquals(0, wipe.callCount, "wipe must not run while counter > 0");
        }
        ISOException terminal =
                assertThrows(ISOException.class, () -> trigger.recordInvocation(wipe));
        assertEquals(Constants.SW_RESET_COUNTDOWN_BASE, terminal.getReason());
        assertEquals(1, wipe.callCount, "wipe must run exactly once on the terminal invocation");
    }

    @Test
    @DisplayName("after the terminal wipe the counter is rearmed for the next round")
    void terminalRearm() {
        for (int i = 0; i < Constants.RESET_REQUIRED_INVOCATIONS; i++) {
            assertThrows(ISOException.class, () -> trigger.recordInvocation(wipe));
        }
        assertEquals(Constants.RESET_REQUIRED_INVOCATIONS, trigger.remaining());
    }

    @Test
    @DisplayName("rearm() restores the counter from any partial countdown state")
    void rearmRestoresCounter() {
        assertThrows(ISOException.class, () -> trigger.recordInvocation(wipe));
        assertEquals(
                (byte) (Constants.RESET_REQUIRED_INVOCATIONS - 1),
                trigger.remaining(),
                "counter should have decremented once");
        trigger.rearm();
        assertEquals(Constants.RESET_REQUIRED_INVOCATIONS, trigger.remaining());
    }

    @Test
    @DisplayName("wipe() exception leaves counter rearmed, NOT at zero")
    void wipeExceptionDoesNotCorruptCounter() {
        wipe.shouldThrow = true;
        for (int i = 0; i < Constants.RESET_REQUIRED_INVOCATIONS - 1; i++) {
            assertThrows(ISOException.class, () -> trigger.recordInvocation(wipe));
        }
        // The terminal invocation rearms the counter, then calls wipe() which throws. The
        // propagating RuntimeException is by design — the invariant under test is purely about
        // the counter state after the throw.
        assertThrows(RuntimeException.class, () -> trigger.recordInvocation(wipe));
        assertEquals(
                Constants.RESET_REQUIRED_INVOCATIONS,
                trigger.remaining(),
                "counter must be rearmed BEFORE wipe() to prevent 0x6FFF on the next"
                        + " invocation");
        assertEquals(1, wipe.callCount);
    }
}

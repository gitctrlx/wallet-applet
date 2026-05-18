/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/**
 * Coordinates the {@code RESET_TO_FACTORY} multi-step trigger described in {@code
 * docs/adr/0008-reset-to-factory-multi-step.md}.
 *
 * <p>Semantics:
 *
 * <ul>
 *   <li>Each {@code RESET_TO_FACTORY} APDU calls {@link #recordInvocation(WipeTrigger)} which
 *       decrements an internal counter.
 *   <li>Any non-{@code RESET_TO_FACTORY} APDU calls {@link #rearm()} to reset the counter back to
 *       {@link Constants#RESET_REQUIRED_INVOCATIONS}.
 *   <li>The status word returned to the host is always {@code SW_RESET_COUNTDOWN_BASE + remaining},
 *       communicating the countdown verbatim.
 *   <li>When {@code remaining} reaches zero the supplied {@link WipeTrigger} is invoked to perform
 *       the destructive wipe, the counter is rearmed, and the terminal status word {@code
 *       SW_RESET_COUNTDOWN_BASE + 0} is thrown.
 * </ul>
 *
 * <p>The counter lives in a {@link JCSystem#CLEAR_ON_RESET}-typed transient byte array, so a power
 * loss between invocations rearms the trigger. Combined with the rearming rule, this means a
 * passive contact-only attack must hold the card for the duration of {@code N} full APDU round
 * trips with no interleaved traffic, which is the explicit design goal.
 */
public final class ResetToFactory {

    private final byte[] remaining;

    /** Constructs a fresh trigger with the counter armed to the configured threshold. */
    public ResetToFactory() {
        this.remaining = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        this.remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
    }

    /** Rearms the counter. Invoked whenever a non-{@code RESET_TO_FACTORY} APDU arrives. */
    public void rearm() {
        remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
    }

    /**
     * Records one {@code RESET_TO_FACTORY} invocation.
     *
     * <p>This method always throws {@link ISOException}; it never returns normally. Callers should
     * treat it as a tail call.
     */
    public void recordInvocation(WipeTrigger trigger) {
        byte step = (byte) (remaining[0] - 1);
        remaining[0] = step;
        if (step == 0) {
            trigger.wipe();
            remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
            ISOException.throwIt(Constants.SW_RESET_COUNTDOWN_BASE);
        }
        ISOException.throwIt((short) (Constants.SW_RESET_COUNTDOWN_BASE + (step & 0xFF)));
    }

    /** Returns the current countdown value, primarily for unit-test assertions. */
    public byte remaining() {
        return remaining[0];
    }
}

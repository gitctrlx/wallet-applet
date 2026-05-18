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
 * <p>Behaviour:
 *
 * <ul>
 *   <li>Each {@code RESET_TO_FACTORY} APDU decrements an internal counter.
 *   <li>Any non-{@code RESET_TO_FACTORY} APDU rearms the counter to {@link
 *       Constants#RESET_REQUIRED_INVOCATIONS}.
 *   <li>The status word returned is always {@code SW_RESET_COUNTDOWN_BASE + remaining}.
 *   <li>When {@code remaining} reaches zero the caller is expected to perform the wipe via {@link
 *       Runnable#run()}, after which the counter is rearmed and the terminal status word {@code
 *       SW_RESET_COUNTDOWN_BASE + 0} is thrown.
 * </ul>
 *
 * <p>The counter lives in a {@code CLEAR_ON_RESET} transient byte array. Power loss between
 * invocations therefore rearms the trigger, making a passive contact-only attack require sustained
 * physical access.
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
     * <p>If the threshold has been reached, runs {@code trigger} (the destructive operation),
     * rearms the counter, and throws {@code SW_RESET_COUNTDOWN_BASE + 0} to signal completion.
     * Otherwise throws {@code SW_RESET_COUNTDOWN_BASE + remaining} to signal the host how many more
     * invocations are needed.
     */
    public void recordInvocation(WipeTrigger trigger) {
        if (remaining[0] > 0) {
            remaining[0]--;
        }
        if (remaining[0] == 0) {
            trigger.wipe();
            remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
            ISOException.throwIt(Constants.SW_RESET_COUNTDOWN_BASE);
        }
        ISOException.throwIt((short) (Constants.SW_RESET_COUNTDOWN_BASE + remaining[0]));
    }

    /** Returns the current countdown value (useful for assertions in unit tests). */
    public byte remaining() {
        return remaining[0];
    }
}

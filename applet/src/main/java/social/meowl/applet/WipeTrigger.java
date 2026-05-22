/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Wipe callback handed to {@link ResetToFactory#recordInvocation}. Implemented by the applet's wipe
 * routine which destroys seed, PIN/PUK and PKI material once the reset counter reaches zero.
 *
 * <p>JavaCard 3.0.5 does not expose {@code java.lang.Runnable}, so we declare our own SAM.
 */
public interface WipeTrigger {

    /** Executes the destructive wipe. */
    void wipe();
}

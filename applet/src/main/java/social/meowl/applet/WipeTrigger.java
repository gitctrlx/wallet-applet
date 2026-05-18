/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Callback hook supplied to {@link ResetToFactory#recordInvocation(WipeTrigger)} which performs the
 * actual destruction of seed, PINs and PKI material when the reset counter reaches zero.
 *
 * <p>Defined inside the applet package because JavaCard 3.0.5 does not expose {@code
 * java.lang.Runnable}.
 */
public interface WipeTrigger {

    /** Executes the destructive wipe. */
    void wipe();
}

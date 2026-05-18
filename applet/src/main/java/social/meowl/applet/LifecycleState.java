/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/**
 * Tracks the applet lifecycle as a four-state finite state machine.
 *
 * <pre>
 *   UNINITIALIZED ──INSTALL──▶ PERSONALIZED ──SETUP──▶ SETUP_DONE ──IMPORT_SEED──▶ SEEDED
 *         ▲                                                                           │
 *         └──────────────────────────RESET_TO_FACTORY─────────────────────────────────┘
 * </pre>
 *
 * <p>States are stored in a single EEPROM byte. All transitions go through {@link
 * #transitionTo(byte)} and are guarded so that an invalid request raises {@link
 * Constants#SW_LIFECYCLE_INVALID} rather than silently corrupting the lifecycle.
 *
 * <p>The {@code authentikey} keypair survives every transition, including reset — see {@code
 * docs/adr/0005-authentikey-lifecycle.md}.
 */
public final class LifecycleState {

    /** Fresh applet instance. The authentikey exists; nothing else has been set up. */
    public static final byte UNINITIALIZED = (byte) 0x00;

    /** PKI personalisation has completed and the manufacturer certificate is installed. */
    public static final byte PERSONALIZED = (byte) 0x01;

    /** User has set up PIN and PUK. No seed is loaded. */
    public static final byte SETUP_DONE = (byte) 0x02;

    /** Master seed is loaded; the card can derive keys and sign. */
    public static final byte SEEDED = (byte) 0x03;

    /**
     * Holds the current state in EEPROM. Using a single-element array is the idiomatic JavaCard
     * pattern for a mutable instance field that is written through a transaction.
     */
    private final byte[] current;

    /** Constructs a fresh FSM seated in {@link #UNINITIALIZED}. */
    public LifecycleState() {
        this.current = new byte[1];
        this.current[0] = UNINITIALIZED;
    }

    /** Returns the current state byte. */
    public byte current() {
        return current[0];
    }

    /**
     * Transitions to {@code target}, throwing {@link Constants#SW_LIFECYCLE_INVALID} if the move is
     * not permitted by the FSM. Writes are wrapped in a JavaCard transaction so a torn power-off
     * leaves the previous state intact.
     */
    public void transitionTo(byte target) {
        if (!canTransition(current[0], target)) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
        JCSystem.beginTransaction();
        current[0] = target;
        JCSystem.commitTransaction();
    }

    /**
     * Force-resets the state machine to {@link #UNINITIALIZED}. Reserved for the reset-to-factory
     * flow which is itself a privileged path; ordinary code paths must use {@link
     * #transitionTo(byte)}.
     */
    public void resetToUninitialized() {
        JCSystem.beginTransaction();
        current[0] = UNINITIALIZED;
        JCSystem.commitTransaction();
    }

    /**
     * Throws {@link Constants#SW_LIFECYCLE_INVALID} unless the current state equals {@code
     * required}.
     */
    public void require(byte required) {
        if (current[0] != required) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
    }

    /**
     * Throws {@link Constants#SW_LIFECYCLE_INVALID} unless the current state is at least {@code
     * minimum}.
     */
    public void requireAtLeast(byte minimum) {
        if (current[0] < minimum) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
    }

    /**
     * Pure decision function for {@link #transitionTo(byte)}. Exposed package-private for direct
     * exercise by unit tests without involving the JavaCard transaction machinery.
     */
    static boolean canTransition(byte from, byte to) {
        // Linear forward progression: each state may only advance to the next ordinal.
        if (to == (byte) (from + 1) && to >= UNINITIALIZED && to <= SEEDED) {
            return true;
        }
        return false;
    }
}

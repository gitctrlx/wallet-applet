/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/**
 * Applet lifecycle as a four-state finite state machine.
 *
 * <pre>
 *   UNINITIALIZED ──personalise──▶ PERSONALIZED ──setup──▶ SETUP_DONE ──importSeed──▶ SEEDED
 *         ▲                                                                               │
 *         └──────────────────────────────reset-to-factory─────────────────────────────────┘
 * </pre>
 *
 * <p>Forward edges advance one ordinal via {@link #transitionTo}; the only retrograde edge is
 * {@link #reset()}, taken by the reset-to-factory flow. Writes execute inside a {@link
 * JCSystem#beginTransaction() JavaCard transaction} so a torn power-off cannot wedge the card
 * mid-transition. The {@code authentikey} keypair survives every transition (protocol.md §5).
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

    /** Persistent EEPROM-backed current state. */
    private byte current;

    /** Constructs a fresh FSM seated in {@link #UNINITIALIZED}. */
    public LifecycleState() {
        this.current = UNINITIALIZED;
    }

    /** Returns the current state byte. */
    public byte current() {
        return current;
    }

    /**
     * Advances to {@code target}, which must equal {@code current + 1}. Caller MUST hold a {@link
     * JCSystem#beginTransaction()} block so the advance commits atomically with sibling mutations.
     * Throws {@link Constants#SW_LIFECYCLE_INVALID} if the move is illegal.
     */
    public void transitionToInTx(byte target) {
        if (!isLegalForward(current, target)) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
        current = target;
    }

    /**
     * Force-resets to {@link #UNINITIALIZED}. Caller MUST hold a {@link
     * JCSystem#beginTransaction()} block; bundled with PIN/PUK, PKI cert and master-seed wipes into
     * the single atomic reset-to-factory commit driven by {@link MeowlApplet#wipe()}.
     */
    public void resetInTx() {
        current = UNINITIALIZED;
    }

    /**
     * Asserts {@code current == required}; throws {@link Constants#SW_LIFECYCLE_INVALID} otherwise.
     */
    public void require(byte required) {
        if (current != required) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
    }

    /**
     * Asserts {@code current >= minimum}; throws {@link Constants#SW_LIFECYCLE_INVALID} otherwise.
     */
    public void requireAtLeast(byte minimum) {
        if (current < minimum) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
    }

    /**
     * Pure decision function for {@link #transitionToInTx}, exposed package-private for unit tests.
     */
    static boolean isLegalForward(byte from, byte to) {
        return to == (byte) (from + 1) && from >= UNINITIALIZED && from < SEEDED && to <= SEEDED;
    }
}

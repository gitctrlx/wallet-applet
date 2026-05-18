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
 *   UNINITIALIZED ──personalise──▶ PERSONALIZED ──setup──▶ SETUP_DONE ──importSeed──▶ SEEDED
 *         ▲                                                                               │
 *         └──────────────────────────────reset-to-factory─────────────────────────────────┘
 * </pre>
 *
 * <p>Forward edges are linear: each state advances to the next ordinal via {@link
 * #transitionTo(byte)}. The only retrograde edge is {@link #reset()}, called from the
 * reset-to-factory flow, which collapses straight back to {@link #UNINITIALIZED}.
 *
 * <p>The current state is held in a single persistent {@code byte} field. Writes go through a
 * {@link JCSystem#beginTransaction() JavaCard transaction} so a torn power-off cannot leave the
 * card in a half-transitioned state. The {@code authentikey} keypair, however, survives every
 * transition — see {@code docs/adr/0005-authentikey-lifecycle.md}.
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
     * Advances to {@code target}, which must equal {@code current + 1} and stay within the legal
     * range. Throws {@link Constants#SW_LIFECYCLE_INVALID} if the move is not permitted.
     */
    public void transitionTo(byte target) {
        if (!isLegalForward(current, target)) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
        JCSystem.beginTransaction();
        current = target;
        JCSystem.commitTransaction();
    }

    /**
     * Force-resets the state machine to {@link #UNINITIALIZED}. Reserved for the reset-to-factory
     * flow which is itself a privileged path; ordinary code paths must use {@link
     * #transitionTo(byte)}.
     */
    public void reset() {
        JCSystem.beginTransaction();
        current = UNINITIALIZED;
        JCSystem.commitTransaction();
    }

    /**
     * Pure decision function for {@link #transitionTo(byte)}. Package-private so unit tests can
     * exercise it without engaging the JavaCard transaction machinery.
     */
    static boolean isLegalForward(byte from, byte to) {
        return to == (byte) (from + 1) && from >= UNINITIALIZED && from < SEEDED && to <= SEEDED;
    }
}

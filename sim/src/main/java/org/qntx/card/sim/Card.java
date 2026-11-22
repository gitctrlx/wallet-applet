// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import com.licel.jcardsim.base.Simulator;
import java.util.List;
import javacard.framework.AID;
import javacard.framework.Applet;

/**
 * Test-facing card facade (architecture spec section 8). Every command runs under {@link
 * CardRuntime}'s bound phase so the {@link Agent}'s persistent-write hooks see the command context;
 * {@link #transmit} maps a {@link PowerLoss} to {@link TornException} after rolling the card back
 * to powered-off state.
 */
public final class Card {

    private final CardRuntime runtime;
    private final Simulator simulator;

    public Card() {
        if (!Agent.installed()) {
            throw new IllegalStateException(
                    "qntx card simulator requires the bytecode agent;"
                            + " run tests with -javaagent:<path>/sim-agent.jar");
        }
        runtime = new CardRuntime();
        simulator = new Simulator(runtime);
    }

    /**
     * Load and install {@code appletClass} under {@code aid} with install parameters {@code
     * params}. Field writes are allowed here; the transient-memory charge and key-write hooks still
     * apply because applet code runs with the runtime bound.
     */
    public void install(byte[] aid, Class<? extends Applet> appletClass) {
        install(aid, appletClass, new byte[0]);
    }

    public void install(byte[] aid, Class<? extends Applet> appletClass, byte[] params) {
        byte[] data = new byte[aid.length + params.length + 3];
        data[0] = (byte) aid.length;
        System.arraycopy(aid, 0, data, 1, aid.length);
        data[aid.length + 1] = 0;
        data[aid.length + 2] = (byte) params.length;
        System.arraycopy(params, 0, data, aid.length + 3, params.length);
        AID aidObject = new AID(aid, (short) 0, (byte) aid.length);
        runtime.bind(CardRuntime.Phase.INSTALL);
        try {
            simulator.loadApplet(aidObject, appletClass);
            // installApplet on the runtime, not Simulator.createApplet, so
            // install failures surface their real reason instead of
            // Simulator's generic SW_APPLET_CREATION_FAILED
            runtime.installApplet(aidObject, data, (short) 0, (byte) data.length);
        } finally {
            runtime.unbind();
        }
    }

    /**
     * Transmit one command APDU; returns the raw response (data + SW).
     *
     * @throws TornException when the armed tear point fired: the command produced no response,
     *     persistent state reflects the torn write sequence, and the card needs SELECT to answer
     *     again
     */
    public byte[] transmit(byte[] apdu) {
        runtime.startCommand();
        try {
            return simulator.transmitCommand(apdu);
        } catch (PowerLoss lost) {
            runtime.powerLoss();
            throw new TornException();
        } finally {
            runtime.unbind();
        }
    }

    /** Arm the tear point on the n-th persistent write of a later command. */
    public void tearAt(int n) {
        runtime.armTear(n);
    }

    /** Power cycle: clears reset/deselect transient state and selection. */
    public void powerCycle() {
        runtime.reset();
    }

    /** Persistent writes counted during the last command. */
    public int writes() {
        return runtime.writes();
    }

    /** Commit-buffer bytes consumed by the last committed or aborted transaction. */
    public int commitBytes() {
        return runtime.lastCommitBytes();
    }

    /** Per-transaction commit-buffer consumption of the last command. */
    public List<Integer> commits() {
        return runtime.commits();
    }

    /** Bytes charged against the 3990 B transient pool. */
    public int transientUsed() {
        return runtime.transientUsed();
    }

    /** One line per charged transient allocation plus a usage total. */
    public String memoryReport() {
        return runtime.memoryReport();
    }
}

/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.cardclient;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * {@link CardClient} backed by a fresh in-JVM jcardsim {@code CardSimulator}.
 *
 * <p>Each {@link #installFresh} call spins up a new simulator instance, installs the applet, and
 * selects it — equivalent to the per-test {@code @BeforeEach} pattern the legacy integration tests
 * used inline.
 *
 * <p>Post-Phase-1 caveat: most integration suites cannot install on this backend any more because
 * jcardsim omits {@code TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT} and rejects prime-modulus RSA. Those
 * suites carry {@code @Tag("real-card")} and are deselected from the default test task; only {@link
 * RealCardClient} can satisfy them.
 */
public final class SimulatorCardClient implements CardClient {

    private final CardSimulator simulator;

    /** Installs {@code appletClass} under {@code aidBytes} on a fresh simulator and selects it. */
    public static SimulatorCardClient installFresh(
            byte[] aidBytes, Class<? extends Applet> appletClass) {
        CardSimulator simulator = new CardSimulator();
        AID aid = AIDUtil.create(aidBytes);
        simulator.installApplet(aid, appletClass);
        simulator.selectApplet(aid);
        return new SimulatorCardClient(simulator);
    }

    private SimulatorCardClient(CardSimulator simulator) {
        this.simulator = simulator;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU cmd) {
        return simulator.transmitCommand(cmd);
    }

    @Override
    public void close() {
        // jcardsim has no explicit teardown; the CardSimulator is GC-eligible after this call.
    }
}

/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MeowlAppletTest {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private CardSimulator simulator;

    @BeforeEach
    void setUp() {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_BYTES);
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
    }

    @Test
    @DisplayName("GET_INFO returns protocol version 0.1")
    void getInfoReturnsVersion() {
        CommandAPDU cmd = new CommandAPDU(0x80, MeowlApplet.INS_GET_INFO, 0x00, 0x00, 0x02);
        ResponseAPDU resp = simulator.transmitCommand(cmd);

        assertEquals(0x9000, resp.getSW(), "Expected success status word");
        assertArrayEquals(new byte[] {0x00, 0x01}, resp.getData(), "Version mismatch");
    }

    @Test
    @DisplayName("Unknown INS is rejected with 6D00")
    void unknownInsRejected() {
        CommandAPDU cmd = new CommandAPDU(0x80, 0x7F, 0x00, 0x00);
        ResponseAPDU resp = simulator.transmitCommand(cmd);

        assertEquals(0x6D00, resp.getSW());
    }

    @Test
    @DisplayName("Wrong CLA is rejected with 6E00")
    void wrongClaRejected() {
        CommandAPDU cmd = new CommandAPDU(0x00, MeowlApplet.INS_GET_INFO, 0x00, 0x00);
        ResponseAPDU resp = simulator.transmitCommand(cmd);

        assertEquals(0x6E00, resp.getSW());
    }
}

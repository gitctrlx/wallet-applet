/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * JCardSim-driven integration tests for the always-reachable outer-frame INS surface of the meowl
 * applet: {@code GET_INFO}, {@code GET_AUTHENTIKEY} and the multi-step {@code RESET_TO_FACTORY}
 * trigger.
 *
 * <p>Every test starts from a freshly installed applet (see {@link #setUp()}), so each scenario is
 * fully isolated. Higher-level protocol behaviour (Secure Channel, PIN, signing) is covered by the
 * dedicated test classes for each subsystem.
 */
class MeowlAppletTest {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.CLA_MEOWL & 0xFF;
    private static final int INS_GET_INFO = Constants.INS_GET_INFO & 0xFF;
    private static final int INS_GET_AUTHENTIKEY = Constants.INS_GET_AUTHENTIKEY & 0xFF;
    private static final int INS_RESET_TO_FACTORY = Constants.INS_RESET_TO_FACTORY & 0xFF;

    private CardSimulator simulator;

    @BeforeEach
    void setUp() {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_BYTES);
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
    }

    @Nested
    @DisplayName("CLA / INS routing")
    class Routing {

        @Test
        @DisplayName("wrong CLA returns 6E00")
        void wrongClaIs6E00() {
            ResponseAPDU resp = send(0x00, INS_GET_INFO, 0x00, 0x00, null);
            assertEquals(0x6E00, resp.getSW());
        }

        @Test
        @DisplayName("unknown INS returns 6D00")
        void unknownInsIs6D00() {
            ResponseAPDU resp = send(CLA, 0xFE, 0x00, 0x00, null);
            assertEquals(0x6D00, resp.getSW());
        }
    }

    @Nested
    @DisplayName("GET_INFO")
    class GetInfo {

        @Test
        @DisplayName("returns 9000 and a well-formed TLV blob")
        void wellFormedTlv() {
            ResponseAPDU resp = send(CLA, INS_GET_INFO, 0x00, 0x00, null);
            assertEquals(0x9000, resp.getSW());
            Map<Integer, byte[]> tlv = parseTlv(resp.getData());
            assertTrue(
                    tlv.containsKey(Constants.TAG_PROTOCOL_VERSION & 0xFF),
                    "protocol version TLV missing");
            assertTrue(
                    tlv.containsKey(Constants.TAG_APPLET_VERSION & 0xFF),
                    "applet version TLV missing");
            assertTrue(
                    tlv.containsKey(Constants.TAG_LIFECYCLE_STATE & 0xFF),
                    "lifecycle state TLV missing");
            assertTrue(
                    tlv.containsKey(Constants.TAG_CAPABILITIES & 0xFF), "capabilities TLV missing");
            assertTrue(
                    tlv.containsKey(Constants.TAG_AUTHENTIKEY_PUBKEY & 0xFF),
                    "authentikey pubkey TLV missing");
        }

        @Test
        @DisplayName("protocol version equals the Constants value")
        void protocolVersionMatches() {
            Map<Integer, byte[]> tlv =
                    parseTlv(send(CLA, INS_GET_INFO, 0x00, 0x00, null).getData());
            byte[] version = tlv.get(Constants.TAG_PROTOCOL_VERSION & 0xFF);
            assertEquals(2, version.length);
            short encoded = (short) (((version[0] & 0xFF) << 8) | (version[1] & 0xFF));
            assertEquals(Constants.PROTOCOL_VERSION, encoded);
        }

        @Test
        @DisplayName("lifecycle state starts at UNINITIALIZED")
        void freshLifecycleIsUninitialized() {
            Map<Integer, byte[]> tlv =
                    parseTlv(send(CLA, INS_GET_INFO, 0x00, 0x00, null).getData());
            byte[] state = tlv.get(Constants.TAG_LIFECYCLE_STATE & 0xFF);
            assertEquals(1, state.length);
            assertEquals(LifecycleState.UNINITIALIZED, state[0]);
        }

        @Test
        @DisplayName("capabilities advertise RESET_TO_FACTORY")
        void capabilitiesAdvertiseReset() {
            Map<Integer, byte[]> tlv =
                    parseTlv(send(CLA, INS_GET_INFO, 0x00, 0x00, null).getData());
            byte[] caps = tlv.get(Constants.TAG_CAPABILITIES & 0xFF);
            assertEquals(2, caps.length);
            int capsValue = ((caps[0] & 0xFF) << 8) | (caps[1] & 0xFF);
            assertTrue(
                    (capsValue & Constants.CAP_RESET_TO_FACTORY) != 0,
                    "CAP_RESET_TO_FACTORY bit must be set");
        }

        @Test
        @DisplayName("authentikey pubkey is a well-formed compressed point")
        void authentikeyIsCompressed() {
            Map<Integer, byte[]> tlv =
                    parseTlv(send(CLA, INS_GET_INFO, 0x00, 0x00, null).getData());
            byte[] pk = tlv.get(Constants.TAG_AUTHENTIKEY_PUBKEY & 0xFF);
            assertEquals(Constants.EC_POINT_COMPRESSED_LEN, pk.length);
            assertTrue(pk[0] == 0x02 || pk[0] == 0x03, "first byte must be 0x02 or 0x03");
        }
    }

    @Nested
    @DisplayName("GET_AUTHENTIKEY")
    class GetAuthentikey {

        @Test
        @DisplayName("returns a 33-byte compressed point identical to GET_INFO's pubkey TLV")
        void matchesGetInfo() {
            byte[] direct = send(CLA, INS_GET_AUTHENTIKEY, 0x00, 0x00, null).getData();
            byte[] fromTlv =
                    parseTlv(send(CLA, INS_GET_INFO, 0x00, 0x00, null).getData())
                            .get(Constants.TAG_AUTHENTIKEY_PUBKEY & 0xFF);
            assertArrayEquals(fromTlv, direct);
        }

        @Test
        @DisplayName("repeated calls return a stable authentikey across the applet's lifetime")
        void stableAcrossCalls() {
            // Authentikey is generated once at install() time and never rotates. Two consecutive
            // GET_AUTHENTIKEY calls must therefore return identical bytes; were the applet to
            // rebuild the keypair on each call we would silently lose the device identity anchor
            // that Secure Channel and PKI personalisation depend on.
            byte[] first = send(CLA, INS_GET_AUTHENTIKEY, 0x00, 0x00, null).getData();
            byte[] second = send(CLA, INS_GET_AUTHENTIKEY, 0x00, 0x00, null).getData();
            assertArrayEquals(first, second, "authentikey must be stable across calls");
        }
    }

    @Nested
    @DisplayName("RESET_TO_FACTORY")
    class ResetToFactory {

        @Test
        @DisplayName("first three invocations return countdown status words")
        void countdownStatusWords() {
            int[] expected = {0x6FA3, 0x6FA2, 0x6FA1};
            for (int sw : expected) {
                assertEquals(
                        sw,
                        send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null).getSW(),
                        "step status word");
            }
        }

        @Test
        @DisplayName("fourth invocation triggers the wipe and returns 0x6FA0")
        void fourthTriggersWipe() {
            for (int i = 0; i < 3; i++) {
                send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null);
            }
            ResponseAPDU last = send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null);
            assertEquals(0x6FA0, last.getSW());
        }

        @Test
        @DisplayName("any other INS rearms the counter")
        void anyOtherInsRearms() {
            send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null); // 0x6FA3
            send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null); // 0x6FA2
            send(CLA, INS_GET_INFO, 0x00, 0x00, null); // rearm
            int sw = send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null).getSW();
            assertEquals(0x6FA3, sw, "counter must restart from RESET_REQUIRED_INVOCATIONS");
        }

        @Test
        @DisplayName("authentikey survives reset")
        void authentikeyPersists() {
            byte[] before = send(CLA, INS_GET_AUTHENTIKEY, 0x00, 0x00, null).getData();
            // Drive a complete reset.
            for (int i = 0; i < 4; i++) {
                send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null);
            }
            byte[] after = send(CLA, INS_GET_AUTHENTIKEY, 0x00, 0x00, null).getData();
            assertArrayEquals(before, after, "authentikey must survive reset-to-factory");
        }
    }

    private ResponseAPDU send(int cla, int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(cla, ins, p1, p2)
                        : new CommandAPDU(cla, ins, p1, p2, data);
        return simulator.transmitCommand(cmd);
    }

    private static Map<Integer, byte[]> parseTlv(byte[] blob) {
        Map<Integer, byte[]> out = new HashMap<>();
        int i = 0;
        while (i < blob.length) {
            int tag = blob[i++] & 0xFF;
            int len = blob[i++] & 0xFF;
            byte[] value = Arrays.copyOfRange(blob, i, i + len);
            out.put(tag, value);
            i += len;
        }
        return out;
    }
}

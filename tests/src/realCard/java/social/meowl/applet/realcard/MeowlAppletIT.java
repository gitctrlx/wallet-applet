/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.realcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import social.meowl.applet.Constants;
import social.meowl.applet.LifecycleState;
import social.meowl.applet.realcard.support.CardLifecycle;
import social.meowl.applet.realcard.support.RealCardClient;

/**
 * Integration tests for the always-reachable outer-frame INS surface of the meowl applet: {@code
 * GET_INFO}, {@code GET_AUTHENTIKEY} and the multi-step {@code RESET_TO_FACTORY} trigger.
 *
 * <p>Drives the applet through {@link RealCardClient} over PCSC. The post-Phase-1 applet only
 * installs on real J3R180 silicon, so this suite lives in the {@code realCard} source set and only
 * the {@code :tests:realCardTest} task compiles and runs it.
 *
 * <p>Each test starts from a freshly-selected applet: {@code @BeforeEach} opens a fresh PCSC
 * channel and {@link #tearDown} disconnects with {@code reset = true} so the {@code CLEAR_ON_RESET}
 * counter (and therefore the {@code RESET_TO_FACTORY} state machine) is restored between tests.
 */
class MeowlAppletIT {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.CLA_MEOWL & 0xFF;
    private static final int INS_GET_INFO = Constants.INS_GET_INFO & 0xFF;
    private static final int INS_GET_AUTHENTIKEY = Constants.INS_GET_AUTHENTIKEY & 0xFF;
    private static final int INS_RESET_TO_FACTORY = Constants.INS_RESET_TO_FACTORY & 0xFF;
    private static final int INS_OPEN_SC = Constants.INS_OPEN_SECURE_CHANNEL & 0xFF;
    private static final int INS_SETUP = Constants.INS_SETUP & 0xFF;
    private static final int INS_SIGN_ECDSA_K1 = Constants.INS_SIGN_ECDSA_K1 & 0xFF;
    private static final int INS_SIGN_SCHNORR_K1 = Constants.INS_SIGN_SCHNORR_K1 & 0xFF;
    private static final int INS_SIGN_ED25519 = Constants.INS_SIGN_ED25519 & 0xFF;
    private static final int INS_IMPORT_SEED = Constants.INS_IMPORT_SEED & 0xFF;

    private RealCardClient card;

    @BeforeEach
    void setUp() {
        card = RealCardClient.connect(APPLET_AID_BYTES);
    }

    @AfterEach
    void tearDown() {
        if (card != null) {
            try {
                CardLifecycle.resetCard(card);
            } catch (Exception ignored) {
                // best-effort reset; the next test's @BeforeEach will surface real problems
            }
            card.close();
        }
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

        @Test
        @DisplayName(
                "inner-only INS dispatched on the outer surface returns 6D00 — never leaks PIN /"
                        + " seed handlers without a Secure Channel")
        void innerOnlyInsReturnsInsNotSupported() {
            // SETUP / IMPORT_SEED / SIGN_xxx must only be reachable through OPEN_SECURE_CHANNEL.
            // The outer-frame switch must reject them with 6D00 even though the underlying handler
            // exists, since the handler is gated on a live SC session and the dispatcher does not
            // route there.
            int[] innerOnlyIns = {
                INS_SETUP, INS_IMPORT_SEED, INS_SIGN_ECDSA_K1, INS_SIGN_SCHNORR_K1, INS_SIGN_ED25519
            };
            for (int ins : innerOnlyIns) {
                ResponseAPDU resp = send(CLA, ins, 0x00, 0x00, null);
                assertEquals(
                        0x6D00,
                        resp.getSW(),
                        "outer-frame dispatch must reject inner-only INS=0x%02X with 6D00"
                                .formatted(ins));
            }
        }

        @Test
        @DisplayName(
                "OPEN_SECURE_CHANNEL without a prior INIT handshake fails before dispatch — no SC"
                        + " state on a fresh card")
        void openSecureChannelWithoutInitFails() {
            // Sending OPEN_SC immediately after select() must not crash and must not dispatch any
            // inner handler. The applet's secure-channel layer rejects with a non-9000 SW; this
            // test is defensive against silent fall-through to dispatchInner with stale session
            // keys.
            byte[] bogusEnvelope = new byte[16 + 16 + 16]; // IV || one-block CT || MAC
            ResponseAPDU resp = send(CLA, INS_OPEN_SC, 0x00, 0x00, bogusEnvelope);
            assertTrue(
                    resp.getSW() != 0x9000,
                    "OPEN_SC without prior handshake must not return 9000 (got 0x%04X)"
                            .formatted(resp.getSW()));
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

        @Test
        @DisplayName(
                "lifecycle reverts to UNINITIALIZED after a complete reset (atomic-wipe"
                        + " regression)")
        void lifecycleRevertsToUninitialized() {
            // Every persistent wipe runs inside a single beginTransaction so a torn power-off
            // cannot leave the card with a half-wiped lifecycle. The post-condition that
            // observably verifies the success path is "after the fourth invocation, GET_INFO
            // reports UNINITIALIZED" — the same state a fresh install would expose. A regression
            // that forgot to reset the lifecycle (or that ran the four wipes outside the same
            // transaction and ate an exception in the middle) would land the card in a different
            // bucket here.
            for (int i = 0; i < 4; i++) {
                send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null);
            }
            Map<Integer, byte[]> tlv =
                    parseTlv(send(CLA, INS_GET_INFO, 0x00, 0x00, null).getData());
            byte[] state = tlv.get(Constants.TAG_LIFECYCLE_STATE & 0xFF);
            assertEquals(1, state.length);
            assertEquals(LifecycleState.UNINITIALIZED, state[0]);
        }

        @Test
        @DisplayName("RESET_TO_FACTORY interleaved with multiple distinct INS rearms cleanly")
        void interleavedReset() {
            // Drive the rearm path with a variety of INS values, including the inner-only ones
            // (which return 6D00 but still rearm) and one that returns 9000. The counter must
            // restart at RESET_REQUIRED_INVOCATIONS each time a non-RESET INS comes through.
            int[] interleaveIns = {INS_GET_INFO, INS_GET_AUTHENTIKEY, INS_SETUP, INS_SIGN_ECDSA_K1};
            for (int ins : interleaveIns) {
                send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null); // 0x6FA3
                send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null); // 0x6FA2
                send(CLA, ins, 0x00, 0x00, null); // rearm regardless of SW
                int sw = send(CLA, INS_RESET_TO_FACTORY, 0x00, 0x00, null).getSW();
                assertEquals(
                        0x6FA3,
                        sw,
                        "after non-RESET INS=0x%02X the counter must restart from %d invocations"
                                .formatted(ins, 4));
            }
        }
    }

    private ResponseAPDU send(int cla, int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(cla, ins, p1, p2)
                        : new CommandAPDU(cla, ins, p1, p2, data);
        return card.transmit(cmd);
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

/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import social.meowl.applet.MeowlApplet;
import social.meowl.tools.core.MeowlAid;

/**
 * End-to-end integration tests for {@link SecureChannelClient} against the real {@code MeowlApplet}
 * inside JCardSim.
 *
 * <p>This test class is the regression net for MEAP-2 wire compatibility: any change in the applet
 * that breaks the host client (or vice versa) shows up here as a failed handshake or a MAC
 * mismatch, long before a real card is involved.
 */
class SecureChannelClientIT {

    private CardSimulator simulator;
    private APDUBIBO bibo;

    @BeforeEach
    void setUp() {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create(MeowlAid.defaultBytes());
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
        bibo = new APDUBIBO(simulatorBibo(simulator));
    }

    @Test
    @DisplayName("handshake completes against a real applet and verifies the signature")
    void handshakeRoundTrip() throws BIBOException {
        SecureChannelClient sc = new SecureChannelClient(bibo, fetchAuthentikey());
        SecureChannelClient.Handshake hs = sc.handshake();

        assertNotNull(hs.cardEphPub());
        assertEquals(HostCrypto.EC_POINT_UNCOMPRESSED_LEN, hs.cardEphPub().length);
        assertEquals(0x04, hs.cardEphPub()[0] & 0xFF);
        assertTrue(hs.signatureDer().length > 0);
        assertEquals(HostCrypto.AES_BLOCK_LEN, hs.ivBase().length);
    }

    @Test
    @DisplayName("envelope round-trip: inner EXPORT_PKI_PUBKEY returns the authentikey pubkey")
    void envelopeRoundTrip() throws BIBOException {
        byte[] plainAuthentikey = fetchAuthentikey();

        SecureChannelClient sc = new SecureChannelClient(bibo, plainAuthentikey);
        sc.handshake();

        // INS_EXPORT_PKI_PUBKEY (0x30) is the simplest inner-band INS that works on a freshly
        // installed applet — it just returns the authentikey, no PIN required.
        byte[] inner = new byte[] {(byte) 0x80, 0x30, 0x00, 0x00, 0x00};
        byte[] decrypted = sc.sendInner(inner);

        assertArrayEquals(plainAuthentikey, decrypted);
    }

    @Test
    @DisplayName("two consecutive envelopes succeed and return identical inner data")
    void twoConsecutiveEnvelopes() throws BIBOException {
        SecureChannelClient sc = new SecureChannelClient(bibo, fetchAuthentikey());
        sc.handshake();

        byte[] inner = new byte[] {(byte) 0x80, 0x30, 0x00, 0x00, 0x00};
        byte[] r1 = sc.sendInner(inner);
        byte[] r2 = sc.sendInner(inner);
        assertArrayEquals(r1, r2);
    }

    @Test
    @DisplayName("handshake against a wrong authentikey fails the host-side signature check")
    void wrongAuthentikeyFails() {
        // A real-format compressed pubkey from a fresh ephemeral keypair — valid SEC1 encoding,
        // valid curve point, but cryptographically not the authentikey the simulator signed
        // with, so signature verification must fail.
        HostCrypto.EphKeyPair imposter = HostCrypto.generateEphKeyPair();
        byte[] uncompressed = imposter.publicEncoded();
        byte[] x = java.util.Arrays.copyOfRange(uncompressed, 1, 1 + HostCrypto.EC_SCALAR_LEN);
        byte[] y = java.util.Arrays.copyOfRange(uncompressed, 1 + HostCrypto.EC_SCALAR_LEN, 65);
        byte[] wrongCompressed = new byte[HostCrypto.EC_POINT_COMPRESSED_LEN];
        wrongCompressed[0] = (y[y.length - 1] & 1) == 0 ? (byte) 0x02 : (byte) 0x03;
        System.arraycopy(x, 0, wrongCompressed, 1, x.length);

        SecureChannelClient sc = new SecureChannelClient(bibo, wrongCompressed);
        SecureChannelException ex = assertThrows(SecureChannelException.class, sc::handshake);
        assertTrue(
                ex.getMessage().toLowerCase().contains("verification")
                        || ex.getMessage().toLowerCase().contains("signature"));
    }

    @Test
    @DisplayName("oversize inner APDU is rejected before transmit (audit H-1.05)")
    void oversizeInnerRejected() throws BIBOException {
        SecureChannelClient sc = new SecureChannelClient(bibo, fetchAuthentikey());
        sc.handshake();

        // Inner payload large enough to push LC over 255 bytes:
        // padded ciphertext = ceil((5 + 230 + 1) / 16) * 16 = 240, envelope = 16 + 240 + 16 = 272.
        byte[] huge = new byte[235];
        huge[0] = (byte) 0x80;
        huge[1] = 0x30;
        huge[4] = (byte) 230;

        SecureChannelException ex =
                assertThrows(SecureChannelException.class, () -> sc.sendInner(huge));
        assertTrue(
                ex.getMessage().toLowerCase().contains("short-form"),
                "expected short-form-cap error, got: " + ex.getMessage());
    }

    @Test
    @DisplayName(
            "session is invalidated after a card-side failure; further sendInner fails fast "
                    + "(audit H-1.12)")
    void sessionInvalidatedOnCardFailure() throws BIBOException {
        SecureChannelClient sc = new SecureChannelClient(bibo, fetchAuthentikey());
        sc.handshake();

        // First call: send an INS the inner dispatcher does not implement (0x7F is unallocated).
        // The applet's dispatchInner switch returns SW_INS_NOT_SUPPORTED, which OPEN_SC wraps
        // and re-emits with an outer non-9000 SW — exercising the host invalidate() path.
        byte[] inner = new byte[] {(byte) 0x80, 0x7F, 0x00, 0x00, 0x00};
        assertThrows(SecureChannelException.class, () -> sc.sendInner(inner));

        // Second call: must fail fast with IllegalStateException rather than encrypting under
        // stale keys and producing a confusing chain of MAC mismatches.
        IllegalStateException invalid =
                assertThrows(IllegalStateException.class, () -> sc.sendInner(inner));
        assertTrue(invalid.getMessage().toLowerCase().contains("invalidated"));
    }

    @Test
    @DisplayName("two handshakes in a row produce different ephemeral pubkeys (forward secrecy)")
    void successiveHandshakesDifferent() throws BIBOException {
        byte[] authentikey = fetchAuthentikey();

        SecureChannelClient sc1 = new SecureChannelClient(bibo, authentikey);
        SecureChannelClient.Handshake hs1 = sc1.handshake();

        SecureChannelClient sc2 = new SecureChannelClient(bibo, authentikey);
        SecureChannelClient.Handshake hs2 = sc2.handshake();

        assertNotEquals(
                java.util.Arrays.toString(hs1.cardEphPub()),
                java.util.Arrays.toString(hs2.cardEphPub()));
    }

    /**
     * Fetches the authentikey via the plain {@code GET_AUTHENTIKEY} INS so the test can use it as
     * the trust anchor for handshake verification.
     */
    private byte[] fetchAuthentikey() throws BIBOException {
        ResponseAPDU resp =
                bibo.transmit(new CommandAPDU(SecureChannelClient.CLA_MEOWL, 0x02, 0x00, 0x00));
        assertEquals(0x9000, resp.getSW());
        return resp.getData();
    }

    /**
     * Wraps a JCardSim {@link CardSimulator} into a {@link BIBO}. JCardSim's transmit is purely
     * synchronous; we adapt by routing each transceive through {@code transmitCommand}.
     */
    private static BIBO simulatorBibo(CardSimulator sim) {
        return new BIBO() {
            @Override
            public byte[] transceive(byte[] command) {
                javax.smartcardio.CommandAPDU cmd = new javax.smartcardio.CommandAPDU(command);
                javax.smartcardio.ResponseAPDU resp = sim.transmitCommand(cmd);
                return resp.getBytes();
            }

            @Override
            public void close() {
                // JCardSim has no per-channel close concept; the simulator outlives the BIBO.
            }
        };
    }
}

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
import java.util.List;
import javacard.framework.AID;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import social.meowl.applet.MeowlApplet;
import social.meowl.tools.core.MeowlAid;

/**
 * End-to-end integration tests for {@link SecureChannelClient}.
 *
 * <p>Backend selection is driven by two system properties:
 *
 * <ul>
 *   <li>{@code -DcardBackend=simulator} — install {@code MeowlApplet} into a fresh jcardsim {@code
 *       CardSimulator}. After the Phase-1 single-target hardening this no longer works (transient
 *       EC keys + prime-modulus RSA are out of jcardsim's surface) so the simulator backend is
 *       preserved only for sanity-checking the test fixture itself; expect every crypto-bearing
 *       test to fail with {@code SystemException}.
 *   <li>{@code -DcardBackend=real} — connect to a PCSC-attached J3R180. The reader is selected by
 *       name via {@code -DcardReader=NAME} (substring match against the JDK reader list); if unset,
 *       the first terminal returned by {@link TerminalFactory#getDefault()} wins.
 * </ul>
 *
 * <p>Default backend is {@code simulator} so {@code :tools:test} (which excludes the {@code
 * real-card} tag entirely) and {@code :tools:realCardTest} can both inspect the suite without
 * needing a card present at compile time. The Gradle {@code realCardTest} task overrides the
 * default to {@code real}.
 */
@Tag("real-card")
class SecureChannelClientIT {

    private static final String PROP_BACKEND = "cardBackend";
    private static final String PROP_READER = "cardReader";

    private CardSimulator simulator;
    private Card realCard;
    private APDUBIBO bibo;

    @BeforeEach
    void setUp() {
        if ("real".equalsIgnoreCase(System.getProperty(PROP_BACKEND, "simulator"))) {
            this.realCard = connectRealCard(System.getProperty(PROP_READER));
            this.bibo = new APDUBIBO(realCardBibo(realCard.getBasicChannel()));
        } else {
            this.simulator = new CardSimulator();
            AID aid = AIDUtil.create(MeowlAid.defaultBytes());
            simulator.installApplet(aid, MeowlApplet.class);
            simulator.selectApplet(aid);
            this.bibo = new APDUBIBO(simulatorBibo(simulator));
        }
    }

    @AfterEach
    void tearDown() {
        if (realCard != null) {
            try {
                // disconnect(true) requests an ICC reset so CLEAR_ON_RESET state is wiped on the
                // card; the next test's @BeforeEach therefore starts on a fresh transient pool.
                realCard.disconnect(true);
            } catch (CardException ignored) {
                // best-effort teardown
            }
            realCard = null;
        }
        // CardSimulator has no per-instance close; setUp creates a fresh one each time.
        simulator = null;
        bibo = null;
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
    @DisplayName("oversize inner APDU is rejected before transmit")
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
    @DisplayName("session is invalidated after a card-side failure; further sendInner fails fast")
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

    /**
     * Connects to a PCSC reader, opens a basic channel, and SELECTs the {@code MeowlApplet} AID.
     * The applet must already be installed on the card; this fixture does not invoke GP install.
     *
     * <p>{@code terminalName} matches the JDK PCSC name verbatim (no substring matching). When
     * {@code null} or empty the first available terminal is used — fine for single-reader laptops
     * but ambiguous on hosts with several readers.
     */
    private static Card connectRealCard(String terminalName) {
        try {
            CardTerminal terminal = pickPcscTerminal(terminalName);
            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            javax.smartcardio.ResponseAPDU select =
                    channel.transmit(
                            new javax.smartcardio.CommandAPDU(
                                    0x00, 0xA4, 0x04, 0x00, MeowlAid.defaultBytes()));
            if (select.getSW() != 0x9000) {
                card.disconnect(false);
                throw new IllegalStateException(
                        "SELECT MeowlApplet failed: SW=0x" + Integer.toHexString(select.getSW()));
            }
            return card;
        } catch (CardException e) {
            throw new IllegalStateException(
                    "PCSC connect failed (terminal=" + terminalName + ")", e);
        }
    }

    private static CardTerminal pickPcscTerminal(String terminalName) throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        if (terminalName == null || terminalName.isEmpty()) {
            List<CardTerminal> terminals = factory.terminals().list();
            if (terminals.isEmpty()) {
                throw new IllegalStateException(
                        "no PCSC terminals; specify one with -DcardReader=NAME");
            }
            return terminals.get(0);
        }
        CardTerminal terminal = factory.terminals().getTerminal(terminalName);
        if (terminal == null) {
            throw new IllegalStateException("PCSC terminal not found: " + terminalName);
        }
        return terminal;
    }

    /**
     * Adapts a {@link CardChannel} to apdu4j's {@link BIBO}. The channel outlives the BIBO; the
     * test's {@link #tearDown} owns the disconnect.
     */
    private static BIBO realCardBibo(CardChannel channel) {
        return new BIBO() {
            @Override
            public byte[] transceive(byte[] command) throws BIBOException {
                try {
                    return channel.transmit(new javax.smartcardio.CommandAPDU(command)).getBytes();
                } catch (CardException e) {
                    throw new BIBOException(e.getMessage());
                }
            }

            @Override
            public void close() {
                // CardChannel lifecycle is owned by the enclosing Card; tearDown closes it.
            }
        };
    }
}

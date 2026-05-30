/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.testkit;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import social.meowl.applet.Constants;
import social.meowl.applet.cardclient.RealCardClient;

/**
 * Reusable lifecycle setup helpers for end-to-end test suites. Each fixture mirrors the legacy
 * inline {@code @BeforeEach} sequences the integration suites used to duplicate verbatim.
 */
public final class MeowlFixtures {

    private MeowlFixtures() {}

    /**
     * Drives the {@code RESET_TO_FACTORY} sequence so the applet's persistent state lands back on
     * {@link social.meowl.applet.LifecycleState#UNINITIALIZED}. Each of the {@link
     * Constants#RESET_REQUIRED_INVOCATIONS} consecutive RESET APDUs must reply with the canonical
     * countdown progression {@code 6FA3 → 6FA2 → 6FA1 → 6FA0}; any other status word indicates the
     * applet's reset state machine has been desynchronised and the test environment is unsafe to
     * proceed.
     *
     * <p>Real-card suites invoke this from {@code @AfterEach} so the next test's
     * {@code @BeforeEach} starts on the same lifecycle floor.
     */
    public static void resetCard(RealCardClient card) {
        int total = Constants.RESET_REQUIRED_INVOCATIONS & 0xFF;
        for (int i = 0; i < total; i++) {
            ResponseAPDU r =
                    card.transmit(
                            new CommandAPDU(
                                    Constants.CLA_MEOWL & 0xFF,
                                    Constants.INS_RESET_TO_FACTORY & 0xFF,
                                    0x00,
                                    0x00));
            int expected = (Constants.SW_RESET_COUNTDOWN_BASE & 0xFFFF) + (total - 1 - i);
            if (r.getSW() != expected) {
                throw new IllegalStateException(
                        "RESET_TO_FACTORY step "
                                + (i + 1)
                                + "/"
                                + total
                                + " expected SW=0x"
                                + Integer.toHexString(expected)
                                + " but got SW=0x"
                                + Integer.toHexString(r.getSW()));
            }
        }
    }

    /**
     * Drives a fresh card all the way to {@code SETUP_DONE + PIN-verified}: opens an initial Secure
     * Channel, imports a synthetic 64-byte PKI cert, locks the PKI surface, re-opens a Secure
     * Channel (LOCK_PKI implicitly closes the previous session), runs SETUP, and verifies the
     * default PIN.
     *
     * @return the live SC session post-VERIFY_PIN, ready for inner-channel commands.
     * @throws IllegalStateException if any step returns a non-{@code 9000} status word.
     */
    public static HostSession bringToSetupDoneAndVerifyPin(RealCardClient card) {
        HostSession session = HostSession.open(card);
        byte[] cert = new byte[64];
        for (int i = 0; i < cert.length; i++) cert[i] = (byte) i;
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_INIT,
                (byte) 0,
                shortBE((short) cert.length));
        byte[] writePayload = new byte[2 + cert.length];
        System.arraycopy(cert, 0, writePayload, 2, cert.length);
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_WRITE,
                (byte) 0,
                writePayload);
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
        session.sendInnerExpectOk(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);

        // LOCK_PKI tears down the SC; open a fresh session before SETUP/VERIFY_PIN.
        HostSession fresh = HostSession.open(card);
        fresh.sendInnerExpectOk(
                Constants.INS_SETUP,
                (byte) 0,
                (byte) 0,
                encodeSetup(TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
        ResponseAPDU vp =
                fresh.sendInner(
                        Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, TestConstants.DEFAULT_PIN);
        if (vp.getSW() != 0x9000) {
            throw new IllegalStateException(
                    "VERIFY_PIN failed during setup: SW=" + Integer.toHexString(vp.getSW()));
        }
        return fresh;
    }

    /** Encodes the SETUP body: {@code [pinLen | pin... | pukLen | puk...]}. */
    public static byte[] encodeSetup(byte[] pin, byte[] puk) {
        byte[] out = new byte[1 + pin.length + 1 + puk.length];
        out[0] = (byte) pin.length;
        System.arraycopy(pin, 0, out, 1, pin.length);
        out[1 + pin.length] = (byte) puk.length;
        System.arraycopy(puk, 0, out, 1 + pin.length + 1, puk.length);
        return out;
    }

    /** Length-prefix a single byte array: {@code [len | data...]}. */
    public static byte[] prefixLen(byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) data.length;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    /** Big-endian {@code short} → 2 bytes. */
    public static byte[] shortBE(short v) {
        return new byte[] {(byte) (v >> 8), (byte) (v & 0xFF)};
    }

    /**
     * Encodes an HD signing request body: {@code [depth | path... | payload]}, where each path
     * index is a big-endian 32-bit word. Shared by the ECDSA / Schnorr / Ed25519 signing suites.
     */
    public static byte[] encodeSignRequest(int[] path, byte[] payload) {
        byte[] out = new byte[1 + 4 * path.length + payload.length];
        out[0] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[1 + i * 4] = (byte) (idx >>> 24);
            out[1 + i * 4 + 1] = (byte) (idx >>> 16);
            out[1 + i * 4 + 2] = (byte) (idx >>> 8);
            out[1 + i * 4 + 3] = (byte) idx;
        }
        System.arraycopy(payload, 0, out, 1 + 4 * path.length, payload.length);
        return out;
    }

    /**
     * Encodes an {@code EXPORT_XPUB} request body: {@code [curve | depth | path...]}, where each
     * path index is a big-endian 32-bit word.
     */
    public static byte[] encodeXpubRequest(byte curve, int[] path) {
        byte[] out = new byte[2 + 4 * path.length];
        out[0] = curve;
        out[1] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[2 + i * 4] = (byte) (idx >>> 24);
            out[2 + i * 4 + 1] = (byte) (idx >>> 16);
            out[2 + i * 4 + 2] = (byte) (idx >>> 8);
            out[2 + i * 4 + 3] = (byte) idx;
        }
        return out;
    }

    /**
     * Walks the {@code GET_INFO} TLV blob and returns the 2-byte capabilities bitmap.
     *
     * @throws IllegalStateException if the capabilities TLV is absent.
     */
    public static short readCapabilities(byte[] tlv) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            int len = tlv[i++] & 0xFF;
            if (tag == (Constants.TAG_CAPABILITIES & 0xFF)) {
                return (short) (((tlv[i] & 0xFF) << 8) | (tlv[i + 1] & 0xFF));
            }
            i += len;
        }
        throw new IllegalStateException("capabilities TLV not found");
    }

    /** Transmits an outer-frame (cleartext) APDU under the meowl CLA. */
    public static ResponseAPDU transmitOuter(
            RealCardClient card, int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(TestConstants.CLA, ins, p1, p2)
                        : new CommandAPDU(TestConstants.CLA, ins, p1, p2, data);
        return card.transmit(cmd);
    }
}

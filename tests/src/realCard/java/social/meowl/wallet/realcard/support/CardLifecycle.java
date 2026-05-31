/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet.realcard.support;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import social.meowl.wallet.Constants;

/**
 * Real-card lifecycle helpers for the integration suites: factory-reset teardown, bring-up to
 * {@code SETUP_DONE + PIN-verified}, and outer-frame APDU transmit. Pure APDU-body encoders live in
 * {@link ApduCodec}.
 */
public final class CardLifecycle {

    private CardLifecycle() {}

    /**
     * Drives the {@code RESET_TO_FACTORY} sequence so the applet's persistent state lands back on
     * {@link social.meowl.wallet.LifecycleState#UNINITIALIZED}. Each of the {@link
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
                ApduCodec.shortBE((short) cert.length));
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
                ApduCodec.encodeSetup(TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
        ResponseAPDU vp =
                fresh.sendInner(
                        Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, TestConstants.DEFAULT_PIN);
        if (vp.getSW() != 0x9000) {
            throw new IllegalStateException(
                    "VERIFY_PIN failed during setup: SW=" + Integer.toHexString(vp.getSW()));
        }
        return fresh;
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

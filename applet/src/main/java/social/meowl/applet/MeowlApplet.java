/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Entry point of the meowl multi-chain hardware-wallet applet.
 *
 * <p>This class is intentionally <em>thin</em>: it parses the outer APDU, dispatches to a
 * single-purpose handler, and turns any uncaught condition into an ISO 7816-4 status word. All
 * cryptographic and business-logic complexity lives in dedicated companion classes ({@link
 * Authentikey}, {@link ResetToFactory}, {@link LifecycleState}, {@link ApduTlv}, {@link Secp256k1})
 * that share this single JavaCard package (a CAP file maps one-to-one to a Java package).
 *
 * <p>Phase 1 scope: identity (authentikey), lifecycle FSM, multi-step reset-to-factory, and a
 * TLV-encoded capability profile via {@code GET_INFO}. Every other INS code returns {@code 6D00
 * (INS not supported)} as a deliberate placeholder for the work in Phases 2–5.
 */
public final class MeowlApplet extends Applet implements WipeTrigger {

    /** TLV response buffer (transient, RAM-backed). 128 bytes is comfortably above current need. */
    private static final short SCRATCH_LEN = (short) 128;

    private final LifecycleState state;
    private final Authentikey authentikey;
    private final ResetToFactory resetTrigger;
    private final byte[] scratch;

    private MeowlApplet() {
        this.state = new LifecycleState();
        this.authentikey = new Authentikey();
        this.resetTrigger = new ResetToFactory();
        this.scratch = JCSystem.makeTransientByteArray(SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        register();
    }

    /** GlobalPlatform install entry point. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MeowlApplet();
    }

    @Override
    public boolean select() {
        // Re-arm the reset trigger so a residual countdown from a previous session never bleeds
        // into a fresh one.
        resetTrigger.rearm();
        return true;
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (cla != Constants.CLA_MEOWL) {
            ISOException.throwIt(Constants.SW_CLA_NOT_SUPPORTED);
        }

        // The reset trigger semantics demand that the counter is rearmed on every non-reset INS.
        // Performing this before dispatch keeps the rule local to the router.
        if (ins != Constants.INS_RESET_TO_FACTORY) {
            resetTrigger.rearm();
        }

        switch (ins) {
            case Constants.INS_GET_INFO:
                handleGetInfo(apdu);
                return;
            case Constants.INS_GET_AUTHENTIKEY:
                handleGetAuthentikey(apdu);
                return;
            case Constants.INS_RESET_TO_FACTORY:
                handleResetToFactory();
                return;
            default:
                ISOException.throwIt(Constants.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Returns the current capability profile as a TLV blob. The buffer is intentionally short and
     * fully self-describing so that a host can interrogate any meowl card without out-of-band
     * version metadata.
     */
    private void handleGetInfo(APDU apdu) {
        short offset = 0;
        offset =
                ApduTlv.putVersion(
                        scratch,
                        offset,
                        Constants.TAG_PROTOCOL_VERSION,
                        Constants.PROTOCOL_VERSION_MAJOR,
                        Constants.PROTOCOL_VERSION_MINOR);
        offset =
                ApduTlv.putVersion(
                        scratch,
                        offset,
                        Constants.TAG_APPLET_VERSION,
                        Constants.APPLET_VERSION_MAJOR,
                        Constants.APPLET_VERSION_MINOR);
        offset = ApduTlv.putByte(scratch, offset, Constants.TAG_LIFECYCLE_STATE, state.current());
        offset =
                ApduTlv.putShort(
                        scratch, offset, Constants.TAG_CAPABILITIES, supportedCapabilities());

        // Compressed authentikey pubkey is part of the public identity profile.
        short pkOffset = (short) (offset + 2);
        short pkEnd = authentikey.writeCompressedPubkeyTo(scratch, pkOffset);
        scratch[offset] = Constants.TAG_AUTHENTIKEY_PUBKEY;
        scratch[(short) (offset + 1)] = (byte) (pkEnd - pkOffset);
        offset = pkEnd;

        emit(apdu, scratch, (short) 0, offset);
    }

    /** Returns the compressed authentikey public key (33 bytes). */
    private void handleGetAuthentikey(APDU apdu) {
        short end = authentikey.writeCompressedPubkeyTo(scratch, (short) 0);
        emit(apdu, scratch, (short) 0, end);
    }

    /**
     * Records one {@code RESET_TO_FACTORY} invocation. Delegates the destructive logic to {@link
     * #wipe()} via the {@link WipeTrigger} interface.
     */
    private void handleResetToFactory() {
        resetTrigger.recordInvocation(this);
    }

    /**
     * Phase 1 wipe behaviour: reset the lifecycle FSM only. Phases 2+ add seed, PIN/PUK and PKI
     * material to this hook; the authentikey is preserved by design.
     */
    @Override
    public void wipe() {
        state.resetToUninitialized();
    }

    private short supportedCapabilities() {
        // Phase 1 advertises only what is actually implemented; subsequent phases OR in their bits
        // when their handlers land.
        return Constants.CAP_RESET_TO_FACTORY;
    }

    private void emit(APDU apdu, byte[] src, short offset, short end) {
        short len = (short) (end - offset);
        byte[] outBuffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(src, offset, outBuffer, (short) 0, len);
        apdu.setOutgoingAndSend((short) 0, len);
    }
}

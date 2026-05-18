/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * Entry point of the meowl multi-chain hardware-wallet applet.
 *
 * <p>This class is intentionally a thin router: it parses the outer APDU, dispatches to a
 * single-purpose handler that writes its response directly into the JCRE-owned APDU buffer, and
 * finally returns the response length so the router can issue {@link APDU#setOutgoingAndSend(short,
 * short)}. Any uncaught condition flows back to the host as an ISO 7816-4 status word via {@link
 * ISOException}.
 *
 * <p>All cryptographic and business-logic complexity lives in dedicated companion classes in this
 * same package — {@link Authentikey}, {@link ResetToFactory}, {@link LifecycleState}, {@link
 * ApduTlv}, {@link Secp256k1} — because in JavaCard each Java package maps one-to-one to a CAP
 * file.
 *
 * <p>Phase 1 surface: {@link Constants#INS_GET_INFO}, {@link Constants#INS_GET_AUTHENTIKEY}, {@link
 * Constants#INS_RESET_TO_FACTORY}. Every other INS returns {@link Constants#SW_INS_NOT_SUPPORTED}
 * as a deliberate placeholder for Phases 2-5.
 */
public final class MeowlApplet extends Applet implements WipeTrigger {

    private final LifecycleState state;
    private final Authentikey authentikey;
    private final ResetToFactory resetTrigger;

    private MeowlApplet() {
        this.state = new LifecycleState();
        this.authentikey = new Authentikey();
        this.resetTrigger = new ResetToFactory();
        register();
    }

    /** GlobalPlatform install entry point. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MeowlApplet();
    }

    @Override
    public boolean select() {
        // Re-arm the reset trigger so a residual countdown from a previous session never bleeds
        // into a fresh one. (The transient counter is also cleared by CLEAR_ON_RESET, but be
        // explicit on every select() for clarity.)
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

        // Rearming policy: any INS other than RESET_TO_FACTORY rearms the multi-step trigger.
        // Placed before dispatch so the rule is local to the router and impossible to forget
        // when a handler is added.
        if (ins != Constants.INS_RESET_TO_FACTORY) {
            resetTrigger.rearm();
        }

        short responseLen;
        switch (ins) {
            case Constants.INS_GET_INFO:
                responseLen = handleGetInfo(buffer);
                break;
            case Constants.INS_GET_AUTHENTIKEY:
                responseLen = handleGetAuthentikey(buffer);
                break;
            case Constants.INS_RESET_TO_FACTORY:
                // Always throws — never returns. The status word encodes the countdown.
                resetTrigger.recordInvocation(this);
                return;
            default:
                ISOException.throwIt(Constants.SW_INS_NOT_SUPPORTED);
                return;
        }
        apdu.setOutgoingAndSend((short) 0, responseLen);
    }

    /**
     * Writes the capability + identity profile as a TLV blob directly into the APDU buffer.
     *
     * <p>The blob is intentionally short and fully self-describing so that a host can interrogate
     * any meowl card without out-of-band version metadata.
     */
    private short handleGetInfo(byte[] buffer) {
        short offset = 0;
        offset =
                ApduTlv.putShort(
                        buffer, offset, Constants.TAG_PROTOCOL_VERSION, Constants.PROTOCOL_VERSION);
        offset =
                ApduTlv.putShort(
                        buffer, offset, Constants.TAG_APPLET_VERSION, Constants.APPLET_VERSION);
        offset = ApduTlv.putByte(buffer, offset, Constants.TAG_LIFECYCLE_STATE, state.current());
        offset =
                ApduTlv.putShort(
                        buffer, offset, Constants.TAG_CAPABILITIES, advertisedCapabilities());

        // Authentikey pubkey: streamed in-place using the reserve / finishReserved pair so the
        // 33-byte value is written directly by Authentikey.writeCompressedPubkeyTo without an
        // intermediate buffer.
        short headerOffset = offset;
        short valueStart = ApduTlv.reserve(buffer, headerOffset, Constants.TAG_AUTHENTIKEY_PUBKEY);
        short valueEnd = authentikey.writeCompressedPubkeyTo(buffer, valueStart);
        ApduTlv.finishReserved(buffer, headerOffset, (short) (valueEnd - valueStart));
        return valueEnd;
    }

    /** Writes the raw 33-byte compressed authentikey public key into the APDU buffer. */
    private short handleGetAuthentikey(byte[] buffer) {
        return authentikey.writeCompressedPubkeyTo(buffer, (short) 0);
    }

    /**
     * Phase 1 wipe behaviour: collapse the lifecycle FSM to {@link LifecycleState#UNINITIALIZED}.
     * Phases 2+ extend this hook to also clear the seed, PIN/PUK and PKI material. The authentikey
     * is preserved by design ({@code docs/adr/0005-authentikey-lifecycle.md}).
     */
    @Override
    public void wipe() {
        state.reset();
    }

    /**
     * Capability bitmask advertised through {@link Constants#TAG_CAPABILITIES}. Each phase ORs in
     * its own bit as its handlers come online.
     */
    private static short advertisedCapabilities() {
        return Constants.CAP_RESET_TO_FACTORY;
    }
}

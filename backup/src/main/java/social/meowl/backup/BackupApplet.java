/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.backup;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Entry point of the meowl backup applet — a BIP-39 seed-backup card aligned with the Ledger
 * Recovery Key threat model, built on the meowl Secure Channel.
 *
 * <p>Outer INS surface (no Secure Channel required): {@code GET_INFO} (status), {@code
 * GET_AUTHENTIKEY}, {@code RESET_TO_FACTORY}, {@code INIT_SECURE_CHANNEL}, {@code
 * OPEN_SECURE_CHANNEL}. Every secret-touching operation — PIN setup/verify/change, seed
 * backup/restore/verify, set-name, factory-reset — is reachable only through {@code
 * OPEN_SECURE_CHANNEL} and dispatched by {@link #dispatchInner}.
 *
 * <p>The cryptographic transport, authentikey, lifecycle FSM and reset countdown are the single
 * {@code social.meowl.shared} sources injected at build time; only the seed vault and the no-PUK,
 * wipe-on-exhaustion PIN are backup-specific.
 */
public final class BackupApplet extends Applet implements WipeTrigger {

    /** Shared transient scratch sized to the Secure Channel handshake requirement. */
    private static final short SHARED_SCRATCH_LEN = SecureChannel.MIN_SCRATCH_LEN;

    /** Capability bitmask reported by {@code GET_INFO}: open Secure Channel + reset-to-factory. */
    private static final short ADVERTISED_CAPABILITIES =
            (short) (Constants.CAP_RESET_TO_FACTORY | Constants.CAP_SC_CBC_HMAC);

    private final LifecycleState state;
    private final Authentikey authentikey;
    private final ResetToFactory resetTrigger;
    private final SecureChannel secureChannel;

    private BackupApplet() {
        byte[] sharedScratch =
                JCSystem.makeTransientByteArray(SHARED_SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.state = new LifecycleState();
        this.authentikey = new Authentikey();
        this.resetTrigger = new ResetToFactory();
        this.secureChannel = new SecureChannel(this.authentikey, sharedScratch);
        register();
    }

    /** GlobalPlatform install entry point. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new BackupApplet();
    }

    @Override
    public boolean select() {
        resetTrigger.rearm();
        secureChannel.reset();
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

        if (ins != Constants.INS_RESET_TO_FACTORY) {
            resetTrigger.rearm();
        }

        short responseLen;
        switch (ins) {
            case Constants.INS_GET_INFO:
                responseLen = handleGetStatus(buffer);
                break;
            case Constants.INS_GET_AUTHENTIKEY:
                responseLen = authentikey.writeCompressedPubkeyTo(buffer, (short) 0);
                break;
            case Constants.INS_RESET_TO_FACTORY:
                resetTrigger.recordInvocation(this);
                return;
            case Constants.INS_INIT_SECURE_CHANNEL:
                responseLen = handleInitSecureChannel(apdu, buffer);
                break;
            case Constants.INS_OPEN_SECURE_CHANNEL:
                responseLen = handleOpenSecureChannel(apdu, buffer);
                break;
            default:
                throw Constants.fail(Constants.SW_INS_NOT_SUPPORTED);
        }
        apdu.setOutgoingAndSend((short) 0, responseLen);
    }

    /**
     * {@code GET_INFO} status TLV: protocol + applet version, lifecycle state, capability bitmask
     * and the compressed authentikey public key. The seed-presence, PIN-tries and card-name tags
     * are added once the seed vault and PIN are wired (P2).
     */
    private short handleGetStatus(byte[] buffer) {
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
                        buffer, offset, Constants.TAG_CAPABILITIES, ADVERTISED_CAPABILITIES);

        short headerOffset = offset;
        short valueStart = ApduTlv.reserve(buffer, headerOffset, Constants.TAG_AUTHENTIKEY_PUBKEY);
        short pkLen = authentikey.writeCompressedPubkeyTo(buffer, valueStart);
        ApduTlv.finishReserved(buffer, headerOffset, pkLen);
        return (short) (valueStart + pkLen);
    }

    /** Opens a fresh Secure Channel session, tearing down any prior session keys first. */
    private short handleInitSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        secureChannel.reset();
        return secureChannel.initHandshake(buffer, ISO7816.OFFSET_CDATA, lc);
    }

    /**
     * Unwraps an encrypted inner APDU, dispatches it via {@link #dispatchInner}, and re-wraps the
     * inner response. The unwrapped plaintext (PIN bytes, seed entropy, …) is wiped from the APDU
     * buffer in the {@code finally} on every path, leaving only the outbound envelope intact.
     */
    private short handleOpenSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        short plainLen = secureChannel.unwrap(buffer, ISO7816.OFFSET_CDATA, lc);
        short envelopeLen = 0;
        try {
            if (plainLen < 5) {
                ISOException.throwIt(Constants.SW_WRONG_LENGTH);
            }
            short innerOff = ISO7816.OFFSET_CDATA;
            byte innerCla = buffer[innerOff];
            byte innerIns = buffer[(short) (innerOff + 1)];
            byte innerP1 = buffer[(short) (innerOff + 2)];
            byte innerP2 = buffer[(short) (innerOff + 3)];
            short innerLc = (short) (buffer[(short) (innerOff + 4)] & 0xFF);
            if ((short) (5 + innerLc) != plainLen) {
                ISOException.throwIt(Constants.SW_WRONG_LENGTH);
            }
            if (innerCla != Constants.CLA_MEOWL) {
                ISOException.throwIt(Constants.SW_CLA_NOT_SUPPORTED);
            }
            short innerDataOff = (short) (innerOff + 5);
            short respLen =
                    dispatchInner(buffer, innerIns, innerP1, innerP2, innerDataOff, innerLc);
            envelopeLen = secureChannel.wrap(buffer, ISO7816.OFFSET_CDATA, respLen);
            return envelopeLen;
        } finally {
            wipeSecureChannelRequestTail(buffer, plainLen, envelopeLen);
        }
    }

    static void wipeSecureChannelRequestTail(byte[] buffer, short plainLen, short envelopeLen) {
        short reqEnd = (short) (ISO7816.OFFSET_CDATA + plainLen);
        short wipeFrom = envelopeLen > ISO7816.OFFSET_CDATA ? envelopeLen : ISO7816.OFFSET_CDATA;
        if (reqEnd > wipeFrom) {
            Util.arrayFillNonAtomic(buffer, wipeFrom, (short) (reqEnd - wipeFrom), (byte) 0);
        }
    }

    /**
     * Inner-APDU router, reachable only through {@code OPEN_SECURE_CHANNEL}. P3 wires {@code
     * SETUP_PIN}, {@code VERIFY_PIN}, {@code CHANGE_PIN}, {@code BACKUP_SEED}, {@code
     * RESTORE_SEED}, {@code VERIFY_SEED}, {@code SET_NAME} and {@code FACTORY_RESET} here.
     */
    private short dispatchInner(
            byte[] buffer, byte ins, byte p1, byte p2, short dataOff, short dataLen) {
        throw Constants.fail(Constants.SW_INS_NOT_SUPPORTED);
    }

    /**
     * Reset-to-factory wipe driven by the {@code RESET_TO_FACTORY} countdown. The authentikey is
     * preserved; Secure Channel state and the lifecycle FSM are reset. The seed vault and PIN wipes
     * are added once those components are wired (P2).
     */
    @Override
    public void wipe() {
        secureChannel.reset();
        JCSystem.beginTransaction();
        state.resetInTx();
        JCSystem.commitTransaction();
    }
}

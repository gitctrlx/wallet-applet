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

    // Backup lifecycle is the shared 3-step forward FSM with backup-meaningful aliases:
    // FRESH --SETUP_PIN--> PIN_SET --BACKUP_SEED--> SEEDED. The wallet's fourth state is unused.
    private static final byte LC_FRESH = LifecycleState.UNINITIALIZED;
    private static final byte LC_PIN_SET = LifecycleState.PERSONALIZED;
    private static final byte LC_SEEDED = LifecycleState.SETUP_DONE;

    private final LifecycleState state;
    private final Authentikey authentikey;
    private final ResetToFactory resetTrigger;
    private final SecureChannel secureChannel;
    private final SeedVault seedVault;
    private final BackupPin backupPin;

    /** User-facing backup card label (persistent); empty until {@code SET_NAME}. */
    private final byte[] cardName;

    private byte cardNameLen;

    /** Transient {@code [off1, len1, off2, len2]} scratch for two-field inner commands. */
    private final short[] twoFieldDesc;

    private BackupApplet() {
        byte[] sharedScratch =
                JCSystem.makeTransientByteArray(SHARED_SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.state = new LifecycleState();
        this.authentikey = new Authentikey();
        this.resetTrigger = new ResetToFactory();
        this.secureChannel = new SecureChannel(this.authentikey, sharedScratch);
        this.seedVault = new SeedVault();
        this.backupPin = new BackupPin();
        this.cardName = new byte[Constants.BACKUP_NAME_MAX_LEN];
        this.cardNameLen = (byte) 0;
        this.twoFieldDesc = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
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
        backupPin.clearSession();
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
        offset =
                ApduTlv.putByte(
                        buffer,
                        offset,
                        Constants.TAG_SEED_PRESENT,
                        seedVault.isSeeded() ? (byte) 1 : (byte) 0);
        offset = ApduTlv.putByte(buffer, offset, Constants.TAG_SEED_LEN, seedVault.length());
        offset =
                ApduTlv.putByte(
                        buffer, offset, Constants.TAG_PIN_TRIES, backupPin.triesRemaining());

        short nameHeader = offset;
        short nameValue = ApduTlv.reserve(buffer, nameHeader, Constants.TAG_CARD_NAME);
        Util.arrayCopyNonAtomic(cardName, (short) 0, buffer, nameValue, cardNameLen);
        ApduTlv.finishReserved(buffer, nameHeader, cardNameLen);
        offset = (short) (nameValue + cardNameLen);

        short headerOffset = offset;
        short valueStart = ApduTlv.reserve(buffer, headerOffset, Constants.TAG_AUTHENTIKEY_PUBKEY);
        short pkLen = authentikey.writeCompressedPubkeyTo(buffer, valueStart);
        ApduTlv.finishReserved(buffer, headerOffset, pkLen);
        return (short) (valueStart + pkLen);
    }

    /**
     * Opens a fresh Secure Channel session, tearing down the prior session keys and the
     * PIN-verified flag first so a re-handshake never inherits the previous session's
     * authentication state (PIN binds to the SC session).
     */
    private short handleInitSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        secureChannel.reset();
        backupPin.clearSession();
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
     * Inner-APDU router, reachable only through {@code OPEN_SECURE_CHANNEL}. {@code FACTORY_RESET}
     * is the outer {@code RESET_TO_FACTORY} countdown (no PIN, anti-fat-finger) handled in {@link
     * #process}; every command below requires the Secure Channel and, past setup, a verified PIN.
     */
    private short dispatchInner(
            byte[] buffer, byte ins, byte p1, byte p2, short dataOff, short dataLen) {
        switch (ins) {
            case Constants.INS_SETUP:
                return handleSetupPin(buffer, dataOff, dataLen);
            case Constants.INS_VERIFY_PIN:
                return handleVerifyPin(buffer, dataOff, dataLen);
            case Constants.INS_CHANGE_PIN:
                return handleChangePin(buffer, dataOff, dataLen);
            case Constants.INS_BACKUP_SEED:
                return handleBackupSeed(buffer, dataOff, dataLen);
            case Constants.INS_RESTORE_SEED:
                return handleRestoreSeed(buffer, dataLen);
            case Constants.INS_VERIFY_SEED:
                return handleVerifySeed(buffer, dataLen);
            case Constants.INS_SET_NAME:
                return handleSetName(buffer, dataOff, dataLen);
            default:
                throw Constants.fail(Constants.SW_INS_NOT_SUPPORTED);
        }
    }

    /** {@code SETUP_PIN} inner data: {@code [pinLen(1), PIN]}. Provisions the PIN, no PUK. */
    private short handleSetupPin(byte[] buffer, short dataOff, short dataLen) {
        state.require(LC_FRESH);
        if (dataLen < 1) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pinLen = (short) (buffer[dataOff] & 0xFF);
        if ((short) (1 + pinLen) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        JCSystem.beginTransaction();
        backupPin.setupInTx(buffer, (short) (dataOff + 1), pinLen);
        state.transitionToInTx(LC_PIN_SET);
        JCSystem.commitTransaction();
        return 0;
    }

    /** {@code VERIFY_PIN} inner data: the PIN bytes. Exhaustion wipes the seed (no PUK). */
    private short handleVerifyPin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LC_PIN_SET);
        verifyPinOrWipe(buffer, dataOff, dataLen);
        return 0;
    }

    /** {@code CHANGE_PIN} inner data: {@code [oldLen(1), old, newLen(1), new]}. */
    private short handleChangePin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LC_PIN_SET);
        parseTwoLengthPrefixedFields(buffer, dataOff, dataLen);
        // A correct old PIN consumes no try, so a later bad new-PIN length cannot burn one; a wrong
        // old PIN consumes a try and may trip the wipe-on-exhaustion path.
        verifyPinOrWipe(buffer, twoFieldDesc[0], twoFieldDesc[1]);
        JCSystem.beginTransaction();
        backupPin.changeInTx(buffer, twoFieldDesc[2], twoFieldDesc[3]);
        JCSystem.commitTransaction();
        return 0;
    }

    /** {@code BACKUP_SEED} inner data: {@code [entropyLen(1), entropy]}. Single-slot, PIN-gated. */
    private short handleBackupSeed(byte[] buffer, short dataOff, short dataLen) {
        state.require(LC_PIN_SET);
        requirePinVerified();
        if (dataLen < 1) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short entropyLen = (short) (buffer[dataOff] & 0xFF);
        if ((short) (1 + entropyLen) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        JCSystem.beginTransaction();
        seedVault.storeInTx(buffer, (short) (dataOff + 1), entropyLen);
        state.transitionToInTx(LC_SEEDED);
        JCSystem.commitTransaction();
        // The entropy plaintext is wiped centrally by handleOpenSecureChannel's finally.
        return 0;
    }

    /** {@code RESTORE_SEED}: no input; returns the stored entropy under the Secure Channel. */
    private short handleRestoreSeed(byte[] buffer, short dataLen) {
        state.require(LC_SEEDED);
        requirePinVerified();
        if (dataLen != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        return seedVault.restore(buffer, ISO7816.OFFSET_CDATA);
    }

    /** {@code VERIFY_SEED}: no input; recomputes the integrity tag, raising on mismatch. */
    private short handleVerifySeed(byte[] buffer, short dataLen) {
        state.require(LC_SEEDED);
        requirePinVerified();
        if (dataLen != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        seedVault.verify();
        return 0;
    }

    /** {@code SET_NAME} inner data: the label bytes (0..{@link Constants#BACKUP_NAME_MAX_LEN}). */
    private short handleSetName(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LC_PIN_SET);
        requirePinVerified();
        if (dataLen > Constants.BACKUP_NAME_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        JCSystem.beginTransaction();
        Util.arrayCopyNonAtomic(buffer, dataOff, cardName, (short) 0, dataLen);
        cardNameLen = (byte) dataLen;
        JCSystem.commitTransaction();
        return 0;
    }

    /** Common gate for handlers that require the PIN verified in this Secure Channel session. */
    private void requirePinVerified() {
        if (!backupPin.isVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    /**
     * Verifies the PIN, applying the scorched-earth policy: a wrong PIN consumes a try and, when
     * the counter reaches zero, wipes the seed and raises {@link Constants#SW_AUTH_BLOCKED};
     * otherwise a {@code 0x63Cn} retry status word carries the remaining count.
     */
    private void verifyPinOrWipe(byte[] buffer, short off, short len) {
        if (backupPin.check(buffer, off, len)) {
            return;
        }
        if (backupPin.triesRemaining() == 0) {
            wipe();
            ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
        }
        ISOException.throwIt(
                (short) (Constants.SW_PIN_RETRIES_BASE | (backupPin.triesRemaining() & 0x0F)));
    }

    /**
     * Parses {@code [len1(1), field1, len2(1), field2]} from {@code
     * buffer[dataOff..dataOff+dataLen]} into {@link #twoFieldDesc} as {@code [off1, len1, off2,
     * len2]}; raises {@link Constants#SW_WRONG_LENGTH} on any overrun.
     */
    private void parseTwoLengthPrefixedFields(byte[] buffer, short dataOff, short dataLen) {
        short cursor = dataOff;
        short len1 = (short) (buffer[cursor++] & 0xFF);
        short off1 = cursor;
        cursor += len1;
        if ((short) (cursor + 1) > (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short len2 = (short) (buffer[cursor++] & 0xFF);
        short off2 = cursor;
        if ((short) (cursor + len2) != (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        twoFieldDesc[0] = off1;
        twoFieldDesc[1] = len1;
        twoFieldDesc[2] = off2;
        twoFieldDesc[3] = len2;
    }

    /**
     * Factory-reset wipe — the single destructive routine, shared by the {@code RESET_TO_FACTORY}
     * countdown, the {@code FACTORY_RESET} command and the PIN-exhaustion trigger. The authentikey
     * is preserved (it is the card's stable Secure Channel identity); the seed, its integrity tag,
     * the PIN, the card label and the lifecycle state are all reset. The persistent gates commit in
     * one transaction so a torn power-off cannot leave half-reset state.
     */
    @Override
    public void wipe() {
        secureChannel.reset();
        backupPin.clearSession();
        JCSystem.beginTransaction();
        seedVault.wipeInTx();
        backupPin.wipeInTx();
        cardNameLen = (byte) 0;
        state.resetInTx();
        JCSystem.commitTransaction();
        Util.arrayFillNonAtomic(cardName, (short) 0, (short) cardName.length, (byte) 0);
    }
}

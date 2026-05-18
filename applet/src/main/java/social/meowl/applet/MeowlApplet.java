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
 * <p>The class is a thin router. Outer-frame APDUs are dispatched by {@link #process}; if the outer
 * INS is {@link Constants#INS_OPEN_SECURE_CHANNEL} the encrypted payload is decrypted by the {@link
 * SecureChannel} and the inner APDU is dispatched by {@link #dispatchInner}. Every cryptographic
 * and business-logic component lives in a single-purpose companion class in this same package (a
 * JavaCard CAP file is one Java package).
 *
 * <p>Outer INS surface (Phases 1 + 2 only):
 *
 * <ul>
 *   <li>{@link Constants#INS_GET_INFO}, {@link Constants#INS_GET_AUTHENTIKEY}, {@link
 *       Constants#INS_RESET_TO_FACTORY}, {@link Constants#INS_INIT_SECURE_CHANNEL} run outside any
 *       Secure Channel and are reachable on a freshly-installed card.
 *   <li>{@link Constants#INS_OPEN_SECURE_CHANNEL} unwraps an encrypted inner APDU and dispatches it
 *       via {@link #dispatchInner}.
 * </ul>
 *
 * <p>Inner INS surface (Phase 3 onward) is reached only through OPEN_SECURE_CHANNEL.
 */
public final class MeowlApplet extends Applet implements WipeTrigger {

    /**
     * Scratch buffer used by inner handlers that need to stage their input before producing a
     * response that would otherwise overlap with the input region.
     */
    private static final short INNER_SCRATCH_LEN = (short) 128;

    private final LifecycleState state;
    private final Authentikey authentikey;
    private final ResetToFactory resetTrigger;
    private final SecureChannel secureChannel;
    private final PinManager pinManager;
    private final PkiManager pkiManager;
    private final MasterSeed masterSeed;
    private final Bip32 bip32;
    private final Slip10 slip10;
    private final EcdsaK1 ecdsaK1;
    private final Schnorr schnorr;
    private final byte[] innerScratch;

    private MeowlApplet() {
        this.state = new LifecycleState();
        this.authentikey = new Authentikey();
        this.resetTrigger = new ResetToFactory();
        this.secureChannel = new SecureChannel(this.authentikey);
        this.pinManager = new PinManager();
        this.pkiManager = new PkiManager(this.authentikey);
        this.masterSeed = new MasterSeed();
        this.bip32 = new Bip32(this.masterSeed);
        this.slip10 = new Slip10(this.masterSeed);
        this.ecdsaK1 = new EcdsaK1(this.bip32);
        this.schnorr = new Schnorr(this.bip32);
        this.innerScratch =
                JCSystem.makeTransientByteArray(INNER_SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        register();
    }

    /** GlobalPlatform install entry point. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MeowlApplet();
    }

    @Override
    public boolean select() {
        // Tear down per-session state so it never bleeds across selects.
        resetTrigger.rearm();
        secureChannel.reset();
        pinManager.clearSession();
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
                responseLen = handleGetInfo(buffer);
                break;
            case Constants.INS_GET_AUTHENTIKEY:
                responseLen = handleGetAuthentikey(buffer);
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
                ISOException.throwIt(Constants.SW_INS_NOT_SUPPORTED);
                return;
        }
        apdu.setOutgoingAndSend((short) 0, responseLen);
    }

    /**
     * Opens a fresh Secure Channel session.
     *
     * <p>Before the handshake we explicitly tear down <em>both</em> the prior Secure Channel
     * session keys (so the new handshake cannot accidentally leave the old key material "borrowed"
     * if it throws) and the PIN-verified flag. Without the latter, an attacker who obtained access
     * to an already-authenticated card could open a fresh Secure Channel session and inherit the
     * {@code OwnerPIN.isValidated()} flag from the previous session, defeating the "PIN binds to
     * the Secure Channel session" property advertised in ADR-0006.
     */
    private short handleInitSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        secureChannel.reset();
        pinManager.clearSession();
        return secureChannel.initHandshake(buffer, ISO7816.OFFSET_CDATA, lc);
    }

    /**
     * Unwraps an encrypted inner APDU, dispatches it via {@link #dispatchInner}, and re-wraps the
     * inner response. The inner APDU layout is {@code [CLA INS P1 P2 LC data]}, identical to the
     * outer frame.
     */
    private short handleOpenSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        short plainLen = secureChannel.unwrap(buffer, ISO7816.OFFSET_CDATA, lc);
        // After unwrap, plaintext sits at buffer[OFFSET_CDATA .. +plainLen]. We parse it as a
        // standard short APDU.
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

        // The inner handler writes its response into buffer[OFFSET_CDATA .. +respLen]. Handlers
        // that need their input bytes past the point where the response overwrites them are
        // expected to stage the input via {@link #innerScratch} first.
        short respLen = dispatchInner(buffer, innerIns, innerP1, innerP2, innerDataOff, innerLc);
        return secureChannel.wrap(buffer, ISO7816.OFFSET_CDATA, respLen);
    }

    private short dispatchInner(
            byte[] buffer, byte ins, byte p1, byte p2, short dataOff, short dataLen) {
        switch (ins) {
            case Constants.INS_SETUP:
                return handleSetup(buffer, dataOff, dataLen);
            case Constants.INS_VERIFY_PIN:
                return handleVerifyPin(buffer, dataOff, dataLen);
            case Constants.INS_CHANGE_PIN:
                return handleChangePin(buffer, dataOff, dataLen);
            case Constants.INS_CHANGE_PUK:
                return handleChangePuk(buffer, dataOff, dataLen);
            case Constants.INS_UNBLOCK_PIN:
                return handleUnblockPin(buffer, dataOff, dataLen);
            case Constants.INS_EXPORT_PKI_PUBKEY:
                return handleExportPkiPubkey(buffer);
            case Constants.INS_SIGN_PKI_CSR:
                return handleSignPkiCsr(buffer, dataOff, dataLen);
            case Constants.INS_IMPORT_PKI_CERT:
                return handleImportPkiCert(buffer, p1, dataOff, dataLen);
            case Constants.INS_EXPORT_PKI_CERT:
                return handleExportPkiCert(buffer, dataOff, dataLen);
            case Constants.INS_LOCK_PKI:
                return handleLockPki();
            case Constants.INS_IMPORT_SEED:
                return handleImportSeed(buffer, dataOff, dataLen);
            case Constants.INS_GENERATE_SEED:
                return handleGenerateSeed(buffer, dataLen);
            case Constants.INS_EXPORT_XPUB:
                return handleExportXpub(buffer, dataOff, dataLen);
            case Constants.INS_SIGN_ECDSA_K1:
                return handleSignEcdsaK1(buffer, dataOff, dataLen);
            case Constants.INS_SIGN_SCHNORR_K1:
                return handleSignSchnorrK1(buffer, dataOff, dataLen);
            default:
                ISOException.throwIt(Constants.SW_INS_NOT_SUPPORTED);
                return 0;
        }
    }

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

        short headerOffset = offset;
        short valueStart = ApduTlv.reserve(buffer, headerOffset, Constants.TAG_AUTHENTIKEY_PUBKEY);
        short pkLen = authentikey.writeCompressedPubkeyTo(buffer, valueStart);
        ApduTlv.finishReserved(buffer, headerOffset, pkLen);
        return (short) (valueStart + pkLen);
    }

    private short handleGetAuthentikey(byte[] buffer) {
        return authentikey.writeCompressedPubkeyTo(buffer, (short) 0);
    }

    /*  Phase 3 inner handlers — all reachable only via OPEN_SECURE_CHANNEL.  */

    /** {@code SETUP} inner data layout: {@code [pinLen(1), PIN, pukLen(1), PUK]}. */
    private short handleSetup(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.PERSONALIZED);
        if (dataLen < (short) (1 + Constants.PIN_MIN_LEN + 1 + Constants.PUK_MIN_LEN)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short cursor = dataOff;
        short pinLen = (short) (buffer[cursor++] & 0xFF);
        short pinDataOff = cursor;
        cursor += pinLen;
        if ((short) (cursor + 1) > (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pukLen = (short) (buffer[cursor++] & 0xFF);
        short pukDataOff = cursor;
        if ((short) (cursor + pukLen) != (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // PIN install, PUK install, provisioned flag and lifecycle advance must commit as one
        // unit: a power loss between them would leave the card in an unrecoverable state where
        // VERIFY_PIN is gated out by the lifecycle FSM and SETUP is rejected by the
        // already-provisioned guard.
        JCSystem.beginTransaction();
        pinManager.setupInTx(buffer, pinDataOff, pinLen, buffer, pukDataOff, pukLen);
        state.transitionToInTx(LifecycleState.SETUP_DONE);
        JCSystem.commitTransaction();
        return 0;
    }

    private short handleVerifyPin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        pinManager.verifyPin(buffer, dataOff, dataLen);
        return 0;
    }

    /** {@code CHANGE_PIN} inner data layout: {@code [oldLen(1), old, newLen(1), new]}. */
    private short handleChangePin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        short cursor = dataOff;
        short oldLen = (short) (buffer[cursor++] & 0xFF);
        short oldOff = cursor;
        cursor += oldLen;
        if ((short) (cursor + 1) > (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short newLen = (short) (buffer[cursor++] & 0xFF);
        short newOff = cursor;
        if ((short) (cursor + newLen) != (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        pinManager.changePin(buffer, oldOff, oldLen, buffer, newOff, newLen);
        return 0;
    }

    /** {@code CHANGE_PUK} inner data layout: {@code [oldLen(1), oldPUK, newLen(1), newPUK]}. */
    private short handleChangePuk(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        // PUK change requires PIN to be currently verified, so a stolen card whose PIN is
        // unknown cannot be hijacked by rotating its PUK.
        if (!pinManager.isPinVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short cursor = dataOff;
        short oldLen = (short) (buffer[cursor++] & 0xFF);
        short oldOff = cursor;
        cursor += oldLen;
        if ((short) (cursor + 1) > (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short newLen = (short) (buffer[cursor++] & 0xFF);
        short newOff = cursor;
        if ((short) (cursor + newLen) != (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        pinManager.changePuk(buffer, oldOff, oldLen, buffer, newOff, newLen);
        return 0;
    }

    /** {@code UNBLOCK_PIN} inner data layout: {@code [pukLen(1), PUK, newPinLen(1), newPIN]}. */
    private short handleUnblockPin(byte[] buffer, short dataOff, short dataLen) {
        state.requireAtLeast(LifecycleState.SETUP_DONE);
        short cursor = dataOff;
        short pukLen = (short) (buffer[cursor++] & 0xFF);
        short pukOff = cursor;
        cursor += pukLen;
        if ((short) (cursor + 1) > (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short newPinLen = (short) (buffer[cursor++] & 0xFF);
        short newPinOff = cursor;
        if ((short) (cursor + newPinLen) != (short) (dataOff + dataLen)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        pinManager.unblockPin(buffer, pukOff, pukLen, buffer, newPinOff, newPinLen);
        return 0;
    }

    private short handleExportPkiPubkey(byte[] buffer) {
        state.require(LifecycleState.UNINITIALIZED);
        return pkiManager.exportPubkey(buffer, ISO7816.OFFSET_CDATA);
    }

    /** {@code SIGN_PKI_CSR} inner data layout: {@code [hash(32)]}. */
    private short handleSignPkiCsr(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.UNINITIALIZED);
        if (dataLen != Constants.EC_SCALAR_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Stage the digest in innerScratch so the signature output, which exceeds 32 bytes, does
        // not overlap the input.
        Util.arrayCopyNonAtomic(buffer, dataOff, innerScratch, (short) 0, Constants.EC_SCALAR_LEN);
        short sigLen = pkiManager.signCsr(innerScratch, (short) 0, buffer, ISO7816.OFFSET_CDATA);
        Util.arrayFillNonAtomic(innerScratch, (short) 0, Constants.EC_SCALAR_LEN, (byte) 0);
        return sigLen;
    }

    /**
     * {@code IMPORT_PKI_CERT}: three-phase protocol selected by {@code P1}.
     *
     * <ul>
     *   <li>{@code P1 = INIT}: data = {@code [totalSize (2 BE)]}.
     *   <li>{@code P1 = WRITE}: data = {@code [offset (2 BE), chunk...]}.
     *   <li>{@code P1 = FINALIZE}: data is empty.
     * </ul>
     */
    private short handleImportPkiCert(byte[] buffer, byte p1, short dataOff, short dataLen) {
        state.require(LifecycleState.UNINITIALIZED);
        switch (p1) {
            case Constants.PKI_IMPORT_P1_INIT:
                if (dataLen != 2) {
                    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
                }
                pkiManager.importInit(Util.getShort(buffer, dataOff));
                return 0;
            case Constants.PKI_IMPORT_P1_WRITE:
                if (dataLen < 3) {
                    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
                }
                short writeOff = Util.getShort(buffer, dataOff);
                short chunkLen = (short) (dataLen - 2);
                pkiManager.importWrite(writeOff, buffer, (short) (dataOff + 2), chunkLen);
                return 0;
            case Constants.PKI_IMPORT_P1_FINALIZE:
                if (dataLen != 0) {
                    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
                }
                pkiManager.importFinalize();
                return 0;
            default:
                ISOException.throwIt(Constants.SW_INCORRECT_P1P2);
                return 0;
        }
    }

    /**
     * {@code EXPORT_PKI_CERT} inner data layout: {@code [offset (2 BE), requestedLen (2 BE)]}. The
     * response starts with the certificate total length (2 BE) so the host knows when to stop
     * paging, followed by the requested window.
     */
    private short handleExportPkiCert(byte[] buffer, short dataOff, short dataLen) {
        // Allow export at any post-personalisation state — host needs the cert to verify the
        // card before unlocking the user PIN flow.
        if (dataLen != 4) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short offset = Util.getShort(buffer, dataOff);
        short requested = Util.getShort(buffer, (short) (dataOff + 2));
        short certLen = pkiManager.certLen();
        Util.setShort(buffer, ISO7816.OFFSET_CDATA, certLen);
        short written =
                certLen > 0
                        ? pkiManager.exportCert(
                                offset, requested, buffer, (short) (ISO7816.OFFSET_CDATA + 2))
                        : (short) 0;
        return (short) (2 + written);
    }

    private short handleLockPki() {
        state.require(LifecycleState.UNINITIALIZED);
        if (!pkiManager.hasCert()) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        state.transitionTo(LifecycleState.PERSONALIZED);
        return 0;
    }

    /*  Phase 4 inner handlers — HD wallet derivation.  */

    /**
     * {@code IMPORT_SEED} inner data layout: {@code [seedLen(1), seed(seedLen)]}. Requires the
     * lifecycle to be {@code SETUP_DONE} and the PIN to be currently verified.
     */
    private short handleImportSeed(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.SETUP_DONE);
        if (!pinManager.isPinVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (dataLen < 1) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short seedLen = (short) (buffer[dataOff] & 0xFF);
        if ((short) (1 + seedLen) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        JCSystem.beginTransaction();
        masterSeed.importSeed(buffer, (short) (dataOff + 1), seedLen);
        state.transitionToInTx(LifecycleState.SEEDED);
        JCSystem.commitTransaction();
        // Overwrite the seed bytes in the APDU buffer before the response goes out.
        Util.arrayFillNonAtomic(buffer, (short) (dataOff + 1), seedLen, (byte) 0);
        return 0;
    }

    /**
     * {@code GENERATE_SEED} — card-internal CSPRNG seed; the raw seed is returned <em>once</em> as
     * the response so the host can render it (e.g. as a BIP-39 mnemonic) for backup. Subsequent
     * derivation only ever exposes the chain code and the public key.
     */
    private short handleGenerateSeed(byte[] buffer, short dataLen) {
        state.require(LifecycleState.SETUP_DONE);
        if (!pinManager.isPinVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (dataLen != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Generate into ISO7816.OFFSET_CDATA so the response is in place when wrap() runs.
        JCSystem.beginTransaction();
        short writtenLen = masterSeed.generateSeed(buffer, ISO7816.OFFSET_CDATA);
        state.transitionToInTx(LifecycleState.SEEDED);
        JCSystem.commitTransaction();
        return writtenLen;
    }

    /**
     * {@code EXPORT_XPUB} inner data layout: {@code [curve(1), depth(1), path(4*depth)]}. Returns
     * {@code [compressed_pubkey(33), chain_code(32)]} for secp256k1 and {@code chain_code(32)} only
     * for Ed25519 (public key requires Phase 5 Ed25519 implementation).
     */
    private short handleExportXpub(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.SEEDED);
        if (!pinManager.isPinVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (dataLen < 2) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        byte curve = buffer[dataOff];
        short depth = (short) (buffer[(short) (dataOff + 1)] & 0xFF);
        if (depth > Constants.HD_MAX_DEPTH || (short) (2 + depth * Bip32.INDEX_LEN) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pathOff = (short) (dataOff + 2);
        switch (curve) {
            case Constants.CURVE_SECP256K1:
                return bip32.derivePath(buffer, pathOff, depth, buffer, ISO7816.OFFSET_CDATA);
            case Constants.CURVE_ED25519:
                return slip10.deriveChainCode(buffer, pathOff, depth, buffer, ISO7816.OFFSET_CDATA);
            default:
                ISOException.throwIt(Constants.SW_INCORRECT_P1P2);
                return 0;
        }
    }

    /*  Phase 5 inner handlers — signing primitives.  */

    /**
     * {@code SIGN_ECDSA_K1} inner data layout: {@code [depth(1), path(4*depth), digest(32)]}.
     * Returns {@code [r(32), s(32)]} with {@code s} low-{@code s} normalised per BIP-62 / EIP-2.
     * See {@code docs/adr/0010-signing-api-contract.md}.
     */
    private short handleSignEcdsaK1(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.SEEDED);
        if (!pinManager.isPinVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (dataLen < (short) (1 + Constants.DIGEST_LEN)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short depth = (short) (buffer[dataOff] & 0xFF);
        if (depth > Constants.HD_MAX_DEPTH
                || (short) (1 + depth * Bip32.INDEX_LEN + Constants.DIGEST_LEN) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pathOff = (short) (dataOff + 1);
        short digestOff = (short) (pathOff + depth * Bip32.INDEX_LEN);
        // Stage the digest in innerScratch so the response (which may exceed the digest length
        // and is anchored at OFFSET_CDATA) cannot trample the input bytes mid-signature.
        Util.arrayCopyNonAtomic(buffer, digestOff, innerScratch, (short) 0, Constants.DIGEST_LEN);
        short sigLen =
                ecdsaK1.signDigest(
                        buffer,
                        pathOff,
                        depth,
                        innerScratch,
                        (short) 0,
                        buffer,
                        ISO7816.OFFSET_CDATA);
        Util.arrayFillNonAtomic(innerScratch, (short) 0, Constants.DIGEST_LEN, (byte) 0);
        return sigLen;
    }

    /**
     * {@code SIGN_SCHNORR_K1} inner data layout: {@code [depth(1), path(4*depth), digest(32)]}.
     * Returns the 64-byte BIP-340 signature {@code bytes(R) ‖ s}. The signature is software-
     * implemented on top of {@link Schnorr}; aux randomness is drawn from the on-card RNG so the
     * resulting signature is non-deterministic. See {@code docs/adr/0010-signing-api-contract.md}.
     */
    private short handleSignSchnorrK1(byte[] buffer, short dataOff, short dataLen) {
        state.require(LifecycleState.SEEDED);
        if (!pinManager.isPinVerified()) {
            ISOException.throwIt(Constants.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (dataLen < (short) (1 + Constants.DIGEST_LEN)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short depth = (short) (buffer[dataOff] & 0xFF);
        if (depth > Constants.HD_MAX_DEPTH
                || (short) (1 + depth * Bip32.INDEX_LEN + Constants.DIGEST_LEN) != dataLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short pathOff = (short) (dataOff + 1);
        short digestOff = (short) (pathOff + depth * Bip32.INDEX_LEN);
        // Stage the digest in innerScratch so the response (anchored at OFFSET_CDATA — the same
        // location as the inner data) cannot trample the input bytes mid-signature.
        Util.arrayCopyNonAtomic(buffer, digestOff, innerScratch, (short) 0, Constants.DIGEST_LEN);
        short sigLen =
                schnorr.signDigest(
                        buffer,
                        pathOff,
                        depth,
                        innerScratch,
                        (short) 0,
                        buffer,
                        ISO7816.OFFSET_CDATA);
        Util.arrayFillNonAtomic(innerScratch, (short) 0, Constants.DIGEST_LEN, (byte) 0);
        return sigLen;
    }

    /**
     * Reset-to-factory wipe. Per {@code docs/adr/0005-authentikey-lifecycle.md} the authentikey
     * itself is preserved. Everything else — Secure Channel session, PIN/PUK, PKI cert, lifecycle
     * state — is destroyed.
     */
    @Override
    public void wipe() {
        secureChannel.reset();
        pinManager.wipe();
        pkiManager.wipe();
        masterSeed.wipe();
        state.reset();
    }

    private static short advertisedCapabilities() {
        return (short)
                (Constants.CAP_RESET_TO_FACTORY
                        | Constants.CAP_SC_CBC_HMAC
                        | Constants.CAP_PKI
                        | Constants.CAP_BIP32
                        | Constants.CAP_SLIP10
                        | Constants.CAP_K1_ECDSA
                        | Constants.CAP_K1_SCHNORR);
    }
}

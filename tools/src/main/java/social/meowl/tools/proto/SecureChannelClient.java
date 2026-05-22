/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Host-side client for the MEAP-2 Secure Channel.
 *
 * <p>One instance corresponds to one open Secure Channel session, identified by the ephemeral
 * keypair generated at {@link #handshake} time. The client tracks the {@code IV} counter, MAC key
 * and encryption key in plain Java fields; we do not attempt cryptographic memory hygiene on the
 * host because the underlying {@link String} / {@code byte[]} primitives the JDK provides cannot
 * give us reliable scrubbing anyway.
 *
 * <p>The implementation strictly mirrors the wire layout in {@code docs/specs/meap-2.md}:
 *
 * <ul>
 *   <li>handshake: {@code [client_eph_pub(65)]} → {@code [card_eph_pub(65) | sigLen(2 BE) | sig]}
 *   <li>HKDF salt = {@code client_eph_x ‖ card_eph_x} (64 bytes)
 *   <li>HKDF info = ASCII {@code "meowl-sc-v1"} (11 bytes)
 *   <li>HKDF L = 80 bytes → {@code K_enc(32) ‖ K_mac(32) ‖ IV_base(16)}
 *   <li>inbound MAC = HMAC-SHA-256(K_mac, [CLA INS P1 P2 LC] ‖ IV ‖ CT)[0..16]
 *   <li>outbound MAC = HMAC-SHA-256(K_mac, 0xFF ‖ IV ‖ CT)[0..16]
 * </ul>
 */
public final class SecureChannelClient {

    /** {@code CLA = 0x80} for every meowl-applet APDU per MEAP-1. */
    public static final int CLA_MEOWL = 0x80;

    /** {@code INS = 0x10} — INIT_SECURE_CHANNEL, MEAP-2 §handshake. */
    public static final int INS_INIT_SC = 0x10;

    /** {@code INS = 0x11} — OPEN_SECURE_CHANNEL, MEAP-2 §record-layer. */
    public static final int INS_OPEN_SC = 0x11;

    /** HKDF info label, MEAP-2 §key-derivation. */
    public static final byte[] HKDF_INFO = "meowl-sc-v1".getBytes(StandardCharsets.UTF_8);

    /** HKDF output length: K_enc(32) + K_mac(32) + IV_base(16) = 80 bytes. */
    private static final int HKDF_OKM_LEN = 80;

    /** Outbound MAC's direction-tag, fixed at 0xFF (MEAP-2 §record-layer outbound). */
    private static final byte OUTBOUND_DIRECTION_TAG = (byte) 0xFF;

    private final APDUBIBO bibo;
    private final byte[] authentikeyCompressed;

    private byte[] kEnc;
    private byte[] kMac;
    private byte[] ivBase;
    private byte[] clientEphPub;
    private byte[] cardEphPub;
    private byte[] handshakeSignature;
    private long inboundCounter;
    private long lastOutboundCounter;
    private boolean invalidated;

    /**
     * @param bibo the underlying APDU transport (typically a decorated PC/SC channel)
     * @param authentikeyCompressed the card's 33-byte compressed authentikey, used to verify the
     *     handshake signature
     */
    public SecureChannelClient(APDUBIBO bibo, byte[] authentikeyCompressed) {
        this.bibo = Objects.requireNonNull(bibo, "bibo");
        if (authentikeyCompressed.length != HostCrypto.EC_POINT_COMPRESSED_LEN) {
            throw new IllegalArgumentException(
                    "authentikey must be %d compressed bytes"
                            .formatted(HostCrypto.EC_POINT_COMPRESSED_LEN));
        }
        this.authentikeyCompressed = authentikeyCompressed.clone();
    }

    /**
     * Drives the {@code INIT_SECURE_CHANNEL} handshake to completion, verifies the card's ECDSA
     * signature with the supplied authentikey, and derives the session keys.
     *
     * @return a snapshot of the session state — the same fields are also accessible via {@link
     *     #cardEphPub()} / {@link #handshakeSignature()}, but returning them here makes the
     *     handshake side-effect explicit
     * @throws SecureChannelException if any of the wire / cryptographic checks fail
     */
    public Handshake handshake() throws BIBOException {
        var keys = HostCrypto.generateEphKeyPair();
        clientEphPub = keys.publicEncoded();

        ResponseAPDU resp =
                bibo.transmit(new CommandAPDU(CLA_MEOWL, INS_INIT_SC, 0x00, 0x00, clientEphPub));
        if (resp.getSW() != 0x9000) {
            throw new SecureChannelException(
                    resp.getSW(), "INIT_SECURE_CHANNEL failed (SW=0x%04X)".formatted(resp.getSW()));
        }

        byte[] body = resp.getData();
        if (body.length < HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2) {
            throw new SecureChannelException(
                    0,
                    "Handshake response too short: %d bytes (need at least %d)"
                            .formatted(body.length, HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2));
        }

        cardEphPub = Arrays.copyOfRange(body, 0, HostCrypto.EC_POINT_UNCOMPRESSED_LEN);
        // Audit F-24: validate the SEC1 0x04 prefix immediately after parsing the handshake
        // body. ECDH (HostCrypto.ecdhSharedX) would also catch this, but failing here lets the
        // host log the precise wire-format mismatch instead of an ECDH-side
        // IllegalArgumentException
        // that could be confused with an off-curve peer key.
        if ((cardEphPub[0] & 0xFF) != 0x04) {
            throw new SecureChannelException(
                    0,
                    "card ephemeral pubkey lacks the SEC1-uncompressed 0x04 prefix (got 0x%02X)"
                            .formatted(cardEphPub[0] & 0xFF));
        }
        int sigLen =
                ((body[HostCrypto.EC_POINT_UNCOMPRESSED_LEN] & 0xFF) << 8)
                        | (body[HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 1] & 0xFF);
        if (body.length != HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2 + sigLen) {
            throw new SecureChannelException(
                    0,
                    "Handshake response length mismatch: declared sigLen %d but body has %d trailing bytes"
                            .formatted(
                                    sigLen,
                                    body.length - HostCrypto.EC_POINT_UNCOMPRESSED_LEN - 2));
        }
        handshakeSignature =
                Arrays.copyOfRange(
                        body,
                        HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2,
                        HostCrypto.EC_POINT_UNCOMPRESSED_LEN + 2 + sigLen);

        // The signature must verify against [card_eph_pub || client_eph_pub] under authentikey.
        byte[] signedMessage = HostCrypto.concat(cardEphPub, clientEphPub);
        if (!HostCrypto.verifyEcdsaSecp256k1(
                authentikeyCompressed, signedMessage, handshakeSignature)) {
            throw new SecureChannelException(
                    0, "authentikey ECDSA signature verification failed during handshake");
        }

        // ECDH on the host side and HKDF schedule.
        byte[] sharedX = HostCrypto.ecdhSharedX(keys.privateScalar(), cardEphPub);
        byte[] clientX = keys.xCoordinate();
        byte[] cardX = Arrays.copyOfRange(cardEphPub, 1, 1 + HostCrypto.EC_SCALAR_LEN);
        byte[] salt = HostCrypto.concat(clientX, cardX);
        byte[] prk = HkdfSha256.extract(salt, sharedX);
        byte[] okm = HkdfSha256.expand(prk, HKDF_INFO, HKDF_OKM_LEN);
        kEnc = Arrays.copyOfRange(okm, 0, HostCrypto.AES_KEY_LEN);
        kMac = Arrays.copyOfRange(okm, HostCrypto.AES_KEY_LEN, HostCrypto.AES_KEY_LEN * 2);
        ivBase = Arrays.copyOfRange(okm, HostCrypto.AES_KEY_LEN * 2, HKDF_OKM_LEN);
        inboundCounter = 0L;
        // outboundCounter starts at 0 on the card and is incremented to 1 before the first
        // wrap, so the first IV we expect on inbound (host-side outbound from the card) has
        // counter = 1. The strict-greater monotonicity check requires lastOutboundCounter
        // to start at 0 (anything > 0 passes).
        lastOutboundCounter = 0L;
        invalidated = false;

        return new Handshake(cardEphPub.clone(), handshakeSignature.clone(), ivBase.clone());
    }

    /**
     * Encrypts the given inner APDU, sends it inside an {@code OPEN_SECURE_CHANNEL} envelope, and
     * decrypts the card's response.
     *
     * @param innerApdu the plaintext inner APDU bytes (ISO 7816-4 short-form, including header)
     * @return the decrypted inner response data; the outer SW is verified to be 0x9000 — any other
     *     value triggers {@link SecureChannelException}
     */
    public byte[] sendInner(byte[] innerApdu) throws BIBOException {
        requireSession();
        Objects.requireNonNull(innerApdu, "innerApdu");

        inboundCounter++;
        byte[] iv = ivFromCounter(inboundCounter);
        byte[] ciphertext = HostCrypto.aesCbcEncrypt(kEnc, iv, innerApdu);

        int lc = iv.length + ciphertext.length + HostCrypto.MAC_LEN;
        // MEAP-2 envelopes ride short-form APDUs; if lc would exceed the single-byte LC
        // field, the host's MAC input (which packs lc into a single byte below) would diverge
        // from what the card observes on the wire and the envelope would be silently
        // rejected with an obscure MAC mismatch. Reject explicitly so callers get an
        // actionable error. (Audit H-1.05.)
        if (lc > 0xFF) {
            throw new SecureChannelException(
                    0,
                    "Envelope too large for short-form APDU: LC = "
                            + lc
                            + " bytes (max 255). Reduce the inner APDU size.");
        }
        byte[] header = {(byte) CLA_MEOWL, (byte) INS_OPEN_SC, 0x00, 0x00, (byte) lc};
        byte[] mac = HostCrypto.hmacSha256Truncated(kMac, header, iv, ciphertext);

        byte[] envelope = HostCrypto.concat(iv, ciphertext, mac);
        ResponseAPDU resp =
                bibo.transmit(new CommandAPDU(CLA_MEOWL, INS_OPEN_SC, 0x00, 0x00, envelope));
        if (resp.getSW() != 0x9000) {
            // The card has already torn down its session on its end; mirror that on the host
            // so a subsequent sendInner() fails fast rather than encrypting under stale keys.
            // (Audit H-1.12.)
            invalidate();
            throw new SecureChannelException(
                    resp.getSW(),
                    "OPEN_SECURE_CHANNEL rejected by card (SW=0x%04X)".formatted(resp.getSW()));
        }
        return decryptOutbound(resp.getData());
    }

    /** Returns the card's ephemeral public key (SEC1 uncompressed, 65 bytes). */
    public byte[] cardEphPub() {
        requireSession();
        return cardEphPub.clone();
    }

    /** Returns the DER-encoded handshake signature surfaced by the card. */
    public byte[] handshakeSignature() {
        requireSession();
        return handshakeSignature.clone();
    }

    /** Returns the IV base derived during handshake (16 bytes). */
    public byte[] ivBase() {
        requireSession();
        return ivBase.clone();
    }

    /** Snapshot of the per-handshake state, returned by {@link #handshake}. */
    public record Handshake(byte[] cardEphPub, byte[] signatureDer, byte[] ivBase) {

        public Handshake {
            Objects.requireNonNull(cardEphPub, "cardEphPub");
            Objects.requireNonNull(signatureDer, "signatureDer");
            Objects.requireNonNull(ivBase, "ivBase");
        }
    }

    private void requireSession() {
        if (invalidated) {
            throw new IllegalStateException(
                    "Secure Channel session has been invalidated by a prior cryptographic"
                            + " failure — call handshake() again to open a fresh session");
        }
        if (kEnc == null) {
            throw new IllegalStateException("no Secure Channel session — call handshake() first");
        }
    }

    /**
     * Wipes the host-side session keys and marks the session invalidated; subsequent {@link
     * #sendInner} calls will fail fast with {@link IllegalStateException}. Called whenever a
     * cryptographic check on the inbound or outbound side fails — the card has already torn down
     * its end at that point, so any further attempt to send under the current keys would only
     * produce a confusing chain of MAC mismatches.
     */
    private void invalidate() {
        if (kEnc != null) Arrays.fill(kEnc, (byte) 0);
        if (kMac != null) Arrays.fill(kMac, (byte) 0);
        if (ivBase != null) Arrays.fill(ivBase, (byte) 0);
        kEnc = null;
        kMac = null;
        ivBase = null;
        invalidated = true;
    }

    /**
     * Builds the inbound IV from a 64-bit counter: the counter occupies the low 8 bytes of a
     * 16-byte big-endian buffer, with the high 8 bytes left zero. The card's strict {@code IV >
     * last_inbound_IV} check operates on the full 16-byte buffer, so this layout makes the IV
     * monotonic in the obvious way.
     */
    private static byte[] ivFromCounter(long counter) {
        byte[] iv = new byte[HostCrypto.AES_BLOCK_LEN];
        for (int i = 0; i < 8; i++) {
            iv[HostCrypto.AES_BLOCK_LEN - 1 - i] = (byte) ((counter >>> (8 * i)) & 0xFF);
        }
        return iv;
    }

    private byte[] decryptOutbound(byte[] envelope) {
        if (envelope.length < HostCrypto.AES_BLOCK_LEN + HostCrypto.MAC_LEN
                || (envelope.length - HostCrypto.AES_BLOCK_LEN - HostCrypto.MAC_LEN)
                                % HostCrypto.AES_BLOCK_LEN
                        != 0) {
            throw new SecureChannelException(
                    0, "Outbound envelope length is malformed: " + envelope.length);
        }
        byte[] iv = Arrays.copyOfRange(envelope, 0, HostCrypto.AES_BLOCK_LEN);
        byte[] ciphertext =
                Arrays.copyOfRange(
                        envelope, HostCrypto.AES_BLOCK_LEN, envelope.length - HostCrypto.MAC_LEN);
        byte[] mac =
                Arrays.copyOfRange(envelope, envelope.length - HostCrypto.MAC_LEN, envelope.length);

        // MAC = HMAC-SHA-256(K_mac, 0xFF || IV || ciphertext)[0..16].
        byte[] expected =
                HostCrypto.hmacSha256Truncated(
                        kMac, new byte[] {OUTBOUND_DIRECTION_TAG}, iv, ciphertext);
        if (!constantTimeEquals(mac, expected)) {
            invalidate();
            throw new SecureChannelException(0, "outbound envelope MAC mismatch");
        }

        // Defense in depth (audit M-1.13): the outbound counter packed into IV ⊕ IV_base must
        // be strictly greater than the previously observed one. The MAC check above already
        // gates this on integrity, but a compromised silicon that re-used a counter would
        // slip past — so we mirror the card's strict-greater rule on the host side too.
        long observed = extractOutboundCounter(iv, ivBase);
        if (Long.compareUnsigned(observed, lastOutboundCounter) <= 0) {
            invalidate();
            throw new SecureChannelException(
                    0,
                    "outbound IV counter regressed: observed "
                            + Long.toUnsignedString(observed)
                            + " <= last "
                            + Long.toUnsignedString(lastOutboundCounter));
        }
        lastOutboundCounter = observed;

        return HostCrypto.aesCbcDecrypt(kEnc, iv, ciphertext);
    }

    /**
     * Recovers the 64-bit outbound counter packed into the low 8 bytes of an outbound IV. The card
     * constructs the IV as {@code IV_base XOR counter} where {@code counter} occupies the low 8
     * bytes of a 16-byte buffer (high 8 bytes zero); XOR-ing with {@code IV_base} reverses the
     * mask.
     */
    private static long extractOutboundCounter(byte[] iv, byte[] ivBase) {
        long counter = 0L;
        for (int i = 0; i < 8; i++) {
            int byteIndex = HostCrypto.AES_BLOCK_LEN - 8 + i;
            int unmasked = (iv[byteIndex] & 0xFF) ^ (ivBase[byteIndex] & 0xFF);
            counter = (counter << 8) | unmasked;
        }
        return counter;
    }

    /**
     * Constant-time equality check; mirrors the applet-side {@code ConstantTime.equals} so a timing
     * attacker observing the host has no easier path than observing the card.
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]) & 0xFF;
        }
        return diff == 0;
    }
}

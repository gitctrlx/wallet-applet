/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * Long-lived secp256k1 keypair that identifies this physical card.
 *
 * <p>Generated exactly once during applet {@code install} and immutable for the lifetime of the
 * applet instance. The private half never leaves the secure element. The public half is exposed via
 * {@code GET_AUTHENTIKEY} and used as the in-band card-identity anchor inside Secure Channel
 * handshakes (see {@code docs/adr/0004-secure-channel-cipher-suite.md}) and as the CSR subject
 * during PKI personalisation.
 *
 * <p>{@code reset-to-factory} does <strong>not</strong> regenerate this keypair — see {@code
 * docs/adr/0005-authentikey-lifecycle.md}.
 */
public final class Authentikey {

    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;

    /**
     * Generates a fresh authentikey keypair via {@link KeyPair#genKeyPair()}, which pulls entropy
     * from the platform CSPRNG, and configures both halves with the secp256k1 curve parameters.
     */
    public Authentikey() {
        this.privateKey =
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        this.publicKey =
                (ECPublicKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.applyTo(this.privateKey);
        Secp256k1.applyTo(this.publicKey);

        KeyPair pair = new KeyPair(this.publicKey, this.privateKey);
        pair.genKeyPair();
    }

    /**
     * Writes the compressed public key into {@code dst} starting at {@code offset}.
     *
     * @return the offset immediately after the 33-byte compressed point.
     */
    public short writeCompressedPubkeyTo(byte[] dst, short offset) {
        // ECPublicKey.getW returns the uncompressed form `04 || x(32) || y(32)`. Compress to
        // `02|03 || x(32)` per SEC 1 §2.3.3 by inspecting the parity of y's least-significant
        // byte.
        short scratch = offset;
        short uncompressedLen = publicKey.getW(dst, scratch);
        if (uncompressedLen != Constants.SECP256K1_UNCOMPRESSED_LEN
                || dst[scratch] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        byte yLsb = dst[(short) (scratch + Constants.SECP256K1_UNCOMPRESSED_LEN - 1)];
        byte parityPrefix = ((yLsb & 0x01) == 0) ? (byte) 0x02 : (byte) 0x03;
        // Overwrite in place: tag prefix at scratch, copy x[0..32] to scratch+1.
        dst[scratch] = parityPrefix;
        // x was already at scratch+1..scratch+32 in the uncompressed layout; no copy needed.
        return (short) (scratch + Constants.SECP256K1_COMPRESSED_LEN);
    }

    /** Package-private access for the Secure Channel handshake signer (added in Phase 2). */
    ECPrivateKey privateKey() {
        return privateKey;
    }

    /** Package-private access for the PKI CSR signer (added in Phase 3). */
    ECPublicKey publicKey() {
        return publicKey;
    }

    /**
     * Erases an externally-supplied buffer that briefly held the compressed pubkey, to keep the
     * applet's transient memory budget tidy. The authentikey itself is not affected.
     */
    public static void wipe(byte[] buffer, short offset, short length) {
        Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0);
    }
}

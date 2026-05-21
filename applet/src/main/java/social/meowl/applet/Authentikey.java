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
 * Long-lived secp256k1 keypair that identifies this physical card. Generated exactly once during
 * applet install and preserved across factory resets per MEAP-4. The private half never leaves the
 * secure element; the public half is the card-identity anchor for the Secure Channel handshake
 * (MEAP-2) and the CSR subject during PKI personalisation (MEAP-4).
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
        Secp256k1.setCurveParameters(this.privateKey);
        Secp256k1.setCurveParameters(this.publicKey);

        new KeyPair(this.publicKey, this.privateKey).genKeyPair();
    }

    /**
     * Writes the SEC 1 §2.3.3 compressed public key into {@code dst} at {@code offset}. Returns
     * {@link Constants#EC_POINT_COMPRESSED_LEN}. The trailing y-coordinate bytes (past the 33-byte
     * compressed point) are zeroised so no ephemeral residue leaks into outbound buffers.
     */
    public short writeCompressedPubkeyTo(byte[] dst, short offset) {
        Bounds.requireCapacity(dst, offset, Constants.EC_POINT_UNCOMPRESSED_LEN);

        short uncompressedLen = publicKey.getW(dst, offset);
        if (uncompressedLen != Constants.EC_POINT_UNCOMPRESSED_LEN || dst[offset] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }

        // After getW(): dst[offset .. offset+64] = 0x04 ‖ x(32) ‖ y(32).
        // SEC 1 §2.3.3 compression keeps `x(32)` in place and replaces the 0x04 prefix with
        // 0x02 (y even) or 0x03 (y odd).
        byte yLsb = dst[(short) (offset + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
        dst[offset] = ((yLsb & 0x01) == 0) ? (byte) 0x02 : (byte) 0x03;
        Util.arrayFillNonAtomic(
                dst,
                (short) (offset + Constants.EC_POINT_COMPRESSED_LEN),
                (short) (Constants.EC_POINT_UNCOMPRESSED_LEN - Constants.EC_POINT_COMPRESSED_LEN),
                (byte) 0);

        return Constants.EC_POINT_COMPRESSED_LEN;
    }

    /** Package-private access for the Secure Channel handshake signer. */
    ECPrivateKey privateKey() {
        return privateKey;
    }

    /** Package-private access for the PKI CSR signer. */
    ECPublicKey publicKey() {
        return publicKey;
    }
}

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
 * Long-lived secp256k1 card-identity keypair. Generated once at install, preserved across factory
 * resets (MEAP-4). The private half never leaves the secure element; the public half anchors the
 * Secure Channel handshake (MEAP-2) and serves as the CSR subject during PKI personalisation.
 */
public final class Authentikey {

    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;

    /** Generates a fresh secp256k1 keypair seeded from the platform CSPRNG. */
    public Authentikey() {
        this.privateKey =
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        this.publicKey =
                (ECPublicKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1Curve.setCurveParameters(this.privateKey);
        Secp256k1Curve.setCurveParameters(this.publicKey);

        new KeyPair(this.publicKey, this.privateKey).genKeyPair();
    }

    /**
     * Writes the SEC 1 §2.3.3 compressed public key into {@code dst} at {@code offset}. The
     * trailing y-coordinate bytes past the 33-byte compressed point are zeroised so no residue
     * leaks into outbound buffers.
     *
     * @return {@link Constants.Ec#POINT_COMPRESSED_LEN}
     */
    public short writeCompressedPubkeyTo(byte[] dst, short offset) {
        Bounds.requireCapacity(dst, offset, Constants.Ec.POINT_UNCOMPRESSED_LEN);

        short uncompressedLen = publicKey.getW(dst, offset);
        if (uncompressedLen != Constants.Ec.POINT_UNCOMPRESSED_LEN || dst[offset] != (byte) 0x04) {
            ISOException.throwIt(Constants.Sw.UNSUPPORTED_FEATURE);
        }

        // SEC 1 §2.3.3: keep x in place, replace the 0x04 prefix with 0x02 (y even) / 0x03 (y odd).
        byte yLsb = dst[(short) (offset + Constants.Ec.POINT_UNCOMPRESSED_LEN - 1)];
        dst[offset] = ((yLsb & 0x01) == 0) ? (byte) 0x02 : (byte) 0x03;
        Util.arrayFillNonAtomic(
                dst,
                (short) (offset + Constants.Ec.POINT_COMPRESSED_LEN),
                (short) (Constants.Ec.POINT_UNCOMPRESSED_LEN - Constants.Ec.POINT_COMPRESSED_LEN),
                (byte) 0);

        return Constants.Ec.POINT_COMPRESSED_LEN;
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

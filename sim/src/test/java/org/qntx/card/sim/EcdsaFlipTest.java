// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import javacard.framework.ISO7816;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.FlipProbe;

/**
 * {@link Fault#armEcdsaFlip}: the {@code nth} applet-created {@code ALG_ECDSA_SHA_256} engine emits
 * its DER signature with the last byte XOR {@code 0x01} — undoing the flip restores a signature
 * BouncyCastle verifies, proving the corruption is exactly that byte — while engines before and
 * after the {@code nth} and non-ECDSA engines stay clean.
 */
final class EcdsaFlipTest {

    private static final byte[] AID = {0x08, 0x02, 0x03, 0x04, 0x05};
    private static final byte INS_SET_DOMAIN = 0x50;
    private static final byte INS_SET_S = 0x51;
    private static final byte INS_SIGN = 0x60;
    private static final byte INS_OTHER = 0x61;

    private static final X9ECParameters SECP256K1 = SECNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(
                    SECP256K1.getCurve(), SECP256K1.getG(), SECP256K1.getN(), SECP256K1.getH());
    private static final BigInteger P = SECP256K1.getCurve().getField().getCharacteristic();
    private static final BigInteger N = SECP256K1.getN();
    private static final BigInteger PRIVATE =
            new BigInteger("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 16);
    private static final ECPoint PUBLIC = SECP256K1.getG().multiply(PRIVATE).normalize();

    private Card card;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private void install() {
        card = new Card();
        card.install(AID, FlipProbe.class);
        byte[] sel = new byte[5 + AID.length];
        sel[ISO7816.OFFSET_INS] = (byte) 0xA4;
        sel[ISO7816.OFFSET_P1] = 0x04;
        sel[ISO7816.OFFSET_LC] = (byte) AID.length;
        System.arraycopy(AID, 0, sel, ISO7816.OFFSET_CDATA, AID.length);
        card.transmit(sel);
        assertSw(card.transmit(cmd(INS_SET_DOMAIN, domainBlob())), 0x9000);
        assertSw(card.transmit(cmd(INS_SET_S, toFixed(PRIVATE, 32))), 0x9000);
    }

    private static byte[] cmd(byte ins, byte[] data) {
        byte[] apdu = new byte[5 + data.length];
        apdu[ISO7816.OFFSET_INS] = ins;
        apdu[ISO7816.OFFSET_LC] = (byte) data.length;
        System.arraycopy(data, 0, apdu, ISO7816.OFFSET_CDATA, data.length);
        return apdu;
    }

    private static byte[] cmd(byte ins) {
        return cmd(ins, new byte[0]);
    }

    private static byte[] data(byte[] response) {
        return Arrays.copyOf(response, response.length - 2);
    }

    private static short sw(byte[] response) {
        return (short)
                (((response[response.length - 2] & 0xFF) << 8)
                        | (response[response.length - 1] & 0xFF));
    }

    private static void assertSw(byte[] response, int expected) {
        assertEquals(
                (short) expected,
                sw(response),
                () -> "SW 0x" + Integer.toHexString(sw(response) & 0xFFFF));
    }

    private static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] fixed = new byte[length];
        int rawLen = raw.length;
        if (rawLen > 0 && raw[0] == 0) {
            rawLen--;
        }
        System.arraycopy(raw, raw.length - rawLen, fixed, length - rawLen, rawLen);
        return fixed;
    }

    private static byte[] domainBlob() {
        // p‖a‖b‖G‖r: 32‖32‖32‖65‖32
        byte[] blob = new byte[193];
        byte[] g = SECP256K1.getG().getEncoded(false);
        System.arraycopy(toFixed(P, 32), 0, blob, 0, 32);
        blob[95] = 7;
        System.arraycopy(g, 0, blob, 96, 65);
        System.arraycopy(toFixed(N, 32), 0, blob, 161, 32);
        return blob;
    }

    /** (r, s) out of a minimal DER SEQUENCE { INTEGER, INTEGER } encoding. */
    private static BigInteger[] decodeDer(byte[] der) {
        int i = 2; // 30 len — signatures stay under 128 bytes
        if ((der[0] & 0xFF) != 0x30 || (der[i] & 0xFF) != 0x02) {
            throw new IllegalArgumentException("not a DER signature");
        }
        int rLen = der[i + 1] & 0xFF;
        byte[] r = Arrays.copyOfRange(der, i + 2, i + 2 + rLen);
        int j = i + 2 + rLen;
        if ((der[j] & 0xFF) != 0x02) {
            throw new IllegalArgumentException("not a DER signature");
        }
        int sLen = der[j + 1] & 0xFF;
        byte[] s = Arrays.copyOfRange(der, j + 2, j + 2 + sLen);
        return new BigInteger[] {new BigInteger(1, r), new BigInteger(1, s)};
    }

    private static boolean bcVerify(byte[] digest, byte[] der) {
        BigInteger[] rs = decodeDer(der);
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(PUBLIC, DOMAIN));
        return signer.verifySignature(digest, rs[0], rs[1]);
    }

    private byte[] sign(byte[] digest) {
        byte[] response = card.transmit(cmd(INS_SIGN, digest));
        assertSw(response, 0x9000);
        return data(response);
    }

    @Test
    void unarmedEngineSignsCleanly() {
        install();
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0x5A);
        byte[] der = sign(digest);
        assertTrue(bcVerify(digest, der));
    }

    @Test
    void armedEngineFlipsExactlyTheLastDerByte() {
        install();
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0x5A);
        byte[] clean = sign(digest);
        Fault.armEcdsaFlip(1);
        byte[] flipped = sign(digest);
        // the armed signature must fail — and restoring the last byte must recover a valid one
        assertFalse(bcVerify(digest, flipped));
        byte[] restored = flipped.clone();
        restored[restored.length - 1] ^= 0x01;
        assertTrue(bcVerify(digest, restored));
        assertEquals(clean[0], flipped[0]);
    }

    @Test
    void onlyTheNthSignCallFlips() {
        install();
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0x33);
        Fault.armEcdsaFlip(2);
        // creating a non-ECDSA engine does not advance the counter
        assertSw(card.transmit(cmd(INS_OTHER)), 0x9000);
        assertTrue(bcVerify(digest, sign(digest)), "sign call 1 stays clean");
        assertFalse(bcVerify(digest, sign(digest)), "sign call 2 is the armed one");
        assertTrue(bcVerify(digest, sign(digest)), "sign call 3 is clean again");
    }

    @Test
    void resetDisarmsTheFlip() {
        install();
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0x77);
        Fault.armEcdsaFlip(1);
        assertFalse(bcVerify(digest, sign(digest)));
        Fault.reset();
        assertTrue(bcVerify(digest, sign(digest)));
    }
}

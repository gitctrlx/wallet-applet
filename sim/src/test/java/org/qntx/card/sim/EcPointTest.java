// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.Arrays;
import javacard.framework.ISO7816;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.EcProbe;

/**
 * EC point validation and agreement semantics on secp256k1: {@code setW} rejects compressed and
 * off-curve points, the raw-point agreements reject compressed input, and PACE_GM fails at
 * infinity.
 */
class EcPointTest {

    private static final byte[] AID = {0x04, 0x02, 0x03, 0x04, 0x05};
    private static final byte INS_SET_DOMAIN = 0x50;
    private static final byte INS_SET_S = 0x51;
    private static final byte INS_SET_W = 0x52;
    private static final byte INS_AGREE_XY = 0x53;
    private static final byte INS_AGREE_GM = 0x54;

    private static final X9ECParameters SECP256K1 = SECNamedCurves.getByName("secp256k1");
    private static final BigInteger P = SECP256K1.getCurve().getField().getCharacteristic();
    private static final BigInteger N = SECP256K1.getN();
    private static final BigInteger PRIVATE =
            new BigInteger("1111111111111111111111111111111111111111111111111111111111111111", 16);

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
        card.install(AID, EcProbe.class);
        card.transmit(selectApdu(AID));
        assertSw(card.transmit(cmd(INS_SET_DOMAIN, domainBlob())), 0x9000);
        assertSw(card.transmit(cmd(INS_SET_S, toFixed(PRIVATE, 32))), 0x9000);
    }

    static byte[] selectApdu(byte[] aid) {
        byte[] apdu = new byte[5 + aid.length];
        apdu[ISO7816.OFFSET_INS] = (byte) 0xA4;
        apdu[ISO7816.OFFSET_P1] = 0x04;
        apdu[ISO7816.OFFSET_LC] = (byte) aid.length;
        System.arraycopy(aid, 0, apdu, ISO7816.OFFSET_CDATA, aid.length);
        return apdu;
    }

    private static byte[] cmd(byte ins, byte[] data) {
        byte[] apdu = new byte[5 + data.length];
        apdu[ISO7816.OFFSET_INS] = ins;
        apdu[ISO7816.OFFSET_LC] = (byte) data.length;
        System.arraycopy(data, 0, apdu, ISO7816.OFFSET_CDATA, data.length);
        return apdu;
    }

    private static short sw(byte[] response) {
        return (short)
                (((response[response.length - 2] & 0xFF) << 8)
                        | (response[response.length - 1] & 0xFF));
    }

    private static byte[] data(byte[] response) {
        return Arrays.copyOf(response, response.length - 2);
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
        // a = 0: blob[32..64) stays zero
        blob[95] = 7; // b = 7
        System.arraycopy(g, 0, blob, 96, 65);
        System.arraycopy(toFixed(N, 32), 0, blob, 161, 32);
        return blob;
    }

    // card A checks only the 0x04 uncompressed tag on setW (F-6)
    @Test
    void setWRejectsNonUncompressedEncodings() {
        byte[] compressed = SECP256K1.getG().getEncoded(true);
        assertEquals(0x02, compressed[0] & 0xFF);
        assertSw(card.transmit(cmd(INS_SET_W, compressed)), 0x6F11);
        compressed[0] = 0x03;
        assertSw(card.transmit(cmd(INS_SET_W, compressed)), 0x6F11);
        compressed[0] = 0x00;
        assertSw(card.transmit(cmd(INS_SET_W, compressed)), 0x6F11);
        compressed[0] = 0x06;
        assertSw(card.transmit(cmd(INS_SET_W, compressed)), 0x6F11);
    }

    @Test
    void setWAcceptsOffCurvePoint() {
        byte[] w = SECP256K1.getG().getEncoded(false);
        w[w.length - 1] ^= 0x01;
        assertSw(card.transmit(cmd(INS_SET_W, w)), 0x9000);
    }

    @Test
    void setWAcceptsGenerator() {
        byte[] w = SECP256K1.getG().getEncoded(false);
        assertSw(card.transmit(cmd(INS_SET_W, w)), 0x9000);
    }

    @Test
    void plainXyMatchesBouncyCastleArithmetic() {
        BigInteger peer =
                new BigInteger(
                        "2222222222222222222222222222222222222222222222222222222222222222", 16);
        byte[] q = SECP256K1.getG().multiply(peer).getEncoded(false);
        byte[] response = card.transmit(cmd(INS_AGREE_XY, q));
        assertSw(response, 0x9000);
        byte[] expected = SECP256K1.getG().multiply(peer).multiply(PRIVATE).getEncoded(false);
        assertArrayEquals(expected, data(response));
    }

    // on the raw-point agreements card A validates the point: any
    // non-0x04 tag, off-curve point or coordinate >= p is ILLEGAL_VALUE
    @Test
    void agreementsRejectCompressedPoints() {
        byte[] compressed = SECP256K1.getG().getEncoded(true);
        assertSw(card.transmit(cmd(INS_AGREE_XY, compressed)), 0x6F11);
        assertSw(card.transmit(cmd(INS_AGREE_GM, compressed)), 0x6F11);
    }

    @Test
    void agreementsRejectOffCurvePoints() {
        byte[] off = SECP256K1.getG().getEncoded(false);
        off[off.length - 1] ^= 0x01;
        assertSw(card.transmit(cmd(INS_AGREE_XY, off)), 0x6F11);
        assertSw(card.transmit(cmd(INS_AGREE_GM, off)), 0x6F11);
    }

    @Test
    void agreementsRejectCoordinateAtFieldSize() {
        // x = p is outside the field
        byte[] w = SECP256K1.getG().getEncoded(false);
        byte[] pBytes = toFixed(P, 32);
        System.arraycopy(pBytes, 0, w, 1, 32);
        assertSw(card.transmit(cmd(INS_AGREE_XY, w)), 0x6F11);
        assertSw(card.transmit(cmd(INS_AGREE_GM, w)), 0x6F11);
    }

    @Test
    void paceGmComputesGSPlusH() {
        BigInteger u =
                new BigInteger(
                        "3333333333333333333333333333333333333333333333333333333333333333", 16);
        byte[] h = SECP256K1.getG().multiply(u).getEncoded(false);
        byte[] response = card.transmit(cmd(INS_AGREE_GM, h));
        assertSw(response, 0x9000);
        // card result is s·G + H encoded uncompressed
        byte[] expected =
                SECP256K1
                        .getG()
                        .multiply(PRIVATE)
                        .add(SECP256K1.getG().multiply(u))
                        .getEncoded(false);
        assertArrayEquals(expected, data(response));
    }

    @Test
    void paceGmFailsWhenResultIsInfinity() {
        // H = -s·G makes s·G + H the point at infinity
        byte[] h = SECP256K1.getG().multiply(PRIVATE).negate().getEncoded(false);
        assertSw(card.transmit(cmd(INS_AGREE_GM, h)), 0x6F11);
    }
}

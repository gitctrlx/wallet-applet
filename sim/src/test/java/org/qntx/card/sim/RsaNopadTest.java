// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.RsaProbe;

/**
 * Raw RSA NOPAD semantics: plain modPow with a prime modulus zero-extended to the 512-bit block,
 * per the card A audit vectors.
 */
class RsaNopadTest {

    private static final byte[] AID = {0x03, 0x02, 0x03, 0x04, 0x05};
    private static final byte INS_SET_MODULUS = 0x40;
    private static final byte INS_SET_EXPONENT = 0x41;
    private static final byte INS_MODPOW = 0x42;
    private static final int MOD_LEN = 64;
    private static final BigInteger MODULUS = new BigInteger(255, 100, new Random(0x5EED));

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
        card.install(AID, RsaProbe.class);
        card.transmit(selectApdu(AID));
        assertSw(card.transmit(cmd(INS_SET_MODULUS, toFixed(MODULUS, MOD_LEN))), 0x9000);
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

    private byte[] modPow(byte[] input) {
        return data(card.transmit(cmd(INS_MODPOW, input)));
    }

    @Test
    void exponentTwoMatchesModPow() {
        setExponent(BigInteger.valueOf(2));
        Random rnd = new Random(7);
        for (int i = 0; i < 5; i++) {
            BigInteger x = new BigInteger(254, rnd).mod(MODULUS);
            byte[] out = modPow(toFixed(x, MOD_LEN));
            assertArrayEquals(
                    toFixed(x.modPow(BigInteger.valueOf(2), MODULUS), MOD_LEN),
                    out,
                    "x^2 mod m mismatch");
        }
    }

    @Test
    void exponentThirtyTwoByteMatchesModPow() {
        BigInteger e = new BigInteger(255, 80, new Random(11));
        setExponent(e);
        BigInteger x = new BigInteger(254, new Random(13)).mod(MODULUS);
        assertArrayEquals(toFixed(x.modPow(e, MODULUS), MOD_LEN), modPow(toFixed(x, MOD_LEN)));
    }

    @Test
    void edgeInputs() {
        setExponent(BigInteger.valueOf(2));
        // x = 0 -> 0, x = 1 -> 1, x = m-1 -> (m-1)^2 mod m = 1
        assertArrayEquals(new byte[MOD_LEN], modPow(new byte[MOD_LEN]));

        byte[] one = new byte[MOD_LEN];
        one[MOD_LEN - 1] = 1;
        assertArrayEquals(one, modPow(one));

        byte[] mMinusOne = toFixed(MODULUS.subtract(BigInteger.ONE), MOD_LEN);
        assertArrayEquals(one, modPow(mMinusOne));
    }

    @Test
    void inputAtModulusIsIllegalValue() {
        setExponent(BigInteger.valueOf(2));
        // x = m: CryptoException.ILLEGAL_VALUE surfaced as 0x6F11
        assertSw(card.transmit(cmd(INS_MODPOW, toFixed(MODULUS, MOD_LEN))), 0x6F11);
        // x = m + 1: also >= m
        byte[] mPlusOne = toFixed(MODULUS.add(BigInteger.ONE), MOD_LEN);
        assertSw(card.transmit(cmd(INS_MODPOW, mPlusOne)), 0x6F11);
        // short input is ILLEGAL_USE -> 0x6F15
        assertSw(card.transmit(cmd(INS_MODPOW, new byte[8])), 0x6F15);
    }

    private void setExponent(BigInteger e) {
        byte[] raw = e.toByteArray();
        int rawLen = raw.length;
        if (rawLen > 0 && raw[0] == 0) {
            rawLen--;
        }
        byte[] exponent = new byte[rawLen];
        System.arraycopy(raw, raw.length - rawLen, exponent, 0, rawLen);
        assertSw(card.transmit(cmd(INS_SET_EXPONENT, exponent)), 0x9000);
    }
}

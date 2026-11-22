// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * {@link ModArith} against {@link BigInteger} for all three moduli — secp256k1 {@code p}, {@code n}
 * and ed25519 {@code ℓ} (architecture §14.4 W7): 10⁵ random {@code mul} and {@code square} rounds
 * per modulus, edge operands, and {@code addMod}, {@code subMod}, {@code half}, {@code below},
 * {@code isZero}, {@code reduce} over random 256-bit inputs.
 */
final class ModArithTest {
    static final int RANDOM_ROUNDS = 100_000;
    private static final SecureRandom RND = new SecureRandom();
    private static final BigInteger P = Crypto.DOMAIN.getCurve().getField().getCharacteristic();
    private static final BigInteger N = Crypto.DOMAIN.getN();
    private static final BigInteger L =
            new BigInteger(
                    "7237005577332262213973186563042994240857116359379907606001950938285454250989");

    private static ModArith modArith() {
        Card card = Vecs.factory();
        return Internals.modArith(card.applet(Spec.WALLET_AID));
    }

    private static byte[] toBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                out,
                Math.max(0, 32 - b.length),
                Math.min(b.length, 32));
        return out;
    }

    private static BigInteger of(byte[] x) {
        return new BigInteger(1, x);
    }

    @Test
    void randomMulSquareAddSubHalf() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        long t0 = System.currentTimeMillis();
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            for (int i = 0; i < RANDOM_ROUNDS; i++) {
                byte[] a = toBytes(of(random32()).mod(mod));
                byte[] b = toBytes(of(random32()).mod(mod));
                byte[] out = new byte[32];
                m.mul(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(
                        toBytes(of(a).multiply(of(b)).mod(mod)), out, "mul " + moduli[mi]);
                m.square(moduli[mi], a, (short) 0, out, (short) 0);
                assertArrayEquals(
                        toBytes(of(a).multiply(of(a)).mod(mod)), out, "square " + moduli[mi]);
                m.addMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(toBytes(of(a).add(of(b)).mod(mod)), out, "addMod " + moduli[mi]);
                m.subMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(
                        toBytes(of(a).subtract(of(b)).mod(mod)), out, "subMod " + moduli[mi]);
                m.half(moduli[mi], a, (short) 0, out, (short) 0);
                BigInteger twoInv = BigInteger.TWO.modInverse(mod);
                assertArrayEquals(
                        toBytes(of(a).multiply(twoInv).mod(mod)), out, "half " + moduli[mi]);
            }
        }
        System.out.println(
                "ModArithTest randomMulSquareAddSubHalf: "
                        + RANDOM_ROUNDS
                        + " rounds x 3 moduli in "
                        + (System.currentTimeMillis() - t0)
                        + " ms");
    }

    @Test
    void edgeOperands() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            byte[][] edges = {
                new byte[32],
                toBytes(BigInteger.ONE),
                toBytes(mod.subtract(BigInteger.ONE)),
                toBytes(mod.subtract(BigInteger.TWO)),
                toBytes(mod.shiftRight(1)),
            };
            for (byte[] a : edges) {
                for (byte[] b : edges) {
                    byte[] out = new byte[32];
                    BigInteger va = of(a);
                    BigInteger vb = of(b);
                    m.mul(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.multiply(vb).mod(mod)), out);
                    m.square(moduli[mi], a, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.multiply(va).mod(mod)), out);
                    m.addMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.add(vb).mod(mod)), out);
                    m.subMod(moduli[mi], a, (short) 0, b, (short) 0, out, (short) 0);
                    assertArrayEquals(toBytes(va.subtract(vb).mod(mod)), out);
                }
            }
        }
    }

    @Test
    void belowIsZeroReduce() {
        ModArith m = modArith();
        byte[] moduli = {ModArith.MOD_P, ModArith.MOD_N, ModArith.MOD_L};
        BigInteger[] mods = {P, N, L};
        byte[][] specials = {
            new byte[32],
            toBytes(BigInteger.ONE),
            toBytes(new BigInteger(256, RND)),
            toBytes(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)),
            toBytes(L),
            toBytes(L.multiply(BigInteger.valueOf(4))),
            toBytes(N),
            toBytes(P),
        };
        for (int mi = 0; mi < moduli.length; mi++) {
            BigInteger mod = mods[mi];
            for (byte[] s : specials) {
                // below: coded x < m
                assertEquals(
                        of(s).compareTo(mod) < 0 ? Const.CHECK_OK : Const.CHECK_FAIL,
                        m.below(moduli[mi], s, (short) 0),
                        "below " + moduli[mi]);
                // isZero
                assertEquals(
                        of(s).signum() == 0 ? Const.CHECK_OK : Const.CHECK_FAIL,
                        ModArith.isZero(s, (short) 0),
                        "isZero");
                // reduce: any 256-bit input lands below m
                byte[] r = s.clone();
                m.reduce(moduli[mi], r, (short) 0);
                assertArrayEquals(toBytes(of(s).mod(mod)), r, "reduce " + moduli[mi]);
            }
            // random 256-bit inputs
            for (int i = 0; i < 1000; i++) {
                byte[] s = random32();
                assertEquals(
                        of(s).compareTo(mod) < 0 ? Const.CHECK_OK : Const.CHECK_FAIL,
                        m.below(moduli[mi], s, (short) 0));
                byte[] r = s.clone();
                m.reduce(moduli[mi], r, (short) 0);
                assertArrayEquals(toBytes(of(s).mod(mod)), r);
            }
        }
    }

    private static byte[] random32() {
        byte[] b = new byte[32];
        RND.nextBytes(b);
        return b;
    }
}

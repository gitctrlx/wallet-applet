/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Verifies {@link Slip10} as a plain Java class under jcardsim's mock JC API:
 *
 * <ul>
 *   <li><b>NEWAUDIT-002 regression</b> — a non-hardened index must raise {@code 6985} <em>and</em>
 *       wipe the walk state, so a torn walk cannot leave the SLIP-10 master (the entire Ed25519
 *       wallet root) resident in the {@code CLEAR_ON_DESELECT} scratch. The pre-fix code skipped
 *       {@code wipeWalkState()} on the throw path; this test fails against it.
 *   <li><b>Functional parity</b> — {@link Slip10#deriveLeafKey} and {@link
 *       Slip10#deriveLeafKeyAndChainCode} agree byte-for-byte with an independent JDK HMAC-SHA-512
 *       SLIP-10 walk, and both leave the walk state zeroed on the success path.
 * </ul>
 *
 * <p>Seed is the SLIP-10 / BIP-32 Vector 1 seed {@code 000102…0f}; the cross-check derives the
 * reference {@code k‖c} the same way {@link Slip10} does, so no hard-coded vector bytes are needed.
 */
class Slip10Test {

    private static final byte[] SEED = hex("000102030405060708090a0b0c0d0e0f");

    @Test
    @DisplayName("non-hardened index throws 6985 and wipes the walk state (NEWAUDIT-002)")
    void nonHardenedIndexRejectedAndStateWiped() throws Exception {
        Slip10 slip10 = newSeededSlip10();
        byte[] path = ser32(0x00000000); // top bit clear → non-hardened, forbidden for Ed25519
        byte[] out = new byte[32];

        ISOException ex =
                assertThrows(
                        ISOException.class,
                        () -> slip10.deriveLeafKey(path, (short) 0, (short) 1, out, (short) 0));

        assertEquals(Constants.SW_CONDITIONS_NOT_SATISFIED, ex.getReason());
        assertTrue(
                allZero(state(slip10)),
                "walk state must be wiped even when walkPath throws on a non-hardened index");
    }

    @Test
    @DisplayName("deriveLeafKey at master matches the reference walk and wipes state")
    void leafKeyMatchesReferenceAtMaster() throws Exception {
        Slip10 slip10 = newSeededSlip10();
        byte[] out = new byte[32];

        short n = slip10.deriveLeafKey(new byte[0], (short) 0, (short) 0, out, (short) 0);

        assertEquals(32, n);
        assertArrayEquals(Arrays.copyOfRange(slip10Ref(SEED, new int[0]), 0, 32), out);
        assertTrue(allZero(state(slip10)), "walk state must be wiped on the success path");
    }

    @Test
    @DisplayName("deriveLeafKeyAndChainCode at m/0H matches the reference walk and wipes state")
    void doubleOutputMatchesReference() throws Exception {
        Slip10 slip10 = newSeededSlip10();
        int[] path = {0x80000000}; // m/0H — hardened, the smallest non-trivial SLIP-10 child
        byte[] out = new byte[64];

        short n =
                slip10.deriveLeafKeyAndChainCode(
                        serPath(path), (short) 0, (short) path.length, out, (short) 0);

        assertEquals(64, n);
        assertArrayEquals(slip10Ref(SEED, path), out, "leaf_key(32) ‖ chain_code(32) mismatch");
        assertTrue(allZero(state(slip10)), "walk state must be wiped on the success path");
    }

    private static Slip10 newSeededSlip10() {
        HmacSha512 hmac = new HmacSha512();
        MasterSeed masterSeed = new MasterSeed(hmac);
        JCSystem.beginTransaction();
        masterSeed.importSeed(SEED, (short) 0, (short) SEED.length);
        JCSystem.commitTransaction();
        return new Slip10(masterSeed, hmac);
    }

    /**
     * Independent SLIP-10 Ed25519 walk in the test process: {@code I = HMAC-SHA-512("ed25519 seed",
     * seed)} for the master, then {@code I = HMAC-SHA-512(c, 0x00 ‖ k ‖ ser32(i))} per hardened
     * level. Returns {@code k(32) ‖ c(32)}.
     */
    private static byte[] slip10Ref(byte[] seed, int[] path) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(
                new SecretKeySpec(
                        "ed25519 seed".getBytes(StandardCharsets.US_ASCII), "HmacSHA512"));
        byte[] iLR = mac.doFinal(seed);
        byte[] k = Arrays.copyOfRange(iLR, 0, 32);
        byte[] c = Arrays.copyOfRange(iLR, 32, 64);
        for (int index : path) {
            mac.init(new SecretKeySpec(c, "HmacSHA512"));
            mac.update((byte) 0x00);
            mac.update(k);
            mac.update(ser32(index));
            iLR = mac.doFinal();
            k = Arrays.copyOfRange(iLR, 0, 32);
            c = Arrays.copyOfRange(iLR, 32, 64);
        }
        byte[] out = new byte[64];
        System.arraycopy(k, 0, out, 0, 32);
        System.arraycopy(c, 0, out, 32, 32);
        return out;
    }

    private static byte[] state(Slip10 slip10) throws Exception {
        Field field = Slip10.class.getDeclaredField("state");
        field.setAccessible(true);
        return (byte[]) field.get(slip10);
    }

    private static byte[] serPath(int[] path) {
        byte[] out = new byte[path.length * 4];
        for (int i = 0; i < path.length; i++) {
            System.arraycopy(ser32(path[i]), 0, out, i * 4, 4);
        }
        return out;
    }

    private static byte[] ser32(int i) {
        return new byte[] {(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
    }

    private static boolean allZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}

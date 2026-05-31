/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MasterSeedTest {

    @Test
    @DisplayName("wipeKeyMaterialNonAtomic physically clears persistent HD master material")
    void wipeKeyMaterialNonAtomicClearsPersistentMaterial() throws Exception {
        MasterSeed masterSeed = new MasterSeed(new HmacSha512());
        byte[] seed = hex("000102030405060708090A0B0C0D0E0F");

        JCSystem.beginTransaction();
        masterSeed.importSeed(seed, (short) 0, (short) seed.length);
        JCSystem.commitTransaction();

        byte[] bip32Material = material(masterSeed, "bip32Material");
        byte[] slip10Material = material(masterSeed, "slip10Material");
        assertFalse(allZero(bip32Material));
        assertFalse(allZero(slip10Material));

        JCSystem.beginTransaction();
        masterSeed.wipeInTx();
        JCSystem.commitTransaction();
        masterSeed.wipeKeyMaterialNonAtomic();

        assertTrue(allZero(bip32Material));
        assertTrue(allZero(slip10Material));
    }

    private static byte[] material(MasterSeed masterSeed, String fieldName) throws Exception {
        Field field = MasterSeed.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (byte[]) field.get(masterSeed);
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

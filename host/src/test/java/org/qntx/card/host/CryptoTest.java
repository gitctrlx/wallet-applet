// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The §1 primitives against the kdf.json vectors (NIST CMAC oracles, SP 800-56C, SP 800-108). */
final class CryptoTest {
    private final Map<String, Object> kdf = Vectors.load("kdf.json");

    @Test
    void cmacMatchesTheNistExamples() {
        for (Map<String, Object> c : Vectors.list(kdf, "cmac")) {
            assertArrayEquals(
                    Vectors.hex(c, "tag"),
                    Crypto.cmac(Vectors.hex(c, "key"), Vectors.hex(c, "message")),
                    (String) c.get("message"));
        }
    }

    @Test
    void oneStepKdfMatchesEveryCase() {
        for (Map<String, Object> c : Vectors.list(kdf, "kdf")) {
            int len = ((Number) c.get("len")).intValue();
            assertArrayEquals(
                    Vectors.hex(c, "out"),
                    Crypto.kdf(
                            Vectors.hex(c, "z"),
                            Vectors.hex(c, "label"),
                            Vectors.hex(c, "ctx"),
                            len));
        }
    }

    @Test
    void kdf108MatchesEveryCase() {
        for (Map<String, Object> c : Vectors.list(kdf, "kdf108")) {
            assertArrayEquals(
                    Vectors.hex(c, "out"),
                    Crypto.kdf108(
                            Vectors.hex(c, "key"), Vectors.hex(c, "label"), Vectors.hex(c, "ctx")));
        }
    }

    @Test
    void m2PaddingRoundTripsAndRejects() {
        for (int len : new int[] {0, 1, 3, 15, 16, 17, 236}) {
            byte[] plain = new byte[len];
            for (int i = 0; i < len; i++) {
                plain[i] = (byte) (i * 31 + 7);
            }
            byte[] padded = Crypto.m2pad(plain);
            assertEquals((len / 16 + 1) * 16, padded.length);
            assertArrayEquals(plain, Crypto.m2unpad(padded), "len " + len);
        }
        assertNull(Crypto.m2unpad(new byte[0]));
        assertNull(Crypto.m2unpad(new byte[16])); // no 0x80 anywhere
        assertNull(Crypto.m2unpad(new byte[15]));
        byte[] longPad = new byte[32]; // 0x80 followed by 28 zeros
        longPad[0] = (byte) 0x80;
        longPad[3] = (byte) 0x80;
        longPad[0] = 0x20;
        assertNull(Crypto.m2unpad(longPad));
    }

    @Test
    void cbcRoundTripsAndBlocksMatchEcb() {
        byte[] key = Vectors.unhex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] block = Vectors.unhex("6bc1bee22e409f96e93d7e117393172a");
        // NIST SP 800-38A F.2.1: AES-128-CBC encrypt example, first block
        byte[] iv = Vectors.unhex("000102030405060708090a0b0c0d0e0f");
        byte[] expect = Vectors.unhex("7649abac8119b246cee98e9b12e9197d");
        assertArrayEquals(expect, Crypto.aesCbc(key, iv, block, true));
        byte[] data = new byte[48];
        byte[] ct = Crypto.aesCbc(key, iv, data, true);
        assertArrayEquals(data, Crypto.aesCbc(key, iv, ct, false));
    }

    @Test
    void u16IsBigEndian() {
        assertArrayEquals(new byte[] {0, 0}, Crypto.u16(0));
        assertArrayEquals(new byte[] {0x12, 0x34}, Crypto.u16(0x1234));
        assertArrayEquals(new byte[] {(byte) 0xFF, (byte) 0xFF}, Crypto.u16(0xFFFF));
    }

    @Test
    void constantTimeEquality() {
        byte[] a = {1, 2, 3};
        assertTrue(Crypto.equalConstantTime(a, new byte[] {1, 2, 3}));
        assertFalse(Crypto.equalConstantTime(a, new byte[] {1, 2, 4}));
        assertFalse(Crypto.equalConstantTime(a, new byte[] {1, 2}));
        assertFalse(Crypto.equalConstantTime(a, new byte[0]));
    }

    @Test
    void compressDecompressRoundTrip() {
        Map<String, Object> cert = Vectors.load("cert.json");
        List<Map<String, Object>> ids = Vectors.list(cert, "identities");
        for (Map<String, Object> id : ids) {
            byte[] pub = Vectors.hex(id, "public");
            byte[] compressed = Vectors.hex(id, "compressed");
            assertArrayEquals(compressed, Crypto.compress(pub));
            assertArrayEquals(pub, Crypto.decompress(compressed));
        }
    }
}

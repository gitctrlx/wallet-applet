// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

/**
 * {@code bip340.json}: BIP-340 schnorr vectors of spec/protocol.md §12.2. {@code official} is the
 * BIP-340 reference CSV (bitcoin/bips bip-0340/test-vectors.csv) copied verbatim and lowercased;
 * each generator's own {@link Bip340} must reproduce every signature of a row with a secret key and
 * must return the row's {@code valid} flag on verification. {@code bip86} is the BIP-86 test-vector
 * section, copied verbatim and reproduced from the BIP-39 seed; {@code cases} covers the tweak and
 * parity combinations of §12.2 under the {@code derivation.json} template seed.
 */
final class Bip340Doc {
    private static final BigInteger N = Crypto.N;
    private static final BigInteger MAX_256 =
            BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    // bip-0340/test-vectors.csv, verbatim and lowercased:
    // index, secretKey, publicKey, auxRand, message, signature, valid, comment
    private static final String[][] OFFICIAL = {
        {
            "0",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
            "true",
            ""
        },
        {
            "1",
            "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
            "true",
            ""
        },
        {
            "2",
            "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
            "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
            "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
            "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
            "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
            "true",
            ""
        },
        {
            "3",
            "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
            "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
            "true",
            "test fails if msg is reduced modulo p or n"
        },
        {
            "4",
            "",
            "d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9",
            "",
            "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703",
            "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4",
            "true",
            ""
        },
        {
            "5",
            "",
            "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            "false",
            "public key not on the curve"
        },
        {
            "6",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2",
            "false",
            "has_even_y(R) is false"
        },
        {
            "7",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd",
            "false",
            "negated message"
        },
        {
            "8",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6",
            "false",
            "negated s value"
        },
        {
            "9",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051",
            "false",
            "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 0"
        },
        {
            "10",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197",
            "false",
            "sG - eP is infinite. Test fails in single verification if has_even_y(inf) is defined as true and x(inf) as 1"
        },
        {
            "11",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            "false",
            "sig[0:32] is not an X coordinate on the curve"
        },
        {
            "12",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            "false",
            "sig[0:32] is equal to field size"
        },
        {
            "13",
            "",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            "false",
            "sig[32:64] is equal to curve order"
        },
        {
            "14",
            "",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
            "",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            "false",
            "public key is not a valid X coordinate because it exceeds the field size"
        },
        {
            "15",
            "0340034003400340034003400340034003400340034003400340034003400340",
            "778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "",
            "71535db165ecd9fbbc046e5ffaea61186bb6ad436732fccc25291a55895464cf6069ce26bf03466228f19a3a62db8a649f2d560fac652827d1af0574e427ab63",
            "true",
            "message of size 0 (added 2022-12)"
        },
        {
            "16",
            "0340034003400340034003400340034003400340034003400340034003400340",
            "778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "11",
            "08a20a0afef64124649232e0693c583ab1b9934ae63b4c3511f3ae1134c6a303ea3173bfea6683bd101fa5aa5dbc1996fe7cacfc5a577d33ec14564cec2bacbf",
            "true",
            "message of size 1 (added 2022-12)"
        },
        {
            "17",
            "0340034003400340034003400340034003400340034003400340034003400340",
            "778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0102030405060708090a0b0c0d0e0f1011",
            "5130f39a4059b43bc7cac09a19ece52b5d8699d1a71e3c52da9afdb6b50ac370c4a482b77bf960f8681540e25b6771ece1e5a37fd80e5a51897c5566a97ea5a5",
            "true",
            "message of size 17 (added 2022-12)"
        },
        {
            "18",
            "0340034003400340034003400340034003400340034003400340034003400340",
            "778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
            "403b12b0d8555a344175ea7ec746566303321e5dbfa8be6f091635163eca79a8585ed3e3170807e7c03b720fc54c7b23897fcba0e9d0b4a06894cfd249f22367",
            "true",
            "message of size 100 (added 2022-12)"
        },
    };

    // BIP-86 test-vector section (bip-0086.mediawiki), verbatim.
    private static final String BIP86_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final String BIP86_ROOT_PRIVATE =
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";

    // path, xprv, xpub, internal_key, output_key — the three BIP-86 addresses.
    private static final String[][] BIP86_KEYS = {
        {
            "m/86'/0'/0'/0/0",
            "xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T",
            "xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B",
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        },
        {
            "m/86'/0'/0'/0/1",
            "xprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ",
            "xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX",
            "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
            "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"
        },
        {
            "m/86'/0'/0'/1/0",
            "xprvA3Ln3Gt3aphvUgzgEDT8vE2cYqb4PjFfpmbiFKphxLg1FjXQpkAk5M1ZKDY15bmCAHA35jTiawbFuwGtbDZogKF1WfjwxML4gK7WfYW5JRP",
            "xpub6GL8SnQwRCGDhB59LEz9HMyM6sRYoByXBzXK3iEKWgCz8XrZNHUzd9L3AUBELW5NzA7dEFvMas1F84TuPH3xqdUA5tumaGWFgihJzWytXe3",
            "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
            "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"
        },
    };

    private Bip340Doc() {}

    static Object document() {
        return Vec.object(
                "official", official(),
                "bip86", bip86(),
                "cases", cases(),
                "invalidTweak", invalidTweak());
    }

    private static List<Object> official() {
        List<Object> out = new ArrayList<>();
        for (String[] row : OFFICIAL) {
            int index = Integer.parseInt(row[0]);
            String secretKey = row[1];
            byte[] publicKey = Vec.unhex(row[2]);
            byte[] message = Vec.unhex(row[4]);
            byte[] signature = Vec.unhex(row[5]);
            boolean valid = row[6].equals("true");
            if (!secretKey.isEmpty()) {
                BigInteger d = new BigInteger(1, Vec.unhex(secretKey));
                assertHex(
                        Bip340.sign(d, message, Vec.unhex(row[3])),
                        row[5],
                        "BIP-340 sign of index " + index);
            }
            if (Bip340.verify(publicKey, message, signature) != valid) {
                throw new IllegalStateException("BIP-340 verify disagrees at index " + index);
            }
            out.add(
                    Vec.object(
                            "index", index,
                            "secretKey", secretKey,
                            "publicKey", row[2],
                            "auxRand", row[3],
                            "message", row[4],
                            "signature", row[5],
                            "valid", valid,
                            "comment", row[7]));
        }
        return out;
    }

    /** BIP-39: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048) as a 64-byte seed. */
    private static byte[] bip39Seed(String mnemonic) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA512Digest());
        gen.init(Vec.ascii(mnemonic), Vec.ascii("mnemonic"), 2048);
        return ((KeyParameter) gen.generateDerivedParameters(512)).getKey();
    }

    private static Object bip86() {
        byte[] seed = bip39Seed(BIP86_MNEMONIC);
        byte[] root = Base58.decodeCheck(BIP86_ROOT_PRIVATE);
        Hd.Node master = Hd.bip32Derive(seed, "m");
        assertHex(
                master.privateKey(), Vec.hex(Arrays.copyOfRange(root, 46, 78)), "BIP-86 root key");
        assertHex(
                master.chainCode(),
                Vec.hex(Arrays.copyOfRange(root, 13, 45)),
                "BIP-86 root chain code");
        List<Object> keys = new ArrayList<>();
        for (String[] k : BIP86_KEYS) {
            String path = k[0];
            Hd.Node node = Hd.bip32Derive(seed, path);
            byte[] xprv = Base58.decodeCheck(k[1]);
            byte[] xpub = Base58.decodeCheck(k[2]);
            assertHex(
                    node.privateKey(),
                    Vec.hex(Arrays.copyOfRange(xprv, 46, 78)),
                    "BIP-86 privateKey of " + path);
            assertHex(
                    node.chainCode(),
                    Vec.hex(Arrays.copyOfRange(xprv, 13, 45)),
                    "BIP-86 xprv chainCode of " + path);
            assertHex(
                    node.chainCode(),
                    Vec.hex(Arrays.copyOfRange(xpub, 13, 45)),
                    "BIP-86 xpub chainCode of " + path);
            ECPoint p =
                    Crypto.DOMAIN.getG().multiply(new BigInteger(1, node.privateKey())).normalize();
            assertHex(
                    Crypto.compress(p.getEncoded(false)),
                    Vec.hex(Arrays.copyOfRange(xpub, 45, 78)),
                    "BIP-86 publicKey of " + path);
            byte[] internal = Bip340.x(p);
            assertHex(internal, k[3], "BIP-86 internal key of " + path);
            byte[] tweak = Bip340.taggedHash("TapTweak", internal);
            assertHex(outputKey(p, new BigInteger(1, tweak)), k[4], "BIP-86 output key of " + path);
            keys.add(
                    Vec.object(
                            "path", path,
                            "wire", Vec.hex(Hd.wire(path)),
                            "xprv", k[1],
                            "xpub", k[2],
                            "internalKey", k[3],
                            "tweak", Vec.hex(tweak),
                            "outputKey", k[4]));
        }
        return Vec.object(
                "mnemonic", BIP86_MNEMONIC,
                "seed", Vec.hex(seed),
                "rootPrivate", BIP86_ROOT_PRIVATE,
                "keys", keys);
    }

    /** {@code x(P_even + t·G)}: the even-y lift of {@code P} tweaked by scalar {@code t}. */
    private static byte[] outputKey(ECPoint p, BigInteger t) {
        if (p.getAffineYCoord().toBigInteger().testBit(0)) {
            p = p.negate();
        }
        return Bip340.x(p.add(Crypto.DOMAIN.getG().multiply(t)).normalize());
    }

    /** {@code d = (d₀' + t) mod n} with {@code d₀' = n − d₀} when {@code y(P)} is odd (§12.2). */
    private static BigInteger tweaked(BigInteger d0, boolean oddY, byte[] tweak) {
        BigInteger d0p = oddY ? N.subtract(d0) : d0;
        return d0p.add(new BigInteger(1, tweak)).mod(N);
    }

    private static List<Object> cases() {
        List<Object> out = new ArrayList<>();
        String[][] parity = {
            {"p-even-q-even", "false", "false"},
            {"p-even-q-odd", "false", "true"},
            {"p-odd-q-even", "true", "false"},
            {"p-odd-q-odd", "true", "true"},
        };
        for (String[] want : parity) {
            String name = want[0];
            boolean wantOddP = want[1].equals("true");
            boolean wantOddQ = want[2].equals("true");
            for (int i = 0; ; i++) {
                String path = "m/86'/0'/0'/0/" + i;
                Hd.Node node = Hd.bip32Derive(DerivationDoc.TEMPLATE_SEED, path);
                BigInteger d0 = new BigInteger(1, node.privateKey());
                ECPoint p = Crypto.DOMAIN.getG().multiply(d0).normalize();
                byte[] tweak = Bip340.taggedHash("TapTweak", Bip340.x(p));
                BigInteger d = tweaked(d0, p.getAffineYCoord().toBigInteger().testBit(0), tweak);
                ECPoint q = Crypto.DOMAIN.getG().multiply(d).normalize();
                if (p.getAffineYCoord().toBigInteger().testBit(0) == wantOddP
                        && q.getAffineYCoord().toBigInteger().testBit(0) == wantOddQ) {
                    out.add(signCase(name, path, node, p, null, tweak, d, q));
                    break;
                }
            }
        }
        out.add(bip86Case("untweaked", "m/86'/0'/0'/0/0", new byte[32], null));
        out.add(
                bip86Case(
                        "script-tree",
                        "m/86'/0'/0'/0/0",
                        null,
                        Vec.det("bip340/script-tree/merkleRoot")));
        out.add(bip86Case("aux-zero", "m/86'/0'/0'/0/0", null, null, true));
        out.add(bip86Case("template-bip86", "m/86'/0'/0'/0/0", null, null));
        out.add(bip86Case("depth-10", "m/0/1'/2/3'/4/5'/6/7'/8/9'", null, null));
        return out;
    }

    /** A §12.2 case at {@code path} with the BIP-86 tweak ({@code tweak} overrides it). */
    private static Object bip86Case(
            String name, String path, byte[] tweakOverride, byte[] merkleRoot) {
        return bip86Case(name, path, tweakOverride, merkleRoot, false);
    }

    private static Object bip86Case(
            String name, String path, byte[] tweakOverride, byte[] merkleRoot, boolean auxZero) {
        Hd.Node node = Hd.bip32Derive(DerivationDoc.TEMPLATE_SEED, path);
        BigInteger d0 = new BigInteger(1, node.privateKey());
        ECPoint p = Crypto.DOMAIN.getG().multiply(d0).normalize();
        byte[] tweak;
        if (tweakOverride != null) {
            tweak = tweakOverride;
        } else if (merkleRoot != null) {
            tweak = Bip340.taggedHash("TapTweak", Bip340.x(p), merkleRoot);
        } else {
            tweak = Bip340.taggedHash("TapTweak", Bip340.x(p));
        }
        BigInteger d = tweaked(d0, p.getAffineYCoord().toBigInteger().testBit(0), tweak);
        ECPoint q = Crypto.DOMAIN.getG().multiply(d).normalize();
        return signCase(name, path, node, p, merkleRoot, tweak, d, q, auxZero);
    }

    private static Object signCase(
            String name,
            String path,
            Hd.Node node,
            ECPoint p,
            byte[] merkleRoot,
            byte[] tweak,
            BigInteger d,
            ECPoint q) {
        return signCase(name, path, node, p, merkleRoot, tweak, d, q, false);
    }

    private static Object signCase(
            String name,
            String path,
            Hd.Node node,
            ECPoint p,
            byte[] merkleRoot,
            byte[] tweak,
            BigInteger d,
            ECPoint q,
            boolean auxZero) {
        byte[] message = Vec.det("bip340/" + name + "/message");
        byte[] aux = auxZero ? new byte[32] : Vec.det("bip340/" + name + "/aux");
        byte[] signature = Bip340.sign(d, message, aux);
        byte[] outputKey = Bip340.x(q);
        if (!Bip340.verify(outputKey, message, signature)) {
            throw new IllegalStateException("BIP-340 case does not verify: " + name);
        }
        List<Object> fields = new ArrayList<>();
        fields.add("name");
        fields.add(name);
        fields.add("path");
        fields.add(path);
        fields.add("wire");
        fields.add(Vec.hex(Hd.wire(path)));
        fields.add("privateKey");
        fields.add(Vec.hex(node.privateKey()));
        fields.add("publicKey");
        fields.add(Vec.hex(p.getEncoded(true)));
        fields.add("internalKey");
        fields.add(Vec.hex(Bip340.x(p)));
        if (merkleRoot != null) {
            fields.add("merkleRoot");
            fields.add(Vec.hex(merkleRoot));
        }
        fields.add("tweak");
        fields.add(Vec.hex(tweak));
        fields.add("tweakedKey");
        fields.add(Vec.hex(Vec.scalar(d)));
        fields.add("outputKey");
        fields.add(Vec.hex(outputKey));
        fields.add("outputKeyOddY");
        fields.add(q.getAffineYCoord().toBigInteger().testBit(0));
        fields.add("message");
        fields.add(Vec.hex(message));
        fields.add("aux");
        fields.add(Vec.hex(aux));
        fields.add("signature");
        fields.add(Vec.hex(signature));
        return Vec.object(fields.toArray());
    }

    private static List<Object> invalidTweak() {
        String path = "m/86'/0'/0'/0/0";
        Hd.Node node = Hd.bip32Derive(DerivationDoc.TEMPLATE_SEED, path);
        BigInteger d0 = new BigInteger(1, node.privateKey());
        ECPoint p = Crypto.DOMAIN.getG().multiply(d0).normalize();
        BigInteger d0p = p.getAffineYCoord().toBigInteger().testBit(0) ? N.subtract(d0) : d0;
        List<Object> out = new ArrayList<>();
        out.add(tweakCase("tweak-is-n", path, Vec.scalar(N), "tweak >= n"));
        out.add(tweakCase("tweak-max", path, Vec.scalar(MAX_256), "tweak >= n"));
        out.add(
                tweakCase(
                        "tweaked-key-zero",
                        path,
                        Vec.scalar(N.subtract(d0p)),
                        "the tweaked key is zero"));
        return out;
    }

    private static Object tweakCase(String name, String path, byte[] tweak, String reason) {
        return Vec.object("name", name, "path", path, "tweak", Vec.hex(tweak), "reason", reason);
    }

    private static void assertHex(byte[] actual, String expected, String what) {
        if (!Vec.hex(actual).equals(expected)) {
            throw new IllegalStateException(what + ": " + Vec.hex(actual) + " != " + expected);
        }
    }
}

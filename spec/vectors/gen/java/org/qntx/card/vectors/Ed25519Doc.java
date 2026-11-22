// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/**
 * {@code ed25519.json}: hedged Ed25519 signing vectors of spec/protocol.md §12.3 and the RFC 8032
 * §7.1 vectors of §10.4. {@code rfc8032} is TEST 1, 2, 3, 1024 and SHA(abc) copied verbatim; each
 * generator's own Ed25519 must reproduce {@code publicKey} and {@code signature}, and {@code wei}
 * is the {@code W(A)} the card would output (asserted to map to {@code publicKey}). {@code cases}
 * computes the card's §12.3 algorithm on Wei25519 with {@code BigInteger} scalars; every signature
 * is asserted with BouncyCastle's RFC 8032 verifier.
 */
final class Ed25519Doc {
    private static final byte[] NONCE_LABEL = Vec.ascii("qntx-card/v1/ed25519-nonce");
    private static final BigInteger L = Wei25519.ORDER;

    // RFC 8032 §7.1 TEST 1, 2, 3, 1024, SHA(abc), verbatim:
    // name, secretKey, publicKey, message, signature
    private static final String[][] RFC8032 = {
        {
            "test-1",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        },
        {
            "test-2",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        },
        {
            "test-3",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        },
        {
            "test-1024",
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
        },
        {
            "test-sha-abc",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
        },
    };

    private Ed25519Doc() {}

    static Object document() {
        return Vec.object(
                "nonceLabel", Vec.hex(NONCE_LABEL),
                "rfc8032", rfc8032(),
                "cases", cases(),
                "wrongStream", wrongStream());
    }

    private static List<Object> rfc8032() {
        List<Object> out = new ArrayList<>();
        for (String[] v : RFC8032) {
            byte[] sk = Vec.unhex(v[1]);
            byte[] pk = Vec.unhex(v[2]);
            byte[] message = Vec.unhex(v[3]);
            byte[] signature = Vec.unhex(v[4]);
            byte[] computedPk = new byte[Ed25519.PUBLIC_KEY_SIZE];
            Ed25519.generatePublicKey(sk, 0, computedPk, 0);
            assertEqual(computedPk, pk, "RFC 8032 public key of " + v[0]);
            byte[] computedSig = new byte[Ed25519.SIGNATURE_SIZE];
            Ed25519.sign(sk, 0, message, 0, message.length, computedSig, 0);
            assertEqual(computedSig, signature, "RFC 8032 signature of " + v[0]);
            if (!Ed25519.verify(signature, 0, pk, 0, message, 0, message.length)) {
                throw new IllegalStateException("RFC 8032 verify failed: " + v[0]);
            }
            byte[] wei = weiPoint(sk);
            assertEqual(Wei25519.encode(wei), pk, "W(A) map of " + v[0]);
            out.add(
                    Vec.object(
                            "name", v[0],
                            "secretKey", v[1],
                            "publicKey", v[2],
                            "message", v[3],
                            "signature", v[4],
                            "wei", Vec.hex(wei)));
        }
        return out;
    }

    private static byte[] weiPoint(byte[] sk) {
        return Wei25519.wei(Wei25519.G.multiply(Wei25519.scalar(sk)));
    }

    /** ID(A) of a cert.json identity ({@code card1} / {@code card2}). */
    private static byte[] cardId(String name, boolean wantOddY) {
        byte[] a = Crypto.compress(Crypto.publicKey(Cards.identityPrivate(name, wantOddY)));
        return Arrays.copyOf(Crypto.sha256(a), 16);
    }

    private static List<Object> cases() {
        List<Object> out = new ArrayList<>();
        byte[] card1 = cardId("cert/card1", false);
        byte[] card2 = cardId("cert/card2", true);
        byte[] zr = Vec.det("ed25519/solana-card1/zr");
        byte[] message = Vec.det("ed25519/solana-card1/message", 32);
        Object case1 = signCase("solana-card1", "m/44'/501'/0'/0'", card1, 1L, zr, message);
        out.add(case1);
        Object case2 = signCase("solana-card2", "m/44'/501'/0'/0'", card2, 1L, zr, message);
        if (((java.util.Map<?, ?>) case1).get("r").equals(((java.util.Map<?, ?>) case2).get("r"))) {
            throw new IllegalStateException("solana-card2 must derive a different r");
        }
        out.add(case2);
        out.add(
                signCase(
                        "empty-message",
                        "m/44'/501'/0'/0'",
                        card1,
                        2L,
                        Vec.det("ed25519/empty-message/zr"),
                        Vec.det("ed25519/empty-message/message", 0)));
        out.add(
                signCase(
                        "long-message",
                        "m/44'/501'/1'/0'",
                        card1,
                        3L,
                        Vec.det("ed25519/long-message/zr"),
                        Vec.det("ed25519/long-message/message", 1232)));
        out.add(
                signCase(
                        "max-counter",
                        "m/44'/501'/0'/0'",
                        card1,
                        0xFFFFFFFFL,
                        Vec.det("ed25519/max-counter/zr"),
                        Vec.det("ed25519/max-counter/message", 32)));
        out.add(
                signCase(
                        "depth-10",
                        "m/0'/1'/2'/3'/4'/5'/6'/7'/8'/9'",
                        card1,
                        7L,
                        Vec.det("ed25519/depth-10/zr"),
                        Vec.det("ed25519/depth-10/message", 100)));
        return out;
    }

    private static Object signCase(
            String name, String path, byte[] cardId, long counter, byte[] zr, byte[] message) {
        Hd.Node node = Hd.slip10Derive(DerivationDoc.TEMPLATE_SEED, path);
        byte[] sk = node.privateKey();
        byte[] h = Crypto.sha512(sk);
        byte[] aBytes = Arrays.copyOf(h, 32);
        aBytes[0] &= 0xf8;
        aBytes[31] &= 0x7f;
        aBytes[31] |= 0x40;
        byte[] prefix = Arrays.copyOfRange(h, 32, 64);
        BigInteger a = intLe(aBytes).mod(L);
        byte[] wei = weiPoint(sk);
        byte[] publicKey = Wei25519.encode(wei);
        byte[] expectedPk = new byte[Ed25519.PUBLIC_KEY_SIZE];
        Ed25519.generatePublicKey(sk, 0, expectedPk, 0);
        assertEqual(expectedPk, publicKey, "publicKey of " + name);

        byte[] nonceHash = Crypto.sha512(NONCE_LABEL, zr, prefix, cardId, u32(counter));
        BigInteger rScalar = intLe(nonceHash).mod(L);
        byte[] weiR = Wei25519.wei(Wei25519.G.multiply(rScalar));
        byte[] encodedR = Wei25519.encode(weiR);
        byte[] stream = concat(encodedR, publicKey, message);
        BigInteger k = intLe(Crypto.sha512(stream)).mod(L);
        BigInteger s = rScalar.add(k.multiply(a)).mod(L);
        byte[] signature = concat(encodedR, le32(s));
        if (!Ed25519.verify(signature, 0, publicKey, 0, message, 0, message.length)) {
            throw new IllegalStateException("Ed25519 case does not verify: " + name);
        }
        return Vec.object(
                "name", name,
                "path", path,
                "wire", Vec.hex(Hd.wire(path)),
                "cardId", Vec.hex(cardId),
                "counter", counter,
                "zr", Vec.hex(zr),
                "privateKey", Vec.hex(sk),
                "prefix", Vec.hex(prefix),
                "scalar", Vec.hex(aBytes),
                "publicKey", Vec.hex(publicKey),
                "wei", Vec.hex(wei),
                "nonceHash", Vec.hex(nonceHash),
                "r", Vec.hex(le32(rScalar)),
                "weiR", Vec.hex(weiR),
                "encodedR", Vec.hex(encodedR),
                "message", Vec.hex(message),
                "k", Vec.hex(le32(k)),
                "s", Vec.hex(le32(s)),
                "signature", Vec.hex(signature));
    }

    /** The {@code wrong-message} entry: case 1's stream with the first message byte flipped. */
    private static List<Object> wrongStream() {
        List<Object> out = new ArrayList<>();
        // Rebuild case 1 to tamper with its stream.
        byte[] card1 = cardId("cert/card1", false);
        byte[] zr = Vec.det("ed25519/solana-card1/zr");
        byte[] message = Vec.det("ed25519/solana-card1/message", 32);
        Hd.Node node = Hd.slip10Derive(DerivationDoc.TEMPLATE_SEED, "m/44'/501'/0'/0'");
        byte[] sk = node.privateKey();
        byte[] h = Crypto.sha512(sk);
        byte[] aBytes = Arrays.copyOf(h, 32);
        aBytes[0] &= 0xf8;
        aBytes[31] &= 0x7f;
        aBytes[31] |= 0x40;
        byte[] prefix = Arrays.copyOfRange(h, 32, 64);
        BigInteger a = intLe(aBytes).mod(L);
        byte[] publicKey = Wei25519.encode(weiPoint(sk));
        byte[] nonceHash = Crypto.sha512(NONCE_LABEL, zr, prefix, card1, u32(1L));
        BigInteger rScalar = intLe(nonceHash).mod(L);
        byte[] encodedR = Wei25519.encode(Wei25519.wei(Wei25519.G.multiply(rScalar)));
        byte[] wrong = message.clone();
        wrong[0] ^= 0x01;
        byte[] stream = concat(encodedR, publicKey, wrong);
        BigInteger k = intLe(Crypto.sha512(stream)).mod(L);
        BigInteger s = rScalar.add(k.multiply(a)).mod(L);
        byte[] signature = concat(encodedR, le32(s));
        if (Ed25519.verify(signature, 0, publicKey, 0, message, 0, message.length)) {
            throw new IllegalStateException("wrong-stream signature verifies");
        }
        out.add(
                Vec.object(
                        "name", "wrong-message",
                        "case", "solana-card1",
                        "stream", Vec.hex(stream),
                        "s", Vec.hex(le32(s)),
                        "signature", Vec.hex(signature),
                        "message", Vec.hex(message),
                        "valid", false));
        return out;
    }

    private static BigInteger intLe(byte[] le) {
        byte[] be = le.clone();
        reverse(be);
        return new BigInteger(1, be);
    }

    private static byte[] le32(BigInteger v) {
        byte[] out = Vec.scalar(v);
        reverse(out);
        return out;
    }

    private static void reverse(byte[] a) {
        for (int i = 0, j = a.length - 1; i < j; i++, j--) {
            byte t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }

    private static byte[] u32(long v) {
        return new byte[] {
            (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v,
        };
    }

    private static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    private static void assertEqual(byte[] a, byte[] b, String what) {
        if (!Arrays.equals(a, b)) {
            throw new IllegalStateException(what + ": " + Vec.hex(a) + " != " + Vec.hex(b));
        }
    }
}

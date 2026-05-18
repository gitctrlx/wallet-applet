/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javacard.framework.AID;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * End-to-end Phase 4 tests: master seed import, card-generated seed, BIP-32 secp256k1 derivation
 * verified against the official BIP-32 vectors, and SLIP-10 Ed25519 chain-code derivation verified
 * against the official SLIP-10 vectors.
 */
class PhaseFourTest {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.CLA_MEOWL & 0xFF;
    private static final int INS_INIT_SC = Constants.INS_INIT_SECURE_CHANNEL & 0xFF;
    private static final int INS_OPEN_SC = Constants.INS_OPEN_SECURE_CHANNEL & 0xFF;

    private static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");
    private static final byte[] HKDF_INFO = "meowl-sc-v1".getBytes();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] DEFAULT_PIN = "123456".getBytes();
    private static final byte[] DEFAULT_PUK = "ABCDEFGH".getBytes();

    /** BIP-32 test vector 1 seed (16 bytes hex 000102030405060708090a0b0c0d0e0f). */
    private static final byte[] BIP32_VECTOR_1_SEED = hex("000102030405060708090a0b0c0d0e0f");

    private CardSimulator simulator;
    private Session session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_BYTES);
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
        session = openSession();
        // Walk the card to SETUP_DONE: install a tiny PKI cert, lock, run SETUP, verify PIN.
        bringToSetupDoneAndVerifyPin();
    }

    @Nested
    @DisplayName("IMPORT_SEED / GENERATE_SEED")
    class SeedInstall {

        @Test
        @DisplayName("IMPORT_SEED with a 16-byte seed advances lifecycle to SEEDED")
        void importAdvancesLifecycle() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
            byte[] info = transmit(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            assertEquals(LifecycleState.SEEDED, readLifecycleFromInfoTlv(info));
        }

        @Test
        @DisplayName("IMPORT_SEED twice fails")
        void importTwiceFails() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
            ResponseAPDU r =
                    sendInner(
                            Constants.INS_IMPORT_SEED,
                            (byte) 0,
                            (byte) 0,
                            prefixLen(BIP32_VECTOR_1_SEED));
            // Lifecycle FSM rejects this because state == SEEDED, not SETUP_DONE.
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("IMPORT_SEED with seed length outside policy fails with SW_WRONG_LENGTH")
        void importBadLengthFails() {
            byte[] tooShort = new byte[10];
            ResponseAPDU r =
                    sendInner(Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(tooShort));
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("GENERATE_SEED returns a 64-byte seed and advances lifecycle to SEEDED")
        void generateAdvancesLifecycle() throws Exception {
            byte[] resp =
                    sendInnerExpectOk(Constants.INS_GENERATE_SEED, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SEED_GENERATED_LEN, resp.length);
            // Sanity: not all zero.
            byte acc = 0;
            for (byte b : resp) {
                acc |= b;
            }
            assertNotEquals(0, acc, "generated seed must contain entropy");

            byte[] info = transmit(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            assertEquals(LifecycleState.SEEDED, readLifecycleFromInfoTlv(info));
        }
    }

    @Nested
    @DisplayName("BIP-32 secp256k1 derivation vs the official vectors")
    class Bip32Vectors {

        @BeforeEach
        void importVector1Seed() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("Vector 1 / m — master xpub matches the reference")
        void masterXpub() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            // BIP-32 v1 master pubkey + chain code, hex from the spec.
            byte[] expectedPub =
                    hex("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
            byte[] expectedChain =
                    hex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
            byte[] gotPub = Arrays.copyOfRange(resp, 0, 33);
            byte[] gotChain = Arrays.copyOfRange(resp, 33, 65);
            assertArrayEquals(expectedPub, gotPub, "master pubkey mismatch");
            assertArrayEquals(expectedChain, gotChain, "master chain code mismatch");
        }

        @Test
        @DisplayName("Vector 1 / m/0H — hardened child matches reference")
        void mZeroHardened() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000});
            byte[] expectedPub =
                    hex("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");
            byte[] expectedChain =
                    hex("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 1 / m/0H/1 — non-hardened child of hardened parent matches reference")
        void mZeroHardenedOne() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000, 1});
            byte[] expectedPub =
                    hex("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c");
            byte[] expectedChain =
                    hex("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName(
                "Vector 1 / m/0H/1/2H/2/1000000000 — full 5-level path matches reference (deepest"
                        + " case)")
        void fullPath() throws Exception {
            byte[] resp =
                    exportXpub(
                            Constants.CURVE_SECP256K1,
                            new int[] {0x80000000, 1, 0x80000002, 2, 1000000000});
            byte[] expectedPub =
                    hex("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011");
            byte[] expectedChain =
                    hex("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }
    }

    @Nested
    @DisplayName("SLIP-10 Ed25519 derivation vs the official vectors")
    class Slip10Vectors {

        @BeforeEach
        void importVector1Seed() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("SLIP-10 Vector 1 / m — master chain code matches")
        void masterChainCode() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {});
            byte[] expected =
                    hex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb");
            assertEquals(Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(expected, resp);
        }

        @Test
        @DisplayName("SLIP-10 Vector 1 / m/0H — hardened child chain code matches")
        void zeroHardenedChainCode() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {0x80000000});
            byte[] expected =
                    hex("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69");
            assertArrayEquals(expected, resp);
        }

        @Test
        @DisplayName("SLIP-10 non-hardened index is rejected for Ed25519")
        void nonHardenedRejected() {
            // Index 0 (top bit clear) is illegal for ed25519 under SLIP-10.
            ResponseAPDU r = exportXpubResp(Constants.CURVE_ED25519, new int[] {0});
            assertEquals(Constants.SW_INCORRECT_P1P2 & 0xFFFF, r.getSW());
        }
    }

    /*  Helpers shared across nested test classes.  */

    private byte[] exportXpub(byte curve, int[] path) {
        byte[] req = encodePath(curve, path);
        return sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU exportXpubResp(byte curve, int[] path) {
        byte[] req = encodePath(curve, path);
        return sendInner(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
    }

    private static byte[] encodePath(byte curve, int[] path) {
        byte[] out = new byte[2 + 4 * path.length];
        out[0] = curve;
        out[1] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[2 + i * 4] = (byte) (idx >>> 24);
            out[2 + i * 4 + 1] = (byte) (idx >>> 16);
            out[2 + i * 4 + 2] = (byte) (idx >>> 8);
            out[2 + i * 4 + 3] = (byte) idx;
        }
        return out;
    }

    private void bringToSetupDoneAndVerifyPin() throws Exception {
        // Install a tiny PKI cert + lock so lifecycle reaches PERSONALIZED.
        byte[] cert = new byte[64];
        for (int i = 0; i < cert.length; i++) cert[i] = (byte) i;
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_INIT,
                (byte) 0,
                shortBE((short) cert.length));
        byte[] writePayload = new byte[2 + cert.length];
        System.arraycopy(cert, 0, writePayload, 2, cert.length);
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_WRITE,
                (byte) 0,
                writePayload);
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
        sendInnerExpectOk(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);
        // PKI lock invalidates the SC and PIN; re-open a session before the user flow.
        session = openSession();
        sendInnerExpectOk(
                Constants.INS_SETUP, (byte) 0, (byte) 0, encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
        assertEquals(
                0x9000,
                sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN).getSW());
    }

    private byte[] sendInnerExpectOk(byte ins, byte p1, byte p2, byte[] data) {
        ResponseAPDU r = sendInner(ins, p1, p2, data);
        assertEquals(0x9000, r.getSW(), "inner INS 0x" + Integer.toHexString(ins & 0xFF));
        try {
            return session.decryptFromCard(r.getData());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ResponseAPDU sendInner(byte ins, byte p1, byte p2, byte[] data) {
        try {
            byte[] inner = innerApdu(ins, p1, p2, data);
            byte[] envelope = session.encryptForCard(inner);
            return transmit(INS_OPEN_SC, 0x00, 0x00, envelope);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] innerApdu(byte ins, byte p1, byte p2, byte[] data) {
        byte[] out = new byte[5 + data.length];
        out[0] = Constants.CLA_MEOWL;
        out[1] = ins;
        out[2] = p1;
        out[3] = p2;
        out[4] = (byte) data.length;
        System.arraycopy(data, 0, out, 5, data.length);
        return out;
    }

    private static byte[] encodeSetup(byte[] pin, byte[] puk) {
        byte[] out = new byte[1 + pin.length + 1 + puk.length];
        out[0] = (byte) pin.length;
        System.arraycopy(pin, 0, out, 1, pin.length);
        out[1 + pin.length] = (byte) puk.length;
        System.arraycopy(puk, 0, out, 1 + pin.length + 1, puk.length);
        return out;
    }

    private static byte[] prefixLen(byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) data.length;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    private static byte[] shortBE(short v) {
        return new byte[] {(byte) (v >> 8), (byte) (v & 0xFF)};
    }

    private static byte readLifecycleFromInfoTlv(byte[] tlv) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            int len = tlv[i++] & 0xFF;
            if (tag == (Constants.TAG_LIFECYCLE_STATE & 0xFF)) {
                return tlv[i];
            }
            i += len;
        }
        throw new IllegalStateException("lifecycle TLV not found");
    }

    private static byte[] hex(String h) {
        h = h.replace(" ", "");
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private Session openSession() {
        BigInteger clientPriv;
        ECPoint clientPub;
        do {
            byte[] cand = new byte[32];
            RANDOM.nextBytes(cand);
            clientPriv = new BigInteger(1, cand);
        } while (clientPriv.signum() == 0 || clientPriv.compareTo(SECP256K1.getN()) >= 0);
        clientPub = SECP256K1.getG().multiply(clientPriv).normalize();
        byte[] clientPubEnc = clientPub.getEncoded(false);

        ResponseAPDU resp = transmit(INS_INIT_SC, 0x00, 0x00, clientPubEnc);
        assertEquals(0x9000, resp.getSW(), "handshake");
        byte[] body = resp.getData();
        byte[] cardEphPub = Arrays.copyOfRange(body, 0, Constants.EC_POINT_UNCOMPRESSED_LEN);

        ECPoint cardPub = SECP256K1.getCurve().decodePoint(cardEphPub).normalize();
        ECPoint sharedPoint = cardPub.multiply(clientPriv).normalize();
        byte[] sharedX = bigIntToFixed(sharedPoint.getAffineXCoord().toBigInteger(), 32);
        byte[] clientX = Arrays.copyOfRange(clientPubEnc, 1, 33);
        byte[] cardX = Arrays.copyOfRange(cardEphPub, 1, 33);
        byte[] salt = concat(clientX, cardX);
        byte[] prk = HkdfSha256.extract(salt, sharedX);
        byte[] okm = HkdfSha256.expand(prk, HKDF_INFO, 32 + 32 + 16);
        return new Session(
                Arrays.copyOfRange(okm, 0, 32),
                Arrays.copyOfRange(okm, 32, 64),
                Arrays.copyOfRange(okm, 64, 80));
    }

    private ResponseAPDU transmit(int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(CLA, ins, p1, p2)
                        : new CommandAPDU(CLA, ins, p1, p2, data);
        return simulator.transmitCommand(cmd);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] bigIntToFixed(BigInteger n, int len) {
        byte[] raw = n.toByteArray();
        if (raw.length == len) return raw;
        byte[] out = new byte[len];
        if (raw.length > len) System.arraycopy(raw, raw.length - len, out, 0, len);
        else System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        return out;
    }

    private static final class Session {
        final byte[] kEnc;
        final byte[] kMac;
        final byte[] ivBase;
        long counter;

        Session(byte[] kEnc, byte[] kMac, byte[] ivBase) {
            this.kEnc = kEnc;
            this.kMac = kMac;
            this.ivBase = ivBase;
            this.counter = 0L;
        }

        byte[] encryptForCard(byte[] plaintext) throws Exception {
            counter++;
            byte[] iv = new byte[Constants.SC_BLOCK_LEN];
            for (int i = 0; i < 8; i++) {
                iv[Constants.SC_BLOCK_LEN - 1 - i] = (byte) ((counter >>> (8 * i)) & 0xFF);
            }
            byte[] padded = pkcs5Pad(plaintext);
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] ct = c.doFinal(padded);

            int lc = iv.length + ct.length + Constants.SC_MAC_LEN;
            byte[] header = {(byte) CLA, (byte) INS_OPEN_SC, 0x00, 0x00, (byte) lc};
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(kMac, "HmacSHA256"));
            m.update(header);
            m.update(iv);
            m.update(ct);
            byte[] tag = Arrays.copyOf(m.doFinal(), Constants.SC_MAC_LEN);

            byte[] out = new byte[lc];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            System.arraycopy(tag, 0, out, iv.length + ct.length, tag.length);
            return out;
        }

        byte[] decryptFromCard(byte[] envelope) throws Exception {
            byte[] iv = Arrays.copyOfRange(envelope, 0, Constants.SC_BLOCK_LEN);
            byte[] ct =
                    Arrays.copyOfRange(
                            envelope,
                            Constants.SC_BLOCK_LEN,
                            envelope.length - Constants.SC_MAC_LEN);
            byte[] tag =
                    Arrays.copyOfRange(
                            envelope, envelope.length - Constants.SC_MAC_LEN, envelope.length);
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(kMac, "HmacSHA256"));
            m.update((byte) 0xFF);
            m.update(iv);
            m.update(ct);
            byte[] expected = Arrays.copyOf(m.doFinal(), Constants.SC_MAC_LEN);
            if (!Arrays.equals(expected, tag)) {
                throw new IllegalStateException("outbound MAC mismatch");
            }
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] padded = c.doFinal(ct);
            int padLen = padded[padded.length - 1] & 0xFF;
            return Arrays.copyOfRange(padded, 0, padded.length - padLen);
        }

        private static byte[] pkcs5Pad(byte[] in) {
            int rem = in.length % Constants.SC_BLOCK_LEN;
            int pad = Constants.SC_BLOCK_LEN - rem;
            byte[] out = new byte[in.length + pad];
            System.arraycopy(in, 0, out, 0, in.length);
            for (int i = in.length; i < out.length; i++) out[i] = (byte) pad;
            return out;
        }
    }

    private static final class HkdfSha256 {
        static byte[] extract(byte[] salt, byte[] ikm) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
                return mac.doFinal(ikm);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        static byte[] expand(byte[] prk, byte[] info, int length) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                byte[] out = new byte[length];
                byte[] prev = new byte[0];
                int pos = 0;
                byte counter = 1;
                while (pos < length) {
                    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                    mac.update(prev);
                    mac.update(info);
                    mac.update(counter);
                    prev = mac.doFinal();
                    int take = Math.min(prev.length, length - pos);
                    System.arraycopy(prev, 0, out, pos, take);
                    pos += take;
                    counter++;
                }
                return out;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}

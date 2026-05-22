/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * jcardsim performance benchmarks for the meowl applet's signing and HD-walk paths.
 *
 * <p>Disabled by default. Enable with {@code -Dbench=true}, e.g.:
 *
 * <pre>
 *   ./gradlew :tests:test --tests social.meowl.applet.BenchmarkSuite \
 *       -Dbench=true -i
 * </pre>
 *
 * <p>Each benchmark:
 *
 * <ol>
 *   <li>Brings the applet to {@code SEEDED + PIN-verified} state once per test.
 *   <li>Runs {@link #WARMUP} iterations to let the JIT warm up.
 *   <li>Runs {@link #SAMPLES} iterations, recording per-call wall-clock latency.
 *   <li>Reports p50 / p95 / p99 / mean / stddev to {@code System.out}.
 * </ol>
 *
 * <p>jcardsim runs in the same JVM as the test; numbers are <strong>not</strong> representative of
 * real silicon, which has its own clock domain and EEPROM write latencies. Use the {@code meowl
 * bench} CLI command for hardware-side numbers.
 */
@EnabledIfSystemProperty(named = "bench", matches = "true")
class BenchmarkSuite {

    private static final int WARMUP = 5;
    private static final int SAMPLES = 50;

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
    private static final byte[] DEFAULT_SEED = new byte[32]; // deterministic seed for reproducibility

    private CardSimulator simulator;
    private Session session;

    @BeforeAll
    static void registerBc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // deterministic 32-byte seed: 0x01 0x02 ... 0x20
        for (int i = 0; i < DEFAULT_SEED.length; i++) {
            DEFAULT_SEED[i] = (byte) (i + 1);
        }
    }

    @BeforeEach
    void bringUp() throws Exception {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_BYTES);
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
        session = openSession();
        // 1. Import a synthetic PKI cert and LOCK_PKI to reach PERSONALIZED state.
        byte[] cert = synthesiseCert(80);
        importCert(cert);
        sendInnerExpectOk(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);
        // 2. SETUP -> SETUP_DONE.
        sendInnerExpectOk(
                Constants.INS_SETUP, (byte) 0, (byte) 0, encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
        // 3. VERIFY_PIN inside the session.
        ResponseAPDU vp = sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN);
        if (vp.getSW() != 0x9000) {
            throw new IllegalStateException(
                    "verify PIN failed: " + Integer.toHexString(vp.getSW()));
        }
        // 4. IMPORT_SEED -> SEEDED. Inner data layout: [seedLen(1), seed(seedLen)].
        byte[] seedPayload = new byte[1 + DEFAULT_SEED.length];
        seedPayload[0] = (byte) DEFAULT_SEED.length;
        System.arraycopy(DEFAULT_SEED, 0, seedPayload, 1, DEFAULT_SEED.length);
        sendInnerExpectOk(Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, seedPayload);
    }

    private static byte[] synthesiseCert(int size) {
        byte[] cert = new byte[size];
        for (int i = 0; i < size; i++) {
            cert[i] = (byte) (i & 0xFF);
        }
        return cert;
    }

    private void importCert(byte[] cert) {
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_INIT,
                (byte) 0,
                shortBE((short) cert.length));
        int written = 0;
        while (written < cert.length) {
            int chunkLen = Math.min(Constants.PKI_CERT_CHUNK_MAX_LEN, cert.length - written);
            byte[] payload = new byte[2 + chunkLen];
            payload[0] = (byte) (written >> 8);
            payload[1] = (byte) (written & 0xFF);
            System.arraycopy(cert, written, payload, 2, chunkLen);
            sendInnerExpectOk(
                    Constants.INS_IMPORT_PKI_CERT,
                    Constants.PKI_IMPORT_P1_WRITE,
                    (byte) 0,
                    payload);
            written += chunkLen;
        }
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
    }

    private static byte[] shortBE(short value) {
        return new byte[] {(byte) (value >> 8), (byte) (value & 0xFF)};
    }

    @Test
    @DisplayName("Bench: SIGN_ECDSA_K1 (m/44'/0'/0'/0/0)")
    void benchEcdsaK1() {
        byte[] payload = signPayloadK1();
        runBench("SIGN_ECDSA_K1", () -> sendInnerExpectOk(
                Constants.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: SIGN_SCHNORR_K1 (m/86'/0'/0'/0/0)")
    void benchSchnorrK1() {
        byte[] payload = signPayloadK1();
        runBench("SIGN_SCHNORR_K1", () -> sendInnerExpectOk(
                Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: SIGN_ED25519 (m/44'/501'/0'/0')")
    void benchEd25519() {
        byte[] payload = signPayloadEd25519();
        runBench("SIGN_ED25519", () -> sendInnerExpectOk(
                Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: EXPORT_XPUB secp256k1 (m/44'/0'/0'/0/0)")
    void benchExportXpubK1() {
        byte[] payload = exportXpubPayload(Constants.CURVE_SECP256K1, new int[] {
                0x8000002C, 0x80000000, 0x80000000, 0, 0});
        runBench("EXPORT_XPUB_K1", () -> sendInnerExpectOk(
                Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: EXPORT_XPUB ed25519 (m/44'/501'/0'/0')")
    void benchExportXpubEd25519() {
        byte[] payload = exportXpubPayload(Constants.CURVE_ED25519, new int[] {
                0x8000002C, 0x800001F5, 0x80000000, 0x80000000});
        runBench("EXPORT_XPUB_ED25519", () -> sendInnerExpectOk(
                Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: OPEN_SECURE_CHANNEL (handshake only)")
    void benchOpenSc() {
        // Re-handshake on a fresh simulator each iteration to isolate handshake cost.
        runBench("OPEN_SECURE_CHANNEL", () -> {
            CardSimulator sim = new CardSimulator();
            AID aid = AIDUtil.create(APPLET_AID_BYTES);
            sim.installApplet(aid, MeowlApplet.class);
            sim.selectApplet(aid);
            simulator = sim;
            session = openSession();
        });
    }

    @FunctionalInterface
    interface Op {
        void run() throws Exception;
    }

    private static void runBench(String label, Op op) {
        try {
            for (int i = 0; i < WARMUP; i++) {
                op.run();
            }
            long[] samples = new long[SAMPLES];
            for (int i = 0; i < SAMPLES; i++) {
                long start = System.nanoTime();
                op.run();
                samples[i] = System.nanoTime() - start;
            }
            report(label, samples);
        } catch (Exception e) {
            throw new RuntimeException(label + " failed", e);
        }
    }

    private static void report(String label, long[] nanos) {
        long[] sorted = nanos.clone();
        Arrays.sort(sorted);
        long p50 = sorted[(int) (sorted.length * 0.50)];
        long p95 = sorted[(int) (sorted.length * 0.95)];
        long p99 = sorted[Math.min(sorted.length - 1, (int) (sorted.length * 0.99))];
        long min = sorted[0];
        long max = sorted[sorted.length - 1];
        double meanMs = mean(sorted) / 1_000_000.0;
        double stddevMs = stddev(sorted, mean(sorted)) / 1_000_000.0;
        System.out.printf(
                "[bench] %-22s n=%d  p50=%5.1fms  p95=%5.1fms  p99=%5.1fms  mean=%5.1fms  σ=%5.1fms"
                        + "  min=%5.1fms  max=%5.1fms%n",
                label,
                sorted.length,
                p50 / 1_000_000.0,
                p95 / 1_000_000.0,
                p99 / 1_000_000.0,
                meanMs,
                stddevMs,
                min / 1_000_000.0,
                max / 1_000_000.0);
    }

    private static double mean(long[] arr) {
        long sum = 0;
        for (long v : arr) {
            sum += v;
        }
        return sum / (double) arr.length;
    }

    private static double stddev(long[] arr, double mean) {
        double sum = 0;
        for (long v : arr) {
            double d = v - mean;
            sum += d * d;
        }
        return Math.sqrt(sum / arr.length);
    }

    private static byte[] signPayloadK1() {
        // depth(1) ‖ path(20) ‖ digest(32)  for m/44'/0'/0'/0/0
        byte[] out = new byte[1 + 20 + 32];
        out[0] = 5;
        encodeUint32BE(out, 1, 0x8000002CL);
        encodeUint32BE(out, 5, 0x80000000L);
        encodeUint32BE(out, 9, 0x80000000L);
        encodeUint32BE(out, 13, 0L);
        encodeUint32BE(out, 17, 0L);
        for (int i = 0; i < 32; i++) {
            out[21 + i] = (byte) (i ^ 0x42);
        }
        return out;
    }

    private static byte[] signPayloadEd25519() {
        // depth(1) ‖ path(16) ‖ message(32)  for m/44'/501'/0'/0'
        byte[] out = new byte[1 + 16 + 32];
        out[0] = 4;
        encodeUint32BE(out, 1, 0x8000002CL);
        encodeUint32BE(out, 5, 0x800001F5L);
        encodeUint32BE(out, 9, 0x80000000L);
        encodeUint32BE(out, 13, 0x80000000L);
        for (int i = 0; i < 32; i++) {
            out[17 + i] = (byte) (i ^ 0x73);
        }
        return out;
    }

    private static byte[] exportXpubPayload(byte curveId, int[] path) {
        // curve(1) ‖ depth(1) ‖ path(4 × depth)
        byte[] out = new byte[2 + 4 * path.length];
        out[0] = curveId;
        out[1] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            encodeUint32BE(out, 2 + 4 * i, path[i] & 0xFFFFFFFFL);
        }
        return out;
    }

    private static void encodeUint32BE(byte[] dst, int off, long val) {
        dst[off] = (byte) ((val >>> 24) & 0xFF);
        dst[off + 1] = (byte) ((val >>> 16) & 0xFF);
        dst[off + 2] = (byte) ((val >>> 8) & 0xFF);
        dst[off + 3] = (byte) (val & 0xFF);
    }
    private byte[] sendInnerExpectOk(byte ins, byte p1, byte p2, byte[] data) {
        ResponseAPDU r = sendInner(ins, p1, p2, data);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException(
                    "INS " + Integer.toHexString(ins & 0xFF) + " SW="
                            + Integer.toHexString(r.getSW()));
        }
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
        if (resp.getSW() != 0x9000) {
            throw new IllegalStateException("handshake SW=" + Integer.toHexString(resp.getSW()));
        }
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

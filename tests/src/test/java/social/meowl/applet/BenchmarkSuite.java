/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import social.meowl.applet.cardclient.CardClient;
import social.meowl.applet.cardclient.CardClientFactory;
import social.meowl.applet.testkit.HostSession;
import social.meowl.applet.testkit.MeowlFixtures;
import social.meowl.applet.testkit.TestConstants;

/**
 * Performance benchmarks for the meowl applet's signing and HD-walk paths, run against a physical
 * J3R180 over PCSC.
 *
 * <p>Tagged {@code real-card} and additionally gated on {@code -Dbench=true}, so it is excluded from
 * the default {@code :tests:test} run and only fires when explicitly requested:
 *
 * <pre>
 *   ./gradlew :tests:realCardTest --tests social.meowl.applet.BenchmarkSuite \
 *       -Dbench=true -i
 * </pre>
 *
 * <p>Each benchmark:
 *
 * <ol>
 *   <li>Brings the applet to {@code SEEDED + PIN-verified} state once per test.
 *   <li>Runs {@link #WARMUP} warm-up iterations.
 *   <li>Runs {@link #SAMPLES} iterations, recording per-call wall-clock latency.
 *   <li>Reports p50 / p95 / p99 / mean / stddev to {@code System.out}.
 * </ol>
 *
 * <p>Latencies reflect real silicon — the card's own clock domain, EC/RSA coprocessor and EEPROM
 * write costs — plus PCSC and host-side framing overhead. They are wall-clock end-to-end numbers,
 * not isolated on-card cycle counts.
 */
@EnabledIfSystemProperty(named = "bench", matches = "true")
@Tag("real-card")
class BenchmarkSuite {

    private static final int WARMUP = 5;
    private static final int SAMPLES = 50;

    private static final byte[] DEFAULT_SEED =
            new byte[32]; // deterministic seed for reproducibility

    private CardClient card;
    private HostSession session;

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

    @AfterEach
    void tearDown() {
        if (card != null) {
            try {
                MeowlFixtures.resetCard(card);
            } catch (Exception ignored) {
                // best-effort reset; the next test's @BeforeEach will surface real problems
            }
            card.close();
        }
    }

    @BeforeEach
    void bringUp() throws Exception {
        card = CardClientFactory.create(TestConstants.APPLET_AID_BYTES);
        session = MeowlFixtures.bringToSetupDoneAndVerifyPin(card);
        // IMPORT_SEED -> SEEDED. Inner data layout: [seedLen(1), seed(seedLen)].
        byte[] seedPayload = new byte[1 + DEFAULT_SEED.length];
        seedPayload[0] = (byte) DEFAULT_SEED.length;
        System.arraycopy(DEFAULT_SEED, 0, seedPayload, 1, DEFAULT_SEED.length);
        session.sendInnerExpectOk(Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, seedPayload);
    }

    @Test
    @DisplayName("Bench: SIGN_ECDSA_K1 (m/44'/0'/0'/0/0)")
    void benchEcdsaK1() {
        byte[] payload = signPayloadK1();
        runBench(
                "SIGN_ECDSA_K1",
                () ->
                        session.sendInnerExpectOk(
                                Constants.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: SIGN_SCHNORR_K1 (m/86'/0'/0'/0/0)")
    void benchSchnorrK1() {
        byte[] payload = signPayloadK1();
        runBench(
                "SIGN_SCHNORR_K1",
                () ->
                        session.sendInnerExpectOk(
                                Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: SIGN_ED25519 (m/44'/501'/0'/0')")
    void benchEd25519() {
        byte[] payload = signPayloadEd25519();
        runBench(
                "SIGN_ED25519",
                () ->
                        session.sendInnerExpectOk(
                                Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: EXPORT_XPUB secp256k1 (m/44'/0'/0'/0/0)")
    void benchExportXpubK1() {
        byte[] payload =
                exportXpubPayload(
                        Constants.CURVE_SECP256K1,
                        new int[] {0x8000002C, 0x80000000, 0x80000000, 0, 0});
        runBench(
                "EXPORT_XPUB_K1",
                () ->
                        session.sendInnerExpectOk(
                                Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: EXPORT_XPUB ed25519 (m/44'/501'/0'/0')")
    void benchExportXpubEd25519() {
        byte[] payload =
                exportXpubPayload(
                        Constants.CURVE_ED25519,
                        new int[] {0x8000002C, 0x800001F5, 0x80000000, 0x80000000});
        runBench(
                "EXPORT_XPUB_ED25519",
                () ->
                        session.sendInnerExpectOk(
                                Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, payload));
    }

    @Test
    @DisplayName("Bench: OPEN_SECURE_CHANNEL (handshake only)")
    void benchOpenSc() {
        // Re-handshake on a fresh card each iteration to isolate handshake cost.
        runBench(
                "OPEN_SECURE_CHANNEL",
                () -> {
                    if (card != null) card.close();
                    card = CardClientFactory.create(TestConstants.APPLET_AID_BYTES);
                    session = HostSession.open(card);
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
}

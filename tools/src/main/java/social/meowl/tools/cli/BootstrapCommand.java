/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.proto.SecureChannelClient;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl bootstrap} — drives a fresh card from {@code POST_INSTALL} to {@code SEEDED +
 * PIN-validated} in one shot, over a real Secure Channel.
 *
 * <ol>
 *   <li>SELECT, GET_AUTHENTIKEY, open Secure Channel.
 *   <li>{@code IMPORT_PKI_CERT} (init / write / finalize) with a synthetic {@code --cert-size} byte
 *       cert so {@code LOCK_PKI} will commit.
 *   <li>{@code LOCK_PKI} → {@code PERSONALIZED}.
 *   <li>{@code SETUP} with {@code --pin}/{@code --puk} → {@code SETUP_DONE}.
 *   <li>{@code VERIFY_PIN} so {@code IMPORT_SEED} sees an authorised session.
 *   <li>{@code IMPORT_SEED} (default: deterministic {@code 0x01 0x02 ... 0x20}; override with
 *       {@code --seed=HEX}, 16-64 bytes) → {@code SEEDED}.
 * </ol>
 *
 * <p><b>Destructive.</b> A successful {@code SETUP} burns the lifecycle transition; re-running on a
 * card past {@code POST_INSTALL} will fail. Run {@code meowl reset} or re-install the CAP first.
 * The synthetic cert is a deterministic byte ramp — developer / CI / hardware-bench tool only, NOT
 * a production provisioning path.
 */
@Command(
        name = "bootstrap",
        mixinStandardHelpOptions = true,
        description =
                "Brings a freshly-installed card to SEEDED in one shot: cert import + LOCK_PKI +"
                        + " SETUP + VERIFY_PIN + IMPORT_SEED. Developer / hardware-bench helper;"
                        + " do NOT use for production provisioning.")
public final class BootstrapCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Option(
            names = {"-p", "--pin"},
            required = true,
            paramLabel = "PIN",
            description = "User PIN to install (4-32 ASCII bytes).")
    public String pin;

    @Option(
            names = "--puk",
            required = true,
            paramLabel = "PUK",
            description = "Unblock PUK to install (4-32 ASCII bytes).")
    public String puk;

    @Option(
            names = "--seed",
            paramLabel = "HEX",
            description =
                    "Seed bytes to import as hex (16-64 bytes). Default: deterministic"
                            + " 32-byte ramp 0x01..0x20 — useful for reproducibility against"
                            + " jcardsim-based KATs.")
    public String seedHex;

    @Option(
            names = "--cert-size",
            paramLabel = "N",
            description =
                    "Synthetic cert size in bytes for the IMPORT_PKI_CERT phase (default: "
                            + "${DEFAULT-VALUE}). Must be ≥ 1 and ≤ 1024.",
            defaultValue = "80")
    public int certSize;

    /** Deterministic seed (bytes {@code 1..32}) for reproducible bootstrap provisioning. */
    private static final byte[] DEFAULT_SEED = new byte[32];

    static {
        for (int i = 0; i < DEFAULT_SEED.length; i++) {
            DEFAULT_SEED[i] = (byte) (i + 1);
        }
    }

    /** Maximum chunk size accepted by IMPORT_PKI_CERT WRITE — mirrors {@code Constants}. */
    private static final int PKI_CERT_CHUNK_MAX_LEN = 200;

    private static final byte PKI_IMPORT_P1_INIT = 0x00;
    private static final byte PKI_IMPORT_P1_WRITE = 0x01;
    private static final byte PKI_IMPORT_P1_FINALIZE = 0x02;

    @Override
    public Integer call() {
        CardTransport.run(parent.globalOptions.toReaderPreferences(), this::runOnCard);
        return 0;
    }

    private Void runOnCard(APDUBIBO bibo) throws BIBOException {
        SecureChannelClient sc = new MeowlCard(bibo, aid.bytes()).openSecureChannel();
        log("Secure Channel established.");

        // 1. IMPORT_PKI_CERT (init / write / finalize).
        importCert(sc);
        log("IMPORT_PKI_CERT: %d bytes installed.", certSize);

        // 2. LOCK_PKI → PERSONALIZED.
        sc.sendInner(MeowlInsn.LOCK_PKI.value(), 0, 0, new byte[0]);
        log("LOCK_PKI: applet now in PERSONALIZED.");

        // 3. SETUP → SETUP_DONE.
        byte[] pinBytes = pin.getBytes();
        byte[] pukBytes = puk.getBytes();
        sc.sendInner(MeowlInsn.SETUP.value(), 0, 0, encodeSetup(pinBytes, pukBytes));
        log("SETUP: PIN/PUK installed (PIN=%d B, PUK=%d B).", pinBytes.length, pukBytes.length);

        // 4. VERIFY_PIN — establishes the session-scoped PIN authorisation IMPORT_SEED needs.
        sc.sendInner(MeowlInsn.VERIFY_PIN.value(), 0, 0, pinBytes);
        log("VERIFY_PIN: authorised.");

        // 5. IMPORT_SEED → SEEDED.
        byte[] seed = resolveSeed();
        byte[] seedPayload = new byte[1 + seed.length];
        seedPayload[0] = (byte) seed.length;
        System.arraycopy(seed, 0, seedPayload, 1, seed.length);
        sc.sendInner(MeowlInsn.IMPORT_SEED.value(), 0, 0, seedPayload);
        log("IMPORT_SEED: %d-byte seed installed; lifecycle now SEEDED.", seed.length);

        log("bootstrap complete — card is ready for `meowl bench --pin %s`.", pin);
        return null;
    }

    private void importCert(SecureChannelClient sc) throws BIBOException {
        if (certSize < 1 || certSize > 1024) {
            throw new IllegalArgumentException(
                    "--cert-size must be between 1 and 1024, got " + certSize);
        }
        // INIT: declare total size (2 bytes BE).
        byte[] sizeBe = {(byte) (certSize >>> 8), (byte) (certSize & 0xFF)};
        sc.sendInner(MeowlInsn.IMPORT_PKI_CERT.value(), PKI_IMPORT_P1_INIT, 0, sizeBe);

        // WRITE: stream the deterministic ramp 0x00, 0x01, ..., (certSize - 1) & 0xFF in chunks.
        int written = 0;
        while (written < certSize) {
            int chunkLen = Math.min(PKI_CERT_CHUNK_MAX_LEN, certSize - written);
            byte[] payload = new byte[2 + chunkLen];
            payload[0] = (byte) (written >>> 8);
            payload[1] = (byte) (written & 0xFF);
            for (int i = 0; i < chunkLen; i++) {
                payload[2 + i] = (byte) ((written + i) & 0xFF);
            }
            sc.sendInner(MeowlInsn.IMPORT_PKI_CERT.value(), PKI_IMPORT_P1_WRITE, 0, payload);
            written += chunkLen;
        }

        // FINALIZE: commit the staged size.
        sc.sendInner(MeowlInsn.IMPORT_PKI_CERT.value(), PKI_IMPORT_P1_FINALIZE, 0, new byte[0]);
    }

    private byte[] resolveSeed() {
        if (seedHex == null || seedHex.isBlank()) {
            return DEFAULT_SEED.clone();
        }
        byte[] bytes;
        try {
            bytes = Hex.decode(seedHex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("--seed is not valid hex: " + e.getMessage());
        }
        if (bytes.length < 16 || bytes.length > 64) {
            throw new IllegalArgumentException("--seed must be 16-64 bytes; got " + bytes.length);
        }
        return bytes;
    }

    private static byte[] encodeSetup(byte[] pinBytes, byte[] pukBytes) {
        byte[] out = new byte[1 + pinBytes.length + 1 + pukBytes.length];
        out[0] = (byte) pinBytes.length;
        System.arraycopy(pinBytes, 0, out, 1, pinBytes.length);
        out[1 + pinBytes.length] = (byte) pukBytes.length;
        System.arraycopy(pukBytes, 0, out, 1 + pinBytes.length + 1, pukBytes.length);
        return out;
    }

    private void log(String fmt, Object... args) {
        if (parent.globalOptions.json) {
            return;
        }
        System.err.println("[bootstrap] " + String.format(fmt, args));
    }
}

/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.gp;

import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistry;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;
import social.meowl.tools.transport.CardTransport;
import social.meowl.tools.transport.ReaderPreferences;

/**
 * In-process wrapper around {@link GPSession} exposing the three card-management operations the
 * {@code meowl gp ...} subcommands need: list installed AIDs, install a CAP, uninstall an applet.
 * Speaking to the library directly (rather than forking {@code GPTool}) lets the picocli execution
 * exception handler distinguish card-I/O from protocol failures and avoids JVM-startup latency.
 *
 * <p>Every operation opens a fresh {@link GPSession}; the facade is stateless.
 */
public final class GpFacade {

    private final ReaderPreferences prefs;
    private final GPCardKeys keys;

    /**
     * @param prefs the reader/transport configuration to use; typically obtained from {@code
     *     GlobalOptions.toReaderPreferences()}
     * @param keys the GP secure-channel keys to authenticate with; pass {@link
     *     PlaintextKeys#defaultKey()} to use the well-known development key
     */
    public GpFacade(ReaderPreferences prefs, GPCardKeys keys) {
        this.prefs = prefs;
        this.keys = keys;
    }

    /** Lists every installed package, applet, and security domain on the card. */
    public InventoryReport list() {
        return CardTransport.run(
                prefs,
                bibo -> {
                    GPSession gp = openSession(bibo);
                    return inventoryOf(gp);
                });
    }

    /**
     * Returns the registry inventory plus, when the card supports the GlobalPlatform {@code GET
     * DATA FF21} ("Card Resources Information") tag, free-memory counters for the persistent and
     * transient pools. JCOP4 / J3R180 ship support for FF21; older cards may return {@code 6A88}
     * ("referenced data not found") in which case the memory block is reported absent.
     */
    public InfoReport info() {
        return CardTransport.run(
                prefs,
                bibo -> {
                    GPSession gp = openSession(bibo);
                    InventoryReport inventory = inventoryOf(gp);
                    Optional<MemoryReport> memory = queryMemory(gp);
                    return new InfoReport(inventory, memory);
                });
    }

    private static InventoryReport inventoryOf(GPSession gp) {
        GPRegistry registry = gp.getRegistry();
        List<Entry> applets = collect(registry.allApplets());
        List<Entry> packages = collect(registry.allPackages());
        List<Entry> domains = collect(registry.allDomains());
        return new InventoryReport(applets, packages, domains);
    }

    private static Optional<MemoryReport> queryMemory(GPSession gp) {
        ResponseAPDU r = gp.transmit(new CommandAPDU(0x80, 0xCA, 0xFF, 0x21, 256));
        if (r.getSW() != GPSession.SW_NO_ERROR) {
            return Optional.empty();
        }
        return MemoryReport.parse(r.getData());
    }

    /**
     * Installs a CAP file on the card with the instance AID defaulting to the CAP's declared applet
     * AID. See {@link #install(Path, Optional)}.
     */
    public InstallResult install(Path capPath) {
        return install(capPath, Optional.empty());
    }

    /**
     * Installs a CAP file on the card. The package and applet (class) AIDs come from the CAP; the
     * instance AID is {@code instanceAidOverride} when present, otherwise the CAP's declared applet
     * AID. If the package is already installed it is deleted (with dependencies) so the install
     * replaces rather than fails.
     *
     * <p>The override exists because an applet can be instantiated under an AID different from the
     * one it declares — e.g. the NDEF tag applet is instantiated under the NFC Forum Type 4
     * well-known AID {@code D2760000850101} so phones auto-discover it on tap.
     */
    public InstallResult install(Path capPath, Optional<byte[]> instanceAidOverride) {
        return CardTransport.run(
                prefs,
                bibo -> {
                    CAPFile cap;
                    try {
                        cap = CAPFile.fromFile(capPath);
                    } catch (java.io.IOException e) {
                        throw new java.io.UncheckedIOException(
                                "Cannot read CAP file " + capPath, e);
                    }

                    AID packageAid = cap.getPackageAID();
                    List<AID> appletAids = cap.getAppletAIDs();
                    if (appletAids.isEmpty()) {
                        throw new IllegalArgumentException(
                                "CAP file declares no applets: " + capPath);
                    }
                    AID classAid = appletAids.get(0);
                    AID instanceAid = instanceAidOverride.map(AID::new).orElse(classAid);

                    GPSession gp = openSession(bibo);

                    // Idempotent install: if the package is already there, remove it (with
                    // dependencies) so the install does not fail with 6985.
                    Optional<AID> existingPackage =
                            gp.getRegistry().allPackages().stream()
                                    .map(GPRegistryEntry::getAID)
                                    .filter(packageAid::equals)
                                    .findFirst();
                    if (existingPackage.isPresent()) {
                        gp.deleteAID(packageAid, true);
                    }

                    gp.loadCapFile(cap, null, pro.javacard.gp.GPData.LFDBH.SHA256);
                    gp.installAndMakeSelectable(
                            packageAid,
                            classAid,
                            instanceAid,
                            EnumSet.noneOf(GPRegistryEntry.Privilege.class),
                            new byte[0]);

                    return new InstallResult(packageAid, classAid, instanceAid);
                });
    }

    /** Removes an applet (and its package, if {@code deleteDependencies} is true) from the card. */
    public void uninstall(byte[] aidBytes, boolean deleteDependencies) {
        AID target = new AID(aidBytes);
        CardTransport.runVoid(
                prefs,
                bibo -> {
                    GPSession gp = openSession(bibo);
                    gp.deleteAID(target, deleteDependencies);
                });
    }

    private GPSession openSession(APDUBIBO bibo) {
        try {
            GPSession gp = GPSession.discover(bibo);
            gp.openSecureChannel(keys, null, null, GPSession.defaultMode);
            return gp;
        } catch (GPException e) {
            throw new GpException(e);
        }
    }

    private static List<Entry> collect(List<GPRegistryEntry> raw) {
        var out = new ArrayList<Entry>(raw.size());
        for (GPRegistryEntry entry : raw) {
            out.add(new Entry(entry.getAID().toString(), entry.getType().toString()));
        }
        return out;
    }

    /** Snapshot of the registry contents at the time of the {@link #list()} call. */
    public record InventoryReport(List<Entry> applets, List<Entry> packages, List<Entry> domains) {}

    /** A single AID + kind row inside an {@link InventoryReport}. */
    public record Entry(String aid, String kind) {}

    /** Outcome of an {@link #install(Path)} call. */
    public record InstallResult(AID packageAid, AID classAid, AID instanceAid) {}

    /** Combined inventory + free-memory snapshot returned by {@link #info()}. */
    public record InfoReport(InventoryReport inventory, Optional<MemoryReport> memory) {}

    /**
     * Free-memory counters returned by {@code GET DATA FF21} (GP 2.3 §11.3). Each field is empty if
     * the card omits the corresponding inner TLV (cards may report only a subset).
     */
    public record MemoryReport(
            OptionalLong freePersistentBytes,
            OptionalInt freeTransientResetBytes,
            OptionalInt freeTransientDeselectBytes) {

        private static final int OUTER_TAG = 0xFF21;
        private static final int TAG_PERSISTENT = 0xC0;
        private static final int TAG_TRANSIENT_RESET = 0xC1;
        private static final int TAG_TRANSIENT_DESELECT = 0xC2;

        /**
         * Parses a {@code FF21} response. Returns {@link Optional#empty()} when the blob is
         * truncated, mistyped, or otherwise unparseable so the caller can degrade gracefully
         * instead of surfacing a stack trace for a missing-feature card.
         */
        public static Optional<MemoryReport> parse(byte[] blob) {
            if (blob == null || blob.length < 4) {
                return Optional.empty();
            }
            int pos = 0;
            int tag = ((blob[pos] & 0xFF) << 8) | (blob[pos + 1] & 0xFF);
            if (tag != OUTER_TAG) {
                return Optional.empty();
            }
            pos += 2;
            int outerLen = readBerLength(blob, pos);
            if (outerLen < 0) {
                return Optional.empty();
            }
            pos += berLengthSize(blob[pos] & 0xFF);
            if (pos + outerLen > blob.length) {
                return Optional.empty();
            }
            int end = pos + outerLen;

            OptionalLong persistent = OptionalLong.empty();
            OptionalInt transientReset = OptionalInt.empty();
            OptionalInt transientDeselect = OptionalInt.empty();

            while (pos < end) {
                if (pos + 2 > end) {
                    return Optional.empty();
                }
                int innerTag = blob[pos++] & 0xFF;
                int innerLen = blob[pos++] & 0xFF;
                if (pos + innerLen > end || innerLen > 8) {
                    return Optional.empty();
                }
                long value = 0L;
                for (int i = 0; i < innerLen; i++) {
                    value = (value << 8) | (blob[pos + i] & 0xFFL);
                }
                pos += innerLen;
                switch (innerTag) {
                    case TAG_PERSISTENT -> persistent = OptionalLong.of(value);
                    case TAG_TRANSIENT_RESET -> transientReset = OptionalInt.of((int) value);
                    case TAG_TRANSIENT_DESELECT -> transientDeselect = OptionalInt.of((int) value);
                    default -> {
                        // Unknown tag inside FF21 — ignore for forward compatibility.
                    }
                }
            }
            return Optional.of(new MemoryReport(persistent, transientReset, transientDeselect));
        }

        private static int readBerLength(byte[] blob, int pos) {
            if (pos >= blob.length) return -1;
            int first = blob[pos] & 0xFF;
            if (first < 0x80) {
                return first;
            }
            if (first == 0x81) {
                return pos + 1 < blob.length ? blob[pos + 1] & 0xFF : -1;
            }
            if (first == 0x82) {
                return pos + 2 < blob.length
                        ? ((blob[pos + 1] & 0xFF) << 8) | (blob[pos + 2] & 0xFF)
                        : -1;
            }
            return -1;
        }

        private static int berLengthSize(int firstByte) {
            if (firstByte < 0x80) return 1;
            if (firstByte == 0x81) return 2;
            if (firstByte == 0x82) return 3;
            return 1;
        }
    }

    /** Wraps a checked {@link GPException} so picocli's exit-code handler can format it. */
    public static final class GpException extends RuntimeException {
        public GpException(GPException cause) {
            super(cause.getMessage(), cause);
        }
    }
}

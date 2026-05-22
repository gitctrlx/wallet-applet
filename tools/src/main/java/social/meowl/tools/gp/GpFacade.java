/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.gp;

import apdu4j.core.APDUBIBO;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import pro.javacard.capfile.AID;
import pro.javacard.capfile.CAPFile;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPRegistry;
import pro.javacard.gp.GPRegistryEntry;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.keys.PlaintextKeys;
import social.meowl.tools.core.MeowlAid;
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
                    GPRegistry registry = gp.getRegistry();
                    List<Entry> applets = collect(registry.allApplets());
                    List<Entry> packages = collect(registry.allPackages());
                    List<Entry> domains = collect(registry.allDomains());
                    return new InventoryReport(applets, packages, domains);
                });
    }

    /**
     * Installs a CAP file on the card. The package and applet AIDs come from the CAP; the instance
     * AID is {@link MeowlAid#defaultBytes}. If the package or instance is already installed it is
     * deleted (with dependencies) so the install replaces rather than fails.
     */
    public InstallResult install(Path capPath) {
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
                    AID instanceAid = new AID(MeowlAid.defaultBytes());

                    GPSession gp = openSession(bibo);

                    // Idempotent install: if either the package or the instance is already there,
                    // remove it (with dependencies) so the install does not fail with 6985.
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

    /** Wraps a checked {@link GPException} so picocli's exit-code handler can format it. */
    public static final class GpException extends RuntimeException {
        public GpException(GPException cause) {
            super(cause.getMessage(), cause);
        }
    }
}

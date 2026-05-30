/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import pro.javacard.capfile.CAPFile;
import social.meowl.tools.core.CapBreakdown;
import social.meowl.tools.gp.GpFacade;

/**
 * {@code meowl gp info} — opens an ISD Secure Channel (default GP development keys; override via
 * {@link GpKeysOption}) and renders three blocks:
 *
 * <ol>
 *   <li>Free memory counters returned by {@code GET DATA FF21} (persistent + transient pools).
 *       Quietly degraded to "unsupported" when the card omits the tag.
 *   <li>Optional CAP file size summary: pass {@code --cap PATH} to compare {@code
 *       CAPFile.getCode()} (the LOAD-stage byte count, i.e. what the package physically occupies on
 *       the card after linking) against the on-card free pool. Also breaks the ZIP wrapper into
 *       Load File components, JVM {@code .class} bytecode, and workshop metadata so the developer
 *       can see what fraction of the wrapper actually ships to the card.
 *   <li>The same applet/package/domain inventory printed by {@code meowl gp list}.
 * </ol>
 */
@Command(
        name = "info",
        mixinStandardHelpOptions = true,
        description =
                "Reports free memory (GET DATA FF21), CAP byte size, and installed applets /"
                        + " packages / domains. ISD keys default to the GP development static set;"
                        + " override with --key-master or --key-enc/--key-mac/--key-kek.")
public final class GpInfoCommand implements Callable<Integer> {

    @ParentCommand private GpCommand parent;

    @Mixin public GpKeysOption keys = new GpKeysOption();

    @Option(
            names = {"--cap"},
            description =
                    "Optional CAP file to size against the card's free memory. Reports both the ZIP"
                            + " wrapper size and the post-link Load File size (CAPFile.getCode).")
    public Path capPath;

    @Override
    public Integer call() {
        MeowlCli root = root();
        GpFacade facade = new GpFacade(root.globalOptions.toReaderPreferences(), keys.toCardKeys());
        GpFacade.InfoReport report = facade.info();
        Optional<CapInfo> cap =
                capPath != null ? Optional.of(CapInfo.measure(capPath)) : Optional.empty();

        if (root.globalOptions.json) {
            renderJson(report, cap);
        } else {
            renderText(report, cap);
        }
        return 0;
    }

    private MeowlCli root() {
        return (MeowlCli) parent.spec.commandLine().getParent().getCommand();
    }

    private static void renderText(GpFacade.InfoReport report, Optional<CapInfo> cap) {
        System.out.println("Card memory:");
        if (report.memory().isEmpty()) {
            System.out.println("  (card does not expose GET DATA FF21)");
        } else {
            GpFacade.MemoryReport memory = report.memory().get();
            renderMemoryLine("Free persistent (EEPROM)", memory.freePersistentBytes());
            renderMemoryLineInt("Free transient CLEAR_ON_RESET", memory.freeTransientResetBytes());
            renderMemoryLineInt(
                    "Free transient CLEAR_ON_DESELECT", memory.freeTransientDeselectBytes());
        }

        cap.ifPresent(c -> renderCap(c, report.memory()));

        System.out.println();
        renderSection("Applets", report.inventory().applets());
        renderSection("Packages", report.inventory().packages());
        renderSection("Domains", report.inventory().domains());
    }

    private static void renderMemoryLine(String label, OptionalLong value) {
        System.out.printf(
                "  %-34s %s%n",
                label + ":", value.isPresent() ? formatBytes(value.getAsLong()) : "(absent)");
    }

    private static void renderMemoryLineInt(String label, OptionalInt value) {
        System.out.printf(
                "  %-34s %s%n",
                label + ":", value.isPresent() ? formatBytes(value.getAsInt()) : "(absent)");
    }

    private static void renderSection(String label, List<GpFacade.Entry> entries) {
        System.out.println(label + ":");
        if (entries.isEmpty()) {
            System.out.println("  (none)");
            return;
        }
        for (GpFacade.Entry e : entries) {
            System.out.printf("  %-20s %s%n", e.kind(), e.aid());
        }
    }

    private static void renderCap(CapInfo c, Optional<GpFacade.MemoryReport> memory) {
        CapBreakdown b = c.breakdown();
        System.out.println();
        System.out.println("CAP file: " + c.path());
        System.out.printf("  Wrapper (ZIP) size:           %s%n", formatBytes(b.zipBytes()));
        System.out.printf("  Load File size (on-card):     %s%n", formatBytes(c.loadFileBytes()));
        System.out.println("  Package: " + c.packageAid());
        if (!c.appletAids().isEmpty()) {
            System.out.println("  Applet AIDs:");
            for (String aid : c.appletAids()) {
                System.out.println("    " + aid);
            }
        }
        memory.flatMap(m -> optionalLongToObject(m.freePersistentBytes()))
                .ifPresent(
                        free -> {
                            long after = free - c.loadFileBytes();
                            System.out.printf(
                                    "  Free persistent after install: %s%n",
                                    after >= 0
                                            ? formatBytes(after)
                                            : "(insufficient by " + formatBytes(-after) + ")");
                        });

        System.out.println();
        System.out.println("CAP wrapper breakdown (what is in the ZIP, what reaches the card):");
        renderBreakdownLine("On-card components (*.cap)", b.componentsBytes(), b.zipBytes());
        renderBreakdownLine("JVM .class bytecode (not on-card)", b.classBytes(), b.zipBytes());
        renderBreakdownLine("Manifest / EXP / loader hints", b.otherBytes(), b.zipBytes());

        if (!b.components().isEmpty()) {
            System.out.println();
            System.out.println("Load File components (descending size):");
            for (CapBreakdown.Component comp : b.components()) {
                System.out.printf("  %-18s %s%n", comp.name() + ".cap", formatBytes(comp.bytes()));
            }
        }
    }

    private static void renderBreakdownLine(String label, long bytes, long total) {
        double pct = total > 0 ? 100.0 * bytes / total : 0.0;
        System.out.printf(
                Locale.ROOT, "  %-34s %,10d B (%5.1f%% of wrapper)%n", label + ":", bytes, pct);
    }

    private static String formatBytes(long bytes) {
        double kib = bytes / 1024.0;
        return String.format(Locale.ROOT, "%,d B (~%.1f KiB)", bytes, kib);
    }

    private static void renderJson(GpFacade.InfoReport report, Optional<CapInfo> cap) {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> mem = new LinkedHashMap<>();
        if (report.memory().isPresent()) {
            GpFacade.MemoryReport memory = report.memory().get();
            mem.put("supported", true);
            mem.put(
                    "free_persistent_bytes",
                    memory.freePersistentBytes().isPresent()
                            ? memory.freePersistentBytes().getAsLong()
                            : null);
            mem.put(
                    "free_transient_reset_bytes",
                    memory.freeTransientResetBytes().isPresent()
                            ? memory.freeTransientResetBytes().getAsInt()
                            : null);
            mem.put(
                    "free_transient_deselect_bytes",
                    memory.freeTransientDeselectBytes().isPresent()
                            ? memory.freeTransientDeselectBytes().getAsInt()
                            : null);
        } else {
            mem.put("supported", false);
        }
        root.put("memory", mem);
        cap.ifPresent(c -> root.put("cap", capJson(c)));
        root.put("applets", report.inventory().applets());
        root.put("packages", report.inventory().packages());
        root.put("domains", report.inventory().domains());
        JsonOutput.write(System.out, root);
    }

    private static Optional<Long> optionalLongToObject(OptionalLong opt) {
        return opt.isPresent() ? Optional.of(opt.getAsLong()) : Optional.empty();
    }

    private static Map<String, Object> capJson(CapInfo c) {
        CapBreakdown b = c.breakdown();
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("path", c.path());
        root.put("zip_bytes", b.zipBytes());
        root.put("load_file_bytes", c.loadFileBytes());
        root.put("package_aid", c.packageAid());
        root.put("applet_aids", c.appletAids());
        Map<String, Object> breakdown = new LinkedHashMap<>();
        breakdown.put("on_card_components_bytes", b.componentsBytes());
        breakdown.put("class_bytecode_bytes", b.classBytes());
        breakdown.put("manifest_and_exp_bytes", b.otherBytes());
        List<Map<String, Object>> comps = new ArrayList<>(b.components().size());
        for (CapBreakdown.Component comp : b.components()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", comp.name());
            entry.put("bytes", comp.bytes());
            comps.add(entry);
        }
        breakdown.put("components", comps);
        root.put("breakdown", breakdown);
        return root;
    }

    private record CapInfo(
            String path,
            long loadFileBytes,
            String packageAid,
            List<String> appletAids,
            CapBreakdown breakdown) {

        static CapInfo measure(Path path) {
            CAPFile cap;
            try {
                cap = CAPFile.fromFile(path);
            } catch (IOException e) {
                throw new UncheckedIOException("Cannot read CAP file " + path, e);
            }
            byte[] code = cap.getCode();
            String pkg = cap.getPackageAID().toString();
            List<String> applets = cap.getAppletAIDs().stream().map(Object::toString).toList();
            CapBreakdown breakdown = CapBreakdown.read(path);
            return new CapInfo(path.toString(), code.length, pkg, applets, breakdown);
        }
    }
}

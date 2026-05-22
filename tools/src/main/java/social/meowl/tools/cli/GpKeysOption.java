/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.keys.PlaintextKeys;
import social.meowl.tools.core.Hex;

/**
 * Picocli mixin contributing the GlobalPlatform ISD authentication keys to {@code meowl gp}.
 *
 * <p>Three modes:
 *
 * <ul>
 *   <li><b>None</b> — well-known development static keys ({@code 40 41 ... 4F}).
 *   <li><b>{@code --key-master HEX}</b> — 16-byte master key; library applies default GP-CPS
 *       per-card diversification.
 *   <li><b>{@code --key-enc HEX --key-mac HEX --key-kek HEX}</b> — pre-diversified ENC / MAC / KEK
 *       triple, used when the vendor ships per-card derived keys.
 * </ul>
 *
 * <p>The two non-default modes are mutually exclusive; mixing them or supplying a partial triple
 * raises {@link ParameterException}.
 *
 * <p><b>Security:</b> the development default and most factory-default keys are publicly known.
 * Production deployments MUST replace the ISD keys via {@code PUT KEY} before loading sensitive
 * applets (see {@code tools/README.md §Production hardening}).
 */
public final class GpKeysOption {

    /** Expected byte length for an SCP02/SCP03 ISD key component. */
    private static final int KEY_LEN = 16;

    @Spec(Spec.Target.MIXEE)
    private CommandSpec mixee;

    @Option(
            names = "--key-master",
            paramLabel = "HEX",
            description =
                    "16-byte ISD master key (hex). Library applies default per-card"
                            + " diversification. Mutually exclusive with"
                            + " --key-enc/--key-mac/--key-kek.")
    public String masterHex;

    @Option(
            names = "--key-enc",
            paramLabel = "HEX",
            description =
                    "16-byte ISD ENC key (hex). Use together with --key-mac and --key-kek when the"
                            + " vendor supplies a pre-diversified triple.")
    public String encHex;

    @Option(
            names = "--key-mac",
            paramLabel = "HEX",
            description = "16-byte ISD MAC key (hex). See --key-enc.")
    public String macHex;

    @Option(
            names = "--key-kek",
            paramLabel = "HEX",
            description = "16-byte ISD KEK (hex). See --key-enc.")
    public String kekHex;

    /**
     * Resolves the parsed options into a {@link GPCardKeys} the {@code GpFacade} can authenticate
     * with. Throws {@link ParameterException} on invalid combinations or malformed hex so picocli
     * surfaces the diagnostic with the canonical usage banner.
     */
    public GPCardKeys toCardKeys() {
        boolean hasMaster = masterHex != null && !masterHex.isBlank();
        boolean hasEnc = encHex != null && !encHex.isBlank();
        boolean hasMac = macHex != null && !macHex.isBlank();
        boolean hasKek = kekHex != null && !kekHex.isBlank();
        boolean hasAnyTriple = hasEnc || hasMac || hasKek;

        if (hasMaster && hasAnyTriple) {
            throw fail(
                    "--key-master is mutually exclusive with --key-enc/--key-mac/--key-kek;"
                            + " pick exactly one mode.");
        }
        if (hasMaster) {
            return PlaintextKeys.fromMasterKey(decodeKey(masterHex, "--key-master"));
        }
        if (hasAnyTriple) {
            if (!(hasEnc && hasMac && hasKek)) {
                throw fail(
                        "--key-enc, --key-mac and --key-kek must all be supplied together"
                                + " (received: enc="
                                + hasEnc
                                + ", mac="
                                + hasMac
                                + ", kek="
                                + hasKek
                                + ").");
            }
            return PlaintextKeys.fromKeys(
                    decodeKey(encHex, "--key-enc"),
                    decodeKey(macHex, "--key-mac"),
                    decodeKey(kekHex, "--key-kek"));
        }
        // No key options provided — fall back to the GP development default 40..4F.
        return PlaintextKeys.defaultKey();
    }

    private byte[] decodeKey(String hex, String optionName) {
        byte[] bytes;
        try {
            bytes = Hex.decode(hex);
        } catch (IllegalArgumentException e) {
            throw fail(optionName + " is not valid hex: " + e.getMessage());
        }
        if (bytes.length != KEY_LEN) {
            throw fail(
                    optionName
                            + " must be exactly "
                            + KEY_LEN
                            + " bytes ("
                            + (KEY_LEN * 2)
                            + " hex chars); got "
                            + bytes.length
                            + " bytes.");
        }
        return bytes;
    }

    private ParameterException fail(String message) {
        // mixee may be null in unit tests that instantiate the option without a CommandLine;
        // fall back to a plain IllegalArgumentException in that case so the assertion is still
        // observable.
        if (mixee == null) {
            throw new IllegalArgumentException(message);
        }
        return new ParameterException(mixee.commandLine(), message);
    }
}

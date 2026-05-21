/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import picocli.CommandLine.Option;
import social.meowl.tools.core.MeowlAid;

/**
 * Picocli mixin contributing a {@code --aid} option to subcommands that need to SELECT an applet.
 *
 * <p>The option defaults to the {@link MeowlAid#DEFAULT_HEX} applet AID; users override it when
 * targeting a card that has a different instance AID provisioned (e.g. multiple meowl applets on a
 * single card).
 */
public final class AidOption {

    @Option(
            names = "--aid",
            paramLabel = "HEX",
            description = "Applet AID to SELECT, hexadecimal (default: ${DEFAULT-VALUE}).",
            defaultValue = MeowlAid.DEFAULT_HEX)
    public String aid = MeowlAid.DEFAULT_HEX;

    /** Returns the parsed AID bytes; throws {@link IllegalArgumentException} for invalid input. */
    public byte[] bytes() {
        return MeowlAid.parse(aid);
    }
}

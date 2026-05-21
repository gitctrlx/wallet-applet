/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools;

import social.meowl.tools.cli.MeowlCli;

/**
 * Entry-point for the {@code meowl} host-side CLI.
 *
 * <p>The class is deliberately a one-liner so that startup latency is dominated by picocli's lazy
 * command-tree initialisation rather than any business logic. All command behaviour lives in {@code
 * social.meowl.tools.cli.MeowlCli} and its subcommand siblings.
 */
public final class Main {

    private Main() {}

    public static void main(String[] args) {
        System.exit(MeowlCli.commandLine().execute(args));
    }
}

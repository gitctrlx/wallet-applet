/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools;

import picocli.CommandLine;

/**
 * Entry-point for the {@code meowl} host-side CLI.
 *
 * <p>This class is intentionally minimal: it exists so the {@code application} plugin can wire up a
 * launcher script while the picocli command tree (see {@code social.meowl.tools.cli.MeowlCli}) is
 * still being phased in. As subcommands land in subsequent phases this file becomes a one-liner
 * that simply delegates to the {@code MeowlCli} root.
 */
public final class Main {

    private Main() {}

    public static void main(String[] args) {
        // Phase 2 will replace this body with `new CommandLine(new MeowlCli()).execute(args)` once
        // the root command and global mixins land. Until then keep the launcher exit-code stable
        // so packagers that smoke-test `meowl --help` get a deterministic response.
        CommandLine.usage(new RootStub(), System.out);
        System.exit(args.length == 0 ? 0 : CommandLine.ExitCode.USAGE);
    }

    @CommandLine.Command(
            name = "meowl",
            mixinStandardHelpOptions = true,
            description =
                    "meowl-applet host-side CLI (scaffolding — full command tree lands in Phase 2)")
    private static final class RootStub {}
}

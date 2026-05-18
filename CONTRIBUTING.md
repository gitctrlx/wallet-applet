# Contributing to meowl-applet

Thanks for your interest! This repo holds the JavaCard applet powering the
meowl.social hardware wallet. Because it ends up on a tamper-resistant chip
running custodial keys, contributions are reviewed strictly.

## Quick start

```bash
git clone --recurse-submodules https://github.com/qntx/meowl-applet.git
cd meowl-applet
./gradlew spotlessCheck :applet:buildCap :tests:test
```

Requires **JDK 25** on `PATH` (Temurin 25 LTS — Gradle auto-provisions if missing).

## Workflow

1. Open an issue first for non-trivial changes.
2. Branch from `main`: `git checkout -b feat/<topic>` or `fix/<topic>`.
3. Make your change. Keep diffs focused.
4. Run the full local pipeline:

   ```bash
   ./gradlew spotlessApply :applet:buildCap :tests:test
   ```

5. Commit using **Conventional Commits** (English):

   ```text
   feat(applet): add PIN unblock flow
   fix(tests): correct expected SW for unknown CLA
   docs: explain target SDK choice
   ```

6. Open a PR against `main`. CI must pass.

## Coding rules

- **Java source compat: 1.8** for `applet/` (JCDK v26.0 converter limit). Use `var` only in `tools/` and `tests/`.
- **No `String` in applet code paths** — concatenation allocates and JC has no GC.
- **No floating point**, **no multi-dim arrays**, **no threading**.
- Sensitive data lives in `JCSystem.makeTransientByteArray(...)` and is wiped
  after use.
- Run **Spotless** (`./gradlew spotlessApply`) before pushing; CI rejects unformatted code.

## Adding new APDUs

1. Reserve an `INS` constant in `MeowlApplet`.
2. Add a private handler and dispatch in `process(...)`.
3. Add a JCardSim test under `tests/` exercising both success and the
   relevant failure SWs.
4. Document the APDU in `docs/protocol.md` (create if missing).

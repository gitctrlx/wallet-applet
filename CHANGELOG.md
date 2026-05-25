# Changelog

All notable changes to `meowl-applet` are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning 2.0.0](https://semver.org/) with the additional convention
that any change to a MEAP wire format is a major-version bump.

## [Unreleased]

### Added

- **Q2-2026 refactor scaffolding (in flight).** ADR framework under
  [`docs/adr/`](docs/adr/), placeholder `:shared` Gradle module for
  cross-module protocol constants, jqwik / spotbugs / OWASP
  Dependency-Check version pins, and SHA-pinned GitHub Actions across CI
  and release workflows. See
  [`docs/audit/2026-05-25-comprehensive-audit-v2-supplement.md`](docs/audit/2026-05-25-comprehensive-audit-v2-supplement.md)
  and `comprehensive-refactor-de728f.md` for the full plan.
- **`testkit` test package.** Common host-side helpers (`HostSession`,
  `TestConstants`, …) now live under
  `tests/src/test/java/social/meowl/applet/testkit/`, owning the card
  lifecycle (handshake, PIN, lifecycle advance) so individual `@Test`
  methods stay focused on the under-test invariant. Closes the
  duplicated-fixture drift surfaced in commit `c0150b1`.
- **`:tools:realCardTest` Gradle task.** `SecureChannelClientIT` now
  connects to a PCSC-attached J3R180 (selected with `-Preader=NAME`),
  mirroring `:tests:realCardTest`. The simulator backend was retired in
  this release window; the fixture issues `Card.disconnect(true)` between
  tests so `CLEAR_ON_RESET` state cannot bleed across `@Test` methods.
- **`:tests:realCardTest` Gradle task.** A second test track that runs the
  `@Tag("real-card")` suites against a physical J3R180 over PCSC, driven
  by the `CardClient` abstraction (`RealCardClient`). Suites covered:
  `MeowlAppletTest`, `SecureChannelTest`, `SchnorrK1Test`, `EcdsaK1Test`,
  `Ed25519SigningTest`, `HdDerivationTest`, `PersonalisationTest`,
  `BenchmarkSuite`.
- **AES-CMAC-128 KBKDF (`Kdf` class).** Replaces `Hkdf` for the Secure
  Channel key schedule. Extract uses `SHA-256(salt)[0..16)` as the AES-CMAC
  key over the ECDH x-coordinate; Expand iterates AES-CMAC-128 in NIST
  SP 800-108 feedback mode until 64 bytes of OKM are produced. Documented
  in [`ADR-002`](docs/adr/ADR-002-secure-channel-aes-cmac-kdf.md).
- **Host SDK mirrors.** `KdfCmac` (`tools/`) and `KdfCmacHost` (`tests/`)
  are byte-identical to the applet KBKDF and act as the canonical
  reference for host SDK authors.
- **`HostCrypto.aesCmac128`.** Host-side AES-CMAC-128 helper backed by
  BouncyCastle's `AESCMAC` MAC engine.

### Changed

- **`RESET_TO_FACTORY` shrunk to fit contactless BWT.** Logical wipe of
  bookkeeping flags only (`MasterSeed.seedLen`, `PinManager.provisioned`,
  `PkiManager.importedLen`, `LifecycleState.UNINITIALIZED`); the bulk
  EEPROM scrub is dropped because the next provisioning command
  re-paints the affected cells. Trade-off and threat model captured in
  [`ADR-001`](docs/adr/ADR-001-reset-to-factory-no-eeprom-wipe.md). Closes
  the J3R180 OwnerPIN-after-wipe quirk and keeps the reset transaction
  inside the ISO/IEC 14443-4 BWT envelope on contactless.
- **`MEAP-2` cipher suite migrated from HMAC-SHA-256 to AES-CMAC-128.** The
  Secure Channel record-layer MAC is now `AES-CMAC-128(K_mac, …)` and the
  KDF is the AES-CMAC-128 KBKDF described above. Output-keying-material
  drops from 80 bytes to 64 bytes (`K_enc(32) ‖ K_mac(16) ‖ IV_base(16)`)
  to match the new MAC's native 128-bit key width. The wire envelope
  shape (`[CLA INS P1 P2 LC] ‖ IV(16) ‖ ciphertext ‖ MAC(16)`) is
  unchanged; only the bytes computed for the MAC field differ. See
  [`docs/specs/meap-2.md`](docs/specs/meap-2.md) for the full spec.
- **`HmacSha` collapsed into `HmacSha512`.** The dual-algorithm RFC 2104
  software engine is now SHA-512-only — its sole consumers (`MasterSeed`,
  `Bip32`, `Slip10`) all need 64-byte tags. Block size and hash size are
  compile-time constants (`BLOCK_LEN = 128`, `HASH_LEN = 64`) instead of
  constructor-assigned fields.
- **`SecureChannelClientIT` is real-card only.** The dual-mode
  `cardBackend=simulator|real` plumbing was retired: post-Phase-1 the
  simulator could not run any crypto-bearing test, and pretending to
  support it was a net source of confusion. Tagged `real-card` so it is
  excluded from the default `:tools:test`.
- **Constants.** `SC_KEY_LEN` split into `SC_ENC_KEY_LEN = 32` and
  `SC_MAC_KEY_LEN = 16`. `CAP_SC_CBC_HMAC` keeps its name for
  backwards-compatible host capability parsing; the bit now advertises
  AES-CMAC-128 instead of HMAC-SHA-256.

### Removed

- **Four jcardsim-bound test suites.** `ResetToFactoryTest`,
  `Wei25519Test` (full coverage moved to real-card paths in
  `Ed25519SigningTest` / `MeowlAppletTest`), `LifecycleStateTest.Stateful`
  nested class, and `Fp25519Test.Multiplicative.inv` — each was
  dead-by-design after Phase-1 because jcardsim cannot model the prime
  modulus that `Fp25519Inv` loads or the transient EC keys that
  `Wei25519` needs. The remaining `LifecycleStateTest.IsLegalForward`
  covers the pure FSM rule.
- **`Hkdf`, `HkdfSha256`, `HkdfSha256Test`.** Replaced wholesale by the
  AES-CMAC-128 KBKDF.
- **`HmacSha.ALG_SHA_256` + supporting code.** Production never
  instantiated the SHA-256 path after the SC MAC redesign; the dual-alg
  switch + 64-byte block buffer + RFC 4231 SHA-256 vectors are gone.
- **`HostCrypto.hmacSha256Truncated`.** No remaining caller; superseded
  by `aesCmac128`.
- **`SimulatorCardClient` and the `cardBackend=simulator` mode of
  `SecureChannelClientIT`.** The simulator could not run any
  crypto-bearing test after Phase-1; the dead branch was removed.
- **`tools/build.gradle.kts` `useSimulator` / `cardBackend` plumbing.** No
  remaining consumer; the Gradle task hard-pins `cardBackend=real`.
- **Workspace residue `realcard.log`.** Stray 335 KiB log captured during
  manual reader probing was not gitignored (it now is) and has been
  removed from the working tree.

### Performance

- **CAP size**: 115,324 bytes (was 128,452 bytes baseline = **−13,128
  bytes / −10.22 %**). The bulk of the saving comes from removing the
  HMAC-SHA-256 + HKDF surface (`HmacSha` SHA-256 case + `Hkdf` class +
  helper truncation); a smaller fraction is the `HmacSha512` simplification.

### Security

- **MAC algorithm.** AES-CMAC-128 has 128-bit forgery resistance, matching
  the prior 16-byte truncated HMAC-SHA-256 exactly. The change is
  security-neutral, motivated by silicon fit (J3R180 native CMAC) and CAP
  footprint.
- **MEAP-2 wire format.** **BREAKING CHANGE for any external host SDK.**
  Hosts that previously implemented the Secure Channel against HMAC-SHA-256
  with HKDF-SHA-256 will need to upgrade to AES-CMAC-128 with the KBKDF
  described in `docs/specs/meap-2.md`. The `meowl-sc-v1` HKDF/KBKDF info
  label is re-used (it now refers to the new construction); a future Secure
  Channel revision MUST allocate a fresh label.

### Verification status

- **Verified — simulator.** `:applet:buildCap`, `:applet:test`,
  `:tools:test`, `:tests:test` and `spotlessCheck` all green on every
  commit in this release window.
- **Verified — real card (J3R180 + ACR1552U-MF).** Byte-level KDF and
  MAC correctness pinned end-to-end against physical silicon:
  - `:tests:realCardTest --tests SecureChannelTest`: 13/13 passing
    (5.77 s). Covers handshake (ECDH + KBKDF + ECDSA signature) and
    envelope round-trip (encrypt, AES-CMAC-128 MAC, IV monotonicity,
    replay defense); MAC bytes match `KdfCmacHost` byte-for-byte.
  - `:tools:realCardTest`: 7/7 passing (2.81 s). Covers
    `SecureChannelClient` MEAP-2 host implementation against the same
    physical card (handshake, oversize rejection, wrong-authentikey
    detection, two-envelope round-trip, session invalidation).
- **Pending — hosted CI.** Real-card verification still gates on a
  manual run against an ACR1552 + J3R180 pairing until a card-attached
  runner is provisioned.

[Unreleased]: https://github.com/qntx/meowl-applet/commits/main

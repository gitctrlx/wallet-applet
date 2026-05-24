# Changelog

All notable changes to `meowl-applet` are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning 2.0.0](https://semver.org/) with the additional convention
that any change to a MEAP wire format is a major-version bump.

## [Unreleased]

### Added

- **`:tools:realCardTest` Gradle task.** `SecureChannelClientIT` now accepts
  `-DcardBackend=real -DcardReader=NAME` and connects to a PCSC-attached
  J3R180 instead of jcardsim, mirroring the `:tests:realCardTest`
  infrastructure. The fixture issues `Card.disconnect(true)` between tests so
  `CLEAR_ON_RESET` state cannot bleed across `@Test` methods.
- **`:tests:realCardTest` Gradle task.** A second test track that runs the
  `@Tag("real-card")` suites against a physical J3R180 over PCSC, driven by
  the new `CardClient` abstraction (`SimulatorCardClient`,
  `RealCardClient`). Suites covered: `MeowlAppletTest`, `SecureChannelTest`,
  `SchnorrK1Test`, `EcdsaK1Test`, `Ed25519SigningTest`, `HdDerivationTest`,
  `PersonalisationTest`, `ResetToFactoryTest`, `Wei25519Test`,
  `BenchmarkSuite`, `LifecycleStateTest.Stateful` and
  `Fp25519Test.Multiplicative.inv`.
- **AES-CMAC-128 KBKDF (`Kdf` class).** Replaces `Hkdf` for the Secure
  Channel key schedule. Extract uses `SHA-256(salt)[0..16)` as the AES-CMAC
  key over the ECDH x-coordinate; Expand iterates AES-CMAC-128 in NIST
  SP 800-108 feedback mode until 64 bytes of OKM are produced.
- **Host SDK mirrors.** New `KdfCmac` (`tools/`) and `KdfCmacHost`
  (`tests/`) classes, byte-identical to the applet KBKDF, are the canonical
  reference for host SDK authors.
- **`HostCrypto.aesCmac128`.** Host-side AES-CMAC-128 helper backed by
  BouncyCastle's `AESCMAC` MAC engine.

### Changed

- **`MEAP-2` cipher suite migrated from HMAC-SHA-256 to AES-CMAC-128.** The
  Secure Channel record-layer MAC is now `AES-CMAC-128(K_mac, …)` and the
  KDF is the AES-CMAC-128 KBKDF described above. Output-keying-material
  drops from 80 bytes to 64 bytes (`K_enc(32) ‖ K_mac(16) ‖ IV_base(16)`)
  to match the new MAC's native 128-bit key width. The wire envelope shape
  (`[CLA INS P1 P2 LC] ‖ IV(16) ‖ ciphertext ‖ MAC(16)`) is unchanged; only
  the bytes computed for the MAC field differ. See `docs/specs/meap-2.md`
  for the full specification update.
- **`HmacSha` collapsed into `HmacSha512`.** The dual-algorithm
  RFC 2104 software engine is now SHA-512-only — its sole consumers
  (`MasterSeed`, `Bip32`, `Slip10`) all need 64-byte tags. Block size and
  hash size are compile-time constants (`BLOCK_LEN = 128`,
  `HASH_LEN = 64`) instead of constructor-assigned fields.
- **`SecureChannelClientIT` is now backend-agnostic.** Drives jcardsim or
  PCSC depending on `cardBackend` system property. Tagged
  `real-card` so it is excluded from the default `:tools:test`.
- **Constants.** `SC_KEY_LEN` split into `SC_ENC_KEY_LEN = 32` and
  `SC_MAC_KEY_LEN = 16`. `CAP_SC_CBC_HMAC` keeps its name for
  backwards-compatible host capability parsing; the bit now advertises
  AES-CMAC-128 instead of HMAC-SHA-256.

### Removed

- **`Hkdf`, `HkdfSha256`, `HkdfSha256Test`.** Replaced wholesale by the
  AES-CMAC-128 KBKDF.
- **`HmacSha.ALG_SHA_256` + supporting code.** Production never
  instantiated the SHA-256 path after the SC MAC redesign; the dual-alg
  switch + 64-byte block buffer + RFC 4231 SHA-256 vectors are gone.
- **`HostCrypto.hmacSha256Truncated`.** No remaining caller; superseded by
  `aesCmac128`.

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
  + HKDF-SHA-256 will need to upgrade to AES-CMAC-128 + the KBKDF described
  in `docs/specs/meap-2.md`. The `meowl-sc-v1` HKDF/KBKDF info label is
  re-used (it now refers to the new construction); a future Secure Channel
  revision MUST allocate a fresh label.

### Verification status

- ✅ `:applet:buildCap`, `:applet:test`, `:tools:test`, `:tests:test`,
  `spotlessCheck` all green on every commit in this release window.
- ⏳ Byte-level KDF / MAC pinning against a physical J3R180 is captured by
  `:tests:realCardTest` and `:tools:realCardTest` but is not yet wired
  into hosted CI; production releases gate on a manual run against an
  ACR1552 + J3R180 pairing until a card-attached runner is provisioned.

[Unreleased]: https://github.com/qntx/meowl-applet/commits/main

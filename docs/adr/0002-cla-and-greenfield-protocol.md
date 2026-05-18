# ADR-0002: CLA = `0x80` and greenfield wire protocol

Date: 2026-05-18

## Status

Accepted

## Context

The Satochip applet (and many older JavaCard wallets that descend from the MUSCLE / Cryptoflex lineage) uses `CLA = 0xB0`. This is a historical artifact: MUSCLE chose `0xB0` so its commands wouldn't collide with the ISO 7816-4 standard CLA values used by the underlying card OS. Today, the JavaCard runtime fully isolates applets, so the historical reason no longer applies.

Inheriting `CLA = 0xB0` would buy compatibility with the existing Satochip client ecosystem (`pysatochip`, Electrum-Satochip, `Satochip-Java`, `SatochipSwift`). It would also lock us into Satochip's INS layout, its HMAC-SHA160 Secure Channel MAC, and its AES-128 session key — none of which meets a 2026 minimum bar.

## Decision

- **CLA = `0x80`** — the lowest ISO 7816-4 private-class CLA byte. Reserved for applet-private command sets.
- The wire protocol is **greenfield**, owing nothing to MUSCLE or Satochip beyond inspiration:
  - INS numbers are allocated in semantic bands (lifecycle / channel / auth / PKI / seed / sign / utility).
  - Error codes use ISO 7816-4 standard values where one exists (`6700`, `6982`, `6985`, `6D00`, `6E00`, `6F00`), with applet-private codes in the `6Fxx` range for everything else.
  - The Secure Channel uses modern primitives (see [ADR-0004](./0004-secure-channel-cipher-suite.md)) and is not wire-compatible with Satochip's.
- All non-public APDUs MUST be wrapped in a Secure Channel envelope. Three APDUs are exempt: `GET_INFO`, `INIT_SECURE_CHANNEL`, `RESET_TO_FACTORY`.

## Consequences

### Positive

- The wire format is free of legacy: no MUSCLE multi-PIN slots, no `KEY_TYPE` / `KEY_ACL` ceremony, no deprecated `PARSE_TRANSACTION` flow.
- Modern security primitives are not held back by backward-compatibility constraints.
- The error and status code namespace is clean and follows ISO 7816-4 conventions, which any third-party auditor or smartcard library can decode.

### Negative

- Existing Satochip clients cannot drive a meowl card. We must ship our own host SDK (bootstrapped in `tools/`).
- Cross-referencing the Satochip protocol documentation no longer applies one-to-one; client developers must read the meowl protocol spec.

### Neutral

- Future meowl protocol revisions can use ISO 7816-4 logical channels on `CLA` low nibble freely.

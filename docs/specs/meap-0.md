---
meap: 0
title: MEAP process and template
status: Final
type: Process
created: 2026-05-19
author: meowl.social contributors
---

# MEAP-0: MEAP process and template

## Abstract

This MEAP defines the format, numbering, lifecycle and contribution workflow of the **Meowl Applet Proposal** (MEAP) set itself. It is a process document; it imposes no on-wire requirement on the applet or its host SDKs. Subsequent MEAPs (MEAP-1 onward) are normative protocol specifications and are written in the format laid out here.

## Motivation

Hardware-wallet protocols deserve the same editorial discipline that BIP, EIP and SLIP brought to their respective ecosystems. ADRs are a good vehicle for *internal* engineering decisions but a poor vehicle for *external* normative contracts because they read as historical narrative rather than prescriptive specification. MEAPs separate the two concerns:

- An MEAP says **"the wire shall do X"** in normative language with explicit status, test vectors and a reference implementation pointer.
- A repository commit log and code review record (the equivalent of a former ADR) says **"we considered X and Y, picked X for these reasons"**.

This separation lets implementers consume the wire contract without wading through design history, and lets contributors record design history without polluting the wire contract.

## Specification

### Header

Every MEAP MUST begin with a YAML preamble delimited by `---` lines. The preamble keys are:

| Key | Required | Type | Allowed values |
| --- | --- | --- | --- |
| `meap` | yes | integer ≥ 0 | The MEAP number. Numbers are allocated densely in submission order and are never re-used. |
| `title` | yes | short string | A descriptive title, written as a noun phrase, max 70 characters. |
| `status` | yes | enum | One of: `Idea`, `Draft`, `Last Call`, `Final`, `Stagnant`, `Withdrawn`, `Superseded`. |
| `type` | yes | enum | One of: `Standards Track`, `Informational`, `Process`. |
| `category` | conditional | enum | REQUIRED iff `type = Standards Track`. One of: `Wire`, `Crypto`, `Process`. |
| `created` | yes | ISO 8601 date | The date the MEAP was first opened as a draft. Never updated thereafter. |
| `updated` | optional | ISO 8601 date | The date of the most recent substantive amendment. SHOULD be added on every Last Call → Final transition. |
| `requires` | optional | list of integers | MEAPs that must be read first to make sense of this one. |
| `replaces` | optional | list of integers | MEAPs that this one supersedes. Set only when `status = Final`. |
| `superseded-by` | optional | integer | The MEAP that supersedes this one. Set automatically when another MEAP lists this in its `replaces:`. |
| `author` | yes | string | A free-form attribution line; SHOULD include a contact handle. |

After the preamble the MEAP body MUST start with an H1 title line of the form `# MEAP-<n>: <title>` matching the preamble exactly.

### Section structure

Every Standards Track MEAP MUST contain the following sections in this order. Sections marked OPTIONAL MAY be omitted; sections marked REQUIRED MUST appear even if empty (with an explicit *N/A — <reason>* line).

1. **Abstract** (REQUIRED) — single paragraph, ≤200 words, plain prose, no jargon.
2. **Motivation** (REQUIRED) — why the change is needed; what problem it solves.
3. **Specification** (REQUIRED) — the normative content. RFC 2119 keywords (MUST, SHOULD, MAY, etc.) carry their [BCP 14](https://datatracker.ietf.org/doc/html/bcp14) meaning. Outside this section those keywords have no normative force.
4. **Rationale** (REQUIRED) — design choices, alternatives considered, references to related work.
5. **Backwards Compatibility** (REQUIRED) — explicit statement, even if it is just *N/A — v1.0 greenfield*.
6. **Test Vectors** (CONDITIONAL) — REQUIRED for any MEAP that defines wire bytes or cryptographic outputs whose value can be deterministically pinned. OPTIONAL for purely behavioural specs.
7. **Reference Implementation** (REQUIRED) — pointer to the in-tree implementation, plus the reference test class.
8. **Security Considerations** (REQUIRED) — explicit statement, even if it is just *N/A — purely cosmetic*.
9. **Copyright** (REQUIRED) — a single line releasing the MEAP under the project licence.

Informational and Process MEAPs MAY omit Test Vectors and Reference Implementation. They MUST still include Backwards Compatibility and Security Considerations sections, even if both are *N/A*.

### Numbering and file layout

- File names: `meap-<n>.md` with no leading zeros, e.g. `meap-7.md`. Stored under `docs/specs/`.
- Body title: `# MEAP-<n>: <title>` matching the YAML preamble.
- Numbers are allocated by the editors in strict submission order. A number assigned to a MEAP that is later **Withdrawn** is **not** recycled.

### Status lifecycle

```text
       (open issue)              (PR opened)            (PR merged)
Idea ──────────────►  Draft ──────────────► Last Call ──────────────► Final
                       │                       │                        │
                       │                       │                        ├──► Superseded (by a later Final MEAP)
                       │                       │                        │
                       └─► Withdrawn           └─► Stagnant ◄────── (no activity for 6 months)
```

Transitions:

- **Idea → Draft**: an issue describing the change is opened; an editor allocates a MEAP number and the author opens a pull request creating `meap-<n>.md` with `status: Draft`.
- **Draft → Last Call**: the author or an editor moves the document to `status: Last Call`. A 14-day comment window opens. Substantive changes during Last Call reset the window.
- **Last Call → Final**: at the end of the unbroken Last Call window, an editor merges the change to `status: Final` and stamps `updated: <date>`. From this point the body is immutable except for editorial errata.
- **Draft → Withdrawn**: the author may withdraw their own draft at any time before Last Call ends.
- **Draft / Last Call → Stagnant**: an editor MAY mark a long-inactive draft as Stagnant after 6 months of no commits or comments. Stagnant MEAPs MAY be re-opened by re-submitting them as a fresh Draft (which gets a new number).
- **Final → Superseded**: when a later MEAP listing this one in `replaces:` reaches Final, the editors update this MEAP's preamble to `status: Superseded` and add a Status block in the body's first H2 section linking to the superseder.

### Editorial errata

After Final, only the following changes are permitted in-place:

- Typographical or grammatical fixes that do not alter normative meaning.
- Clarifying parentheticals that explicitly carry the marker `*[Errata <date>]*`.
- Adding a `superseded-by:` header when another MEAP supersedes this one.

Any change that affects what a conforming implementation must do MUST be made via a new MEAP that supersedes the affected one.

## Rationale

The MEAP format is a deliberate borrow from BIP-2, EIP-1, SIP-1 and SLIP-0044 conventions:

- **YAML preamble** matches BIP-2 / EIP-1 so existing tooling that scrapes those ecosystems can read MEAPs with one regex change.
- **RFC 2119 normative language** matches every IETF and W3C protocol document that has stood the test of time. Implementers do not need to learn a new vocabulary to read a MEAP.
- **Status lifecycle** matches EIP-1's Idea → Draft → Last Call → Final flow with the same time-bounded comment window.
- **Test Vectors as a first-class section** matches SLIP-10 and BIP-39: the most reliable way to debug a host SDK against a card is to step the spec's vectors through your implementation, and the spec MUST make that possible.

The departures from those models are deliberate:

- **Numbering is dense**. EIP allows huge gaps; we expect ≤ 50 MEAPs in the v1.0 horizon and dense numbering is faster to read.
- **Process MEAPs and Informational MEAPs use the same template** as Standards Track ones, with two sections optional. EIP splits the template per type; we don't, because the simplification is worth the redundancy.
- **No `discussions-to:` header**. We prefer GitHub issues threaded under the PR; a separate URL field invites link rot.

## Backwards Compatibility

N/A — this MEAP defines the documentation system itself; there is no prior format being superseded. Future revisions of MEAP-0 will list themselves as `replaces: [0]` and explicitly call out compatibility with documents authored under this revision.

## Test Vectors

N/A — Process MEAP, no wire bytes to pin.

## Reference Implementation

N/A — Process MEAP, no reference implementation.

## Security Considerations

The MEAP set IS itself part of the trust surface of the wallet. A misleading specification can lead a host SDK to send the wrong bytes to the card, so editors MUST treat MEAP merges with the same care as code merges:

- A MEAP MUST be reviewed by at least two editors before reaching Last Call.
- A MEAP that contradicts the reference implementation in `applet/` MUST be flagged: either the spec or the implementation is wrong, and the discrepancy MUST be resolved before Final.
- Test vectors in the MEAP MUST round-trip against the reference test suite as a CI gate; an editor merging a MEAP without that gate is in violation of this MEAP.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).

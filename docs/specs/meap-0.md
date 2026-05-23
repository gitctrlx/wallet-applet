---
meap: 0
title: MEAP process and template
description: Format, numbering, lifecycle and contribution workflow of the MEAP set itself.
status: Draft
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
- A repository commit log and code-review record (the equivalent of a former ADR) captures **how a given design was chosen — the alternatives considered, the trade-offs weighed, the decision made**.

This separation lets implementers consume the wire contract without wading through design history, and lets contributors record design history without polluting the wire contract.

## Specification

### Header

Every MEAP MUST begin with a YAML preamble delimited by `---` lines. The preamble keys are:

| Key | Required | Type | Allowed values |
| --- | --- | --- | --- |
| `meap` | yes | integer ≥ 0 | The MEAP number. Numbers are allocated densely in submission order and are never re-used. |
| `title` | yes | short string | A descriptive title, written as a noun phrase, max 70 characters. |
| `description` | yes | short string | A one-sentence summary of the MEAP, written in declarative prose, max 140 characters. Used by the index page in [`README.md`](./README.md) and by any external tooling that scrapes the MEAP set. |
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
5. **Backwards Compatibility** (REQUIRED) — explicit statement, even if it is just *N/A — no prior revision*.
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

```mermaid
stateDiagram-v2
    direction LR
    [*] --> Idea
    Idea --> Draft : number allocated, PR opened
    Idea --> [*] : abandoned (no number kept)
    Draft --> LastCall : author requests review
    Draft --> Withdrawn : author withdraws
    Draft --> Stagnant : inactive ≥ 6 months
    LastCall --> Draft : substantive change resets window
    LastCall --> Final : 14-day window elapses unbroken
    LastCall --> Stagnant : inactive ≥ 6 months
    Final --> Superseded : later MEAP lists this in replaces:
    Stagnant --> Draft : re-opened with a fresh number
    Withdrawn --> [*]
    Superseded --> [*]
    Final --> [*]
```

| Transition | Trigger | Side effects |
| ---------- | ------- | ------------ |
| `Idea → Draft` | An editor allocates a MEAP number; author opens a PR creating `meap-<n>.md`. | `status: Draft` set. |
| `Draft → Last Call` | Author or editor moves the document to `status: Last Call`. | A 14-day public comment window opens. Substantive changes during Last Call reset the window. |
| `Last Call → Final` | The 14-day window elapses without substantive change. | `status: Final` set; `updated: <date>` stamped. The body becomes immutable except for editorial errata. |
| `Draft → Withdrawn` | Author withdraws before Last Call ends. | Number is retired and not recycled. |
| `Draft ∨ Last Call → Stagnant` | No commit or comment for 6 months. | An editor marks the document `Stagnant`. May be re-opened by re-submitting as a fresh Draft with a new number. |
| `Final → Superseded` | A later MEAP listing this one in `replaces:` reaches Final. | This MEAP's preamble gains `superseded-by: <n>`; a Status block linking to the successor is added under the H1. |

### Editorial errata

After Final, only the following changes are permitted in-place:

- Typographical or grammatical fixes that do not alter normative meaning.
- Clarifying parentheticals that explicitly carry the marker `*[Errata <date>]*`.
- Adding a `superseded-by:` header when another MEAP supersedes this one.

Any change that affects what a conforming implementation must do MUST be made via a new MEAP that supersedes the affected one.

## Rationale

The MEAP format inherits the parts of BIP-2, EIP-1 and SLIP-0044 that have proven durable, with deliberate simplifications appropriate to a single-protocol applet ecosystem rather than a multi-protocol public registry.

**Inherited from BIP / EIP / SLIP:**

- **YAML preamble** — BIP-2 / EIP-1 shape, so any tooling that already scrapes those ecosystems parses MEAPs unchanged.
- **RFC 2119 normative vocabulary** — every IETF and W3C protocol document that has stood the test of time uses BCP 14; readers do not need a new vocabulary.
- **Lifecycle `Idea → Draft → Last Call → Final`** — EIP-1 shape; a time-boxed comment window gives downstream SDK authors a predictable freeze.
- **First-class Test Vectors section** — SLIP-10 / BIP-39 convention; bit-for-bit reproducible vectors are the most reliable host-SDK debugging surface.

**Deliberate departures:**

- **Dense numbering.** EIP tolerates large gaps because thousands of proposals coexist; the MEAP set is bounded in size and dense numbering keeps the index scannable.
- **One template across types.** Standards Track, Informational and Process MEAPs share the same nine-section template, with Test Vectors and Reference Implementation optional for non-normative types. EIP-1 maintains type-specific templates; the redundancy here is small enough to favour a single shape.
- **No `discussions-to:` header.** GitHub issues threaded under the PR carry the discussion; a dedicated URL field invites link rot.
- **No `Review` substate.** EIP-1's Review phase, in practice, gates editor sign-off before the public comment window. A single-repository review surface (the PR itself) makes that ceremony unnecessary; the lifecycle stays at four active states.
- **No `last-call-deadline:` field.** The 14-day window is documented in prose rather than encoded per-MEAP. A dated field is only useful when many MEAPs are simultaneously in Last Call against a fixed editorial calendar.

## Backwards Compatibility

N/A — this MEAP defines the documentation system itself; there is no prior format being superseded. Future revisions of MEAP-0 will list themselves as `replaces: [0]` and explicitly call out compatibility with documents authored under this revision.

## Test Vectors

N/A — Process MEAP, no wire bytes to pin.

## Reference Implementation

N/A — Process MEAP, no reference implementation.

## Security Considerations

The MEAP set is part of the wallet's trust surface: a misleading specification can lead a host SDK to send the wrong bytes to the card. The following invariants therefore apply to every MEAP merge:

- **Spec/implementation parity.** A MEAP that contradicts the reference implementation in `applet/` MUST be flagged. Either the prose or the code is wrong; the discrepancy MUST be resolved before the MEAP advances to Final.
- **Test vectors are binding.** Every Test Vectors entry MUST round-trip against the reference test suite as a CI gate. A merge that ships divergent vectors is non-conforming.
- **Verifiable cross-references.** Every reference to a Java class, method, file path or test name in a MEAP MUST resolve to a symbol that exists in the same commit. Reviewers SHOULD `grep`-verify each citation before approval.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).

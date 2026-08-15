# Tauri vs Qt UI Parity Audit

Date: 2026-06-06

## Historical status

This document is a dated engineering parity audit.

It records a point-in-time snapshot from June 6, 2026 in the evolution of the
experimental Tauri desktop frontend relative to the reference Qt desktop UI.

It is not the canonical current UI contract.

Current product/presentation semantics are defined by:

- [presentation_contract.md](presentation_contract.md)
- current production code
- current user documentation

Many gaps listed in the original June 2026 audit were later reduced or closed.
This file is retained for engineering history and design context rather than as
an always-current parity matrix.

## How to read this document

- Treat the findings below as historical observations, not current guarantees.
- Later product evolution may have closed, reduced, or reframed many of the
  original gaps.
- Do not use this file by itself to define present-tense Qt/Tauri behavior.

## Original audit purpose

The original audit compared the experimental Tauri shell against the reference
Qt desktop UI to identify where Tauri still lagged in:

- workspace coverage;
- presentation depth;
- export/action workflows;
- source-availability handling;
- statistics;
- analysis;
- large-flow responsiveness.

## Preserved historical findings

The original June 6, 2026 snapshot identified these major themes:

### 1. Qt was the reference desktop frontend

Qt was treated as the fuller desktop implementation across:

- flows browsing;
- selected-flow packets and stream;
- packet details;
- statistics;
- selected-flow analysis;
- export workflows;
- status and unavailable-state presentation.

### 2. Tauri was already beyond a placeholder shell

Even in the dated audit snapshot, the experimental Tauri frontend was already
being evaluated as a meaningful desktop alternative over the same shared
backend/session semantics, not as a mockup.

### 3. Major gaps were mostly presentation/workflow depth

The most important historical gaps were not “Tauri has no backend semantics”.
They were things like:

- inspector richness;
- stream-item-details polish;
- export progress/cancel UX;
- source/index warning presentation;
- statistics compactness/drill-down polish;
- analysis workspace maturity;
- responsiveness on very large selected flows.

### 4. Some parity work was intentionally semantic, not pixel-perfect

The original audit did not require exact pixel parity. It focused on whether
Tauri could share the same semantic workflows and backend/session meaning while
keeping a webview-native presentation.

## Later evolution note

After the dated audit snapshot:

- Tauri gained most primary product workflows;
- many shared packet/statistics/analysis semantics moved behind stronger shared
  backend/session presentation boundaries;
- Packet Details and Stream Item Details terminology converged to
  `Summary / Bytes` and `Summary / Item Data`;
- Supported Protocols and Protocol Path presentation became much more explicitly
  shared-backend-driven.

This note is intentionally high-level. It does not try to re-audit every row of
the old parity matrix as if this file were a current living contract.

## What this file is still useful for

This historical audit remains useful when asking:

- which classes of parity gaps mattered during the Tauri bring-up period;
- which concerns were semantic versus merely visual;
- why some later shared DTO/presentation work was prioritized;
- how the team historically framed “Qt reference UI” versus “experimental
  Tauri frontend”.

## What this file is not

This file is not:

- the canonical current presentation contract;
- a complete current parity checklist;
- a current roadmap;
- a substitute for checking the current code and current user docs.

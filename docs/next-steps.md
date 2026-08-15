# Next Steps

## Status

Status: superseded working-plan snapshot.

This file captured priorities during an earlier Stream, TLS, QUIC, and UI
stabilization period. It is no longer the authoritative current project
roadmap, and many items originally listed here have already landed.

Current implemented behavior belongs in:

- `docs/current-state.md`
- `docs/architecture.md`
- `docs/stream_architecture.md`
- `docs/selected-flow-contract.md`
- current protocol-support and UI contract docs

## Historical planning themes

This snapshot mainly recorded work in these areas:

- Stream correctness and retransmission handling;
- convergence toward one bounded selected-flow materialization path;
- richer TLS / HTTP / QUIC selected-flow detail;
- fixture-backed regression expansion;
- metadata-only Analysis boundaries;
- wording and usability improvements in the UI.

Those themes were real and useful at the time, but the list below must no
longer be read as a current authoritative commitment.

## Historical notes

Many earlier priorities mentioned in this file have since been implemented or
partially implemented, including work around:

- Stream model convergence and bounded `Load more` behavior;
- selected-flow loading and retained bounded context;
- richer TLS, HTTP, DNS/mDNS, and QUIC selected-flow presentation;
- removal of old visible Protocol-tab assumptions from current packet/stream
  inspection surfaces;
- fixture-backed QUIC and Stream stabilization.

Some ideas from the old snapshot may still remain relevant as future work, but
that does not make this file authoritative.

Examples of historical themes that may still echo in future work:

- more TCP correctness and hardening;
- broader parser convergence;
- additional QUIC hardening;
- further compactness and performance work.

## Current role

This file should be treated as a historical planning snapshot only.

It should not continue to claim that it reflects current working priorities.

Genuine current deferred work should be tracked through:

- current contract docs where appropriate;
- active backlog documents;
- issues / PR planning / future release planning outside this file.

## Recommended future location

This file is a strong candidate for later relocation to:

- `docs/history/plans/`

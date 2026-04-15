# Pcap Flow Lab v0.1.0 Draft Release Notes

Pcap Flow Lab `v0.1.0` is the first public release of a flow-first PCAP analysis tool for large captures.

It focuses on a practical workflow: open captures quickly, persist reusable indexes, return to large captures without starting from zero, and inspect only the selected flow in more detail when that extra work is worth doing.

This release is not trying to be a Wireshark replacement. It is a bounded, pragmatic tool for flow-oriented exploration with explicit limits.

## Highlights

- Fast open path for PCAP and PCAPNG captures.
- Reusable index files for large-capture reopen workflows.
- Index-only reopen flow with later source-capture attach for byte-dependent features.
- Flow-first browsing with filtering, protocol hints, statistics, and top endpoints.
- Selected-flow Analysis workspace with summaries, histograms, timelines, directional ratios, and rate graph views.
- Selected-flow Stream inspection for practical TCP, TLS, HTTP, and meaningful bounded QUIC cases.
- Packet Details views and selected-flow export workflows.

## Platform availability for v0.1.0

- Windows: prebuilt UI archive intended.
- Ubuntu: prebuilt archive only if it was manually built and manually verified for this release; otherwise treat this release as source-build-only on Ubuntu.
- macOS: source-build-only.

`v0.1.0` release artifacts are expected to be assembled manually. This release does not assume automated packaging or automated multi-platform publication.

## What this release does well

- Large-capture usability through fast open and reusable indexes.
- Flow-first navigation instead of packet-first hunting.
- Selected-flow Analysis that stays useful without requiring global payload reconstruction.
- Practical bounded protocol inspection where enough data is available.
- Conservative fallback behavior when captures are incomplete, imperfect, or not fully reconstructible.

## Current limitations

- No full TCP-correct stream reconstruction under adverse capture conditions.
- No deep TCP recovery after gaps, major reordering, or loss.
- HTTP Stream reconstruction is bounded and selected-flow-only.
- QUIC inspection is meaningful but intentionally bounded; there is no full QUIC reconstruction or decryption-backed session model.
- Packet detail depth is intentionally below Wireshark.
- Stream results are practical and heuristic, not full protocol-forensics output.

## Non-goals

- Competing with Wireshark on protocol breadth or packet-detail depth.
- Promising full semantic reconstruction for malformed or hostile captures.
- Claiming broad platform packaging maturity beyond what was manually built and verified for this release.

## Suggested GitHub Release Summary

Pcap Flow Lab `v0.1.0` is the first public release of a flow-first PCAP analyzer built for large-capture exploration. It emphasizes fast open, reusable indexes, selected-flow Analysis and Stream workflows, and practical bounded protocol inspection for TCP, TLS, HTTP, and meaningful QUIC cases. It is not a Wireshark replacement, and the current release stays explicit about limits around deep TCP recovery, transport-complete reconstruction, and full QUIC coverage.
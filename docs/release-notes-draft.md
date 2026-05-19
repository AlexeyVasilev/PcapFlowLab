# Pcap Flow Lab Draft Release Notes

Pcap Flow Lab is a flow-based PCAP analysis tool for large captures.

It is built around a practical workflow: open captures quickly, persist reusable indexes, return to large captures without starting from zero, and inspect only the selected flow in more detail when deeper work is actually worth doing.

This release is not trying to be a Wireshark replacement. It is a bounded, pragmatic tool for flow-based exploration with explicit limits.

## Highlights

- Fast open path for PCAP and PCAPNG captures.
- Reusable index files for large-capture reopen workflows.
- Index-only reopen flow with later source-capture attach for byte-dependent features.
- Flow-based browsing with filtering, protocol hints, statistics, and top endpoints.
- Selected-flow Analysis workspace with summaries, histograms, timelines, directional ratios, and rate graph views.
- Selected-flow Stream inspection for practical TCP, TLS, HTTP, and meaningful bounded QUIC cases.
- Packet Details views, checksum validation, and selected-flow export workflows.
- Smart Export with per-flow output mode, manifest export, progress reporting, and cooperative cancellation.
- Clearer captured/original length handling for constricted or truncated packet cases.

## Major workflows

- Open a large capture, inspect the flow table first, and narrow attention before deeper packet work.
- Save an index and reopen it later without paying the full import cost again.
- Reopen an index in index-only mode and attach the source capture only when byte-dependent features are needed.
- Use the selected-flow Analysis workspace for bounded metrics and visual summaries.
- Use the selected-flow Stream view for practical TCP, TLS, HTTP, and bounded QUIC inspection.
- Export useful subsets without turning the product into a full protocol-forensics environment.
- Use Smart Export to emit either one filtered output capture or one output file per chosen bidirectional flow.

## Platform availability

- Windows: prebuilt UI archive provided.
- Ubuntu: prebuilt archive only if it was manually built and manually verified for this release; otherwise treat this release as source-build-only.
- macOS: source-build-only.

Release artifacts are expected to be assembled manually. This release does not assume automated packaging or automated multi-platform publication.

Windows remains the primary prebuilt artifact target, but Linux source builds and manual validation can still be described explicitly in the release notes when that release was actually checked on Linux.

If a prebuilt archive is not attached for your platform, use the source build instructions from the repository instead of assuming that a missing binary is a packaging error.

## What this release does well

- Large-capture usability through fast open and reusable indexes.
- Flow-based navigation instead of packet-first hunting.
- Selected-flow Analysis that stays useful without requiring global payload reconstruction.
- Practical bounded protocol inspection where enough data is available.
- Stream and packet views that keep captured/original length semantics explicit on constricted packets.
- Practical export workflows, including Smart Export and per-flow output for selected cases.
- Conservative fallback behavior when captures are incomplete, imperfect, or not fully reconstructible.

## Current limitations

- No full TCP-correct stream reconstruction under adverse capture conditions.
- No deep TCP recovery after gaps, major reordering, or loss.
- HTTP Stream reconstruction is bounded and selected-flow-only, even when requests and responses can be assembled across multiple segments.
- QUIC inspection is meaningful but intentionally bounded; selected-flow packet and Stream views can expose practical frame-level and handshake-aware details for supported cases, but there is no full QUIC reconstruction or broad decryption-backed session model.
- Packet detail depth is intentionally below Wireshark.
- Stream results are practical and heuristic, not full protocol-forensics output.

## Non-goals

- Competing with Wireshark on protocol breadth or packet-detail depth.
- Promising full semantic reconstruction for malformed or hostile captures.
- Claiming broad platform packaging maturity beyond what was manually built and verified for this release.

## Suggested GitHub Release Summary

Pcap Flow Lab is a flow-based PCAP analyzer built for large-capture exploration. It emphasizes fast open, reusable indexes, selected-flow Analysis and Stream workflows, practical Smart Export paths, and bounded protocol inspection for TCP, TLS, HTTP, and meaningful QUIC cases. It is not a Wireshark replacement, and the current release stays explicit about limits around deep TCP recovery, transport-complete reconstruction, and full QUIC coverage.

## Repository metadata suggestion

Recommended repository description:

Flow-based PCAP analyzer for large captures with reusable indexes and selected-flow inspection.

Recommended GitHub topics:

- pcap
- pcapng
- packet-analysis
- network-analysis
- network-forensics
- qt
- qt-quick
- qml
- cpp
- cmake
- wireshark-alternative
- traffic-analysis

# Pcap Flow Lab 0.3.0

Pcap Flow Lab 0.3.0 is a substantial release for flow-based packet-capture
inspection. It expands the product well beyond a simple large-capture utility
and brings together flow navigation, Protocol Path-aware identity, selected
packet and Stream inspection, selected-flow Analysis, capture-wide Statistics,
reusable indexes, practical export workflows, and a modern CLI.

Pcap Flow Lab remains **a flow-based PCAP analyzer.** It is not intended to
replace Wireshark. Instead, it provides a different flow-based analysis model
that can complement deeper packet-based Wireshark inspection.

## Highlights

- Flow-based capture exploration with Protocol Path-aware identity and
  presentation.
- Structured selected-packet `Summary` and protocol-aware `Bytes`.
- Bounded selected-flow Stream inspection with useful structured HTTP,
  DNS/mDNS, TLS, and QUIC cases where supported.
- Selected-flow Analysis for timing, rates, directionality, distributions, and
  sequence context.
- Capture/index-wide Statistics including detected protocols, QUIC/TLS
  summaries, top endpoints/ports, Unrecognized Packets, and Protocol Path
  aggregation.
- A modern CLI built around `summary`, `flows`, `export-flows`, `flow-info`,
  and `packet-info`.
- Practical export workflows including Smart Export, per-flow output where
  supported, flow metadata export, and selected byte export.
- A versioned showcase capture for ready-to-open demos and release smoke tests.

## Flow-based analysis and Protocol Path

Protocol Path-aware flow identity and presentation are major capabilities in
0.3.0. Pcap Flow Lab can preserve meaningful encapsulation context so that
flows whose effective inner tuples would otherwise look identical remain
distinguishable when identity-bearing layers differ.

Representative examples include:

- VLAN VID
- MPLS label
- VXLAN VNI
- Geneve VNI
- GTP-U TEID
- GRE key
- AH SPI
- ESP SPI

This same context is visible in the user-facing Protocol Path presentation
across Flows and Statistics, making nested traffic and overlay identity easier
to understand at both the per-flow and whole-capture levels.

## Packet and Stream inspection

Selected-packet inspection now centers on two current Packet Details surfaces:

- `Summary`
- `Bytes`

`Summary` provides structured packet inspection, while `Bytes` exposes
authoritative packet and supported derived byte views.

Selected-flow Stream inspection is bounded, practical, and protocol-aware where
enough evidence exists. Stream Item Details currently uses:

- `Summary`
- `Item Data`

Useful structured Stream behavior is available for supported HTTP, DNS/mDNS,
TLS, and bounded QUIC cases, with generic fallback where a specialized Stream
parser is not available. This does not imply full TCP-correct session
reconstruction.

## Analysis and Statistics

Selected-flow Analysis is one of the major user-facing surfaces in 0.3.0. It
provides timing, rates, directionality, packet-size and inter-arrival
distributions, burst/idle information, sequence context, and related metrics
for one selected flow.

Statistics is the capture-wide or index-wide quantitative workspace. Important
current capabilities include:

- transport and IP-family summary
- packet and flow distributions
- detected protocol summaries
- QUIC and TLS summaries
- top endpoints and ports
- Unrecognized Packets tracking
- Protocol Path aggregation

Together, Analysis and Statistics give both the local flow view and the global
capture view without forcing every expensive computation into capture-open time.

## CLI and export

The current CLI is an important part of the 0.3.0 release. Its public command
set is:

- `summary`
- `flows`
- `export-flows`
- `flow-info`
- `packet-info`

The release also includes practical export workflows across the shared backend,
including Smart Export, per-flow output where supported, flow metadata export,
and selected byte export from the interactive inspection surfaces.

## Protocol coverage

0.3.0 significantly expands protocol coverage at the user-facing level.
Representative supported families now include:

- PCAP and PCAPNG
- Ethernet and Linux cooked captures
- VLAN and MPLS
- IPv4 and IPv6
- TCP, UDP, and SCTP
- GRE and IP-in-IP
- VXLAN, Geneve, and GTP-U
- AH and ESP
- HTTP
- DNS and mDNS
- TLS
- QUIC
- additional supported control, link, and tunnel protocol families from the
  current protocol catalog

Support depth varies by protocol. Recognition, flow identity, structured Packet
Summary, Stream semantics, and service metadata are not identical for every
protocol family.

## Large captures and reusable indexes

Large-capture usability remains a meaningful strength of Pcap Flow Lab 0.3.0,
but it is not the sole definition of the product. The application has been
tested with real captures measuring several tens of gigabytes, and expensive
inspection stays bounded and on demand rather than globally materialized.

Reusable indexes are another major part of the release. After processing a raw
capture, users can save an analysis index and reopen it later without starting
from zero, while still attaching the original source capture for byte-backed
workflows when needed.

## Showcase capture

The versioned showcase capture:

- [`examples/showcase/pcap_flow_lab_showcase.pcap`](../examples/showcase/pcap_flow_lab_showcase.pcap)

provides ready-to-open examples for important flows, protocols, Analysis,
Statistics, Stream inspection, Protocol Path identity, tunnels, and selected
edge cases.

Suggested scenarios and stable scenario IDs are documented in:

- [`examples/showcase/README.md`](../examples/showcase/README.md)

## Platform availability

Pcap Flow Lab 0.3.0 is planned to publish four prebuilt application archives:

- `PcapFlowLab-0.3.0-windows-x64-qt.zip`
- `PcapFlowLab-0.3.0-windows-x64-tauri.zip`
- `PcapFlowLab-0.3.0-ubuntu-x64-qt.tar.gz`
- `PcapFlowLab-0.3.0-ubuntu-x64-tauri.tar.gz`

Windows therefore has prebuilt Qt and Tauri applications. Ubuntu therefore has
prebuilt Qt and Tauri applications. Qt remains the primary desktop UI. Tauri
remains an experimental alternative frontend over the shared backend model.

macOS is source-build-only for this release. Linux distributions other than the
published Ubuntu target are source-build-only.

Release artifacts remain manually assembled and manually verified.

## Compatibility

Pcap Flow Lab currently uses exact-version index loading. The current capture
index format version is `14`.

Indexes produced by older releases may not be compatible with 0.3.0. When an
older index is rejected, rebuild it from the original PCAP or PCAPNG rather
than expecting automatic migration.

## Current limitations

- Pcap Flow Lab does not provide full TCP recovery or reassembly under adverse
  capture conditions.
- Selected-flow Stream inspection is bounded and practical rather than a full
  forensic TCP/session reconstruction engine.
- QUIC inspection does not attempt complete session reconstruction or general
  application-data decryption.
- Tauri remains experimental and is not guaranteed to match every Qt workflow
  perfectly.
- Packet-detail breadth remains intentionally below Wireshark.
- Malformed and truncated data is handled conservatively.

## Download / source-build guidance

Release assets will be published through the GitHub release page for `0.3.0`.
Users who need source-build instructions can use:

- [`README.md`](../README.md)
- [`user_docs/build-from-source.md`](../user_docs/build-from-source.md)

## Suggested GitHub Release Summary

Pcap Flow Lab 0.3.0 is a substantial release for flow-based packet-capture
analysis. It adds Protocol Path-aware identity and presentation, structured
Packet Details `Summary` / `Bytes`, bounded selected-flow Stream inspection,
selected-flow Analysis, capture-wide Statistics, a modern CLI, practical export
workflows, reusable indexes, and a versioned showcase capture. Pcap Flow Lab
complements Wireshark rather than replacing it, and remains explicit about
bounds around TCP recovery, full session reconstruction, and broad QUIC
decryption.

## Repository metadata suggestion

Recommended repository description:

Flow-based PCAP analyzer with protocol-aware Stream inspection, Analysis,
Statistics, reusable indexes, and CLI.

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
- traffic-analysis

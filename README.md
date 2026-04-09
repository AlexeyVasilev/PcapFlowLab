# Pcap Flow Lab

Flow-centric PCAP analyzer for large network captures.

Pcap Flow Lab is an open-source C++ project focused on flow-first analysis of packet captures. The current import path auto-detects classic PCAP and current PCAPNG support, and the decode path supports Ethernet II, Linux cooked captures (SLL and SLL2), up to two VLAN tags, ARP, IPv4/IPv6, ICMP, ICMPv6, TCP/UDP, conservative traversal of common IPv6 extension headers, and always-on IP fragmentation detection as diagnostic metadata.

## Project status

Usable prototype with flow browsing, packet inspection, saved analysis indexes, and on-demand Stream analysis for selected flows.

## CLI

The main read/query commands accept either a capture file or a saved analysis index.

Examples:

`pcap-flow-lab summary sample.pcap --mode fast`

`pcap-flow-lab summary sample.idx`

`pcap-flow-lab flows sample.pcapng --mode deep`

`pcap-flow-lab flows sample.idx`

`pcap-flow-lab inspect-packet sample.idx --packet-index 0`

`pcap-flow-lab hex sample.pcapng --packet-index 0`

`pcap-flow-lab export-flow sample.idx --flow-index 0 --out selected-flow.pcap`

`pcap-flow-lab save-index sample.pcapng --out sample.idx --mode deep`

`pcap-flow-lab load-index-summary sample.idx`

`pcap-flow-lab chunked-import sample.pcap --checkpoint sample.ckp --max-packets 100000`

`pcap-flow-lab resume-import --checkpoint sample.ckp --max-packets 100000`

`pcap-flow-lab finalize-import --checkpoint sample.ckp --out sample.idx`

## Desktop UI

The Qt Quick desktop UI can:

- open captures and analysis indexes via native file dialogs
- show non-modal open progress and allow cooperative cancellation while preserving the previous valid session if the open is cancelled
- save the current analysis state back to an index (disabled for partial-open captures)
- export the currently selected flow to classic PCAP
- browse flows, packets, protocol statistics, top endpoints, and top ports
- switch Statistics tab protocol presentation between flows, packets, and bytes (presentation only over existing metadata)
- include SSH, STUN, BitTorrent, DHCP, and mDNS in protocol summary/distribution when detected by cheap flow hints
- optionally classify unresolved TCP/UDP port 443 flows as Possible TLS / Possible QUIC with a user setting; these remain separate from confirmed protocol detection
- show QUIC and TLS protocol-recognition statistics aggregated from existing flow metadata only (no extra parsing pass for statistics)
- materialize selected-flow packet rows in bounded initial batches with explicit Load more continuation for heavy flows
- mark exact-duplicate payload-bearing TCP packets in the selected flow as `Suspected retransmission` on demand only; this marker is ephemeral and does not affect import, counts, or stream materialization
- show fragmented packets and flows as diagnostic metadata
- open indexes in explicit index-only mode and attach the matching source capture later
- inspect packet details in Summary, Raw, and Protocol views
- show a payload-oriented Stream tab for the selected flow
- expose Analysis as a dedicated selected-flow workspace with compact flow selection and MVP overview and directional stats only
- include a bounded metadata-only Sequence Preview block in Analysis for the first packets of the selected flow
- export the full selected-flow sequence from Analysis to CSV using existing packet metadata only, without payload bytes
- include a bounded metadata-only Timeline block in Analysis for selected-flow timing summary
- include a bounded metadata-only Packet Size Histogram block in Analysis for selected-flow captured-length distribution
- include a bounded metadata-only Inter-arrival Histogram block in Analysis for selected-flow timing distribution
- explain directional histogram modes inline in Analysis so packet-size filtering and inter-arrival attribution stay understandable without changing analysis logic
- include a bounded metadata-only Derived Metrics block in Analysis for selected-flow summary rates and averages
- include a bounded metadata-only Directional Ratio block in Analysis for selected-flow directional imbalance summary
- include a bounded metadata-only Flow Rate graph in Analysis with auto windowing and A->B/B->A/Both directional rendering from packet metadata only
- keep the Analysis tab organized with summary-first blocks followed by histogram/detail evidence blocks for readability only; this step does not add new analysis logic
- materialize selected-flow Stream items in bounded initial batches with explicit `Load more` continuation for heavy flows

### Stream tab

The Stream tab is on-demand, flow-local, and ephemeral.

- It runs only for the currently selected flow.
- It requires source capture access because raw packet bytes are still read lazily from the original capture.
- It does not store stream items in indexes or checkpoints.
- Selected-flow packet metadata may also include ephemeral `Suspected retransmission` markers derived on demand from exact duplicate TCP payload/sequence/ack matches within the active flow only.
- The Stream view now uses bounded initial materialization for the selected flow and loads additional items only through explicit `Load more` continuation.
- TLS parsing uses bounded directional reassembly, so TLS records spanning multiple TCP packets can appear as one logical stream item when enough bytes are available.
- HTTP parsing uses bounded directional reassembly for complete request/response header blocks.
- This remains heuristic analysis, not full TCP-correct stream reconstruction.

Deep mode remains available as a separate open path for richer packet-level protocol details. Fast mode remains the default browsing path and does not perform global reassembly during open.

If capture import fails after a strictly valid parsed prefix, the session may still open partially with a warning. Only the accepted prefix is kept; corrupted trailing data is never parsed or included, and saving an index from that partial session is disabled initially.

## Developer note

Creating `perf-open.enabled` next to the executable or in the current working directory enables append-only open-time CSV logging to `perf_open_log.csv` for `capture_fast`, `capture_deep`, and `index_load` operations. This is intended only for local regression tracking during development and has no effect in normal usage.

Console logging in open/import paths is intentionally quiet by default. If temporary developer logging is needed there, use the compile-time flags in `src/core/debug_logging.h` so disabled builds stay effectively free of logging overhead.

Current large-list strategy also stays intentionally simple: Flow, Packet, and Stream surfaces use virtualization-friendly `ListView`-based rendering, explicit scrollbars, and lightweight delegates, while pagination remains deferred until there is stronger evidence that the current approach is insufficient. Selected-flow packet and Stream loading now stays fully materialized for small flows that fit within the initial budgets, while heavy flows still use bounded initial materialization with explicit `Load more` continuation.










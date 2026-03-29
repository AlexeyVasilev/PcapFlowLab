# Architecture

Pcap Flow Lab is organized as a layered C++20 codebase built around flow-oriented analysis rather than packet-by-packet UI workflows.

## Modules

- `core/domain`: lightweight domain types such as connection keys, directional flow keys, packet references, runtime flows, runtime connections, and capture summaries.
- `core/io`: classic PCAP and initial PCAPNG file access, random-access byte reading, lazy packet-data retrieval by file offset, and classic PCAP writing.
- `core/index`: persistent analysis index read/write support, plus import checkpoint read/write support for source-capture metadata, partial state, flows, packet references, and resume progress.
- `core/decode`: packet metadata decoding from raw frames into ingestion-ready flow keys.
- `core/reassembly`: deep-only reassembly service scaffolding and shared request/result types for future analyzer-driven stream work.
- `core/services`: orchestration logic such as packet ingestion, capture import, chunked import/resume, flow aggregation, queries, enrichment, exports, and on-demand packet inspection.
- `app/session`: application-facing session state and use-case entry points, including small read-only query helpers and unified open helpers for captures and saved indexes.
- `cli`: a small command-line interface that exercises the current core and session stack.

## Design Principles

- Flow-first design: connection lookup uses canonical bidirectional connection keys, while per-direction packet grouping keeps exact directional flow keys.
- Runtime ingestion path: import auto-detects classic PCAP vs PCAPNG, decodes packet metadata, and ingests it into IPv4 and IPv6 connection tables grouped as Flow A and Flow B.
- Import modes: the project now distinguishes a fast import mode and a deep import mode. Fast mode is the default path and is kept simple for responsiveness and minimal branching. Deep mode is a separate architectural integration point for future richer analyzers and reassembly, but currently remains functionally close to fast mode. Planned reassembly boundaries and first-scope goals are captured in `docs/reassembly-rfc.md`.
- Reassembly architecture: `docs/reassembly-rfc.md` is the design basis for future reassembly-backed analysis. The current tree now also includes a minimal `core/reassembly` service shape plus a first bounded v1 TCP packet-order payload concatenation helper. That helper is intentionally heuristic and analyzer-oriented, not full transport-correct reassembly. Interactive Stream analysis is flow-local, ephemeral, and on-demand for the selected flow when source capture data is available, independent of the original Fast or Deep open mode. Persisted deep-analysis outputs remain small and durable, while temporary stream-view artifacts are rebuilt on demand.
- Analysis settings: import options also carry a small `AnalysisSettings` structure so future analyzer behavior can be configured without widening the session API. The first implemented setting is `http_use_path_as_service_hint`, and the current desktop UI exposes it in a temporary Settings tab. Settings apply to newly opened captures and are not retroactive.
- Current import scope: classic PCAP is supported directly, and current PCAPNG support is focused on SHB + IDB + EPB with packet ingestion for Ethernet and common Linux cooked link-layer captures. Richer block and option handling will come later.
- Current decode scope: the decode path supports Ethernet II, Linux cooked capture headers (SLL and SLL2), up to two VLAN tags, ARP, IPv4/IPv6, ICMP, ICMPv6, TCP/UDP, conservative traversal of common IPv6 extension headers to reach TCP, UDP, and ICMPv6 safely, and always-on IP fragmentation detection for IPv4 and IPv6 Fragment headers. Fragmentation is surfaced as diagnostic metadata before any future reassembly support. Richer layered decode will come later.
- Packet byte access: `PacketRef` stores packet-data offsets, timestamps, transport payload length, and TCP flags from the original capture file, and raw packet bytes are read lazily from the capture on demand.
- Cheap flow hints: import now attaches conservative single-packet protocol and service hints such as TLS, HTTP, DNS, and QUIC when they can be extracted safely from one packet payload. When enabled through analysis settings, HTTP request paths can be used as a fallback service hint if no Host header is present. Fragmented packets are tracked explicitly and skipped for cheap hint extraction until reassembly exists. Deep parsing and reassembly remain future work.
- On-demand inspection: packet details and hex dump text are decoded only when requested, and the CLI reuses the same service layer. Malformed and truncated packets are handled with explicit safe-failure behavior across decode, details, payload, and protocol inspection paths.
- Flow export: selected connections can be exported back to classic PCAP by reusing `PacketRef` metadata and lazy reads from the source capture.
- Persistent capture index: analysis state can be saved to a compact binary index file and loaded later without re-importing the source capture. The index stores source metadata, capture summary, connections, flows, and packet refs, while raw packet bytes are still read lazily from the original capture file. Source validation now uses capture format, file size, last-write time, and a lightweight FNV-1a 64-bit fingerprint over the first and last 64 KB of the capture. The desktop UI makes index-only mode explicit and allows the matching source capture to be attached later. The current index and checkpoint formats are explicitly sectioned for robustness and future evolution, but they remain unstable and backward compatibility is not guaranteed yet.
- First-class index inputs: the current session and CLI stack can now open either a capture file or a saved index file explicitly, without sidecar discovery.
- Chunked import v1: partial imports can be checkpointed by storing the current `CaptureState` together with source validation metadata, processed-packet count, and the next reader offset. This is a first step toward large-capture workflows, not yet a disk-backed merge engine.

This separation keeps the core reusable across future CLI and desktop frontends while supporting large captures with predictable memory use.















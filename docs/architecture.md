# Architecture

Pcap Flow Lab is organized as a layered C++20 codebase built around flow-oriented analysis rather than packet-by-packet UI workflows.

## Modules

- `core/domain`: lightweight domain types such as connection keys, directional flow keys, packet references, runtime flows, runtime connections, and capture summaries.
- `core/io`: classic PCAP and initial PCAPNG file access, random-access byte reading, lazy packet-data retrieval by file offset, and classic PCAP writing.
- `core/index`: persistent analysis index read/write support, plus import checkpoint read/write support for source-capture metadata, partial state, flows, packet references, and resume progress.
- `core/decode`: packet metadata decoding from raw frames into ingestion-ready flow keys.
- `core/services`: orchestration logic such as packet ingestion, capture import, chunked import/resume, flow aggregation, queries, enrichment, exports, and on-demand packet inspection.
- `app/session`: application-facing session state and use-case entry points, including small read-only query helpers and unified open helpers for captures and saved indexes.
- `cli`: a small command-line interface that exercises the current core and session stack.

## Design Principles

- Flow-first design: connection lookup uses canonical bidirectional connection keys, while per-direction packet grouping keeps exact directional flow keys.
- Runtime ingestion path: import auto-detects classic PCAP vs PCAPNG, decodes packet metadata, and ingests it into IPv4 and IPv6 connection tables grouped as Flow A and Flow B.
- Current import scope: classic PCAP is supported directly, and current PCAPNG support is focused on SHB + IDB + EPB with Ethernet-oriented packet ingestion. Richer block and option handling will come later.
- Current decode scope: the decode path supports Ethernet II with up to two VLAN tags plus IPv4/IPv6 with TCP/UDP. Richer layered decode will come later.
- Packet byte access: `PacketRef` stores packet-data offsets and timestamps from the original capture file, and raw packet bytes are read lazily from the capture on demand.
- On-demand inspection: packet details and hex dump text are decoded only when requested, and the CLI reuses the same service layer.
- Flow export: selected connections can be exported back to classic PCAP by reusing `PacketRef` metadata and lazy reads from the source capture.
- Persistent capture index: analysis state can be saved to a compact binary index file and loaded later without re-importing the source capture. The index stores source metadata, capture summary, connections, flows, and packet refs, while raw packet bytes are still read lazily from the original capture file.
- First-class index inputs: the current session and CLI stack can now open either a capture file or a saved index file explicitly, without sidecar discovery.
- Chunked import v1: partial imports can be checkpointed by storing the current `CaptureState` together with source validation metadata, processed-packet count, and the next reader offset. This is a first step toward large-capture workflows, not yet a disk-backed merge engine.

This separation keeps the core reusable across future CLI and desktop frontends while supporting large captures with predictable memory use.

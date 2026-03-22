# Architecture

Pcap Flow Lab is organized as a layered C++20 codebase built around flow-oriented analysis rather than packet-by-packet UI workflows.

## Modules

- `core/domain`: lightweight domain types such as connection keys, directional flow keys, packet references, runtime flows, runtime connections, and capture summaries.
- `core/io`: classic PCAP file access, random-access byte reading, and lazy packet-data retrieval by file offset.
- `core/index`: packet indexing and persistent lookup structures for efficient random access.
- `core/decode`: packet metadata decoding from raw frames into ingestion-ready flow keys.
- `core/services`: orchestration logic such as packet ingestion, capture import, flow aggregation, queries, enrichment, and exports.
- `app/session`: application-facing session state and use-case entry points.
- `cli`: command-line interface built on top of the application layer.

## Design Principles

- Flow-first design: connection lookup uses canonical bidirectional connection keys, while per-direction packet grouping keeps exact directional flow keys.
- Runtime ingestion path: decoded packet metadata is ingested into IPv4 and IPv6 connection tables, then grouped inside each connection as Flow A and Flow B.
- Current import scope: the import path supports classic PCAP only, and the current decode path supports Ethernet II plus IPv4/IPv6 with TCP/UDP. Richer layered decode will come later.
- Packet byte access: `PacketRef` stores packet-data offsets into the original capture file, and raw packet bytes are read lazily from the capture on demand.
- Persistent capture index: capture metadata and packet offsets should be reusable across queries and future sessions.

This separation keeps the core reusable across future CLI and desktop frontends while supporting large captures with predictable memory use.

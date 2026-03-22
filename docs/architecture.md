# Architecture

Pcap Flow Lab is organized as a layered C++20 codebase built around flow-oriented analysis rather than packet-by-packet UI workflows.

## Modules

- `core/domain`: lightweight domain types such as connection keys, directional flow keys, packet references, runtime flows, runtime connections, and capture summaries.
- `core/io`: capture file access, readers, and low-level packet source abstractions.
- `core/index`: packet indexing and persistent lookup structures for efficient random access.
- `core/decode`: protocol decoding stages that transform raw packet bytes into structured metadata.
- `core/services`: orchestration logic such as packet ingestion, flow aggregation, queries, enrichment, and exports.
- `app/session`: application-facing session state and use-case entry points.
- `cli`: command-line interface built on top of the application layer.

## Design Principles

- Flow-first design: connection lookup uses canonical bidirectional connection keys, while per-direction packet grouping keeps exact directional flow keys.
- Runtime ingestion path: decoded packet metadata is ingested into IPv4 and IPv6 connection tables, then grouped inside each connection as Flow A and Flow B.
- Lazy packet access: packet payloads should be fetched on demand through references and indexes instead of being loaded eagerly into memory.
- Persistent capture index: capture metadata and packet offsets should be reusable across queries and future sessions.
- Layered protocol decoding: low-level framing, transport interpretation, and higher-level protocol enrichment should remain separated.

This separation keeps the core reusable across future CLI and desktop frontends while supporting large captures with predictable memory use.

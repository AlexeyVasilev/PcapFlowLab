# Large-File Read Optimization Plan

Date: 2026-06-20

This note is a follow-up to [docs/packet-read-path-analysis.md](packet-read-path-analysis.md). It keeps the existing packet-read ownership map, then narrows the next optimization steps to the smallest safe passes for large captures and heavy selected-flow workloads.

Related context:

- [docs/packet-read-path-analysis.md](packet-read-path-analysis.md)
- [docs/large-capture-rfc.md](large-capture-rfc.md)
- [docs/architecture.md](architecture.md)
- [docs/decisions.md](decisions.md)

Status:

- first conservative import-time hint-detection gating pass is now implemented;
- second import-time pass now avoids transport-payload allocation/copy during flow-hint detection by using non-owning payload views;
- third import-time pass now uses hybrid classic-PCAP import: sequential full reads for normal packets and staged/prefix reading for large packets with adaptive full fallback;
- fourth import-time pass now reuses a caller-owned packet byte buffer for below-threshold classic-PCAP sequential full-read packets;
- reader ownership, index serialization, export behavior, and on-demand packet detail rereads remain unchanged.

Implemented first pass:

- skip import-time hint detection for TCP/UDP packets with zero transport payload;
- skip import-time hint detection once a connection already has a settled user-visible hint state;
- cap unresolved payload-bearing TCP/UDP hint attempts at `10` per connection during import/open;
- store that per-connection attempt state only in runtime `Connection` objects; it is not serialized into indexes.

Implemented second pass:

- `PacketPayloadService` now exposes a transport-payload view helper that returns payload-found state, byte offset, byte length, and a non-owning span into the current packet bytes;
- `FlowHintService` now uses that non-owning helper for TCP/UDP import-time hint detection instead of first copying transport payload bytes into a temporary vector;
- the existing vector-returning payload extraction API remains available for packet details, payload dumps, stream/presentation paths, and other callers that still need owning bytes;
- QUIC Initial assembly still intentionally copies retained payload fragments into per-flow runtime state when multi-packet SNI extraction is enabled.

Implemented third pass:

- classic `.pcap` import is now hybrid: packets below `16 KiB` use old-style sequential full reads, while packets at or above `16 KiB` are eligible for staged prefix import;
- staged-eligible classic packets start with a `192`-byte header prefix instead of always materializing full captured bytes up front;
- staged classic import leaves the reader positioned immediately after the current packet prefix until the import path decides whether the packet needs full bytes;
- when classic import can determine flow key, packet metadata, and unrecognized-vs-recognized status from that prefix, the unread packet remainder is skipped exactly once and the reader then advances to the next packet record;
- when the current prefix is insufficient for safe header/flow decoding, classic import reads the remaining bytes of the current packet sequentially, decodes from full captured bytes, and grows the future adaptive header prefix in `64`-byte increments;
- adaptive classic-import header prefix growth is capped at `4096` bytes;
- full packet materialization for TLS/QUIC/HTTP/DNS and other transport payload hints still happens per-packet when the existing unresolved hint budget says hint detection is still worthwhile;
- hint-triggered sequential full materialization does not grow the adaptive header prefix;
- classic import still preserves true `PacketRef.byte_offset`, `captured_length`, `original_length`, timestamps, and data-link type from the file;
- normal staged classic import no longer seeks backward by `data_offset` to materialize the current packet;
- the `16 KiB` staging threshold is intentional to avoid prefix-read plus remainder-skip overhead on ordinary MTU-sized traffic;
- `pcapng` import remains on the unchanged full-read path in this pass.

Implemented fourth pass:

- classic `.pcap` import now has an import-only reusable-buffer API for the hybrid import path;
- below-threshold classic packets still use sequential full reads, but those reads now resize/fill a caller-owned `RawPcapPacket.bytes` buffer instead of always allocating a brand-new vector;
- public full `PcapReader::read_next()` remains unchanged and still returns an owning independent `RawPcapPacket`;
- staged large-packet behavior remains separate and semantically equivalent to the previous hybrid pass;
- `pcapng` remains unchanged and does not participate in reusable-buffer import;
- classic import explicitly releases oversized reusable-packet capacity after a staged packet grows beyond the small-packet threshold, so the normal small-packet buffer does not accidentally retain a huge materialized packet allocation;
- selected-flow reread/stream/detail optimization remains deferred.

## 1. Current byte ownership

### Classic PCAP

`PcapReader::read_next()` in [src/core/io/PcapReader.cpp](../src/core/io/PcapReader.cpp) reads the packet header, allocates `std::vector<std::uint8_t> bytes(packet_header.included_length)`, reads the full captured packet into that vector, then moves it into `RawPcapPacket`.

### PCAPNG

`PcapNgReader::read_next()` in [src/core/io/PcapNgReader.cpp](../src/core/io/PcapNgReader.cpp) first allocates `remaining` for the whole block payload, validates the block trailer, then allocates a second `bytes` vector of `captured_length` and copies the captured packet bytes into it before moving that into `RawPcapPacket`.

So current `pcapng` import pays:

- one allocation for the full block remainder;
- one allocation for captured packet bytes;
- one copy from block storage into packet storage.

### Where `RawPcapPacket.bytes` lives

`RawPcapPacket` is defined in [src/core/io/PcapReader.h](../src/core/io/PcapReader.h) and owns packet bytes as:

- `std::vector<std::uint8_t> bytes`

That ownership is per-packet and per-reader-call. It lives only as long as the returned `RawPcapPacket` object lives.

### Import/open lifetime

During import, `read_next()` returns a temporary `RawPcapPacket` into `import_packets(...)` inside [src/core/services/CaptureImportProcessor.cpp](../src/core/services/CaptureImportProcessor.cpp).

Within that loop iteration:

- `PacketDecoder::decode(...)` reads `packet.bytes` through a span;
- `FlowHintService::detect(...)` reads `packet.bytes` through a span;
- fallback ARP decoding and unrecognized-packet classification also read the same bytes.

After `process_packet(...)` returns, the owning byte vector is dropped.

### What is persisted

`CaptureState` in [src/core/domain/CaptureState.h](../src/core/domain/CaptureState.h) stores:

- connections;
- packet refs;
- unrecognized packet records;
- summary counters.

It does not store packet byte vectors.

Index serialization in [src/core/index/Serialization.cpp](../src/core/index/Serialization.cpp) persists only `PacketRef` metadata such as:

- `packet_index`
- `byte_offset`
- `data_link_type`
- `captured_length`
- `original_length`
- `payload_length`
- `tcp_flags`
- fragmentation flag

The index does not persist raw packet bytes.

### Which later features re-read bytes

Later byte-backed features re-read from the source capture by `PacketRef` rather than reusing import-time buffers.

Primary path:

1. `CaptureSession::read_packet_data(...)` in [src/app/session/CaptureSession.cpp](../src/app/session/CaptureSession.cpp)
2. `CaptureFilePacketReader`
3. `PacketDataReader`
4. file read at `PacketRef.byte_offset` for `PacketRef.captured_length`

Notable consumers:

- packet details;
- raw hex dump;
- payload hex dump;
- protocol details text;
- selected-flow packet payload cache;
- selected-flow stream building;
- selected-flow TLS / QUIC presentation;
- on-demand QUIC service-hint derivation;
- classic per-packet export path via `CaptureFilePacketReader`.

## 2. Import-time byte consumers

### `PacketDecoder`

File:

- [src/core/decode/PacketDecoder.cpp](../src/core/decode/PacketDecoder.cpp)

Behavior:

- consumes `packet.bytes` through `std::span<const std::uint8_t>`;
- does not copy payload bytes on the happy path;
- persists only parsed metadata into `PacketRef` and flow keys.

Byte need:

- more than a tiny fixed prefix;
- enough bytes to parse:
  - link-layer envelope;
  - MPLS envelope if present;
  - IPv4 or IPv6 header, including IPv4 IHL / IPv6 extension traversal;
  - TCP/UDP/ICMP/IGMP header bounds;
  - transport payload boundary metadata.

Implication:

- IPv4 Options, TCP Options, MPLS, and IGMP already make this path sensitive to correct header-length parsing;
- the decoder is metadata-oriented, but it still expects the captured bytes needed to prove those bounds.

### `CaptureImportProcessor`

File:

- [src/core/services/CaptureImportProcessor.cpp](../src/core/services/CaptureImportProcessor.cpp)

Behavior:

- constructs a span over full captured bytes;
- calls decode;
- calls `FlowHintService::detect(...)` for recognized non-fragment IPv4/IPv6 packets;
- for fallback ARP, calls `PacketDetailsService::decode(...)`;
- for unrecognized packets, classifies a reason from packet bytes.

Byte need:

- full currently captured packet, because the current reader always delivers it;
- import processor itself does not make additional owned copies except via downstream services.

### `PacketIngestor`

File:

- [src/core/services/PacketIngestor.cpp](../src/core/services/PacketIngestor.cpp)

Behavior:

- does not read packet bytes directly;
- consumes already-decoded metadata only.

Byte need:

- none after decode.

### `FlowHintService`

File:

- [src/core/services/FlowHintService.cpp](../src/core/services/FlowHintService.cpp)

Behavior:

- for ARP and IGMP, inspects packet bytes directly with spans;
- for TCP/UDP application hinting, first calls `PacketPayloadService::extract_transport_payload(...)`;
- that helper copies payload bytes into a new vector;
- hint detectors then operate on a span over the copied payload.

Byte need:

- ARP: header-only plus variable sender/target address fields;
- IGMP: IPv4 header plus IGMP header/body prefix;
- TCP/UDP hints: transport payload, currently as an owned copied vector.

Copy behavior:

- yes, for TCP/UDP transport payload classification;
- no, for direct ARP / IGMP packet-byte inspection.

### `PacketPayloadService`

File:

- [src/core/services/PacketPayloadService.cpp](../src/core/services/PacketPayloadService.cpp)

Behavior:

- parses envelope/header bounds;
- returns a new `std::vector<std::uint8_t>` copy of transport payload;
- also used later for packet-details payload extraction.

Byte need:

- header parsing plus exact payload-range computation.

Copy behavior:

- always copies the selected payload range into a new vector.

### QUIC Initial hint / SNI state

Files:

- [src/core/services/FlowHintService.cpp](../src/core/services/FlowHintService.cpp)
- [src/core/services/QuicInitialParser.h](../src/core/services/QuicInitialParser.h)

Behavior:

- QUIC detection first works over copied UDP payload bytes;
- when client-initial SNI assembly is enabled, per-flow QUIC state stores `initial_payloads`;
- each payload fragment is copied into `std::vector<std::uint8_t>`.

Stored result:

- protocol hint / version / service hint metadata only;
- no long-lived reference into reader-owned bytes.

### ARP handling

Import-time ARP touches bytes in two ways:

- `PacketDecoder` recognizes ARP and emits a flow key;
- fallback ARP ingestion path in `CaptureImportProcessor` may call `PacketDetailsService` if normal decode did not recognize it cleanly.

Byte need:

- ARP header and variable-length address fields.

Storage:

- only metadata and hints.

### IGMP handling

Import-time IGMP touches bytes in:

- `PacketDecoder` to classify IGMP flow key and effective group address;
- `FlowHintService::detect_igmp_hint(...)` for protocol/service hints;
- unrecognized classification if malformed/truncated.

Byte need:

- IPv4 header with correct IHL;
- IGMP header/body prefix.

Storage:

- only metadata and hints.

### Unrecognized-packet handling

Import-time unrecognized classification in `classify_unrecognized_packet_reason(...)` inspects:

- link envelope;
- MPLS structure;
- ARP lengths;
- IPv4 header bounds;
- IPv6 header bounds;
- TCP / UDP / ICMP / IGMP truncation status.

Byte need:

- enough bytes to reason about where parsing stopped;
- no byte persistence afterward.

### IPv4 Options / TCP Options / MPLS implications

These do not create separate import-time owned byte caches, but they make early staged reading trickier:

- IPv4 Options mean transport offset is not fixed;
- TCP Options mean payload start is not fixed and malformed option lengths can still be semantically important;
- MPLS means inner payload offsets are not fixed and can require multiple label steps before network parsing;
- IGMP and ARP can be fully recognized without transport payload, but only if enough protocol header bytes are present.

This is the main reason that staged prefix/full reading is broader than it first appears.

## 3. Non-import consumers of `read_next()`

Production non-import callers:

- `FlowExportService::export_marked_packets_to_pcap(...)`
- `FlowExportService::export_owned_packets_to_pcaps(...)`
- `ChunkedCaptureImporter` import/resume path

Files:

- [src/core/services/FlowExportService.cpp](../src/core/services/FlowExportService.cpp)
- [src/core/services/ChunkedCaptureImporter.cpp](../src/core/services/ChunkedCaptureImporter.cpp)

Notes:

- flow export paths consume full `RawPcapPacket.bytes` and write them immediately;
- chunked import reuses the same import processor and therefore the same byte-consumption model;
- tests and fixture helpers also call `read_next()`, but they are not production hot spots.

## 4. Likely static hot spots and waste

### 4.1 Full captured packet read during import

Current import always reads the entire captured packet into memory for every packet, even though most persisted import output is metadata only.

Most important consequence:

- large captures with large payload-bearing packets pay full capture-byte I/O and allocation cost during import even when later details remain on-demand.

### 4.2 PCAPNG extra allocation/copy

`PcapNgReader::read_next()` allocates:

- full block remainder;
- per-packet byte vector;
- then copies packet bytes.

This is a clear static inefficiency for large `pcapng` inputs.

### 4.3 Transport payload vector copy in hint detection

That import-time copy has now been removed for `FlowHintService`.

Current state:

1. parse packet bounds;
2. build a non-owning payload span/view into the current packet bytes;
3. run hint detection over that span;
4. only specialized downstream paths such as retained QUIC Initial assembly still copy when they intentionally need ownership.

### 4.4 Repeated `FlowHintService::detect(...)` after hints are already stable

`CaptureImportProcessor::process_packet(...)` still calls `hint_service_.detect(...)` for every non-fragment TCP/UDP packet in recognized flows.

`Connection::apply_hints(...)` only fills fields while they are unknown/empty, but the expensive detection work is still repeated even after:

- protocol hint is known;
- service hint is known;
- TLS / QUIC version hints are known.

This is the smallest obvious waste on the current import path.

### 4.5 Repeated later packet re-reads

Several later features reopen a reader path and re-read bytes on demand:

- packet details;
- protocol details text;
- payload hex;
- selected-flow payload cache building;
- QUIC/TLS selected-flow presentation.

That is architecturally intentional, but it means selected-flow latency on large files is still sensitive to repeated random-access reads.

### 4.6 Logging / progress path

Open progress updates are packet-counted and callback-driven every 1000 packets in `CaptureImportProcessor`.

Static read:

- this does not look like the main hot spot;
- bytes processed are counted from `packet->bytes.size()`;
- default noisy perf logging is not enabled by default.

So progress is worth keeping in mind, but it is not the first optimization target.

## 5. Phase options

### A. Short-circuit repeated `FlowHintService::detect`

Status:

- implemented as the first optimization pass.

Idea:

- stop calling expensive hint detection once a connection already has the hints this pass can realistically add.

Implemented behavior:

- TCP/UDP packets with `payload_length == 0` no longer invoke import-time hint detection;
- connections with settled hint state no longer invoke import-time hint detection;
- unresolved payload-bearing TCP/UDP hint attempts stop after `10` attempts per connection.

Expected benefit:

- immediate import-time CPU reduction on long TCP/UDP flows;
- no reader rewrite;
- no byte-ownership rewrite;
- no export/index/session API change.

Risk:

- low if gating conditions are conservative;
- moderate only if detection is skipped too early and blocks later useful service hints.

Affected areas:

- [src/core/services/CaptureImportProcessor.cpp](../src/core/services/CaptureImportProcessor.cpp)
- possibly a tiny helper near connection hint state

Tests to focus:

- flow hint tests;
- QUIC/TLS recognition tests;
- service-hint regression fixtures;
- partial ARP/IGMP/unrecognized behavior should remain unchanged.

Rollback:

- trivial; remove the guard and restore always-detect behavior.

Behavior/API impact:

- none intended;
- purely import-time work reduction.

### B. Remove or reduce transport-payload copies in hint detection

Idea:

- change hint detection to use spans/views into packet bytes instead of always materializing a new payload vector.

Status:

- implemented for import-time `FlowHintService` payload inspection;
- broader vector-removal for other later consumers remains deferred.

Observed intended benefit:

- per-packet allocation/copy reduction for TCP/UDP imports;
- especially helpful on large payload captures where hint detection previously copied payloads that were only read once.

Residual risk:

- low to medium;
- shared payload-boundary logic is now reused by both the view helper and the legacy vector helper, so regressions would affect both paths and need fixture coverage.

Affected areas:

- [src/core/services/PacketPayloadService.cpp](../src/core/services/PacketPayloadService.cpp)
- [src/core/services/FlowHintService.cpp](../src/core/services/FlowHintService.cpp)

Tests to focus:

- all hint-recognition suites;
- IPv4 options / IPv6 extension / MPLS / truncation fixtures;
- packet payload tests.

Rollback:

- moderate but straightforward; reintroduce vector-return helper.

Behavior/API impact:

- likely local API churn in payload helpers;
- still no user-facing behavior change intended.

### C. Reader scratch-buffer / packet-buffer reuse during import

Idea:

- keep external behavior similar, but reduce repeated allocations inside reader/import loops through reusable scratch buffers.

Expected benefit:

- allocation churn reduction;
- especially helpful for classic pcap sequential import;
- can also reduce pcapng block-storage churn.

Risk:

- medium to high;
- easy to accidentally change ownership/lifetime assumptions;
- `RawPcapPacket` currently returns owning vectors by value.

Affected areas:

- [src/core/io/PcapReader.cpp](../src/core/io/PcapReader.cpp)
- [src/core/io/PcapNgReader.cpp](../src/core/io/PcapNgReader.cpp)
- maybe import-only helper wrappers

Tests to focus:

- import/open tests;
- export paths using `read_next()`;
- chunked import resume;
- malformed reader tests.

Rollback:

- moderate; reader internals are shared by import and export.

Behavior/API impact:

- should stay local, but lifetime mistakes here are high-risk.

### D. Prefix-budget / staged prefix-full packet reading

Idea:

- read only an initial prefix during import for most packets, then fall back to full read only when a consumer actually needs more.

Expected benefit:

- largest long-term I/O reduction opportunity for very large captures;
- strongest alignment with metadata-first import.

Risk:

- high;
- affects reader contract, decoder assumptions, hinting, ARP/IGMP/unrecognized classification, truncation semantics, progress accounting, export invariants, and later debugging.

Affected areas:

- readers;
- import processor;
- decoder;
- hint service;
- unrecognized classification;
- likely test fixtures across many protocols.

Tests to focus:

- import/open;
- ARP / IGMP / MPLS / IPv4 options / TCP options;
- malformed packet handling;
- unrecognized packets;
- partial-open behavior;
- progress and cancel behavior.

Rollback:

- expensive.

Behavior/API impact:

- broad, even if intended to be transparent.

### E. Optional mmap-backed random access behind existing abstractions

Idea:

- keep sequential import model intact, but improve later random-access packet reads behind `CaptureFilePacketReader` / `PacketDataReader`.

Expected benefit:

- helps packet details, stream building, selected-flow caches, exports, and repeated packet reads;
- useful for large-file selected-flow latency.

Risk:

- medium to high;
- cross-platform complexity;
- different failure modes and lifetime concerns;
- not the smallest first pass.

Affected areas:

- byte-source / packet-data reader abstraction layer;
- possibly source-capture attachment and session lifetime rules.

Tests to focus:

- packet details;
- payload/protocol details;
- stream building;
- export;
- source attach / reopen / unavailable source behavior.

Rollback:

- moderate if cleanly kept behind current abstractions.

Behavior/API impact:

- should be backend-only, but operational complexity is non-trivial.

## 6. Recommended first implementation pass

Recommended first pass: **A. short-circuit repeated `FlowHintService::detect` once connection hint state is already settled enough that this import packet cannot add new user-visible value**.

Why this first:

- smallest safe surface area;
- no reader changes;
- no ownership/lifetime changes;
- no index changes;
- no export changes;
- no packet-details or stream changes;
- directly reduces repeated work on long TCP/UDP flows;
- easy rollback if any hint regression is found.

Why not staged prefix/full reads first:

- that path is the most architecturally promising, but it is not the safest first move;
- current import-time parsing correctness for MPLS, IPv4 options, TCP options, IGMP, ARP fallback, and unrecognized classification still assumes access to the currently captured bytes;
- staged reads would broaden the change from “less repeated work” into “new reader/import contract”.

## 7. Acceptance criteria and invariants

Any first optimization pass should preserve these invariants:

- `RawPcapPacket` ownership remains local to current reader/import/export call sites.
- `CaptureState` still stores metadata only, not payload bytes.
- Saved indexes still store only `PacketRef` metadata and source info.
- `PacketRef.byte_offset`, `captured_length`, and `original_length` remain exact.
- Flow export behavior and output format remain unchanged.
- Chunked import behavior remains unchanged.
- Selected-flow stream, packet details, payload hex, and protocol details still re-read from source capture as they do today.
- Partial-open and malformed/unrecognized packet behavior remain unchanged.
- No new global background analysis is introduced.

Acceptance criteria for recommended pass A:

- no change in user-visible hints on existing fixtures;
- fewer `FlowHintService::detect(...)` calls on long stable flows by inspection/instrumentation;
- no change to index format or exported packet bytes;
- no regression in ARP / IGMP / QUIC / TLS hint coverage.

## 8. Phased roadmap after the current passes

1. Re-measure import CPU and large-flow responsiveness after passes A and B together.
2. If import allocation churn still dominates, evaluate pass C for reader-local scratch reuse.
3. Only after that, design pass D as a dedicated reader-contract change with explicit protocol-fixture coverage.
4. Treat pass E as a separate random-access optimization track for selected-flow latency, not as an import rewrite.

## 9. Bottom line

Current architecture already does one important thing right for large files:

- raw bytes are not persisted into runtime capture state or index files.

Current biggest static wastes are:

- full captured-packet read during import;
- pcapng extra allocation/copy;
- repeated hint detection after connection hints are already stable.

The copied transport-payload vector on the flow-hint path is no longer one of those wastes; the remaining large items are still full import-time packet reads and pcapng block-copy overhead.

The safest initial wins were reducing repeated hint work, removing unnecessary hint-path payload copies, and keeping staged prefix import limited to large classic packets while preserving the current reader/import ownership model for ordinary traffic.

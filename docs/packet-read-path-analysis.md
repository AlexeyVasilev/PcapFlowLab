# Packet Read Path Analysis

This note maps the current packet-byte flow starting at `PcapReader::read_next()` and `PcapNgReader::read_next()` before any reader/import optimization.

## Scope

- No code changes were made for this analysis.
- Focus is the current open/import path and the production callers that consume `read_next()`.
- Goal: understand byte ownership, lifetime, and optimization risk before touching the reader/import path.
- Follow-up architecture work for unifying packet traversal is now documented separately in `docs/dissection-engine-rfc.md`; this note remains about the current production byte path only.

## 1. Current call chains from `read_next()`

### Main open/import chain

Classic pcap:

1. `CaptureSession::open_capture(...)`
2. `CaptureImporter::import_capture_result(...)`
3. `import_capture_from_path(...)`
4. `PcapReader::open(...)`
5. `import_capture_from_reader(PcapReader&, ...)`
6. `import_packets(...)`
7. `PcapReader::read_next()`
8. `CaptureImportProcessor::process_packet(...)`
9. `PacketDecoder::decode(...)`
10. `PacketIngestor::ingest(...)`
11. `FlowHintService::detect(...)`
12. `Connection::apply_hints(...)`
13. `CaptureSession::state_ = imported_state`

Pcapng:

1. `CaptureSession::open_capture(...)`
2. `CaptureImporter::import_capture_result(...)`
3. `import_capture_from_path(...)`
4. `PcapNgReader::open(...)`
5. `import_capture_from_reader(PcapNgReader&, ...)`
6. `import_packets(...)`
7. `PcapNgReader::read_next()`
8. `CaptureImportProcessor::process_packet(...)`
9. `PacketDecoder::decode(...)`
10. `PacketIngestor::ingest(...)`
11. `FlowHintService::detect(...)`
12. `Connection::apply_hints(...)`
13. `CaptureSession::state_ = imported_state`

### Chunked import chain

`ChunkedCaptureImporter` uses the same processing path:

1. `ChunkedCaptureImporter::import_chunk(...)` / `resume_chunk(...)`
2. `import_from_checkpoint(...)`
3. `PcapReader::read_next()` or `PcapNgReader::read_next()`
4. `CaptureImportProcessor::process_packet(...)`
5. `PacketDecoder` + `PacketIngestor` + `FlowHintService`
6. checkpoint state is serialized later by `ImportCheckpointWriter`

### Other production callers of `read_next()`

These are not part of open/import, but they matter for ownership-risk analysis because they also depend on `RawPcapPacket.bytes`:

- `FlowExportService::export_marked_packets_to_pcap(...)`
  - `read_next()` -> `PcapWriter::write_packet(...)`
- `FlowExportService::export_owned_packets_to_pcaps(...)`
  - `read_next()` -> buffered per-flow serializer / file append

These export paths currently consume the full owning `bytes` vector directly.

## 2. What `RawPcapPacket.bytes` is and how long it lives

`RawPcapPacket` currently contains:

- packet metadata
- `data_offset`
- `data_link_type`
- owning `std::vector<std::uint8_t> bytes`

### Reader-side ownership

`PcapReader::read_next()`:

- allocates one `std::vector<std::uint8_t>` of `included_length`
- reads packet bytes directly into it
- moves that vector into `RawPcapPacket`

`PcapNgReader::read_next()`:

- allocates `remaining` for the whole block payload
- copies the captured packet bytes out of that block into a second `std::vector<std::uint8_t>`
- moves that second vector into `RawPcapPacket`

So `pcapng` currently pays both:

- block-body allocation
- per-packet captured-bytes allocation/copy

### Import-path lifetime

In the import loop, `read_next()` returns `std::optional<RawPcapPacket>` by value. The owning packet object lives only for the current loop iteration inside `import_packets(...)`.

Within that iteration:

- `PacketDecoder::decode(...)` reads `packet.bytes` through a local `std::span`
- `CaptureImportProcessor::process_packet(...)` also passes a local `std::span` to `FlowHintService::detect(...)`

After `process_packet(...)` returns, the only things persisted into `CaptureState` are metadata objects:

- `PacketRef`
- `FlowKey`
- connection/flow counters
- protocol/service/version hints

`CaptureState` does **not** store `RawPcapPacket.bytes`, a pointer into it, or a span into it.

### Stored references vs stored copies

Current import path does **not** store references/spans/pointers into `RawPcapPacket.bytes`.

What it does store:

- `PacketRef.byte_offset`
- `PacketRef.captured_length`
- `PacketRef.original_length`
- `PacketRef.payload_length`
- `PacketRef.tcp_flags`

Those fields are copied into flows and later serialized into indexes.

### One important exception: QUIC Initial SNI state

`FlowHintService` has mutable per-flow QUIC Initial state used during import:

- `quic_initial_ipv4_states_`
- `quic_initial_ipv6_states_`

When QUIC Initial SNI assembly is enabled, it does **not** keep a span into `RawPcapPacket.bytes`; it copies UDP payload bytes into:

- `std::vector<std::vector<std::uint8_t>> initial_payloads`

That means current QUIC multi-packet hinting is ownership-safe relative to a temporary packet buffer, but it also introduces an explicit payload copy at import time.

## 3. Where raw bytes are consumed

### During open/import

`PacketDecoder::decode(...)`

- consumes `packet.bytes`
- no allocation on the happy path
- no persistent byte ownership afterward

`FlowHintService::detect(...)`

- consumes `packet.bytes`
- first calls `PacketPayloadService::extract_transport_payload(...)`
- that helper allocates a **new vector copy** of the transport payload
- hint detectors then work on a span over that copied payload

### During export

`FlowExportService`

- consumes `RawPcapPacket.bytes` directly from `read_next()`
- writes them immediately to output
- does not keep a long-lived reference after the iteration

### After import/open completes

Later features do **not** reuse import-time `RawPcapPacket.bytes`. They re-read from the source capture using `PacketRef.byte_offset` and `PacketRef.captured_length`.

The re-read path is:

1. `CaptureSession::read_packet_data(const PacketRef&)`
2. `CaptureFilePacketReader`
3. `PacketDataReader`
4. `IByteSource::read_at(...)`

This path is used by:

- packet details
- packet hex dump
- packet payload hex dump
- protocol details analyzers
- selected-flow packet cache
- on-demand QUIC service-hint derivation
- TLS/QUIC stream presentation helpers
- reassembly

So import-time bytes do not survive, but `PacketRef` offsets must remain correct because many later consumers depend on re-reading full captured bytes from the source file.

## 4. Byte requirement by stage

### Reader

`PcapReader::read_next()`

- currently reads full captured bytes
- classic pcap format itself does not force deeper parse here

`PcapNgReader::read_next()`

- currently reads the full EPB body
- validates the trailer
- then copies the captured packet bytes out

### Link / network / transport decode

`PacketDecoder::decode(...)`

- needs more than a tiny fixed prefix
- effectively needs enough captured bytes to:
  - parse link-layer envelope
  - parse IPv4/IPv6 headers
  - parse TCP/UDP headers
  - compute payload boundaries using captured size and nominal lengths
- current implementation uses actual captured-byte extent for conservative truncation handling

Classification:

- needs header bytes plus enough captured bytes to validate transport-header bounds
- not naturally “no bytes”
- not currently written as a prefix-budgeted stage

### Flow key construction / packet metadata population

`PacketDecoder::decode(...)` + `PacketIngestor::ingest(...)`

- flow key construction needs only parsed header information
- `PacketIngestor` itself needs no bytes after decode

Classification:

- decode needs header-range bytes
- ingestor needs no bytes after earlier decoding

### Protocol hint extraction

`FlowHintService::detect(...)`

- always copies the transport payload first
- TCP hint path tries:
  - DNS-over-TCP
  - TLS
  - HTTP
  - SSH
  - SMTP
  - POP3
  - IMAP
  - BitTorrent
- UDP hint path tries:
  - mDNS
  - DNS
  - QUIC
  - DHCP
  - STUN

Classification:

- requires transport payload bytes
- many checks need only a prefix
- some checks may need a larger prefix:
  - TLS SNI parsing
  - QUIC Initial parsing / decryption / crypto prefix assembly
  - HTTP header scan until end-of-headers

### TLS / QUIC per-packet enrichment during import

There is **no** packet-details text generation during import.

What import does perform:

- TLS hint detection (`FlowHintService`)
  - protocol hint
  - TLS version hint
  - optional SNI/service hint
- QUIC hint detection (`FlowHintService`)
  - protocol hint
  - QUIC version hint
  - optional multi-packet Initial SNI assembly

Classification:

- payload bytes required
- currently done during import

### Packet text / packet details / protocol analyzers

Not part of open/import.

These happen later on-demand through `CaptureSession::read_packet_data(...)`.

Classification:

- no bytes required during import
- full captured bytes re-read later when needed

## 5. Copies, moves, and persistence summary

### `PcapReader::read_next()`

- allocates packet `bytes`
- moves `bytes` into `RawPcapPacket`
- no second packet-byte copy in the reader itself

### `PcapNgReader::read_next()`

- allocates `remaining` block buffer
- allocates packet `bytes`
- copies captured bytes from `remaining` into `bytes`
- moves `bytes` into `RawPcapPacket`

### `PacketDecoder`

- reads through span only
- no stored references
- no persistent byte ownership

### `FlowHintService`

- copies transport payload into a fresh vector via `PacketPayloadService`
- may additionally copy QUIC Initial UDP payloads into per-flow state
- stores no span/reference into `RawPcapPacket.bytes`

### `CaptureState`

- stores only metadata and hints
- no packet-byte ownership

### Later session features

- re-read from capture file on demand
- do not depend on import-time byte buffers surviving

## 6. Early-stop and over-work opportunities in the current code

These are observations only; nothing was changed.

### 1. Repeated hint detection after the connection already has stable hints

`CaptureImportProcessor::process_packet(...)` calls `FlowHintService::detect(...)` for every non-fragmented TCP/UDP packet.

`Connection::apply_hints(...)` only fills fields if they are still unset:

- protocol hint only if unknown
- service hint only if empty
- version hints only if unknown

So once a connection already has:

- stable protocol hint
- stable service hint
- stable TLS/QUIC version hint

the code still keeps:

- extracting payload
- trying protocol detectors
- possibly parsing TLS/HTTP/etc again

This is a concrete current early-stop opportunity.

### 2. Per-packet transport-payload copy during hint detection

`FlowHintService::detect(...)` always goes through `PacketPayloadService::extract_transport_payload(...)`, which allocates and copies the transport payload into a new vector before any detector runs.

That means current import does:

1. reader allocates packet bytes
2. decoder reads packet bytes
3. hint service copies payload bytes again

This is probably the most obvious import-path byte-copy hot spot after the reader itself.

### 3. Unified import currently uses one decode + hint path

`CaptureImporter` currently uses one shared decode + hint path for capture open.

So there is no separate staged fast-vs-deep packet-details path in the current design.

### 4. Pcapng reader does more byte work than classic pcap reader

Current `PcapNgReader::read_next()` allocates the whole remaining block payload and then copies packet bytes out again.

That is a concrete extra-cost point compared with classic pcap.

## 7. Optimization risk points

### Reusable scratch buffer inside the reader

#### What looks safe

For the open/import path alone, a reusable scratch buffer looks **structurally safe** because:

- `PacketDecoder` does not retain references
- `PacketIngestor` stores only copied metadata
- `FlowHintService` does not retain spans into packet bytes
- QUIC multi-packet hinting stores copied payload vectors, not views

So within `import_packets(...)`, packet bytes are effectively iteration-local.

#### What makes a drop-in replacement risky

`read_next()` is also used by:

- `ChunkedCaptureImporter`
- `FlowExportService::export_marked_packets_to_pcap(...)`
- `FlowExportService::export_owned_packets_to_pcaps(...)`

Those paths also consume bytes synchronously and do not appear to retain views after the iteration, but they currently rely on `RawPcapPacket` being an owning object.

Changing `RawPcapPacket.bytes` from owning storage to a non-owning scratch view would therefore be an API-level behavior change that touches:

- reader call sites
- tests that build or compare `RawPcapPacket`
- any future code that assumes `RawPcapPacket` is self-contained

Conclusion:

- import-only scratch-buffer usage looks safe
- a global semantic change to `RawPcapPacket.bytes` is higher risk

### Passing spans/views instead of owning vectors

#### Low-risk direction

Inside import, replacing the payload copy in `FlowHintService` with:

- offset/length computation
- span views over the current packet buffer

looks much safer than changing reader ownership first.

#### Risk

Any span-based API must remain strictly iteration-local.
It cannot be cached in:

- `CaptureState`
- connection objects
- flow objects
- checkpoint/index serialization structures

The current code already respects that boundary, but a refactor would need to preserve it carefully.

### Staged prefix-read + optional full-read

This is the riskiest of the discussed reader-side options in the current code.

Reasons:

1. `PacketDecoder::decode(...)` currently uses actual captured-byte extent as part of conservative bounds behavior.
2. `FlowHintService::detect(...)` expects immediate access to transport payload bytes.
3. Some hints require more than a tiny prefix:
   - TLS SNI
   - HTTP host/path
   - QUIC Initial SNI assembly/decryption
4. `PcapNgReader` currently validates and walks whole block bodies, not just a packet prefix.
5. Later consumers rely on `PacketRef.byte_offset` + `captured_length` to re-read full bytes, so any staged path must still preserve exact offsets and lengths.

A staged prefix/full design is possible in principle, but current code is not structured around explicit “prefix budgets” or “need more bytes” escalation points.

### Stopping deeper analysis once hints already exist

This looks relatively low risk because:

- `Connection::apply_hints(...)` already treats hints as fill-once
- fast/deep import currently do no later import-time work that depends on repeating the same hint detection forever

The main caution is QUIC service hint assembly:

- some flows need up to a few Initial packets before service hint becomes available
- stopping too early for QUIC would have to be state-aware, not just “protocol already known”

## 8. Practical recommendation

### Recommendation

**Option D: optimize in two smaller steps before any staged prefix/full read design.**

Recommended sequence:

1. First reduce avoidable import-path work **without changing reader ownership semantics**:
   - stop calling the full hint-detection chain once a connection already has the needed stable hints
   - remove the per-packet transport-payload vector copy in `FlowHintService` and operate on packet-local spans/offsets instead
2. Then, if more improvement is still needed, add an **import-only** scratch-buffer reader/processor path rather than changing `RawPcapPacket.bytes` semantics globally.
3. Leave staged prefix/full reads for later, after explicit prefix-budget boundaries exist in decode and hinting code.

### Why this is the best first step in the current code

- The current import path already drops packet bytes immediately after processing, so import-local lifetime is favorable.
- But `read_next()` is shared with export paths, so changing its ownership model globally is not the smallest-risk first move.
- There is already a clear, concrete copy hotspot in `FlowHintService` on every hinted packet.
- There is also a clear repeated-work hotspot where hint detection continues after the connection already has stable values.
- Staged prefix/full reads would require larger structural changes because decode and hint code are not currently organized around partial-byte escalation.

So the safest first optimization is **not** staged reading, and **not** a global `RawPcapPacket` ownership rewrite.
The safest first optimization is to cut the avoidable work *inside the current import pipeline*, then consider an import-specific scratch-buffer path.

## 9. Bottom line

- Import-time packet bytes are short-lived and are not stored in `CaptureState`.
- Later session features re-read bytes from the source capture using `PacketRef.byte_offset`.
- A reusable scratch buffer looks safe for the import path, but risky as a drop-in semantic replacement for every `read_next()` consumer.
- Staged prefix/full reading is feasible only after refactoring decode/hint stages around explicit byte budgets; today it is the riskier path.
- The best first optimization target is the current import-time repeated hint work and payload-copy churn, not the staged-read design.

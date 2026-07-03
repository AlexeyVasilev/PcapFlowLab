# Overlay Inner Flow Tuple Branch

## Goal

Add support for common encapsulation protocols that appear above outer UDP and carry an inner IPv4/IPv6 plus TCP/UDP packet, so Pcap Flow Lab can build flows from the effective inner 5-tuple.

This branch is intentionally focused on UDP-based overlays first.

Target protocols:

1. VXLAN
2. Geneve
3. GTP-U

## Non-goals

This branch does not aim to:

- extend flow identity with tunnel namespace fields such as VNI, TEID, or GRE key;
- solve flow-key collisions across different tunnel namespaces;
- add decapsulated export;
- add outer-plus-inner dual flow table modes;
- add full tunnel session tracking;
- parse encrypted tunnel payloads;
- add application-layer parsers beyond existing inner IPv4/IPv6 TCP/UDP handling;
- make open/import materially more expensive through deep recursive packet materialization.

## Known limitation: tunnel namespace collisions

The initial branch rule is to use the deepest successfully decoded inner IPv4/IPv6 plus TCP/UDP tuple as the effective flow tuple.

This can merge traffic from different tunnel namespaces when the inner tuple is identical. Example:

- VXLAN VNI 100 inner `10.0.0.1:1234 -> 10.0.0.2:443`
- VXLAN VNI 200 inner `10.0.0.1:1234 -> 10.0.0.2:443`

Both would currently collapse to the same flow if only the inner 5-tuple is used.

Accepted branch limitation:

- initial flow grouping uses only the effective deepest inner IPv4/IPv6 plus TCP/UDP tuple;
- future flow identity should include an optional tunnel discriminator such as VXLAN VNI, Geneve VNI, GTP-U TEID, GRE key, or similar namespace metadata.

## Effective tuple rule

The intended tuple rule for this branch is:

- if no supported overlay is present, keep current tuple behavior;
- if a supported overlay is present and an inner IPv4/IPv6 plus TCP/UDP tuple is successfully decoded, use the inner tuple as the effective flow tuple;
- if overlay parsing succeeds but the inner packet does not yield a valid IPv4/IPv6 plus TCP/UDP tuple, stay conservative and do not fabricate a normal flow.

Expected initial protocol shapes:

- VXLAN: outer IPv4/IPv6 -> UDP/4789 -> VXLAN -> inner Ethernet -> inner IPv4/IPv6 -> TCP/UDP
- Geneve: outer IPv4/IPv6 -> UDP/6081 -> Geneve -> inner Ethernet -> inner IPv4/IPv6 -> TCP/UDP
- GTP-U: outer IPv4/IPv6 -> UDP/2152 -> GTP-U -> inner IPv4/IPv6 -> TCP/UDP

## Current tuple construction path

Current flow-key construction is concentrated in the import/decode path:

- `src/core/decode/PacketDecoder.cpp`
  - `PacketDecoder::decode(...)`
  - calls `detail::parse_network_payload(...)` to resolve Ethernet/L2 shim continuation;
  - then directly builds `FlowKeyV4` or `FlowKeyV6` from the resolved network packet and transport header;
  - today the decoder stops at ARP / IPv4 / IPv6 plus TCP / UDP / ICMP / IGMP / ICMPv6.
- `src/core/services/CaptureImportProcessor.cpp`
  - consumes `DecodedPacket`;
  - passes `IngestedPacketV4` / `IngestedPacketV6` to `PacketIngestor`;
  - hint detection then runs on the chosen flow key.
- `src/core/services/PacketIngestor.cpp`
  - inserts into `state.ipv4_connections` / `state.ipv6_connections` using `make_connection_key(...)`.
- `src/core/domain/Connection.cpp`
  - stores per-direction packets under the chosen flow key.

This means the smallest place to change effective flow tuple behavior is `PacketDecoder::decode(...)`, before `DecodedPacket` is returned to the importer.

## Current L2/L3 shim continuation model

Existing shim work already established a useful continuation pattern:

- `src/core/decode/PacketDecodeSupport.h`
  - `parse_network_payload(...)` resolves Ethernet / VLAN / LLC-SNAP / MPLS / PPPoE / PBB style continuation;
  - bounded inner payloads are represented through:
    - `protocol_type`
    - `payload_offset`
    - optional `bounded_packet_end`
- `src/core/services/PacketDetailsService.cpp`
  - keeps outer layers in `PacketDetails`;
  - then continues decode into resolved inner payload;
  - already supports preserving outer and inner layers for MPLS pseudowire, PBB, PPPoE, LLC/SNAP, and similar shim cases.

This is the main design precedent for UDP overlay work.

## Recommended parser insertion point

Recommended first insertion point:

- extend `PacketDecoder::decode(...)` in the outer UDP paths only;
- after outer IPv4/IPv6 and UDP header validation succeeds, but before the final `FlowKeyV4` / `FlowKeyV6` is returned;
- attempt bounded overlay resolution only for the known ports:
  - VXLAN `4789`
  - Geneve `6081`
  - GTP-U `2152`

Recommended structure:

1. Keep existing outer Ethernet/L2/L3 shim resolution unchanged.
2. In the IPv4 UDP / IPv6 UDP branches, call a small helper such as:
   - `resolve_udp_overlay_inner_tuple(...)`
3. That helper should:
   - validate the overlay header conservatively;
   - derive bounded inner payload offsets;
   - for VXLAN/Geneve, continue through inner Ethernet using the same Ethernet continuation helpers already used elsewhere;
   - for GTP-U, continue directly to inner IPv4/IPv6;
   - if a valid inner IPv4/IPv6 plus TCP/UDP tuple is found, return an effective inner flow key and payload metadata;
   - otherwise return no inner tuple and let the current outer UDP behavior stand or remain conservative, depending on the final per-protocol policy.

Why this is the safest initial insertion point:

- it changes the effective tuple before import/connection tables are touched;
- it reuses current bounded decode patterns;
- it does not require controller, UI, or DTO redesign to start supporting inner flow grouping;
- it keeps tunnel parsing on the import/decode hot path, where the tuple decision already lives.

## Recommended Packet Details representation

`PacketDetailsService.cpp` already demonstrates the right pattern:

- preserve outer Ethernet / VLAN / IPv4 / IPv6 / UDP layers;
- append overlay-specific layer details;
- continue into inner Ethernet or inner IPv4/IPv6 details when bounded inner payload is valid.

Recommended initial representation:

- add protocol-specific detail structs for:
  - VXLAN
  - Geneve
  - GTP-U
- keep them narrow:
  - presence flag
  - available header bytes
  - truncation flag(s)
  - discriminator metadata:
    - VXLAN VNI
    - Geneve VNI
    - GTP-U TEID
  - bounded inner payload offsets / lengths as needed for decode and presentation

For VXLAN and Geneve:

- reuse the existing inner Ethernet presentation pattern already used for:
  - MPLS pseudowire
  - PBB
- continue with:
  - `has_inner_ethernet`
  - `inner_ethernet`
  - existing inner Ethernet continuation helpers where practical

For GTP-U:

- no inner Ethernet layer is required in the common case;
- preserve outer UDP plus GTP-U layer, then continue directly into inner IPv4/IPv6.

This avoids a broad data-model redesign while still letting Packet Details show both outer and inner protocol stacks.

## Protocol hint / tunnel summary expectations

The branch should distinguish two concepts:

1. effective flow tuple for grouping;
2. tunnel metadata for presentation.

Recommended initial rule:

- keep grouping based on the effective inner tuple when available;
- keep tunnel metadata in packet details / summary layers first;
- do not make flow identity depend on VNI/TEID yet;
- avoid overloading `protocol_hint` with tunnel namespace identity in this first pass.

Conservative expectation for flow-list hints:

- if existing inner traffic already yields a stronger app/protocol hint such as DNS/TLS/QUIC/HTTP, keep that existing hint path;
- tunnel metadata such as VXLAN VNI, Geneve VNI, or GTP-U TEID should appear first in selected-packet Summary / Protocol details, not as a replacement for the inner app hint;
- if a later branch wants combined wording such as `VXLAN (VNI 100)` or `GTP-U (TEID ...)`, that should be added as presentation metadata, not flow identity.

## Test and fixture plan

Recommended pattern should mirror the recent L2/L3 shim work:

Fixture directories:

- `tests/data/parsing/vxlan/`
- `tests/data/parsing/geneve/`
- `tests/data/parsing/gtpu/`

Fixture README files:

- one README per protocol directory describing fixture intent, supported cases, malformed cases, and conservative current behavior

Unit test files:

- `tests/unit/VxlanPcapFixtureTests.cpp`
- `tests/unit/GenevePcapFixtureTests.cpp`
- `tests/unit/GtpuPcapFixtureTests.cpp`

Test registration pattern:

- add `run_*_pcap_fixture_tests()` entries in `tests/unit/test_main.cpp`, matching existing shim fixture suites such as:
  - `VlanPcapFixtureTests.cpp`
  - `PppoePcapFixtureTests.cpp`
  - `MplsPseudowirePcapFixtureTests.cpp`
  - `PbbPcapFixtureTests.cpp`
  - `MacsecPcapFixtureTests.cpp`
  - `LlcSnapPcapFixtureTests.cpp`

Recommended fixture cases per protocol:

- basic inner IPv4 TCP
- basic inner IPv4 UDP
- basic inner IPv6 TCP
- basic inner IPv6 UDP
- malformed / truncated overlay header
- malformed / truncated inner Ethernet or inner IP
- unsupported inner payload cases
- namespace-collision documentation fixture pair, if practical, even if grouping remains intentionally merged for this branch

Recommended assertion shape:

- open/import succeeds where supported;
- expected inner IPv4/IPv6 TCP/UDP flow is created from the effective inner tuple;
- selected-packet Summary shows outer UDP plus overlay layer plus inner layers;
- malformed cases stay conservative and do not fabricate normal flows;
- protocol details can show tunnel metadata and truncation warnings when present.

## Likely docs to update in later implementation steps

After each protocol is implemented, update:

- `docs/protocols/protocol_support.md`
  - support matrix row(s)
  - known limitations
  - fixture coverage section
- protocol fixture README under the new parsing directory
- optionally a short branch note or release-note draft only after behavior is actually merged

## Proposed implementation order

1. VXLAN
   - simplest mainstream UDP overlay entry point
   - clear inner Ethernet continuation model
2. Geneve
   - similar to VXLAN but with option handling and more variable header shape
3. GTP-U
   - direct inner IP continuation
   - TEID presentation
   - likely more edge cases around extension headers and message types

## Current implementation status

Implemented in this branch so far:

- VXLAN effective inner tuple extraction for valid UDP/4789 traffic carrying:
  - inner Ethernet -> IPv4 -> TCP/UDP
  - inner Ethernet -> IPv6 -> TCP/UDP
  - inner Ethernet -> VLAN -> IPv4 -> TCP when the existing inner Ethernet continuation resolves the VLAN path
- outer IPv4 and outer IPv6 VXLAN carrier paths both switch flow grouping to the decoded inner tuple
- basic VXLAN header validation is enforced:
  - UDP destination port must be `4789`
  - payload must include the fixed 8-byte VXLAN header
  - the VXLAN I flag must be set
  - reserved header bytes must be zero

Still intentionally not solved:

- VNI is not part of flow identity
- invalid/truncated/unsupported VXLAN payloads fall back to existing outer behavior instead of fabricating an inner flow
- VXLAN Packet Details / Summary currently expose lightweight metadata only:
  - outer IPv4/IPv6 and UDP presentation remains intact
  - selected-packet Summary / Protocol details now show a VXLAN layer with flags and VNI
  - when the VXLAN payload contains a bounded Ethernet header, Summary then appends sequential `Inner Ethernet`, `Inner VLAN`, `Inner IPv4` / `Inner IPv6`, and `Inner TCP` / `Inner UDP` layers as available
  - supported inner continuation now extends into bounded inner VLAN / IPv4 / IPv6 / TCP / UDP presentation for valid fixtures
  - outer IPv4/IPv6 and UDP remain the primary top-level packet details stack, followed by VXLAN and then the sequential inner continuation layers

## Risks and unknowns

- inner-tuple-only grouping can merge traffic from distinct tunnel namespaces;
- Geneve option handling may require a strict bounded parser even if options are not deeply interpreted;
- GTP-U has multiple message types and optional extension-header paths, so the first pass should stay narrow;
- hint detection currently assumes the chosen flow key already reflects the effective conversation, so tunnel parsing must happen before ingest;
- Packet Details can likely reuse current layer patterns, but summary/protocol wording will need care to keep outer and inner layers understandable without becoming noisy;
- import-time tunnel parsing must remain cheap enough for large captures and should avoid broad packet-byte materialization or deep recursive retries.

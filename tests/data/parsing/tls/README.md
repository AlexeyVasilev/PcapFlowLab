# TLS Fixture Contracts

This directory contains the current TLS PCAP fixture corpus used by multiple test layers.

The fixtures currently fall into three broad categories:

1. small single-record / handshake fixtures;
2. session and reassembly fixtures;
3. constricted/truncated fixtures.

The same fixture may support more than one test layer:

- flow detection and service hints;
- Packet Details Summary;
- Packet Details Protocol;
- stream item construction;
- stream item details;
- reassembly and packet contributions;
- import/protocol-path parity;
- Qt UI projection.

This document records the current contract only. It distinguishes facts already asserted by automated tests from expectations that still require manual Wireshark review.

## Verification terminology

- `Automated contract`: explicitly asserted by current tests.
- `Manual verification required`: useful fixture facts that are not yet asserted and should be checked in Wireshark before strengthening tests.
- `Planned contract`: a future contract that would be valuable but is not yet enforced.
- `Unknown source`: the origin of the capture has not been established in-repo.

Rules for reading this document:

- untested packet facts are not treated as established;
- TLS version, segmentation shape, record count, or source software are not inferred solely from filenames;
- filename similarity is not treated as proof of redundancy.

## Inventory

| Fixture | Category | Current consumers | Current contract strength | Unique role | Manual verification | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| `ipv4_tls_constricted_1.pcap` | Constricted/truncated | `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests`, `DissectionImportSessionParityTests` | Strong | Exact IPv4 constricted stream and UI contract | Yes | Keep for now |
| `ipv6_tls_constricted_1.pcap` | Constricted/truncated | `FlowHintsRealFixturesTests`, `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests` | Strong | Exact IPv6 constricted stream contract | Yes | Keep for now |
| `ipv6_tls_strong_constrict_1.pcap` | Constricted/truncated | `FlowHintsRealFixturesTests`, `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests` | Strong | Exact strong-constriction contribution contract | Yes | Keep for now |
| `tls_1_2_app_data_3.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS AppData hint coverage | Yes | Keep for now |
| `tls_1_2_change_cipher_spec_2.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS ChangeCipherSpec hint coverage | Yes | Keep for now |
| `tls_1_2_new_session_ticket_9.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP NewSessionTicket hint coverage | Yes | Keep for now |
| `tls_1_2_server_hello_4.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS 1.2 ServerHello hint coverage | Yes | Keep for now |
| `tls_1_3_app_data_7.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS 1.3 AppData hint coverage | Yes | Keep for now |
| `tls_1_3_change_cipher_spec_8.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS 1.3 ChangeCipherSpec hint coverage | Yes | Keep for now |
| `tls_1_3_client_hello_5.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `ImportTests` | Medium | Import/service-hint TLS ClientHello coverage | Yes | Keep for now |
| `tls_1_3_server_hello_6.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `PacketProtocolDetailsTests` | Medium | Current ServerHello protocol-details fixture | Yes | Keep for now |
| `tls_client_hello_1.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `PacketDetailsTests`, `PacketProtocolDetailsTests`, `MainControllerUiTests` | Strong | Strongest current ClientHello packet-details and UI fixture | Yes | Keep for now |
| `tls_normal_1.pcap` | Session and reassembly | `StreamQueryTests` | Medium | Current full-session stream smoke coverage | Yes | Keep for now |
| `tls_partial_tail_5.pcap` | Session and reassembly | `StreamQueryTests` | Medium | Conservative incomplete-tail coverage | Yes | Keep for now |
| `tls_server_handshake_retransmit_6.pcap` | Session and reassembly | `StreamQueryTests` | Medium | Retransmission/deduplication and multi-packet contribution coverage | Yes | Keep for now |

## Related raw fixtures

TLS byte arrays in `tests/unit/ParsingRawFixtures.h` overlap conceptually with several small PCAP fixtures:

- `tls_1_2_change_cipher_spec_2`
- `tls_1_2_app_data_3`
- `tls_1_2_server_hello_4`
- `tls_1_2_new_session_ticket_9`
- `tls_1_3_client_hello_5`
- `tls_1_3_server_hello_6`
- `tls_1_3_app_data_7`
- `tls_1_3_change_cipher_spec_8`

This overlap is not currently classified as unwanted duplication.

- Raw fixtures provide deterministic low-level input to hint detection.
- PCAP fixtures exercise reader, import, session, and UI paths.

No raw fixture or PCAP fixture should be removed in this pass.

## Cleanup policy

A TLS fixture may be removed only when all of the following are true:

1. all of its unique assertions are identified;
2. another fixture covers the same TLS shape, segmentation, and presentation behavior;
3. all consuming tests have been migrated;
4. replacement tests pass;
5. the removal is documented in this README.

Filename similarity or a matching TLS record type is not enough to prove redundancy.

## Per-fixture contracts

### ipv4_tls_constricted_1.pcap

**Category:** Constricted/truncated fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/StreamQueryTests.cpp`
  - capture opens in fast mode;
  - flow packet count is `14`;
  - stream row count is `10`;
  - exact row labels, byte counts, packet indices, and constricted-contribution notes are asserted;
  - no `TLS Gap` row is present;
  - selected AppData protocol text contains `Record Type: ApplicationData` and `Record Length: 3056`;
  - constricted packet notes appear in stream details, not in protocol text.
- `tests/ui/MainControllerUiTests.cpp`
  - Qt projection mirrors the exact stream row labels, byte counts, source packet text, and constricted-contribution flags;
  - selected stream item details show exact constricted contribution lines and packet notes;
  - no `TLS Gap` row is present.
- `tests/unit/ProtocolPathTests.cpp`
  - fixture remains a single flow/path family under current protocol-path rules.
- `tests/unit/DissectionImportSessionParityTests.cpp`
  - fixture participates in current import parity coverage.

#### Unique purpose

- Strongest current IPv4 TLS constricted stream contract.
- Anchors exact multi-packet contribution text for stream/UI projection.

#### Missing assertions

- Packet Details Summary expectations are not asserted directly for this fixture.
- Packet Details Protocol expectations are not asserted directly for this fixture.
- Wireshark-correlated record boundary notes are not encoded in tests.

#### Manual Wireshark verification required

- exact TCP payload lengths per contributing frame;
- exact TLS record boundaries across contributing packets;
- whether all asserted constricted contributions match canonical Wireshark interpretation.

### ipv6_tls_constricted_1.pcap

**Category:** Constricted/truncated fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`;
  - service hint `www.youtube.com` is present.
- `tests/unit/StreamQueryTests.cpp`
  - one flow is present with packet count `19`;
  - exact row count `9`;
  - exact labels, byte counts, source packet groupings, and constricted flags are asserted;
  - no `TLS Gap` or `TCP Payload` row is present.
- `tests/ui/MainControllerUiTests.cpp`
  - Qt stream model mirrors exact labels, byte counts, source packet text, and constricted flags;
  - selected row details show exact contribution and constricted-packet text.
- `tests/unit/ProtocolPathTests.cpp`
  - fixture remains a single flow/path family.

#### Unique purpose

- Exact IPv6 constricted stream contract with service-hint coverage.

#### Missing assertions

- Packet Details Summary expectations are not asserted directly.
- Packet Details Protocol expectations are not asserted directly.
- Exact canonical distinction from `ipv6_tls_strong_constrict_1.pcap` is not encoded.

#### Manual Wireshark verification required

- exact intended capture-constriction pattern;
- whether source-packet groupings align with canonical TLS record boundaries;
- exact intended distinction from `ipv6_tls_strong_constrict_1.pcap`.

### ipv6_tls_strong_constrict_1.pcap

**Category:** Constricted/truncated fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`;
  - service hint `www.youtube.com` is present.
- `tests/unit/StreamQueryTests.cpp`
  - one flow with packet count `19`;
  - exact row count `9`;
  - exact labels, byte counts, and stronger constricted-contribution expectations are asserted;
  - no `TLS Gap` or `TCP Payload` row is present.
- `tests/ui/MainControllerUiTests.cpp`
  - Qt projection mirrors exact rows and stronger contribution notes;
  - selected AppData details include the expected multi-packet contribution breakdown.
- `tests/unit/ProtocolPathTests.cpp`
  - fixture remains a single flow/path family.

#### Unique purpose

- Strongest current exact contract for aggressive constricted contribution reporting in IPv6 TLS streams.

#### Missing assertions

- Packet Details Summary expectations are not asserted directly.
- Packet Details Protocol expectations are not asserted directly.
- Exact semantic difference from `ipv6_tls_constricted_1.pcap` is not formally characterized.

#### Manual Wireshark verification required

- exact intended distinction from `ipv6_tls_constricted_1.pcap`;
- whether the stronger contribution notes reflect canonical record segmentation.

### tls_1_2_app_data_3.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.

#### Unique purpose

- Real-PCAP coverage for a minimal TLS AppData hint path.

#### Missing assertions

- Packet Details Summary is not tested.
- Packet Details Protocol is not tested.
- Stream label is not tested.
- Exact record type, record version, and record length are not asserted from the PCAP path.

#### Manual Wireshark verification required

- whether the fixture really contains only the intended TLS shape;
- exact record fields and packet direction;
- expected stream label and Packet Details text.

### tls_1_2_change_cipher_spec_2.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.

#### Unique purpose

- Real-PCAP coverage for a minimal TLS ChangeCipherSpec hint path.

#### Missing assertions

- Packet Details Summary is not tested.
- Packet Details Protocol is not tested.
- Stream label is not tested.
- Exact ChangeCipherSpec presentation is not asserted from the PCAP path.

#### Manual Wireshark verification required

- exact record fields, direction, and payload length;
- expected Packet Details and stream label.

### tls_1_2_new_session_ticket_9.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.

#### Unique purpose

- Only named real-PCAP fixture currently associated with NewSessionTicket intent.

#### Missing assertions

- Packet Details Summary is not tested.
- Packet Details Protocol is not tested.
- Stream label is not tested.
- Any NewSessionTicket-specific fields are unasserted.

#### Manual Wireshark verification required

- exact handshake type and record framing;
- whether the filename accurately reflects the payload;
- expected Packet Details text.

### tls_1_2_server_hello_4.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.

#### Unique purpose

- Real-PCAP TLS 1.2 ServerHello hint coverage distinct from TLS 1.3 ServerHello protocol-details coverage.

#### Missing assertions

- Packet Details Summary is not tested.
- Packet Details Protocol is not tested.
- Stream label is not tested.
- No ServerHello-specific fields are asserted from the PCAP path.

#### Manual Wireshark verification required

- exact handshake type and selected parameters;
- whether the fixture is actually the intended TLS 1.2 ServerHello artifact.

### tls_1_3_app_data_7.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.

#### Unique purpose

- Real-PCAP TLS 1.3 AppData hint coverage.

#### Missing assertions

- Packet Details Summary is not tested.
- Packet Details Protocol is not tested.
- Stream label is not tested.
- No exact AppData presentation is asserted from the PCAP path.

#### Manual Wireshark verification required

- exact record framing and payload length;
- expected stream label and Packet Details text.

### tls_1_3_change_cipher_spec_8.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.

#### Unique purpose

- Real-PCAP TLS 1.3 ChangeCipherSpec hint coverage.

#### Missing assertions

- Packet Details Summary is not tested.
- Packet Details Protocol is not tested.
- Stream label is not tested.
- No exact ChangeCipherSpec presentation is asserted from the PCAP path.

#### Manual Wireshark verification required

- exact record framing and payload length;
- expected Packet Details and stream presentation.

### tls_1_3_client_hello_5.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`;
  - service hint `p101-fmf.icloud.com` is present.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`;
  - matching raw bytes yield service hint `p101-fmf.icloud.com`.
- `tests/unit/ImportTests.cpp`
  - imported flow list contains a `tls` flow with service hint `p101-fmf.icloud.com`.

#### Unique purpose

- Current import/service-hint TLS ClientHello coverage.

#### Missing assertions

- Packet Details Summary is not tested.
- Packet Details Protocol is not tested from the PCAP path.
- Stream label is not tested.
- Exact ClientHello fields other than service hint are not asserted.

#### Manual Wireshark verification required

- exact ClientHello fields and SNI;
- expected Packet Details protocol text;
- whether this should also become a packet-details contract fixture.

### tls_1_3_server_hello_6.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.
- `tests/unit/PacketProtocolDetailsTests.cpp`
  - Packet Details Protocol contains `TLS`;
  - `Handshake Type: ServerHello`;
  - `Selected TLS Version:`;
  - `Selected Cipher Suite:`;
  - `Session ID:`.

#### Unique purpose

- Current ServerHello protocol-details fixture.

#### Missing assertions

- Packet Details Summary is not tested directly.
- Stream label is not tested.
- Exact selected-version and cipher-suite values are not asserted.

#### Manual Wireshark verification required

- exact selected TLS version and cipher suite;
- whether other ServerHello fields should become explicit automated contracts.

### tls_client_hello_1.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`;
  - service hint `auth.split.io` is present.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary layers end with `tcp` then `tls`;
  - TCP is not expanded by default;
  - TLS is expanded by default;
  - TLS title contains `Transport Layer Security`.
- `tests/unit/PacketProtocolDetailsTests.cpp`
  - Packet Details Protocol contains `TLS`;
  - `Record Type: Handshake`;
  - `Record Version:`;
  - `Handshake Type: ClientHello`;
  - `Handshake Version:`;
  - `Cipher Suites:`;
  - `Extensions:`;
  - `SNI: auth.split.io`.
- `tests/ui/MainControllerUiTests.cpp`
  - analysis pane reports protocol hint `TLS`;
  - protocol version text is non-empty;
  - service hint and protocol service text are `auth.split.io`;
  - selected packet protocol text contains TLS and the SNI.

#### Unique purpose

- Strongest current ClientHello packet-details and UI fixture.

#### Missing assertions

- Stream label is not tested from the PCAP path.
- Exact selected summary fields are not exhaustively asserted.
- Exact ClientHello extension inventory is not asserted.

#### Manual Wireshark verification required

- exact extension set;
- whether the Packet Details Summary field set matches Wireshark cleanly;
- whether this should become the canonical recorded ClientHello fixture.

### tls_normal_1.pcap

**Category:** Session and reassembly fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/StreamQueryTests.cpp`
  - capture opens in fast mode;
  - stream rows are non-empty;
  - rows contain `TLS ClientHello`, `TLS ServerHello`, and `TLS ChangeCipherSpec`;
  - client and server hello protocol text is non-empty and contains expected high-level fields;
  - at least one AppData/Payload-style row exists with non-empty protocol text and hex dump;
  - bounded prefix query excludes `HTTP` rows.

#### Unique purpose

- Current full-session stream smoke coverage.

#### Missing assertions

- Exact row count is not pinned.
- Exact packet contributions are not pinned.
- Packet Details Summary and Packet Details Protocol are not asserted directly.

#### Manual Wireshark verification required

- exact record/packet boundary characterization;
- exact row ordering and whether the smoke contract should be strengthened.

### tls_partial_tail_5.pcap

**Category:** Session and reassembly fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/StreamQueryTests.cpp`
  - rows contain `TLS ClientHello`, `TLS ServerHello`, and `TLS ChangeCipherSpec`;
  - final row is accepted as either `TLS Payload (partial)` or `TLS Record Fragment (partial)`;
  - partial protocol text is conservative and avoids rich decoded handshake/certificate fields.

#### Unique purpose

- Conservative incomplete-tail coverage.

#### Missing assertions

- Final label is intentionally permissive rather than exact.
- Exact point of truncation is not asserted.
- Packet Details coverage is absent.

#### Manual Wireshark verification required

- whether the final state should use one exact label;
- exact final record/header visibility;
- whether the current permissive alternatives are both semantically valid.

### tls_server_handshake_retransmit_6.pcap

**Category:** Session and reassembly fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Automated contract

- `tests/unit/StreamQueryTests.cpp`
  - rows include `TLS ClientHello`, `TLS ServerHello`, `TLS Certificate`, `TLS ServerKeyExchange`, and `TLS ServerHelloDone`;
  - `TLS ServerHello`, `TLS Certificate`, `TLS ServerKeyExchange`, and `TLS ServerHelloDone` each appear exactly once as rows;
  - certificate protocol text contains `Certificate Entries:` and `Leaf Certificate Size:`;
  - at least one of several handshake rows spans multiple source packets and retains protocol text.

#### Unique purpose

- Retransmission/deduplication and multi-packet contribution coverage.

#### Missing assertions

- Exact packet ordering is not fully pinned as a canonical contract.
- Exact contribution map per row is not fully asserted.
- Packet Details Summary and Packet Details Protocol coverage is absent.

#### Manual Wireshark verification required

- canonical retained packet order;
- exact retransmission relationship and source-packet contribution map;
- whether any additional dedup expectations should become explicit.

## Planned contract coverage gaps

These are useful future fixture areas, not current facts.

### Record boundaries

- multiple records in one TCP payload;
- record header split across TCP packets;
- record body split across TCP packets;
- truncated header;
- truncated body;
- invalid record length;
- unknown content type.

### Handshake boundaries

- handshake header split across TCP packets;
- handshake body split across TCP packets;
- multiple handshake messages in one record;
- handshake message spanning records;
- unsupported handshake type.

### Structured details

- ClientHello extensions;
- ServerHello selected parameters;
- Alert;
- HelloRetryRequest;
- unknown and GREASE extensions.

## Manual Wireshark inspection checklist

Use this checklist when characterizing or strengthening a TLS fixture:

- frame number;
- direction;
- TCP payload length;
- TLS record count;
- content type;
- record legacy version;
- record length;
- handshake type;
- handshake length;
- significant ClientHello/ServerHello fields;
- whether the record crosses TCP packet boundaries;
- whether several records share one TCP payload;
- expected Packet Details Summary;
- expected Packet Details Protocol;
- expected Stream label;
- expected Stream details;
- expected contributing packets.

## Known unresolved questions

- exact intended distinction between `ipv6_tls_constricted_1.pcap` and `ipv6_tls_strong_constrict_1.pcap`;
- whether the final state of `tls_partial_tail_5.pcap` should have one exact label rather than the current permissive alternatives;
- whether packet ordering in `tls_server_handshake_retransmit_6.pcap` is the canonical retained order;
- whether the small single-record captures are canonical recorded artifacts or replaceable generated assets.

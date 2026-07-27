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

This document records the current contract only. It distinguishes facts already asserted by automated tests from facts manually verified in Wireshark exports and from expectations that still require more characterization.

## Verification terminology

- `Automated contract`: explicitly asserted by current tests.
- `Manual verification required`: useful fixture facts that are not yet asserted and still need Wireshark characterization.
- `Planned contract`: a future contract that would be valuable but is not yet enforced.
- `Unknown source`: the origin of the capture has not been established in-repo.

Rules for reading this document:

- untested packet facts are not treated as established;
- TLS version, segmentation shape, record count, or source software are not inferred solely from filenames;
- when Wireshark and current PcapFlowLab presentation differ, Wireshark ground truth wins;
- Protocol is treated as a temporary legacy presentation source, not as the future UI contract;
- filename similarity is not treated as proof of redundancy.

For the first four manually characterized fixtures, this document now distinguishes:

- manually verified Wireshark ground truth from `tmp/tls_inspection_1/wireshark/*.txt`;
- current PcapFlowLab presentation baseline from `tmp/tls_inspection_1/pfl/*.txt`;
- current automated test coverage from repository tests;
- planned presentation contracts that are not yet implemented.

## Structured TLS inspection parser status

A bounded structured TLS inspection parser now has isolated direct fixture contracts for:

- `tls_client_hello_1.pcap`;
- `tls_1_3_client_hello_5.pcap`;
- `tls_1_2_server_hello_4.pcap`;
- `tls_1_3_server_hello_6.pcap`.

Current structured-parser limitations and boundaries:

- handshake messages spanning multiple TLS records are not reconstructed across record boundaries yet;
- the parser consumes only the supplied TLS byte span and does not inspect Ethernet/IP/TCP state itself;
- Packet Details Summary, Stream presentation, flow hints, and UI are not yet migrated to this parser in this pass.

## Inventory

| Fixture | Category | Current consumers | Current contract strength | Unique role | Manual verification | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| `ipv4_tls_constricted_1.pcap` | Constricted/truncated | `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests`, `DissectionImportSessionParityTests` | Strong | Exact IPv4 constricted stream and UI contract | Yes | Keep for now |
| `ipv6_tls_constricted_1.pcap` | Constricted/truncated | `FlowHintsRealFixturesTests`, `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests` | Strong | Exact IPv6 constricted stream contract | Yes | Keep for now |
| `ipv6_tls_strong_constrict_1.pcap` | Constricted/truncated | `FlowHintsRealFixturesTests`, `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests` | Strong | Exact strong-constriction contribution contract | Yes | Keep for now |
| `tls_1_2_app_data_3.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS AppData hint coverage | Yes | Keep for now |
| `tls_1_2_change_cipher_spec_2.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS ChangeCipherSpec hint coverage | Yes | Keep for now |
| `tls_1_2_new_session_ticket_9.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP NewSessionTicket hint coverage | Yes | Keep for now |
| `tls_1_2_server_hello_4.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `TlsInspectionParserTests` | Weak | Small TLS 1.2 ServerHello PCAP with newly documented manual baseline | Partially complete | Keep for now |
| `tls_1_3_app_data_7.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS 1.3 AppData hint coverage | Yes | Keep for now |
| `tls_1_3_change_cipher_spec_8.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS 1.3 ChangeCipherSpec hint coverage | Yes | Keep for now |
| `tls_1_3_client_hello_5.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `ImportTests`, `TlsInspectionParserTests` | Medium | Import/service-hint TLS ClientHello coverage with newly documented manual baseline | Partially complete | Keep for now |
| `tls_1_3_server_hello_6.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `PacketProtocolDetailsTests`, `TlsInspectionParserTests` | Medium | Current ServerHello protocol-details fixture; packet-local multiple-record baseline | Partially complete | Keep for now |
| `tls_client_hello_1.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `PacketDetailsTests`, `PacketProtocolDetailsTests`, `MainControllerUiTests`, `TlsInspectionParserTests` | Strong | Strongest current ClientHello packet-details and UI fixture with newly documented manual baseline | Partially complete | Keep for now |
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

#### Manually verified ground truth

- Source: `tmp/tls_inspection_1/wireshark/wireshark_tls_1_2_server_hello_4_info.txt`
- Frame `1`, direction `B->A`.
- TCP payload length: `96` bytes.
- TLS record count in the TCP payload: `1`.
- Record 1:
  - Content Type: `Handshake (22)`;
  - Record Legacy Version: `TLS 1.2 (0x0303)`;
  - Record Length: `91`;
  - Handshake Type: `Server Hello (2)`;
  - Handshake Length: `87`;
  - Handshake Legacy Version: `TLS 1.2 (0x0303)`;
  - Session ID Length: `32`;
  - Cipher Suite: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)`;
  - Compression Method: `null (0)`;
  - Extension Count: `3`;
  - Known Extensions: `ec_point_formats`, `renegotiation_info`, `extended_master_secret`.
- Several TLS records do not share this TCP payload.
- No partial trailing record is present.

#### Current PFL baseline

Source: `tmp/tls_inspection_1/pfl/pfl_tls_1_2_server_hello_4_info.txt`

##### Packet Details Summary

Currently shown:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ServerHello`;
- TLS fields: `Handshake Type`, `Record Type`, `Record Version`, `Selected TLS Version`.

##### Packet Details Protocol

Current additional TLS fields available only in Protocol:

- `Record Length`;
- `Handshake Length`;
- `Selected Cipher Suite`;
- `Session ID`;
- `Extensions`.

Protocol is a temporary legacy presentation source, not the future UI contract.

##### Stream items

- `Item #1 | TLS ServerHello | A->B | 96 bytes | packet #1`

The intended stream label is `TLS ServerHello`, not `TLS ClientHello`.

##### Stream Item Summary

Currently shown:

- `Label`;
- `Size`;
- `Source packet`;
- `Details source`.

##### Stream Item Protocol

Current additional TLS fields available only in Protocol:

- `Record Type`;
- `Record Version`;
- `Record Length`;
- `Handshake Type`;
- `Handshake Length`;
- `Selected TLS Version`;
- `Selected Cipher Suite`;
- `Session ID`;
- `Extensions`.

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.
- `tests/unit/TlsInspectionParserTests.cpp`
  - direct structured parser asserts one complete record;
  - consumed bytes `96`;
  - Record Legacy Version `0x0303`, record payload length `91`;
  - one complete `ServerHello`, handshake length `87`;
  - ServerHello Legacy Version `0x0303`;
  - session ID length `32`, selected cipher suite `0xc02f`, compression method `0`;
  - ordered extensions `ec_point_formats`, `renegotiation_info`, `extended_master_secret`;
  - Selected TLS Version `0x0303`.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary exposes a default-expanded TLS `ServerHello` layer;
  - summary fields assert `Handshake Type`, `Record Type`, `Record Version`, and `Selected TLS Version`.
- `tests/unit/PacketProtocolDetailsTests.cpp`
  - packet-local raw TLS parsing asserts:
    - one complete record and no trailing bytes;
    - payload length `96`, record length `91`, handshake length `87`;
    - handshake type `ServerHello`, selected TLS version `TLS 1.2`, selected cipher suite `0xc02f`;
    - session ID length `32`, compression method `0`, extension count `3`.
  - Packet Details Protocol text asserts the current rendered values for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`;
    - `Selected TLS Version`, `Selected Cipher Suite`;
    - extension names `ec_point_formats`, `renegotiation_info`, `extended_master_secret`.
- `tests/unit/StreamQueryTests.cpp`
  - fast-mode stream query returns one row:
    - `TLS ServerHello | 96 bytes | packet #1`;
    - stream direction matches the packet-row direction for packet `0`.
  - stream protocol details stay semantically aligned with packet protocol details for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`;
    - `Selected TLS Version`, `Selected Cipher Suite`.

#### Unique purpose

- Small real-PCAP TLS 1.2 ServerHello artifact with manually verified packet-level baseline.
- Current contrast case for `Selected TLS Version` equal to the handshake legacy version.

#### Missing assertions

- Direction text in the PFL export should be normalized against the manually verified server-to-client packet direction before turning it into a future contract.
- No user-facing field currently surfaces compression method directly, so that fact is only pinned through packet-local TLS payload parsing.
- Packet Details Summary still does not expose structured session-ID or extension inventories.

#### Manual Wireshark verification required

- None for the packet-level TLS facts recorded above.
- Remaining work is presentation-contract work and automated coverage expansion.

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

#### Manually verified ground truth

- Source: `tmp/tls_inspection_1/wireshark/wireshark_tls_1_3_client_hello_5.pcap_info.txt`
- Frame `1`, direction `A->B`.
- TCP payload length: `517` bytes.
- TLS record count in the TCP payload: `1`.
- Record 1:
  - Content Type: `Handshake (22)`;
  - Record Legacy Version: `TLS 1.0 (0x0301)`;
  - Record Length: `512`;
  - Handshake Type: `Client Hello (1)`;
  - Handshake Length: `508`;
  - Handshake Legacy Version: `TLS 1.2 (0x0303)`;
  - Session ID Length: `32`;
  - Cipher Suites Length: `42`;
  - Cipher Suites Count: `21`;
  - Compression Methods Length: `1`;
  - Compression Methods Count: `1`;
  - Extension Count: `16`;
  - Known Extensions: `Reserved (GREASE)`, `server_name`, `extended_master_secret`, `renegotiation_info`, `supported_groups`, `ec_point_formats`, `application_layer_protocol_negotiation`, `status_request`, `signature_algorithms`, `signed_certificate_timestamp`, `key_share`, `psk_key_exchange_modes`, `supported_versions`, `compress_certificate`, `Reserved (GREASE)`, `padding`;
  - SNI: `p101-fmf.icloud.com`;
  - ALPN: present in Wireshark as `application_layer_protocol_negotiation`;
  - Supported TLS Versions: `TLS 1.3`, `TLS 1.2`, `TLS 1.1`, `TLS 1.0`.
- Several TLS records do not share this TCP payload.
- No partial trailing record is present.

#### Current PFL baseline

Source: `tmp/tls_inspection_1/pfl/pfl_tls_1_3_client_hello_5_info.txt`

##### Packet Details Summary

Currently shown:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ClientHello`;
- TLS fields: `Handshake Type`, `Record Type`, `Record Version`, `SNI`.

##### Packet Details Protocol

Current additional TLS fields available only in Protocol:

- `Record Length`;
- `Handshake Length`;
- `Handshake Version`;
- `Session ID`;
- `Cipher Suites` with count suffix;
- `Extensions` with count suffix;
- `SNI`;
- `ALPN`;
- `Supported Versions`.

Protocol is a temporary legacy presentation source, not the future UI contract.

##### Stream items

- `Item #1 | TLS ClientHello | A->B | 517 bytes | packet #1`

##### Stream Item Summary

Currently shown:

- `Label`;
- `Size`;
- `Source packet`;
- `Details source`.

##### Stream Item Protocol

Current additional TLS fields available only in Protocol:

- `Record Type`;
- `Record Version`;
- `Record Length`;
- `Handshake Type`;
- `Handshake Length`;
- `Handshake Version`;
- `Session ID`;
- `Cipher Suites`;
- `Extensions`;
- `SNI`;
- `ALPN`;
- `Supported Versions`.

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`;
  - service hint `p101-fmf.icloud.com` is present.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`;
  - matching raw bytes yield service hint `p101-fmf.icloud.com`.
- `tests/unit/ImportTests.cpp`
  - imported flow list contains a `tls` flow with service hint `p101-fmf.icloud.com`.
- `tests/unit/TlsInspectionParserTests.cpp`
  - direct structured parser asserts one complete record and consumed bytes `517`;
  - Record Legacy Version `0x0301`, record payload length `512`;
  - one complete `ClientHello`, handshake length `508`;
  - ClientHello Legacy Version `0x0303`;
  - session ID length `32`, cipher-suite count `21`, compression-method count `1`, extension count `16`;
  - SNI `p101-fmf.icloud.com`;
  - ALPN `h2`, `http/1.1`;
  - supported versions retain wire order `0x3a3a`, `0x0304`, `0x0303`, `0x0302`, `0x0301`.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary exposes a default-expanded TLS `ClientHello` layer;
  - summary title contains `Transport Layer Security` and `ClientHello`;
  - summary fields assert `Handshake Type`, `Record Type`, `Record Version`, and `SNI`.
- `tests/unit/PacketProtocolDetailsTests.cpp`
  - packet-local raw TLS parsing asserts:
    - one complete record and no trailing bytes;
    - payload length `517`, record length `512`, handshake length `508`;
    - handshake type `ClientHello`, handshake version `TLS 1.2`;
    - session ID length `32`, cipher-suite count `21`, compression-method count `1`, extension count `16`;
    - SNI `p101-fmf.icloud.com`;
    - ALPN includes `h2` and `http/1.1`;
    - supported versions include `TLS 1.3`, `TLS 1.2`, `TLS 1.1`, and `TLS 1.0`.
  - Packet Details Protocol text asserts the current rendered values for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`, `Handshake Version`;
    - `Session ID`, `Cipher Suites`, `Extensions`;
    - `SNI`, `ALPN`, `Supported Versions`.
- `tests/unit/StreamQueryTests.cpp`
  - fast-mode stream query returns one row:
    - `TLS ClientHello | 517 bytes | packet #1`;
    - stream direction matches the packet-row direction for packet `0`.
  - stream protocol details stay semantically aligned with packet protocol details for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`, `Handshake Version`;
    - `SNI`, `ALPN`, `Supported Versions`.

#### Unique purpose

- Current import/service-hint TLS ClientHello coverage.
- Manually characterized contrast case to `tls_client_hello_1.pcap` with a larger cipher-suite set and wider supported-version list.

#### Missing assertions

- Exact extension-name inventory is not asserted yet.
- The current Packet Details Summary does not expose structured cipher-suite, extension, or supported-version lists, so those remain protocol-text/raw-parse contracts only.

#### Manual Wireshark verification required

- None for the packet-level TLS facts recorded above.
- Remaining work is presentation-contract work and automated coverage expansion.

### tls_1_3_server_hello_6.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Manually verified ground truth

- Source: `tmp/tls_inspection_1/wireshark/wireshark_tls_1_3_server_hello_6_info.txt`
- Frame `1`, direction `B->A`.
- TCP payload length: `1400` bytes.
- TLS record count in the TCP payload: `2 complete records + 1 partial trailing fragment`.
- Record 1:
  - Content Type: `Handshake (22)`;
  - Record Legacy Version: `TLS 1.2 (0x0303)`;
  - Record Length: `1210`;
  - Handshake Type: `Server Hello (2)`;
  - Handshake Length: `1206`;
  - Handshake Legacy Version: `TLS 1.2 (0x0303)`;
  - Session ID Length: `32`;
  - Cipher Suite: `TLS_AES_128_GCM_SHA256 (0x1301)`;
  - Compression Method: `null (0)`;
  - Extension Count: `2`;
  - Known Extensions: `key_share`, `supported_versions`;
  - Selected TLS Version: `TLS 1.3`.
- Record 2:
  - Content Type: `Change Cipher Spec (20)`;
  - Record Legacy Version: `TLS 1.2 (0x0303)`;
  - Record Length: `1`.
- Trailing bytes after the complete records:
  - `179` bytes of TLS segment data remain;
  - this is a partial trailing record, not a complete third TLS record.
- Multiple TLS records share one TCP payload.

#### Current PFL baseline

Source: `tmp/tls_inspection_1/pfl/pfl_tls_1_3_server_hello_6_info.txt`

##### Packet Details Summary

Currently shown:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ServerHello`;
- TLS fields: `Handshake Type`, `Record Type`, `Record Version`, `Selected TLS Version`.

##### Packet Details Protocol

Current additional TLS fields available only in Protocol:

- `Record Length`;
- `Handshake Length`;
- `Selected Cipher Suite`;
- `Session ID`;
- `Extensions`.

Protocol is a temporary legacy presentation source, not the future UI contract.

##### Stream items

- `Item #1 | TLS ServerHello | A->B | 1215 bytes | packet #1`
- `Item #2 | TLS ChangeCipherSpec | A->B | 6 bytes | packet #1`
- `Item #3 | TLS Record Fragment (partial) | A->B | 179 bytes | packet #1`

The second and third items are intentionally `6` and `179` bytes. The earlier manual transcription that repeated `1215` bytes for them was incorrect and must not become contract data.

##### Stream Item Summary

Currently shown:

- `Label`;
- `Size`;
- `Source packet`;
- `Details source`.

##### Stream Item Protocol

For `TLS ServerHello`, current additional TLS fields available only in Protocol:

- `Record Type`;
- `Record Version`;
- `Record Length`;
- `Handshake Type`;
- `Handshake Length`;
- `Selected TLS Version`;
- `Selected Cipher Suite`;
- `Session ID`;
- `Extensions`.

For `TLS ChangeCipherSpec`, current additional TLS fields available only in Protocol:

- `Record Type`;
- `Record Version`;
- `Record Length`.

For `TLS Record Fragment (partial)`, current Protocol text is a conservative partial-record message only.

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`.
- `tests/unit/FlowHintsRawFixturesTests.cpp`
  - matching raw bytes are detected as `FlowProtocolHint::tls`.
- `tests/unit/TlsInspectionParserTests.cpp`
  - direct structured parser asserts exact ordered records:
    - complete `Handshake` record at offset `0`, total size `1215`, payload length `1210`, Record Legacy Version `0x0303`;
    - complete `ServerHello` with handshake length `1206`, ServerHello Legacy Version `0x0303`, session ID length `32`, selected cipher suite `0x1301`, compression method `0`, ordered extensions `key_share`, `supported_versions`, Selected TLS Version `0x0304`;
    - complete `ChangeCipherSpec` record at offset `1215`, total size `6`, payload length `1`, Record Legacy Version `0x0303`, no handshake messages;
    - partial trailing record at offset `1221` with `179` available bytes and no fabricated complete handshake.
  - total input length `1400` and consumed bytes `1400`.
- `tests/unit/PacketProtocolDetailsTests.cpp`
  - packet-local raw TLS parsing asserts:
    - payload length `1400`;
    - two complete records plus `179` trailing bytes;
    - first record `Handshake`, record version `TLS 1.2`, record length `1210`, handshake length `1206`;
    - `ServerHello` selects `TLS 1.3` and cipher suite `0x1301`;
    - session ID length `32`, compression method `0`, extension count `2`;
    - second record is `ChangeCipherSpec` with record length `1`.
  - Packet Details Protocol text asserts the current rendered values for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`;
    - `Selected TLS Version`, `Selected Cipher Suite`, `Session ID`, `Extensions`.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary exposes a TLS `ServerHello` layer with current title and fields;
  - summary fields assert `Handshake Type`, `Record Type`, `Record Version`, and `Selected TLS Version`;
  - the test deliberately does not pin multi-record packet-local summary layer count.
- `tests/unit/StreamQueryTests.cpp`
  - fast-mode stream query returns exactly three rows:
    - `TLS ServerHello | 1215 bytes | packet #1`;
    - `TLS ChangeCipherSpec | 6 bytes | packet #1`;
    - `TLS Record Fragment (partial) | 179 bytes | packet #1`.
  - all three rows keep the packet-row direction for packet `0`.
  - `TLS ServerHello` stream protocol details stay semantically aligned with packet protocol details for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`;
    - `Selected TLS Version`, `Selected Cipher Suite`.
  - `TLS ChangeCipherSpec` protocol details assert:
    - `Record Type: ChangeCipherSpec`;
    - `Record Version: TLS 1.2 (0x0303)`;
    - `Record Length: 1`;
    - no `Handshake Type` field.
  - `TLS Record Fragment (partial)` asserts only the current conservative partial-record message and absence of fabricated `Record Type`, `Handshake Type`, `Selected TLS Version`, and `Selected Cipher Suite` fields.

#### Unique purpose

- Current ServerHello protocol-details fixture.
- Only manually characterized small fixture in this set that already demonstrates multiple complete TLS records plus a partial trailing fragment in one TCP payload.

#### Missing assertions

- Ordered multi-record packet-local Summary projection is not tested because current Packet Details Summary exposes only one TLS layer.
- ChangeCipherSpec and partial-fragment packet-local Summary cards do not yet exist.

#### Manual Wireshark verification required

- None for the packet-level TLS facts recorded above.
- Remaining work is summary-contract implementation and later automated coverage.

### tls_client_hello_1.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Manually verified ground truth

- Source: `tmp/tls_inspection_1/wireshark/wireshark_tls_client_hello_1_info.txt`
- Frame `1`, direction `A->B`.
- TCP payload length: `517` bytes.
- TLS record count in the TCP payload: `1`.
- Record 1:
  - Content Type: `Handshake (22)`;
  - Record Legacy Version: `TLS 1.0 (0x0301)`;
  - Record Length: `512`;
  - Handshake Type: `Client Hello (1)`;
  - Handshake Length: `508`;
  - Handshake Legacy Version: `TLS 1.2 (0x0303)`;
  - Session ID Length: `32`;
  - Cipher Suites Length: `32`;
  - Cipher Suites Count: `16`;
  - Compression Methods Length: `1`;
  - Compression Methods Count: `1`;
  - Extension Count: `18`;
  - Known Extensions: `Reserved (GREASE)`, `server_name`, `extended_master_secret`, `renegotiation_info`, `supported_groups`, `ec_point_formats`, `session_ticket`, `application_layer_protocol_negotiation`, `status_request`, `signature_algorithms`, `signed_certificate_timestamp`, `key_share`, `psk_key_exchange_modes`, `supported_versions`, `compress_certificate`, `application_settings_old`, `Reserved (GREASE)`, `padding`;
  - SNI: `auth.split.io`;
  - ALPN: present in Wireshark as `application_layer_protocol_negotiation`;
  - Supported TLS Versions: `TLS 1.3`, `TLS 1.2`.
- Several TLS records do not share this TCP payload.
- No partial trailing record is present.

#### Current PFL baseline

Source: `tmp/tls_inspection_1/pfl/pfl_tls_client_hello_1_info.txt`

##### Packet Details Summary

Currently shown:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ClientHello`;
- TLS fields: `Handshake Type`, `Record Type`, `Record Version`, `SNI`.

##### Packet Details Protocol

Current additional TLS fields available only in Protocol:

- `Record Length`;
- `Handshake Length`;
- `Handshake Version`;
- `Session ID`;
- `Cipher Suites` with count suffix;
- `Extensions` with count suffix;
- `SNI`;
- `ALPN`;
- `Supported Versions`.

Protocol is a temporary legacy presentation source, not the future UI contract.

##### Stream items

- `Item #1 | TLS ClientHello | A->B | 517 bytes | packet #1`

##### Stream Item Summary

Currently shown:

- `Size`;
- `Source packet`;
- `Details source`.

##### Stream Item Protocol

Current additional TLS fields available only in Protocol:

- `Record Type`;
- `Record Version`;
- `Record Length`;
- `Handshake Type`;
- `Handshake Length`;
- `Handshake Version`;
- `Session ID`;
- `Cipher Suites`;
- `Extensions`;
- `SNI`;
- `ALPN`;
- `Supported Versions`.

#### Automated contract

- `tests/unit/FlowHintsRealFixturesTests.cpp`
  - at least one flow is detected as `tls`;
  - service hint `auth.split.io` is present.
- `tests/unit/TlsInspectionParserTests.cpp`
  - direct structured parser asserts one complete record and consumed bytes `517`;
  - Record Legacy Version `0x0301`, record payload length `512`;
  - one complete `ClientHello`, handshake length `508`;
  - ClientHello Legacy Version `0x0303`;
  - session ID length `32`, cipher-suite count `16`, compression-method count `1`, extension count `18`;
  - SNI `auth.split.io`;
  - ALPN `h2`, `http/1.1`;
  - supported versions retain wire order `0x5a5a`, `0x0304`, `0x0303`.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary layers end with `tcp` then `tls`;
  - TCP is not expanded by default;
  - TLS is expanded by default;
  - TLS title contains `Transport Layer Security` and `ClientHello`;
  - summary fields assert `Handshake Type`, `Record Type`, `Record Version`, and `SNI`.
- `tests/unit/PacketProtocolDetailsTests.cpp`
  - packet-local raw TLS parsing asserts:
    - one complete record and no trailing bytes;
    - payload length `517`, record length `512`, handshake length `508`;
    - handshake type `ClientHello`, handshake version `TLS 1.2`;
    - session ID length `32`, cipher-suite count `16`, compression-method count `1`, extension count `18`;
    - SNI `auth.split.io`;
    - ALPN includes `h2` and `http/1.1`;
    - supported versions include `TLS 1.3` and `TLS 1.2`.
  - Packet Details Protocol text asserts the current rendered values for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`, `Handshake Version`;
    - `Session ID`, `Cipher Suites`, `Extensions`;
    - `SNI`, `ALPN`, `Supported Versions`.
- `tests/unit/StreamQueryTests.cpp`
  - fast-mode stream query returns one row:
    - `TLS ClientHello | 517 bytes | packet #1`;
    - stream direction matches the packet-row direction for packet `0`.
  - stream protocol details stay semantically aligned with packet protocol details for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`, `Handshake Version`;
    - `SNI`, `ALPN`, `Supported Versions`.
- `tests/ui/MainControllerUiTests.cpp`
  - analysis pane reports protocol hint `TLS`;
  - protocol version text is non-empty;
  - service hint and protocol service text are `auth.split.io`;
  - selected packet protocol text contains TLS and the SNI.

#### Unique purpose

- Strongest current ClientHello packet-details and UI fixture.
- Current best baseline for future ClientHello Summary parity work.

#### Missing assertions

- Exact ClientHello extension-name inventory is not asserted.
- The current Packet Details Summary does not expose structured cipher-suite, extension, or supported-version lists.

#### Manual Wireshark verification required

- None for the packet-level TLS facts recorded above.
- Remaining work is target Summary design and test expansion.

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

## Target TLS Summary presentation contract

The global direction is to remove the Protocol tab. TLS data therefore needs a structured Summary contract first, with Protocol retained only temporarily for parity and debugging.

### Packet Summary mapping rule

- One complete TLS record maps to one TLS Summary layer/card.
- One partial trailing TLS record maps to one TLS Summary layer/card representing a partial fragment.
- If a packet contains several TLS records, Packet Details Summary must expose all of them in wire order.

For `tls_1_3_server_hello_6.pcap`, the target ordered packet-local TLS layers are:

1. `TLS ServerHello`, `1215` total bytes;
2. `TLS ChangeCipherSpec`, `6` total bytes;
3. `TLS Record Fragment`, `179` available bytes.

### Target Packet Summary fields

#### Generic TLS record

- Label;
- total bytes for a complete record, or available bytes for a partial fragment;
- Record Type;
- Record Legacy Version;
- Record Length when available;
- status: complete or partial trailing fragment.

#### ClientHello

- Handshake Type;
- Handshake Length;
- Handshake Legacy Version;
- Session ID;
- Cipher Suites count plus expandable structured list;
- Compression Methods count plus expandable structured list;
- Extensions count plus expandable structured list;
- SNI when present;
- ALPN protocols when present;
- Supported TLS Versions when present.

#### ServerHello

- Handshake Type;
- Handshake Length;
- Handshake Legacy Version;
- Session ID;
- Selected TLS Version when present;
- Selected Cipher Suite;
- Compression Method when available;
- Extensions count plus expandable structured list.

#### ChangeCipherSpec

- Record Type;
- Record Legacy Version;
- Record Length.

#### Partial record fragment

- Label indicating a partial TLS record fragment;
- available byte count;
- whether the record header is complete;
- conservative explanatory status message.

## Target Stream Item Summary contract

Before the Protocol tab is removed, all meaningful TLS data currently shown only in Stream Item Protocol must be available in Stream Item Summary.

Target Stream Item Summary should contain:

- generic item metadata;
- a structured TLS record section;
- a structured handshake section when applicable;
- structured ClientHello or ServerHello fields when applicable;
- partial/contribution information when applicable.

For complete stream items, Summary should contain the same meaningful TLS facts as the current Protocol text, but represented as structured fields and expandable lists rather than long comma-separated strings.

For constricted or partial items, Summary should also preserve:

- source-packet contributions;
- constricted contribution notes;
- constricted packet notes;
- partial-record status.

## Multiple-record packet behavior

Packet-local TLS Summary must no longer collapse a multi-record packet into a single TLS layer. The manually characterized `tls_1_3_server_hello_6.pcap` fixture is the current anchor for this rule:

- the packet contains a complete `ServerHello` record;
- then a complete `ChangeCipherSpec` record;
- then a partial trailing TLS fragment;
- all three items must remain visible and ordered in both packet-local and stream-local summary views.

## Structured list presentation

The target Summary presentation should use structured expandable lists for:

- cipher suites;
- compression methods;
- extensions;
- supported versions;
- ALPN protocols;
- supported groups;
- signature algorithms;
- key shares.

The current long comma-separated Protocol strings are a temporary migration format, not the target UI representation.

## Proposed shared structured TLS model

This is now partially implemented as an isolated bounded parser with direct tests, but it is not wired into production presentation in this pass.

The current code still has partial structured parsing in `src/app/session/SessionTlsPresentation.cpp`, a packet-local textual analyzer in `src/core/services/TlsPacketProtocolAnalyzer.cpp`, and Summary extraction in `src/app/session/SessionFormatting.cpp` that reparses Protocol text. The new direct parser tests are an intermediate step toward replacing that text-driven Summary dependency with one shared structured TLS model.

Suggested narrow internal model:

- `TlsRecordModel`
  - record type;
  - record legacy version;
  - declared record length when known;
  - total bytes for a complete item;
  - available bytes for a partial item;
  - completeness state: complete vs partial trailing fragment;
  - optional handshake payload.
- `TlsHandshakeModel`
  - handshake type;
  - handshake length;
  - handshake legacy version when present;
  - optional handshake-specific payload model.
- `TlsClientHelloModel`
  - session ID;
  - cipher suite list;
  - compression method list;
  - extension list;
  - derived SNI;
  - derived ALPN protocol list;
  - derived supported TLS version list;
  - optional supported groups, signature algorithms, key shares.
- `TlsServerHelloModel`
  - session ID;
  - selected cipher suite;
  - compression method;
  - extension list;
  - derived selected TLS version;
  - optional key-share metadata.
- `TlsExtensionModel`
  - extension type code;
  - display name;
  - raw length when known;
  - optional decoded structured values.
- `TlsContributionModel`
  - contributing packet indices;
  - per-packet contribution sizes;
  - constricted contribution notes;
  - constricted packet notes.

The same structured model should support:

- packet-local parsing;
- bounded reassembled Stream parsing;
- Packet Details Summary;
- Stream Item Summary;
- temporary Protocol text generation during migration.

TLS details remain on-demand and ephemeral. This proposal does not define persistence.

## Protocol-tab migration rule

- Do not add new TLS information exclusively to Protocol.
- Future TLS fields should be implemented in structured Summary data first.
- Protocol remains a temporary parity/debugging view during migration.
- Protocol can be removed only after Summary parity is complete for packet-local and stream-item TLS presentation.

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
- Record Legacy Version;
- record length;
- handshake type;
- handshake length;
- Handshake Legacy Version;
- Supported TLS Versions;
- Selected TLS Version;
- cipher suite information;
- session ID information;
- extension count and known extension names;
- SNI;
- ALPN;
- whether the record crosses TCP packet boundaries;
- whether several records share one TCP payload;
- whether a partial trailing record exists;
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

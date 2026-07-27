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
- extension-local structured parsing now covers `supported_groups`, `signature_algorithms`, `key_share`, `psk_key_exchange_modes`, `status_request`, `compress_certificate`, and `padding`;
- decoded extension vectors preserve exact wire order and raw numeric values, including GREASE and unknown codes;
- a bounded but malformed known extension body marks only that extension as malformed and does not discard an otherwise valid bounded `ClientHello` or `ServerHello`;
- `key_share` modeling records only entry order, raw group ID, and key-exchange length; raw key-exchange bytes are not retained in this pass;
- the 2-byte ServerHello `key_share` selected-group / HelloRetryRequest form remains present as extension metadata but is left `not_attempted`;
- packet-local Packet Details Summary and selected Stream Item Summary now use the same shared structured TLS summary mapping;
- Packet Details Protocol remains the legacy presentation source for richer raw field dumps in this pass;
- flow hints are not migrated to this parser in this pass.

## Inventory

| Fixture | Category | Current consumers | Current contract strength | Unique role | Manual verification | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| `ipv4_tls_constricted_1.pcap` | Constricted/truncated | `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests`, `DissectionImportSessionParityTests` | Strong | Exact IPv4 constricted stream and UI contract | Yes | Keep for now |
| `ipv6_tls_constricted_1.pcap` | Constricted/truncated | `FlowHintsRealFixturesTests`, `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests` | Strong | Exact IPv6 constricted stream contract | Yes | Keep for now |
| `ipv6_tls_strong_constrict_1.pcap` | Constricted/truncated | `FlowHintsRealFixturesTests`, `StreamQueryTests`, `MainControllerUiTests`, `ProtocolPathTests` | Strong | Exact strong-constriction contribution contract | Yes | Keep for now |
| `tls_1_2_app_data_3.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS AppData hint coverage | Yes | Keep for now |
| `tls_1_2_change_cipher_spec_2.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS ChangeCipherSpec hint coverage | Yes | Keep for now |
| `tls_1_2_new_session_ticket_9.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP NewSessionTicket hint coverage | Yes | Keep for now |
| `tls_1_2_server_hello_4.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `PacketDetailsTests`, `StreamQueryTests`, `TlsInspectionParserTests` | Medium | Small TLS 1.2 ServerHello PCAP with manually verified packet/stream structured Summary baseline | Partially complete | Keep for now |
| `tls_1_3_app_data_7.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS 1.3 AppData hint coverage | Yes | Keep for now |
| `tls_1_3_change_cipher_spec_8.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests` | Weak | Real-PCAP TLS 1.3 ChangeCipherSpec hint coverage | Yes | Keep for now |
| `tls_1_3_client_hello_5.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `ImportTests`, `PacketDetailsTests`, `StreamQueryTests`, `TlsInspectionParserTests` | Medium | Import/service-hint TLS ClientHello coverage with shared packet/stream structured Summary baseline | Partially complete | Keep for now |
| `tls_1_3_server_hello_6.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `FlowHintsRawFixturesTests`, `PacketDetailsTests`, `PacketProtocolDetailsTests`, `StreamQueryTests`, `TlsInspectionParserTests` | Strong | Current anchor for packet-local and stream-item multiple-record TLS Summary behavior | Partially complete | Keep for now |
| `tls_client_hello_1.pcap` | Small single-record / handshake | `FlowHintsRealFixturesTests`, `PacketDetailsTests`, `PacketProtocolDetailsTests`, `StreamQueryTests`, `MainControllerUiTests`, `TlsInspectionParserTests` | Strong | Strongest current ClientHello packet/stream summary and UI fixture with manually verified baseline | Partially complete | Keep for now |
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
  - selected AppData Stream Item Summary is conservative and does not fabricate `Record Type` or `Record Length`;
  - constricted packet notes appear in stream details, not in protocol text.
- `tests/ui/MainControllerUiTests.cpp`
  - Qt projection mirrors the exact stream row labels, byte counts, source packet text, and constricted-contribution flags;
  - selected stream item details show exact constricted contribution lines and packet notes;
  - selected AppData Stream Item Summary remains conservative and avoids fabricated complete-record fields;
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

- Source: `tmp/tls_inspection_1/wireshark_extended/wireshark_tls_1_2_server_hello_4_info_extended.txt`
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
  - Compression Methods (wire order): `[null (0)]`;
  - Extension Count: `3`;
  - Ordered Extensions:
    1. `ec_point_formats`, type `11`, length `2`;
    2. `renegotiation_info`, type `65281`, length `1`;
    3. `extended_master_secret`, type `23`, length `0`.
- Several TLS records do not share this TCP payload.
- No partial trailing record is present.

#### Current PFL baseline

Source: `tmp/tls_inspection_1/pfl/pfl_tls_1_2_server_hello_4_info.txt`

##### Packet Details Summary

Now shown from the structured packet-local TLS parser:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ServerHello`;
- TLS fields: `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
- TLS fields: `Handshake Type`, `Handshake Length`, `ServerHello Legacy Version`, `Session ID Length`;
- TLS fields: `Selected TLS Version`, `Selected Cipher Suite`, `Compression Method`, `Extension Count`.
- structured child group: `Extensions (3)`;
- ordered extension child rows:
  - `[0] ec_point_formats`;
  - `[1] renegotiation_info`;
  - `[2] extended_master_secret`.

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

Now shown from structured Stream Item Summary:

- generic `Stream Item` metadata layer with `Label`, `Size`, `Source packet`, and `Details source`;
- structured `Transport Layer Security, ServerHello` layer;
- TLS fields: `Record Length`, `Total Record Size`, `Handshake Length`, `ServerHello Legacy Version`;
- TLS fields: `Selected TLS Version`, `Selected Cipher Suite`, `Session ID Length`, `Compression Method`, and `Extension Count`.
- structured child group: `Extensions (3)`;
- ordered extension child rows match Packet Details Summary through the shared mapping.

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
  - ordered extensions exactly:
    - `ec_point_formats`, type `11`, length `2`;
    - `renegotiation_info`, type `65281`, length `1`;
    - `extended_master_secret`, type `23`, length `0`;
  - Selected TLS Version `0x0303`.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary exposes a default-expanded TLS `ServerHello` layer;
  - summary fields assert `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
  - summary fields assert `Handshake Type`, `Handshake Length`, `ServerHello Legacy Version`, `Session ID Length`;
  - summary fields assert `Selected TLS Version`, `Selected Cipher Suite`, `Compression Method`, and `Extension Count`;
  - summary asserts ordered `Extensions (3)` child rows with exact type values.
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
  - stream summary asserts ordered `Extensions (3)` child rows;
  - the stream extension group is semantically identical to the packet-summary extension group.
  - stream protocol details stay semantically aligned with packet protocol details for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`;
    - `Selected TLS Version`, `Selected Cipher Suite`.

#### Unique purpose

- Small real-PCAP TLS 1.2 ServerHello artifact with manually verified packet-level baseline.
- Current contrast case for `Selected TLS Version` equal to the handshake legacy version.

#### Structured parser contract

- No additional extension-specific structures are required beyond the ordered extension inventory already captured above.

#### Structured Summary contract

- Packet Details Summary and Stream Item Summary use one shared structured TLS Summary mapping.
- Packet and Stream both expose the ordered extension inventory through that shared mapping with semantically identical rows.
- Raw Session ID bytes are still carried as a scalar field, not as a separate structured child group.
- No extension-local scalar collections are modeled for this fixture beyond the ordered extension inventory already listed above.

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

- Source: `tmp/tls_inspection_1/wireshark_extended/wireshark_tls_1_3_client_hello_5.pcap_info_extended.txt`
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
  - Cipher Suites (wire order):
    1. `Reserved (GREASE) (0x8a8a)`;
    2. `TLS_AES_128_GCM_SHA256 (0x1301)`;
    3. `TLS_AES_256_GCM_SHA384 (0x1302)`;
    4. `TLS_CHACHA20_POLY1305_SHA256 (0x1303)`;
    5. `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)`;
    6. `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)`;
    7. `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)`;
    8. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)`;
    9. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)`;
    10. `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)`;
    11. `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)`;
    12. `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)`;
    13. `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)`;
    14. `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)`;
    15. `TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)`;
    16. `TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)`;
    17. `TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)`;
    18. `TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)`;
    19. `TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)`;
    20. `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)`;
    21. `TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)`.
  - Compression Methods Length: `1`;
  - Compression Methods Count: `1`;
  - Compression Methods (wire order): `[null (0)]`;
  - Extension Count: `16`;
  - Ordered Extensions:
    1. `Reserved (GREASE)`, type `39578 (0x9a9a)`, length `0`;
    2. `server_name`, type `0`, length `24`;
    3. `extended_master_secret`, type `23`, length `0`;
    4. `renegotiation_info`, type `65281`, length `1`;
    5. `supported_groups`, type `10`, length `12`;
    6. `ec_point_formats`, type `11`, length `2`;
    7. `application_layer_protocol_negotiation`, type `16`, length `14`;
    8. `status_request`, type `5`, length `5`;
    9. `signature_algorithms`, type `13`, length `22`;
    10. `signed_certificate_timestamp`, type `18`, length `0`;
    11. `key_share`, type `51`, length `43`;
    12. `psk_key_exchange_modes`, type `45`, length `2`;
    13. `supported_versions`, type `43`, length `11`;
    14. `compress_certificate`, type `27`, length `3`;
    15. `Reserved (GREASE)`, type `2570 (0x0a0a)`, length `1`;
    16. `padding`, type `21`, length `189`.
  - SNI (wire order): `p101-fmf.icloud.com`;
  - ALPN (wire order): `h2`, `http/1.1`;
  - Supported TLS Versions (wire order): `Reserved (GREASE) (0x3a3a)`, `TLS 1.3 (0x0304)`, `TLS 1.2 (0x0303)`, `TLS 1.1 (0x0302)`, `TLS 1.0 (0x0301)`.
- Several TLS records do not share this TCP payload.
- No partial trailing record is present.

#### Current PFL baseline

Source: `tmp/tls_inspection_1/pfl/pfl_tls_1_3_client_hello_5_info.txt`

##### Packet Details Summary

Now shown from the structured packet-local TLS parser:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ClientHello`;
- TLS fields: `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
- TLS fields: `Handshake Type`, `Handshake Length`, `ClientHello Legacy Version`, `Session ID Length`, `Session ID`;
- TLS fields: `Cipher Suite Count`, `Compression Method Count`, `Extension Count`, `SNI`, `ALPN`, `Supported TLS Versions`.
- ordered scalar collection rows:
  - `Cipher Suites (21)` with indexed fields `[0]` ... `[20]`;
  - `Compression Methods (1)` with indexed fields.
- structured child group:
  - `Extensions (16)`.
- `server_name`, `application_layer_protocol_negotiation`, and `supported_versions`
  extension rows expose direct indexed fields such as `Server Name [0]`,
  `ALPN [0]`, and `Version [0]` instead of nested child groups.

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

Now shown from structured Stream Item Summary:

- generic `Stream Item` metadata layer with `Label`, `Size`, `Source packet`, and `Details source`;
- structured `Transport Layer Security, ClientHello` layer;
- TLS fields: `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
- TLS fields: `Handshake Type`, `Handshake Length`, `ClientHello Legacy Version`, `Session ID Length`, `Session ID`;
- TLS fields: `Cipher Suite Count`, `Compression Method Count`, `Extension Count`, `SNI`, `ALPN`, and `Supported TLS Versions`.
- ordered scalar collection rows:
  - `Cipher Suites (21)` with indexed fields;
  - `Compression Methods (1)` with indexed fields.
- structured child group:
  - `Extensions (16)`.
- extension-local `Server Name [N]`, `ALPN [N]`, and `Version [N]` fields match
  Packet Details Summary through the shared mapping.

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
  - exact ordered cipher-suite vector, including GREASE `0x8a8a`;
  - exact ordered compression-method vector `[0x00]`;
  - exact ordered extension metadata:
    - type;
    - known name when currently modeled;
    - declared length;
    - wire order;
  - extension-local structured parse status distinguishes:
    - modeled complete bodies;
    - bounded malformed bodies;
    - known but intentionally unmodeled bodies;
  - SNI `p101-fmf.icloud.com`;
  - ALPN `h2`, `http/1.1`;
  - supported versions retain wire order `0x3a3a`, `0x0304`, `0x0303`, `0x0302`, `0x0301`;
  - exact structured values are asserted for:
    - `supported_groups` IDs `0x4a4a`, `0x001d`, `0x0017`, `0x0018`, `0x0019`;
    - `signature_algorithms` IDs `0x0403`, `0x0804`, `0x0401`, `0x0503`, `0x0805`, `0x0805`, `0x0501`, `0x0806`, `0x0601`, `0x0201`;
    - `key_share` entry metadata `(0x4a4a, 1)` then `(0x001d, 32)`;
    - `psk_key_exchange_modes` value `1`;
    - `status_request` fields `(status_type=1, responder_id_list_length=0, request_extensions_length=0)`;
    - `compress_certificate` algorithm ID `0x0001`;
    - `padding` length `189`.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary exposes a default-expanded TLS `ClientHello` layer;
  - summary title contains `Transport Layer Security` and `ClientHello`;
  - summary fields assert `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
  - summary fields assert `Handshake Type`, `Handshake Length`, `ClientHello Legacy Version`, `Session ID Length`;
  - summary fields assert `Cipher Suite Count`, `Compression Method Count`, `Extension Count`, `SNI`, `ALPN`, and `Supported TLS Versions`;
  - summary asserts ordered `Cipher Suites (21)` and `Compression Methods (1)` indexed fields plus the `Extensions (16)` child group;
  - summary asserts exact GREASE values in cipher suites, extension types, and supported versions.
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
  - stream summary asserts ordered `Cipher Suites (21)` and `Compression Methods (1)` indexed fields plus the `Extensions (16)` child group;
  - stream extension rows expose direct `Server Name [N]`, `ALPN [N]`, and `Version [N]` fields matching the packet summary through the shared mapping.
  - stream protocol details stay semantically aligned with packet protocol details for:
    - `Record Type`, `Record Version`, `Record Length`;
    - `Handshake Type`, `Handshake Length`, `Handshake Version`;
    - `SNI`, `ALPN`, `Supported Versions`.

#### Unique purpose

- Current import/service-hint TLS ClientHello coverage.
- Manually characterized contrast case to `tls_client_hello_1.pcap` with a larger cipher-suite set and wider supported-version list.

#### Structured parser contract

- `supported_groups`, extension type `10`, length `12`:
  - `Reserved (GREASE) (0x4a4a)`;
  - `x25519 (0x001d)`;
  - `secp256r1 (0x0017)`;
  - `secp384r1 (0x0018)`;
  - `secp521r1 (0x0019)`.
- `signature_algorithms`, extension type `13`, length `22`:
  - `ecdsa_secp256r1_sha256 (0x0403)`;
  - `rsa_pss_rsae_sha256 (0x0804)`;
  - `rsa_pkcs1_sha256 (0x0401)`;
  - `ecdsa_secp384r1_sha384 (0x0503)`;
  - `rsa_pss_rsae_sha384 (0x0805)`;
  - `rsa_pss_rsae_sha384 (0x0805)`;
  - `rsa_pkcs1_sha384 (0x0501)`;
  - `rsa_pss_rsae_sha512 (0x0806)`;
  - `rsa_pkcs1_sha512 (0x0601)`;
  - `rsa_pkcs1_sha1 (0x0201)`.
- `key_share`, extension type `51`, length `43`:
  - entry 0: `Reserved (GREASE)`, group `19018 (0x4a4a)`, key-exchange length `1`;
  - entry 1: `x25519`, group `29 (0x001d)`, key-exchange length `32`.
- `psk_key_exchange_modes`, extension type `45`, length `2`:
  - `psk_dhe_ke (1)`.
- `status_request`, extension type `5`, length `5`:
  - certificate status type `OCSP (1)`;
  - responder ID list length `0`;
  - request extensions length `0`.
- `compress_certificate`, extension type `27`, length `3`:
  - algorithm `zlib (1)`.
- `padding`, extension type `21`, length `189`.
- Exact GREASE values and positions are part of the manual fixture contract:
  - cipher suite `0x8a8a`;
  - extension types `0x9a9a` and `0x0a0a`;
  - supported-version entry `0x3a3a`;
  - supported-group entry `0x4a4a`;
  - key-share group `0x4a4a`.

#### Structured Summary contract

- Packet Details Summary and Stream Item Summary use one shared structured TLS Summary mapping.
- Scalar extension collections render as direct indexed fields inside their owning extension:
  - `Group [N]`;
  - `Signature Scheme [N]`;
  - `Mode [N]`;
  - `Algorithm [N]`.
- `status_request` renders direct scalar metadata fields:
  - `Status Type`;
  - `Responder ID List Length`;
  - `Request Extensions Length`.
- `padding` renders direct scalar field `Padding Length`.
- `key_share` renders ordered structured child rows rather than flattened parallel field lists:
  - `[0] GREASE (0x4a4a), 1 byte`;
  - `[1] x25519 (0x001d), 32 bytes`.
- Key-exchange bytes are intentionally neither retained nor shown in Summary.
- Compact extension-title previews are shared between Packet and Stream for `supported_groups`, `signature_algorithms`, `key_share`, `psk_key_exchange_modes`, `status_request`, `compress_certificate`, and `padding`.
- Malformed known extension bodies keep the normal extension row plus generic `Type` / `Length` metadata and a conservative `Structured Details: Malformed` diagnostic with no partial structured values.
- Intentionally undecoded known forms may show `Structured Details: Not decoded`; this remains relevant for the deferred ServerHello two-byte HRR selected-group `key_share` form rather than normal parsed key-share entries in this fixture.

#### Manual Wireshark verification required

- None for the packet-level TLS facts recorded above.
- Remaining work is presentation-contract work and automated coverage expansion.

### tls_1_3_server_hello_6.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Manually verified ground truth

- Source: `tmp/tls_inspection_1/wireshark_extended/wireshark_tls_1_3_server_hello_6_info_extended.txt`
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
  - Compression Methods (wire order): `[null (0)]`;
  - Extension Count: `2`;
  - Ordered Extensions:
    1. `key_share`, type `51`, length `1124`;
    2. `supported_versions`, type `43`, length `2`;
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

Now shown from the structured packet-local TLS parser:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ServerHello`;
- `Transport Layer Security, ChangeCipherSpec`;
- `TLS Record Fragment (partial)`;
- complete-record fields include `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
- handshake fields include `Handshake Type`, `Handshake Length`, `ServerHello Legacy Version`, `Session ID Length`;
- `ServerHello` additionally exposes `Selected TLS Version`, `Selected Cipher Suite`, `Compression Method`, and `Extension Count`;
- the `ServerHello` layer now also exposes structured child group `Extensions (2)` with:
  - `[0] key_share (0x0033), 1124 bytes`;
  - `[1] supported_versions (0x002b), 2 bytes - TLS 1.3 (0x0304)`;
- the `supported_versions` extension now exposes direct field `Version [0] = TLS 1.3 (0x0304)`;
- the trailing fragment exposes only conservative partial-record fields such as `Status`, `Available Bytes`, and header-derived values when present.

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

Now shown from structured Stream Item Summary:

- `Item #1` exposes generic item metadata plus a structured `ServerHello` Summary layer;
- `Item #1` also exposes the same `Extensions (2)` child group and direct supported-version field as Packet Details Summary;
- `Item #2` exposes generic item metadata plus a structured `ChangeCipherSpec` Summary layer;
- `Item #3` exposes generic item metadata plus a conservative partial-record Summary layer with no fabricated handshake fields.

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
    - complete `ServerHello` with handshake length `1206`, ServerHello Legacy Version `0x0303`, session ID length `32`, selected cipher suite `0x1301`, compression method `0`, ordered extensions:
      - `key_share`, type `51`, length `1124`, group ID `4588`, key-exchange length `1120`;
      - `supported_versions`, type `43`, length `2`, value `0x0304`;
      Selected TLS Version `0x0304`;
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
  - packet summary exposes exactly three TLS layers after TCP in wire order:
    - `Transport Layer Security, ServerHello`;
    - `Transport Layer Security, ChangeCipherSpec`;
    - `TLS Record Fragment (partial)`;
  - the first layer asserts `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`, `Handshake Type`, `Handshake Length`, `ServerHello Legacy Version`, `Session ID Length`, `Selected TLS Version`, `Selected Cipher Suite`, `Compression Method`, and `Extension Count`;
  - the first layer asserts ordered `Extensions (2)` child rows and direct `Version [0]` on `supported_versions`;
  - the second layer asserts `Record Type`, `Record Legacy Version`, `Record Length`, and `Total Record Size`, with no fabricated handshake fields;
  - the third layer asserts conservative partial-record fields only, including `Status` and `Available Bytes`.
- `tests/unit/StreamQueryTests.cpp`
  - fast-mode stream query returns exactly three rows:
    - `TLS ServerHello | 1215 bytes | packet #1`;
    - `TLS ChangeCipherSpec | 6 bytes | packet #1`;
    - `TLS Record Fragment (partial) | 179 bytes | packet #1`.
  - all three rows keep the packet-row direction for packet `0`.
  - `TLS ServerHello` stream summary asserts ordered `Extensions (2)` child rows and direct `Version [0]`;
  - the `TLS ServerHello` extension group is semantically identical to the packet-summary extension group.
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

#### Structured parser contract

- `key_share`, extension type `51`, length `1124`:
  - group `X25519MLKEM768`;
  - group ID `4588`;
  - key-exchange length `1120`.
- `supported_versions`, extension type `43`, length `2`:
  - selected version `TLS 1.3 (0x0304)`.

#### Structured Summary contract

- Packet Details Summary and Stream Item Summary use one shared structured TLS Summary mapping.
- `supported_versions` renders as direct indexed scalar field `Version [0] = TLS 1.3 (0x0304)`.
- `key_share` renders one ordered structured child row with:
  - `Group = X25519MLKEM768 (0x11ec)`;
  - `Key Exchange Length = 1120 bytes`.
- The key-share child title is bounded and semantically identical in Packet and Stream Summary:
  - `[0] X25519MLKEM768 (0x11ec), 1120 bytes`.
- Key-exchange bytes are intentionally neither retained nor shown in Summary.
- Raw Session ID bytes remain a scalar field rather than a separate structured child group.
- The deferred ServerHello two-byte HRR selected-group `key_share` form is not represented as a normal key-share entry.
- No current fixture asserts the multiple-handshakes-in-one-record child-layer behavior.

#### Manual Wireshark verification required

- None for the packet-level TLS facts recorded above.
- Remaining work is summary-contract implementation and later automated coverage.

### tls_client_hello_1.pcap

**Category:** Small single-record / handshake fixture  
**Source:** Unknown source  
**Decision:** Keep for now

#### Manually verified ground truth

- Source: `tmp/tls_inspection_1/wireshark_extended/wireshark_tls_client_hello_1_info_extended.txt`
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
  - Cipher Suites (wire order):
    1. `Reserved (GREASE) (0x8a8a)`;
    2. `TLS_AES_128_GCM_SHA256 (0x1301)`;
    3. `TLS_AES_256_GCM_SHA384 (0x1302)`;
    4. `TLS_CHACHA20_POLY1305_SHA256 (0x1303)`;
    5. `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)`;
    6. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)`;
    7. `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)`;
    8. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)`;
    9. `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)`;
    10. `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)`;
    11. `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)`;
    12. `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)`;
    13. `TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)`;
    14. `TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)`;
    15. `TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)`;
    16. `TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)`.
  - Compression Methods Length: `1`;
  - Compression Methods Count: `1`;
  - Compression Methods (wire order): `[null (0)]`;
  - Extension Count: `18`;
  - Ordered Extensions:
    1. `Reserved (GREASE)`, type `64250 (0xfafa)`, length `0`;
    2. `server_name`, type `0`, length `18`;
    3. `extended_master_secret`, type `23`, length `0`;
    4. `renegotiation_info`, type `65281`, length `1`;
    5. `supported_groups`, type `10`, length `10`;
    6. `ec_point_formats`, type `11`, length `2`;
    7. `session_ticket`, type `35`, length `138`;
    8. `application_layer_protocol_negotiation`, type `16`, length `14`;
    9. `status_request`, type `5`, length `5`;
    10. `signature_algorithms`, type `13`, length `18`;
    11. `signed_certificate_timestamp`, type `18`, length `0`;
    12. `key_share`, type `51`, length `43`;
    13. `psk_key_exchange_modes`, type `45`, length `2`;
    14. `supported_versions`, type `43`, length `7`;
    15. `compress_certificate`, type `27`, length `3`;
    16. `application_settings_old`, type `17513 (0x4469)`, length `5`;
    17. `Reserved (GREASE)`, type `39578 (0x9a9a)`, length `1`;
    18. `padding`, type `21`, length `64`.
  - SNI (wire order): `auth.split.io`;
  - ALPN (wire order): `h2`, `http/1.1`;
  - Supported TLS Versions (wire order): `Reserved (GREASE) (0x5a5a)`, `TLS 1.3 (0x0304)`, `TLS 1.2 (0x0303)`.
- Several TLS records do not share this TCP payload.
- No partial trailing record is present.

#### Current PFL baseline

Source: `tmp/tls_inspection_1/pfl/pfl_tls_client_hello_1_info.txt`

##### Packet Details Summary

Now shown from the structured packet-local TLS parser:

- `Frame`;
- `Ethernet II`;
- `802.1Q Virtual LAN`;
- `IPv4`;
- `TCP`;
- `Transport Layer Security, ClientHello`;
- TLS fields: `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
- TLS fields: `Handshake Type`, `Handshake Length`, `ClientHello Legacy Version`, `Session ID Length`, `Session ID`;
- TLS fields: `Cipher Suite Count`, `Compression Method Count`, `Extension Count`, `SNI`, `ALPN`, `Supported TLS Versions`.
- ordered scalar collection rows:
  - `Cipher Suites (16)` with indexed fields `[0]` ... `[15]`;
  - `Compression Methods (1)` with indexed fields.
- structured child group:
  - `Extensions (18)`.
- `server_name`, `application_layer_protocol_negotiation`, and `supported_versions`
  extension rows expose direct indexed fields such as `Server Name [0]`,
  `ALPN [0]`, and `Version [0]` instead of nested child groups.

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

Now shown from structured Stream Item Summary:

- generic `Stream Item` metadata layer with `Label`, `Size`, `Source packet`, and `Details source`;
- structured `Transport Layer Security, ClientHello` layer;
- TLS fields: `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
- TLS fields: `Handshake Type`, `Handshake Length`, `ClientHello Legacy Version`, `Session ID Length`, `Session ID`;
- TLS fields: `Cipher Suite Count`, `Compression Method Count`, `Extension Count`, `SNI`, `ALPN`, and `Supported TLS Versions`.
- ordered scalar collection rows:
  - `Cipher Suites (16)` with indexed fields;
  - `Compression Methods (1)` with indexed fields.
- structured child group:
  - `Extensions (18)`.
- extension-local `Server Name [N]`, `ALPN [N]`, and `Version [N]` fields match
  Packet Details Summary through the shared mapping.

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
  - exact ordered cipher-suite vector, including GREASE `0x8a8a`;
  - exact ordered compression-method vector `[0x00]`;
  - exact ordered extension metadata:
    - type;
    - known name when currently modeled;
    - declared length;
    - wire order;
  - extension-local structured parse status distinguishes:
    - modeled complete bodies;
    - bounded malformed bodies;
    - known but intentionally unmodeled bodies;
  - SNI `auth.split.io`;
  - ALPN `h2`, `http/1.1`;
  - supported versions retain wire order `0x5a5a`, `0x0304`, `0x0303`;
  - exact structured values are asserted for:
    - `supported_groups` IDs `0x5a5a`, `0x001d`, `0x0017`, `0x0018`;
    - `signature_algorithms` IDs `0x0403`, `0x0804`, `0x0401`, `0x0503`, `0x0805`, `0x0501`, `0x0806`, `0x0601`;
    - `key_share` entry metadata `(0x5a5a, 1)` then `(0x001d, 32)`;
    - `psk_key_exchange_modes` value `1`;
    - `status_request` fields `(status_type=1, responder_id_list_length=0, request_extensions_length=0)`;
    - `compress_certificate` algorithm ID `0x0002`;
    - `padding` length `64`;
  - synthetic parser tests assert that malformed known extension bodies stay local to the extension and do not make an otherwise bounded `ClientHello` fail as a whole.
- `tests/unit/PacketDetailsTests.cpp`
  - packet summary layers end with `tcp` then `tls`;
  - TCP is not expanded by default;
  - TLS is expanded by default;
  - TLS title contains `Transport Layer Security` and `ClientHello`;
  - summary fields assert `Record Type`, `Record Legacy Version`, `Record Length`, `Total Record Size`;
  - summary fields assert `Handshake Type`, `Handshake Length`, `ClientHello Legacy Version`, `Session ID Length`;
  - summary fields assert `Cipher Suite Count`, `Compression Method Count`, `Extension Count`, `SNI`, `ALPN`, and `Supported TLS Versions`;
  - summary asserts ordered `Cipher Suites (16)` and `Compression Methods (1)` indexed fields plus the `Extensions (18)` child group;
  - summary asserts exact GREASE values in cipher suites, extension types, and supported versions.
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
  - stream summary asserts ordered `Cipher Suites (16)` and `Compression Methods (1)` indexed fields plus the `Extensions (18)` child group;
  - stream extension rows expose direct `Server Name [N]`, `ALPN [N]`, and `Version [N]` fields matching the packet summary through the shared mapping.
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

- Strongest current ClientHello packet-summary and UI fixture.
- Current best baseline for packet-local structured ClientHello Summary parity.

#### Structured parser contract

- `supported_groups`, extension type `10`, length `10`:
  - `Reserved (GREASE) (0x5a5a)`;
  - `x25519 (0x001d)`;
  - `secp256r1 (0x0017)`;
  - `secp384r1 (0x0018)`.
- `signature_algorithms`, extension type `13`, length `18`:
  - `ecdsa_secp256r1_sha256 (0x0403)`;
  - `rsa_pss_rsae_sha256 (0x0804)`;
  - `rsa_pkcs1_sha256 (0x0401)`;
  - `ecdsa_secp384r1_sha384 (0x0503)`;
  - `rsa_pss_rsae_sha384 (0x0805)`;
  - `rsa_pkcs1_sha384 (0x0501)`;
  - `rsa_pss_rsae_sha512 (0x0806)`;
  - `rsa_pkcs1_sha512 (0x0601)`.
- `key_share`, extension type `51`, length `43`:
  - entry 0: `Reserved (GREASE)`, group `23130 (0x5a5a)`, key-exchange length `1`;
  - entry 1: `x25519`, group `29 (0x001d)`, key-exchange length `32`.
- `psk_key_exchange_modes`, extension type `45`, length `2`:
  - `psk_dhe_ke (1)`.
- `status_request`, extension type `5`, length `5`:
  - certificate status type `OCSP (1)`;
  - responder ID list length `0`;
  - request extensions length `0`.
- `compress_certificate`, extension type `27`, length `3`:
  - algorithm `brotli (2)`.
- `padding`, extension type `21`, length `64`.
- Exact GREASE values and positions are part of the manual fixture contract:
  - cipher suite `0x8a8a`;
  - extension types `0xfafa` and `0x9a9a`;
  - supported-version entry `0x5a5a`;
  - supported-group entry `0x5a5a`;
  - key-share group `0x5a5a`.

#### Structured Summary contract

- Packet Details Summary and Stream Item Summary use one shared structured TLS Summary mapping.
- Scalar extension collections render as direct indexed fields inside their owning extension:
  - `Group [N]`;
  - `Signature Scheme [N]`;
  - `Mode [N]`;
  - `Algorithm [N]`.
- `status_request` renders direct scalar metadata fields:
  - `Status Type`;
  - `Responder ID List Length`;
  - `Request Extensions Length`.
- `padding` renders direct scalar field `Padding Length`.
- `key_share` renders ordered structured child rows rather than flattened parallel field lists:
  - `[0] GREASE (0x5a5a), 1 byte`;
  - `[1] x25519 (0x001d), 32 bytes`.
- Key-exchange bytes are intentionally neither retained nor shown in Summary.
- Compact extension-title previews are shared between Packet and Stream for `supported_groups`, `signature_algorithms`, `key_share`, `psk_key_exchange_modes`, `status_request`, `compress_certificate`, and `padding`.
- Malformed known extension bodies keep the normal extension row plus generic `Type` / `Length` metadata and a conservative `Structured Details: Malformed` diagnostic with no partial structured values.
- Intentionally undecoded known forms may show `Structured Details: Not decoded`; this remains relevant for the deferred ServerHello two-byte HRR selected-group `key_share` form rather than normal parsed key-share entries in this fixture.

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

The global direction is still to remove the Protocol tab. Packet and Stream TLS Summary now use the structured parser with shared TLS field mapping; Protocol remains temporary for parity and debugging while stream record construction still uses the legacy reassembly/presentation path.

### Packet Summary mapping rule

- One complete TLS record maps to one TLS Summary layer/card.
- One partial trailing TLS record maps to one TLS Summary layer/card representing a partial fragment.
- If a packet contains several TLS records, Packet Details Summary must expose all of them in wire order.

For `tls_1_3_server_hello_6.pcap`, the current ordered packet-local TLS layers are:

1. `Transport Layer Security, ServerHello`, `1215` total bytes;
2. `Transport Layer Security, ChangeCipherSpec`, `6` total bytes;
3. `TLS Record Fragment (partial)`, `179` available bytes.

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
- It must not recover structured TLS record fields by reparsing legacy Protocol text.

## Multiple-record packet behavior

Packet-local TLS Summary no longer collapses a multi-record packet into a single TLS layer. The manually characterized `tls_1_3_server_hello_6.pcap` fixture is the current anchor for this rule:

- the packet contains a complete `ServerHello` record;
- then a complete `ChangeCipherSpec` record;
- then a partial trailing TLS fragment;
- all three items must remain visible and ordered in packet-local Summary;
- Stream Item Summary now exposes the same structured ordered TLS records for this fixture.

## Structured list presentation

The current Summary presentation uses:

- ordered indexed fields for scalar collections such as cipher suites, compression methods, server names, ALPN values, and supported versions;
- expandable child rows only for structured extension objects.

The fixture-first target contract is ordered rows and fields, not long comma-separated strings. Conceptually:

```text
Cipher Suites (N)
  [0]: TLS_AES_128_GCM_SHA256 (0x1301)
  [1]: GREASE (0x8a8a)

Compression Methods (N)
  [0]: null (0)

Extensions (N)
  [0] server_name (0x0000), 18 bytes - auth.split.io
      Server Name [0]: auth.split.io
  [1] supported_versions (0x002b), 7 bytes - GREASE, TLS 1.3 (0x0304), TLS 1.2 (0x0303)
      Version [0]: GREASE (0x5a5a)
      Version [1]: TLS 1.3 (0x0304)
```

Packet Summary and Stream Item Summary must use the same mapping and preserve exact wire order.

Protocol strings remain a temporary migration format, not the target UI representation.

## Proposed shared structured TLS model

This is now partially adopted in production presentation: packet-local Summary and selected Stream Item Summary use the bounded structured parser, while Packet Details Protocol and stream record construction still use legacy text-oriented paths.

The current code still has partial structured parsing in `src/app/session/SessionTlsPresentation.cpp`, a packet-local textual analyzer in `src/core/services/TlsPacketProtocolAnalyzer.cpp`, and legacy stream record construction feeding the selected-item Summary adapter. `src/app/session/SessionFormatting.cpp` no longer derives TLS Summary fields by reparsing Protocol text, and Packet/Stream Summary now share the same TLS field mapping.

Current migration limitation: selected Stream Item Summary still decodes the existing `payload_hex_text` on demand because stream rows do not yet expose direct logical TLS bytes separately from the legacy presentation path. Partial and constricted items therefore fall back to conservative metadata-only TLS Summary fields instead of fabricated record semantics.

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

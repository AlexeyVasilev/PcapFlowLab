Synthetic GTP-U / GTPv1-U parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- outer IPv4 or IPv6 / UDP / GTP-U carrying direct inner IPv4 / IPv6 transport traffic;
- malformed or truncated GTP-U base headers;
- invalid GTP version handling;
- unsupported non-T-PDU GTP-U message types;
- malformed or truncated inner IPv4 / IPv6 payload after GTP-U;
- unknown inner payload bytes behind a valid-looking GTP-U T-PDU;
- the known branch limitation where identical inner 5-tuples from different TEIDs may still merge;
- future bidirectional inner-flow grouping cases that should collapse into one inner TCP flow;
- same-outer-tuple cases that should eventually split by the inner tuple instead of the outer UDP carrier tuple;
- outer IPv6 GTP-U carriage, UDP port-gating negative controls, TEID boundary values, and bounded optional-field coverage.

These fixtures are for the `feature/overlay-inner-flow-tuples` branch.

Current branch intent:
- supported tunnel/overlay parsing should eventually recover an effective inner IPv4/IPv6 plus TCP/UDP tuple;
- GTP-U TEID is presentation metadata for now, not part of flow identity;
- malformed or unsupported GTP-U cases should remain conservative and should not fabricate inner flow tuples.

Current implemented status:
- the GTP-U fixture generator and README are committed for fixture-first parser work;
- generated `.pcap` files are not created in this edit step;
- parser support, unit tests, and selected-packet presentation are still pending for GTP-U.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python tests/data/parsing/gtpu/generate_gtpu_pcaps.py --output-dir tests/data/parsing/gtpu
```

To overwrite previously generated fixtures:

```bash
python tests/data/parsing/gtpu/generate_gtpu_pcaps.py --output-dir tests/data/parsing/gtpu --force
```

Notes:
- The generator is committed, but generated `.pcap` files are not created in this edit step.
- Review generated `.pcap` files locally before committing them.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/port/TEID values.
- GTP-U headers are assembled from explicit bytes to keep the base-header and optional-header cases stable across Scapy versions.
- The extension-header fixture uses one minimal deterministic 4-byte extension-header block for bounded parser coverage; exact semantics are documented below and can be refined if later Wireshark comparison suggests a different extension-header type is preferable.

## Shared constants

- Outer source MAC: `02:00:00:00:60:01`
- Outer destination MAC: `02:00:00:00:60:02`
- Outer source IPv4: `203.0.113.60`
- Outer destination IPv4: `203.0.113.61`
- Outer source IPv6: `2001:db8:60:1::1`
- Outer destination IPv6: `2001:db8:60:1::2`
- Outer UDP source port base: `55000`
- GTP-U UDP destination port: `2152`
- Negative-control non-GTP-U UDP destination port: `2162`
- Inner IPv4 source: `10.60.0.10`
- Inner IPv4 destination: `10.60.0.20`
- Alternate inner IPv4 source: `10.60.0.11`
- Alternate inner IPv4 destination: `10.60.0.21`
- Inner IPv6 source: `2001:db8:60::10`
- Inner IPv6 destination: `2001:db8:60::20`
- Inner TCP source port: `49660`
- Inner TCP destination port: `443`
- Inner UDP source port: `53760`
- Inner UDP destination port: `443`
- Alternate inner TCP source ports: `10021`, `10022`
- Default TEID: `0x01020304`
- Alternate TEID: `0x11223344`
- T-PDU message type: `0xff`
- Example unsupported message type fixture value: `0x01` (Echo Request)

## Future support assumptions for this branch

Planned GTP-U behavior for later implementation steps:
- valid GTPv1-U T-PDU over UDP/2152 with a valid inner IPv4/IPv6 plus TCP/UDP tuple should eventually create a normal flow keyed by the inner tuple;
- selected-packet Summary / Protocol details should preserve outer IPv4 / IPv6 / UDP plus GTP-U metadata, including TEID and optional-field presence;
- malformed, unsupported, or truncated GTP-U / inner payload cases should remain conservative and should not fabricate normal inner flows;
- identical inner tuples from different TEIDs are a known limitation in this branch because TEID is not yet part of flow identity.

## GTP-U fixture encoding notes

- The base GTPv1-U header is encoded as:
  - flags/version/PT/E/S/PN in byte 0;
  - message type in byte 1;
  - 16-bit length in bytes 2-3;
  - 32-bit TEID in bytes 4-7.
- The length field is the number of bytes after the first 8-byte base header. For optional-field fixtures that means the length includes:
  - the 4-byte optional field block when any of E/S/PN is set;
  - any extension-header bytes;
  - the inner payload.
- When any of E/S/PN is set, the generator emits the 4-byte optional block:
  - sequence number, 2 bytes;
  - N-PDU number, 1 byte;
  - next extension header type, 1 byte.
- For `18_gtpu_with_extension_header_inner_ipv4_tcp.pcap`, the fixture uses one deterministic minimal extension-header block:
  - optional block next extension header type: `0x85`
  - extension header bytes: `01 de ad 00`
  - this is intentionally small and bounded for parser-skipping coverage rather than deep semantic extension-header validation.

---

### 01_gtpu_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.60:55000 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner tuple: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: one normal inner IPv4/TCP flow using the inner tuple as the effective flow endpoints.

### 02_gtpu_inner_ipv4_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv4 / UDP / Raw
- Outer tuple: `203.0.113.60:55001 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner tuple: `10.60.0.10:53760 -> 10.60.0.20:443`
- Expected future behavior: one normal inner IPv4/UDP flow using the inner tuple as the effective flow endpoints.

### 03_gtpu_inner_ipv6_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv6 / TCP / Raw
- Outer tuple: `203.0.113.60:55002 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner tuple: `2001:db8:60::10:49660 -> 2001:db8:60::20:443`
- Expected future behavior: one normal inner IPv6/TCP flow using the inner tuple as the effective flow endpoints.

### 04_gtpu_inner_ipv6_udp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv6 / UDP / Raw
- Outer tuple: `203.0.113.60:55003 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner tuple: `2001:db8:60::10:53760 -> 2001:db8:60::20:443`
- Expected future behavior: one normal inner IPv6/UDP flow using the inner tuple as the effective flow endpoints.

### 05_gtpu_truncated_base_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / partial GTP-U
- Outer tuple: `203.0.113.60:55004 -> 203.0.113.61:2152`
- GTP-U payload length: less than the minimum 8-byte base header
- Expected future behavior: no inner tuple extraction; conservative outer/fallback or unrecognized handling only.

### 06_gtpu_invalid_version.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / malformed GTP-U / inner IPv4 / TCP
- Outer tuple: `203.0.113.60:55005 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- Encoded GTP version: `2`
- TEID: `0x01020304`
- Inner tuple if decapsulated hypothetically: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: no strict inner tuple extraction; later packet details may show GTP-U warning and bounded best-effort presentation only if safe.

### 07_gtpu_unsupported_message_type.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U non-T-PDU / inner IPv4 / TCP
- Outer tuple: `203.0.113.60:55006 -> 203.0.113.61:2152`
- Message type: `0x01` (Echo Request)
- TEID: `0x01020304`
- Inner tuple if decapsulated hypothetically: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: no inner user-plane tuple extraction for unsupported non-T-PDU message types.

### 08_gtpu_truncated_inner_ipv4.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / partial inner IPv4
- Outer tuple: `203.0.113.60:55007 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner payload starts with IPv4 version nibble but is truncated
- Expected future behavior: no normal inner flow tuple; later details may show partial inner IPv4 warning.

### 09_gtpu_truncated_inner_ipv6.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / partial inner IPv6
- Outer tuple: `203.0.113.60:55008 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner payload starts with IPv6 version nibble but is truncated
- Expected future behavior: no normal inner flow tuple.

### 10_gtpu_unknown_inner_payload.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / unknown inner payload / Raw
- Outer tuple: `203.0.113.60:55009 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner payload first nibble is neither IPv4 nor IPv6
- Expected future behavior: GTP-U may be recognized later, but no inner IP/TCP/UDP tuple should be extracted.

### 11_gtpu_inner_ipv4_tcp_bidirectional.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.60:55010 -> 203.0.113.61:2152`
  - packet 2: `203.0.113.60:55011 -> 203.0.113.61:2152`
- Message type for both packets: `0xff` (T-PDU)
- TEID for both packets: `0x01020304`
- Inner tuples:
  - packet 1: `10.60.0.10:49660 -> 10.60.0.20:443`
  - packet 2: `10.60.0.20:443 -> 10.60.0.10:49660`
- Expected future behavior: both packets should belong to one bidirectional inner IPv4/TCP flow after GTP-U support is implemented.

### 12_gtpu_same_outer_tuple_different_inner_flows.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv4 / TCP / Raw
- Outer tuple for both packets: `203.0.113.60:55012 -> 203.0.113.61:2152`
- Message type for both packets: `0xff` (T-PDU)
- TEID for both packets: `0x01020304`
- Inner tuples:
  - packet 1: `10.60.0.10:10021 -> 10.60.0.20:443`
  - packet 2: `10.60.0.10:10022 -> 10.60.0.20:443`
- Expected future behavior: after GTP-U support, these should become two distinct inner IPv4/TCP flows based on the inner tuple.

### 13_gtpu_outer_ipv6_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / UDP / GTP-U T-PDU / inner IPv4 / TCP / Raw
- Outer tuple: `2001:db8:60:1::1:55013 -> 2001:db8:60:1::2:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Inner tuple: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: outer IPv6 carriage should not prevent GTP-U recognition or inner IPv4/TCP tuple extraction.

### 14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP(non-2152) / bytes that otherwise resemble GTP-U / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.60:55014 -> 203.0.113.61:2162`
- Embedded TEID bytes: `0x01020304`
- Inner tuple if decapsulated hypothetically: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: negative control for UDP port gating; do not treat this as GTP-U in the basic parser and do not extract an inner GTP-U tuple.

### 15_gtpu_teid_boundary_values.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.60:55015 -> 203.0.113.61:2152`
  - packet 2: `203.0.113.60:55016 -> 203.0.113.61:2152`
- Message type for both packets: `0xff` (T-PDU)
- TEIDs:
  - packet 1: `0x00000000`
  - packet 2: `0xffffffff`
- Inner tuples:
  - packet 1: `10.60.0.10:49660 -> 10.60.0.20:443`
  - packet 2: `10.60.0.11:10021 -> 10.60.0.21:443`
- Expected future behavior: TEID metadata extraction should preserve and later display TEID boundary values. TEID still remains outside flow identity in this branch.

### 16_gtpu_with_sequence_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU with optional sequence block / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.60:55017 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Optional-field flags: `S=1`, `E=0`, `PN=0`
- Sequence number: `0x1234`
- Inner tuple: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: parser should skip the optional 4-byte block correctly and extract the inner IPv4/TCP tuple.

### 17_gtpu_with_npdu_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU with optional N-PDU block / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.60:55018 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Optional-field flags: `PN=1`, `E=0`, `S=0`
- N-PDU number: `0x5a`
- Inner tuple: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: parser should skip the optional 4-byte block correctly and extract the inner tuple.

### 18_gtpu_with_extension_header_inner_ipv4_tcp.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU with extension header / inner IPv4 / TCP / Raw
- Outer tuple: `203.0.113.60:55019 -> 203.0.113.61:2152`
- Message type: `0xff` (T-PDU)
- TEID: `0x01020304`
- Optional-field flags: `E=1`, `S=0`, `PN=0`
- Optional-field next extension header type: `0x85`
- Extension header bytes: `01 de ad 00`
- Inner tuple: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior: parser should skip the bounded extension-header chain and extract the inner tuple.

### 19_gtpu_truncated_optional_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / partial GTP-U optional header
- Outer tuple: `203.0.113.60:55020 -> 203.0.113.61:2152`
- Optional-field flags indicate the 4-byte optional block should be present
- Packet ends before the optional 4-byte block completes
- Expected future behavior: no inner tuple extraction.

### 20_gtpu_truncated_extension_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U optional header / partial extension header
- Outer tuple: `203.0.113.60:55021 -> 203.0.113.61:2152`
- Optional-field flags: `E=1`
- Optional block is present, but the extension header bytes are truncated
- Expected future behavior: no inner tuple extraction.

### 21_gtpu_same_inner_tuple_different_teid.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / UDP / GTP-U T-PDU / inner IPv4 / TCP / Raw
- Outer tuples:
  - packet 1: `203.0.113.60:55022 -> 203.0.113.61:2152`
  - packet 2: `203.0.113.60:55023 -> 203.0.113.61:2152`
- Message type for both packets: `0xff` (T-PDU)
- TEIDs:
  - packet 1: `0x01020304`
  - packet 2: `0x11223344`
- Inner tuple for both packets: `10.60.0.10:49660 -> 10.60.0.20:443`
- Expected future behavior for this branch: known limitation case; current branch may merge both packets into one flow because TEID is not part of flow identity yet.

## Expected generated file list

- `01_gtpu_inner_ipv4_tcp.pcap`
- `02_gtpu_inner_ipv4_udp.pcap`
- `03_gtpu_inner_ipv6_tcp.pcap`
- `04_gtpu_inner_ipv6_udp.pcap`
- `05_gtpu_truncated_base_header.pcap`
- `06_gtpu_invalid_version.pcap`
- `07_gtpu_unsupported_message_type.pcap`
- `08_gtpu_truncated_inner_ipv4.pcap`
- `09_gtpu_truncated_inner_ipv6.pcap`
- `10_gtpu_unknown_inner_payload.pcap`
- `11_gtpu_inner_ipv4_tcp_bidirectional.pcap`
- `12_gtpu_same_outer_tuple_different_inner_flows.pcap`
- `13_gtpu_outer_ipv6_inner_ipv4_tcp.pcap`
- `14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap`
- `15_gtpu_teid_boundary_values.pcap`
- `16_gtpu_with_sequence_inner_ipv4_tcp.pcap`
- `17_gtpu_with_npdu_inner_ipv4_tcp.pcap`
- `18_gtpu_with_extension_header_inner_ipv4_tcp.pcap`
- `19_gtpu_truncated_optional_header.pcap`
- `20_gtpu_truncated_extension_header.pcap`
- `21_gtpu_same_inner_tuple_different_teid.pcap`

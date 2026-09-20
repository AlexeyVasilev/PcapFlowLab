# ERF Ethernet Parsing Fixtures

This directory defines the deterministic fixture contract for the first
PcapFlowLab ERF Ethernet capture-support pass. The generated `.pcap` files are
not committed by this pass; they are produced later by the local generator.

## Target First ERF Support

The first intended ERF support is deliberately narrow:

- classic PCAP only;
- `LINKTYPE_ERF` / `DLT_ERF` `197`;
- ERF `TYPE_ETH` only;
- explicit selected-packet ERF Packet Summary layer;
- continuation into the existing Ethernet parser;
- no ERF Protocol Path layer;
- no ERF Service hint;
- no ERF-specific Stream semantics;
- network-oriented `PacketRef` semantics;
- lazy/source-backed ERF details for selected-packet inspection;
- no index revision expected;
- PCAPNG `LINKTYPE_ERF` and native `.erf` files are out of scope.

An ERF Ethernet packet is expected to inspect as:

```text
Frame
Extensible Record Format
Ethernet II
IPv4 / IPv6
TCP / UDP
...
```

The Protocol Path for the same packet must still omit ERF. For example,
`ERF / Ethernet / IPv4 / TCP` has the network Protocol Path:

```text
EthernetII -> IPv4 -> TCP
```

not:

```text
ERF -> EthernetII -> IPv4 -> TCP
```

ERF is a capture/storage envelope, not network-path identity.

## Local Generation

The committed generator is self-contained and uses only the Python 3 standard
library:

```bash
python tests/data/parsing/erf/generate_erf_pcaps.py --output-dir tests/data/parsing/erf --force
```

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and omit `--output-dir`:

```bash
python /path/to/tests/data/parsing/erf/generate_erf_pcaps.py --force
```

The generator creates the output directory when necessary, refuses to overwrite
existing fixture files unless `--force` is supplied, writes only the ten files
listed below, and prints the generated paths. It performs no network access and
does not depend on Scapy or libpcap.

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the generator and regenerate the PCAPs.

## ERF Layout Used by Fixtures

All ERF fixtures are classic little-endian PCAP savefiles whose global link type
is `197`.

Each valid ERF record uses the 16-byte generic ERF header:

| Bytes | Field | Encoding |
| --- | --- | --- |
| `0..7` | ERF timestamp | little-endian 64-bit 32.32 fixed-point UNIX timestamp |
| `8` | type | low 7 bits are ERF type; bit 7 indicates extension headers |
| `9` | flags | deterministic `0x00` in these fixtures |
| `10..11` | `rlen` | big-endian physical ERF record length |
| `12..13` | `lctr` / color | big-endian, deterministic `0x0000` |
| `14..15` | `wlen` | big-endian original network packet length |

For `TYPE_ETH` records:

```text
generic ERF header
zero or more 8-byte extension headers
1-byte TYPE_ETH Offset
1-byte TYPE_ETH Pad
Ethernet frame bytes
```

Normal fixtures use:

- type low 7 bits: `2` (`TYPE_ETH`);
- Offset: `0`;
- Pad: `0`;
- no storage padding;
- no Ethernet FCS.

Fixture `05_erf_eth_extension_header_ipv4_tcp.pcap` uses one extension header:

```text
10 01 02 03 04 05 06 07
```

The first byte `0x10` is extension-header type `16` (`Flow ID`) with no
following-extension bit set. The remaining seven bytes are deterministic Flow
ID payload bytes. The extension is present only to prove bounded extension-chain
traversal before `TYPE_ETH`; no semantic Flow ID interpretation is expected.

## Length Semantics

These fixtures intentionally keep three length domains distinct:

- outer PCAP `incl_len` / `orig_len` describe the stored `DLT_ERF` record
  representation;
- ERF `rlen` describes the physical ERF record length;
- ERF `wlen` describes the original network packet length;
- stored Ethernet byte count describes captured network bytes in the record;
- future PFL `captured_length` is the stored Ethernet/network byte count;
- future PFL `original_length` is ERF `wlen`.

`ERF rlen` is not a PFL traffic length.

For valid non-truncated fixtures, the outer PCAP `incl_len` and `orig_len` are
the same and equal to the complete ERF record byte count. For malformed
fixtures `08` and `09`, outer `orig_len` records the intended stored ERF record
representation while `incl_len` is deliberately shorter.

Fixture `06_erf_eth_truncated_network_packet.pcap` is valid ERF with network
truncation:

```text
stored Ethernet bytes = 62
ERF wlen              = 175
ERF rlen              = 80
outer PCAP lengths    = 80 / 80
```

The intended future PFL truncation signal is therefore:

```text
captured_length = 62
original_length = 175
captured_length < original_length
```

not `80 < 175` and not any comparison involving ERF `rlen`.

## FCS Policy

The first synthetic ERF fixture contract is FCS-free.

No fixture appends Ethernet FCS bytes, no generator helper calculates FCS, and
no future parser should infer a four-byte subtraction from this fixture set.
For normal generated fixtures:

```text
ERF wlen == exact Ethernet bytes stored in the fixture
```

FCS/provenance normalization is intentionally deferred. Real ERF captures may
retain FCS even though these synthetic fixtures do not, and the eventual product
policy may need ERF capture provenance to know whether FCS was retained or
stripped.

## Shared Deterministic Values

- Client/source MAC: `02:00:00:00:50:01`
- Server/destination MAC: `02:00:00:00:50:02`
- Client IPv4: `192.0.2.200`
- Server IPv4: `192.0.2.210`
- Client IPv6: `2001:db8:50::10`
- Server IPv6: `2001:db8:50::20`
- Client TCP port: `50123`
- Server TCP port: `443`
- Client UDP port: `50124`
- Server UDP port: `4443`
- VLAN VID: `420`
- TLS SNI: `erf.example.test`
- Base timestamp: UNIX seconds `1700000000`

For valid fixtures the outer PCAP timestamp and ERF timestamp describe the same
deterministic instant. The ERF timestamp is encoded as 64-bit little-endian
32.32 fixed-point seconds; the outer PCAP timestamp uses classic PCAP
seconds/microseconds.

## Fixture Map

### `00_reference_ethernet_ipv4_tcp.pcap`

- Packets: `1`
- Outer link type: `DLT_EN10MB` / `LINKTYPE_ETHERNET` `1`
- Structure: Ethernet II / IPv4 / TCP / deterministic payload
- Ethernet byte count: `120`
- Purpose: reference side of the central Ethernet-vs-ERF parity pair
- Expected future PFL behavior: one normal TCP flow with ordinary Ethernet
  Protocol Path and network lengths `120 / 120`

### `01_erf_eth_ipv4_tcp.pcap`

- Packets: `1`
- Outer link type: `LINKTYPE_ERF` `197`
- Structure: ERF `TYPE_ETH` / Ethernet II / IPv4 / TCP / same payload as `00`
- Extension headers: none
- ERF `rlen`: `138`
- ERF `wlen`: `120`
- Stored Ethernet bytes: `120`
- Ethernet start: byte `18` of the ERF record (`16` generic + `2` TYPE_ETH)
- Purpose: primary positive ERF Ethernet baseline
- Expected future PFL behavior: same network Flow identity, Protocol Path,
  network lengths, payload semantics, Statistics, and Analysis as fixture `00`;
  selected-packet Summary additionally exposes ERF

### `02_erf_eth_ipv6_udp.pcap`

- Packets: `1`
- Structure: ERF `TYPE_ETH` / Ethernet II / IPv6 / UDP / deterministic payload
- ERF `rlen`: `138`
- ERF `wlen`: `120`
- Stored Ethernet bytes: `120`
- Purpose: prove first ERF support is not IPv4-specific and reuses existing
  Ethernet-to-IPv6 continuation
- Expected future PFL behavior: one UDP flow with no ERF Protocol Path layer

### `03_erf_eth_vlan_ipv4_udp.pcap`

- Packets: `1`
- Structure: ERF `TYPE_ETH` / Ethernet II / VLAN VID `420` / IPv4 / UDP
- ERF `rlen`: `114`
- ERF `wlen`: `96`
- Stored Ethernet bytes: `96`
- Purpose: prove ERF terminates at the Ethernet root and normal VLAN
  continuation remains shared Ethernet logic
- Expected future PFL behavior: normal Ethernet/VLAN/IPv4/UDP network semantics
  with no ERF Protocol Path layer

### `04_erf_eth_ipv4_tcp_tls_client_hello.pcap`

- Packets: `1`
- Structure: ERF `TYPE_ETH` / Ethernet II / IPv4 / TCP / TLS ClientHello
- TLS SNI: `erf.example.test`
- ERF `rlen`: `168`
- ERF `wlen`: `150`
- Stored Ethernet bytes: `150`
- Purpose: end-to-end proof that ERF root handling reaches existing TLS
  detection, service/SNI extraction, Packet Summary, and later Stream behavior
  without ERF-specific application logic
- Expected future PFL behavior: one TCP flow detected as TLS with service/SNI
  derived by the existing TLS path

### `05_erf_eth_extension_header_ipv4_tcp.pcap`

- Packets: `1`
- Structure: ERF `TYPE_ETH` with extension-present bit / one 8-byte Flow ID
  extension header / Ethernet II / IPv4 / TCP
- Generic type byte: `0x82`
- Extension header bytes: `10 01 02 03 04 05 06 07`
- Extension type: `16`
- Following-extension bit: clear
- ERF `rlen`: `129`
- ERF `wlen`: `103`
- Stored Ethernet bytes: `103`
- Ethernet start: byte `26` of the ERF record (`16` generic + `8` extension +
  `2` TYPE_ETH)
- Purpose: bounded extension-chain traversal before Ethernet
- Expected future PFL behavior: same network handling as ordinary ERF Ethernet;
  extension metadata is not interpreted for Flow identity

### `06_erf_eth_truncated_network_packet.pcap`

- Packets: `1`
- Structure: valid ERF `TYPE_ETH` / Ethernet II / IPv4 / TCP, with network
  payload capture-truncated after complete Ethernet/IP/TCP headers and a small
  visible payload prefix
- Stored Ethernet bytes: `62`
- ERF `wlen`: `175`
- ERF `rlen`: `80`
- Purpose: lock in the network-length truncation invariant
- Expected future PFL behavior: truncation is based on `62 < 175`; ERF headers
  and `rlen` do not contribute to traffic lengths

### `07_erf_unsupported_record_type.pcap`

- Packets: `1`
- Structure: structurally valid ERF type `1` (`POS/HDLC` family), outside the
  first PFL support scope
- ERF `rlen`: `51`
- ERF `wlen`: `35`
- Purpose: unsupported-but-valid ERF record handling
- Expected future PFL behavior: no crash, no fabricated Ethernet, no fake Flow,
  conservative unsupported/unrecognized handling

### `08_erf_truncated_base_header.pcap`

- Packets: `1`
- Outer link type: `LINKTYPE_ERF` `197`
- Captured bytes: `8`
- Outer original length: `16`
- Structure: capture ends before the complete 16-byte generic ERF header
- Purpose: safe malformed/truncated root handling
- Expected future PFL behavior: no crash, no fabricated Ethernet, no normal Flow

### `09_erf_truncated_extension_header.pcap`

- Packets: `1`
- Captured bytes: `20`
- Outer original length / intended ERF `rlen`: `110`
- Generic ERF header: complete and says extension headers are present
- Captured extension bytes: `10 01 02 03`
- Purpose: bounded extension parsing and no read beyond captured bytes
- Expected future PFL behavior: no crash, no fabricated Ethernet, conservative
  malformed/unrecognized handling

## Ethernet-vs-ERF Parity Contract

Fixtures `00_reference_ethernet_ipv4_tcp.pcap` and
`01_erf_eth_ipv4_tcp.pcap` contain byte-for-byte identical Ethernet network
bytes.

Future PFL behavior should be identical for network semantics:

- Flow count;
- Flow identity;
- endpoint orientation;
- Protocol;
- Detected Protocol;
- Service;
- Protocol Path;
- packet payload length;
- Stream behavior;
- Analysis;
- captured-byte totals;
- original-byte totals;
- packet-size histograms;
- Flow Data Size bucket;
- truncation state.

The only expected difference is capture-envelope inspection:

```text
00: Frame -> Ethernet II -> IPv4 -> TCP
01: Frame -> Extensible Record Format -> Ethernet II -> IPv4 -> TCP
```

## Manual Wireshark Guidance

After generation, useful manual wire checks include:

- `01`-`06`: Wireshark recognizes `LINKTYPE_ERF` and decodes `TYPE_ETH`.
- `01`: Ethernet bytes after TYPE_ETH metadata match fixture `00`.
- `01`-`05`: ERF `rlen` and `wlen` match the values documented above.
- `05`: the generic type byte has the extension-present bit set, one Flow ID
  extension header is present, and Ethernet begins after the extension plus
  TYPE_ETH Offset/Pad.
- `06`: ERF `wlen` is larger than stored Ethernet bytes.
- `07`: ERF type is valid-family but non-Ethernet and outside the first PFL
  support scope.
- `08`/`09`: truncation is visible and safely bounded.
- `04`: the TLS ClientHello carries SNI `erf.example.test`.

Wireshark is useful for wire verification; it is not the authority for
PcapFlowLab product semantics.

## Cases Left to Synthetic Unit Tests

Permanent fixture files are intentionally not added for every malformed case.
Later small unit tests can cover:

- impossible `rlen`;
- arithmetic overflow;
- excessive extension-header chain;
- complete extension header but truncated TYPE_ETH Offset/Pad;
- `rlen` shorter than structural minimum;
- malformed relationships that cannot occur in a normal generated fixture.

## Intentionally Unsupported / Deferred

This first fixture contract does not cover:

- non-Ethernet ERF decoding;
- PCAPNG ERF;
- native `.erf` files;
- ERF metadata/provenance records;
- broad extension-header semantic interpretation;
- FCS normalization;
- ERF Protocol Path;
- ERF-specific Stream behavior;
- source-less persisted ERF details;
- Advanced Flow Filter ERF predicates;
- broad ERF record-family support.

These omissions are intentional first-version boundaries, not claims that the
wire forms can never be supported.

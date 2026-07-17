Synthetic ESP parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- outer IPv4 and outer IPv6 ESP carriage using IP protocol `50` / IPv6 next-header `50`;
- conservative ESP header extraction for SPI and Sequence Number only;
- same-endpoint different-SPI namespace coverage;
- repeated-packet same-SPI grouping baselines;
- outer VLAN / QinQ before ESP;
- opaque encrypted payload handling with no inner decode or decryption;
- truncated ESP base-header robustness;
- SPI boundary and sequence high-range formatting coverage;
- staged UDP/4500 NAT-T coverage for later work.

The local helper script that generates these pcaps is intentionally **not** committed as a project artifact. It is a local stdlib-only helper under `tmp/`.

## Local generation

Run from the repository root with a local Python 3 interpreter:

```bash
python3 tmp/generate_esp_pcaps.py tests/data/parsing/esp --force
```

Notes:
- the script is a local helper only and should not be treated as production tooling;
- it writes classic little-endian Ethernet `.pcap` files with deterministic MAC/IP/SPI/sequence values;
- ESP payload bytes are synthetic opaque placeholders and are intentionally not decryptable;
- truncated fixtures are written manually so captured length and original wire length can differ when useful.

## ESP basics

- IPv4 protocol number for ESP: `50`
- IPv6 next-header value for ESP: `50`
- ESP fixed leading header:
  - SPI: 32 bits
  - Sequence Number: 32 bits
- Remaining bytes after the first 8 ESP bytes are encrypted / opaque payload in this fixture set.

Current parser intent for this fixture family:
- recognize ESP from IPv4 protocol `50` / IPv6 next-header `50`;
- parse SPI and Sequence Number conservatively;
- keep payload opaque with no inner decode/decryption;
- include ESP in the protocol path with SPI:
  - `EthernetII -> IPv4 -> ESP(spi=0x01020304)`
  - `EthernetII -> IPv6 -> ESP(spi=0x01020304)`
- SPI participates in protocol-path identity;
- Sequence Number remains details-only metadata, not flow identity.

## Shared constants

- Outer client MAC: `02:00:00:00:50:01`
- Outer server MAC: `02:00:00:00:50:02`
- Outer IPv4 client: `192.0.2.50`
- Outer IPv4 server: `198.51.100.50`
- Outer IPv6 client: `2001:db8:50::1`
- Outer IPv6 server: `2001:db8:50::2`
- ESP SPI A: `0x01020304`
- ESP SPI B: `0x11121314`
- ESP SPI reverse: `0x21222324`
- ESP sequence A: `1`
- ESP sequence B: `2`
- Outer VLAN ID: `550`
- Outer QinQ service VLAN IDs: `551`, `552`
- NAT-T UDP source port: `45000`
- NAT-T UDP destination port: `4500`

## Current implementation status

Current committed behavior now supports:
- direct IPv4 protocol `50` / IPv6 next-header `50` ESP recognition when the full 8-byte ESP lead-in is available;
- conservative parsing of:
  - SPI;
  - Sequence Number;
  - opaque payload length after the ESP lead-in;
- protocol path identity with SPI, for example:
  - `EthernetII -> IPv4 -> ESP(spi=0x01020304)`
  - `EthernetII -> IPv6 -> ESP(spi=0x01020304)`
- same-endpoint different-SPI split behavior;
- same-SPI multi-packet grouping;
- minimal selected-packet Summary / Protocol details for ESP.

Still staged / deferred:
- UDP/4500 NAT-T ESP detection and Non-ESP Marker handling;
- any interpretation of SPI `0` beyond conservative formatting/identity;
- ESP trailer, padding, or authentication-data parsing;
- any decryption or inner decode behind ESP.

### 01_ipv4_esp_basic.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / ESP / opaque payload
- ESP metadata: SPI `0x01020304`, Sequence `1`
- Current behavior: path `EthernetII -> IPv4 -> ESP(spi=0x01020304)` with conservative opaque-payload handling.

### 02_ipv6_esp_basic.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / ESP / opaque payload
- ESP metadata: SPI `0x01020304`, Sequence `1`
- Current behavior: path `EthernetII -> IPv6 -> ESP(spi=0x01020304)`.

### 03_ipv4_esp_same_hosts_different_spi.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / ESP / opaque payload
- ESP metadata:
  - packet 1: SPI `0x01020304`, Sequence `1`
  - packet 2: SPI `0x11121314`, Sequence `1`
- Current behavior: separate identity because SPI participates in protocol-path identity.

### 04_ipv4_esp_same_spi_two_packets.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / ESP / opaque payload
- ESP metadata:
  - packet 1: SPI `0x01020304`, Sequence `1`
  - packet 2: SPI `0x01020304`, Sequence `2`
- Current behavior: one ESP flow / grouping bucket because SPI participates but sequence does not.

### 05_ipv6_esp_same_hosts_different_spi.pcap

- Packets: 2
- Layer chain: Ethernet / IPv6 / ESP / opaque payload
- ESP metadata:
  - packet 1: SPI `0x01020304`, Sequence `1`
  - packet 2: SPI `0x11121314`, Sequence `1`
- Current behavior: IPv6 analogue of fixture `03`.

### 06_outer_vlan_ipv4_esp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / IPv4 / ESP / opaque payload
- VLAN ID: `550`
- Current behavior: outer VLAN preserved before IPv4 / ESP.

### 07_outer_qinq_ipv4_esp.pcap

- Packets: 1
- Layer chain: Ethernet / VLAN / VLAN / IPv4 / ESP / opaque payload
- VLAN IDs: `551`, `552`
- Current behavior: outer QinQ preserved before IPv4 / ESP.

### 08_ipv4_esp_large_opaque_payload.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / ESP / larger opaque payload
- Current behavior: payload remains opaque; no inner decode.

### 09_ipv4_esp_minimal_header_only.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / ESP
- ESP metadata: SPI `0x01020304`, Sequence `1`
- Opaque payload length after the 8-byte ESP lead-in: `0`
- Current behavior: header recognized with zero opaque payload length.

### 10_ipv4_esp_truncated_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / partial ESP
- Captured ESP bytes after IP header: fewer than `8`
- Current behavior: conservative truncated-ESP handling; no crash and no fabricated flow.

### 11_ipv4_esp_truncated_spi_only.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / partial ESP
- Captured ESP bytes after IP header: exactly `4`
- Current behavior: conservative partial-SPI handling; no fabricated flow.

### 12_ipv6_esp_truncated_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / partial ESP
- Captured ESP bytes after IPv6 header: fewer than `8`
- Current behavior: conservative truncated handling; no crash.

### 13_ipv4_esp_zero_spi.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / ESP / opaque payload
- ESP metadata: SPI `0x00000000`, Sequence `1`
- Current behavior: recognized conservatively with SPI shown as `0x00000000`.
- Staged note: any special semantic treatment for SPI `0` remains deferred.

### 14_ipv4_esp_high_spi_value.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / ESP / opaque payload
- ESP metadata: SPI `0xffffffff`, Sequence `1`
- Current behavior: formatting handles full 32-bit SPI range.

### 15_ipv4_esp_sequence_wrapish_values.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / ESP / opaque payload
- ESP metadata:
  - packet 1: SPI `0x01020304`, Sequence `0xfffffffe`
  - packet 2: SPI `0x01020304`, Sequence `0xffffffff`
- Current behavior: sequence is displayed as details-only metadata and does not split identity.

### 16_udp4500_nat_t_esp_non_ike_marker.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / opaque NAT-T ESP-like payload
- UDP ports: `45000 -> 4500`
- Payload shape: UDP/4500 payload begins directly with ESP SPI `0x01020304` and Sequence `1`, with no Non-ESP Marker prefix.
- Staged/deferred behavior: NAT-T ESP detection may later treat this as ESP-in-UDP; no parser implementation is added in this pass.

### 17_udp4500_nat_t_ike_marker_staged.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Non-ESP Marker / opaque bytes
- UDP ports: `45000 -> 4500`
- Payload shape: starts with Non-ESP Marker `0x00000000`
- Staged/deferred behavior: future NAT-T logic must not misclassify this as ESP payload.

### 18_ipv4_esp_two_directions_different_spi.pcap

- Packets: 2
- Layer chain: Ethernet / IPv4 / ESP / opaque payload
- ESP metadata:
  - client -> server: SPI `0x01020304`, Sequence `1`
  - server -> client: SPI `0x21222324`, Sequence `1`
- Current behavior: two directional ESP identities are acceptable v1 behavior when SPI participates in protocol-path identity, similar to TEID-based or key-based tunnel namespace splits.

## Expected generated file list

- `01_ipv4_esp_basic.pcap`
- `02_ipv6_esp_basic.pcap`
- `03_ipv4_esp_same_hosts_different_spi.pcap`
- `04_ipv4_esp_same_spi_two_packets.pcap`
- `05_ipv6_esp_same_hosts_different_spi.pcap`
- `06_outer_vlan_ipv4_esp.pcap`
- `07_outer_qinq_ipv4_esp.pcap`
- `08_ipv4_esp_large_opaque_payload.pcap`
- `09_ipv4_esp_minimal_header_only.pcap`
- `10_ipv4_esp_truncated_header.pcap`
- `11_ipv4_esp_truncated_spi_only.pcap`
- `12_ipv6_esp_truncated_header.pcap`
- `13_ipv4_esp_zero_spi.pcap`
- `14_ipv4_esp_high_spi_value.pcap`
- `15_ipv4_esp_sequence_wrapish_values.pcap`
- `16_udp4500_nat_t_esp_non_ike_marker.pcap`
- `17_udp4500_nat_t_ike_marker_staged.pcap`
- `18_ipv4_esp_two_directions_different_spi.pcap`

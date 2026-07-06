Synthetic SCTP parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- plain IPv4 and IPv6 SCTP carrying minimal DATA chunks;
- known SCTP PPID recognition cases for future selected-packet presentation;
- non-DATA first-chunk cases such as INIT and SACK;
- truncated SCTP common-header and DATA-chunk metadata cases;
- bidirectional SCTP flow grouping by the normal normalized IP + port tuple;
- SCTP behind already-supported VLAN and MPLS shim paths;
- SCTP behind already-supported VXLAN, Geneve, and GTP-U overlay inner-IP paths.

These fixtures are for the `feature/sctp-transport-support` branch.

Current branch intent:
- add SCTP as a third port-based L4 transport protocol alongside TCP and UDP;
- extract SCTP source and destination ports during open/import;
- show SCTP common-header fields in selected-packet details;
- show bounded first-chunk metadata when available;
- recognize known DATA-chunk PPID values as presentation metadata only.

Non-goals for this branch:
- no SCTP stream reassembly;
- no deep SCTP upper-layer protocol decoding;
- no SCTP checksum validation;
- no ASN.1 / SIGTRAN / Diameter deep parsing;
- no application payload decoding beyond PPID naming;
- no full SCTP chunk-chain parser;
- no SCTP fragmentation/reassembly semantics.

## Local generation

Run from the repository root:

```bash
python tests/data/parsing/sctp/generate_sctp_pcaps.py --output-dir tests/data/parsing/sctp --force
```

Notes:
- The generator is committed and does not require Scapy.
- The script writes classic little-endian Ethernet `.pcap` files with deterministic bytes.
- SCTP headers and chunks are assembled explicitly so the fixtures stay stable across Python environments.
- SCTP checksum correctness is intentionally out of scope here; the checksum field stays deterministic.

## SCTP basics used by these fixtures

- SCTP common header: 12 bytes
  - Source Port: 2 bytes
  - Destination Port: 2 bytes
  - Verification Tag: 4 bytes
  - Checksum: 4 bytes
- SCTP chunk header: 4 bytes
  - Type: 1 byte
  - Flags: 1 byte
  - Length: 2 bytes
- DATA chunk fixed metadata used by these fixtures:
  - TSN: 4 bytes
  - Stream Identifier: 2 bytes
  - Stream Sequence Number: 2 bytes
  - Payload Protocol Identifier: 4 bytes
  - User payload bytes: tiny deterministic dummy bytes

Expected strict future behavior:
- normal SCTP flow extraction requires at least the full 12-byte SCTP common header;
- truncated SCTP common-header packets must not fabricate a normal SCTP port-based flow;
- selected-packet details may later show conservative partial/truncated metadata;
- truncated DATA chunk metadata must not fabricate a PPID-derived pseudo-layer.

PPID behavior expected later in the branch:
- known PPID values may add a named next layer in selected-packet Summary / Protocol details;
- unknown PPID values remain generic SCTP payload presentation;
- PPID recognition is presentation metadata only and does not affect flow identity.

Overlay and shim expectations:
- VLAN and MPLS are regression cases for already-supported shim paths;
- VXLAN, Geneve, and GTP-U inner SCTP cases are committed now so later parser work can extend overlay inner tuple extraction from TCP/UDP to SCTP without introducing new fixture churn.

## Shared constants

- Plain source MAC: `02:00:00:00:84:01`
- Plain destination MAC: `02:00:00:00:84:02`
- Overlay outer source MAC: `02:00:00:00:85:01`
- Overlay outer destination MAC: `02:00:00:00:85:02`
- Overlay inner source MAC: `02:00:00:00:86:01`
- Overlay inner destination MAC: `02:00:00:00:86:02`
- Plain IPv4 source: `10.132.0.10`
- Plain IPv4 destination: `10.132.0.20`
- Plain IPv6 source: `2001:db8:132::10`
- Plain IPv6 destination: `2001:db8:132::20`
- Overlay outer IPv4 source: `203.0.113.132`
- Overlay outer IPv4 destination: `203.0.113.133`
- SCTP source port: `49132`
- SCTP destination port: `36412`
- SCTP verification tag: `0x10213243`
- SCTP checksum field: `0x00000000`
- DATA TSN: `0x00000001`
- Stream Identifier: `0`
- Stream Sequence Number: `0`
- VLAN ID: `132`
- VXLAN VNI: `132`
- Geneve VNI: `132`
- GTP-U TEID: `0x01020384`

## Known PPID mapping used by this branch

- `1` -> `IUA`
- `2` -> `M2UA`
- `3` -> `M3UA`
- `4` -> `SUA`
- `5` -> `M2PA`
- `10` -> `DUA`
- `18` -> `S1AP`
- `19` -> `RUA`
- `20` -> `HNBAP`
- `24` -> `SBc-AP`
- `25` -> `NBAP`
- `27` -> `X2AP`
- `29` -> `LCS-AP`
- `31` -> `SABP`
- `43` -> `M2AP`
- `44` -> `M3AP`
- `46` -> `Diameter`
- `60` -> `NGAP`
- `61` -> `XnAP`
- `62` -> `F1AP`
- `64` -> `E1AP`

Expected future examples:
- `SCTP DATA, PPID: S1AP (18)`
- next pseudo-layer: `S1 Application Protocol`
- `SCTP DATA, PPID: M3UA (3)`
- next pseudo-layer: `MTP 3 User Adaptation Layer`

---

### 01_sctp_ipv4_data_s1ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / S1AP-like payload bytes
- PPID: `18` / `S1AP`
- Expected future behavior: normal SCTP IPv4 flow plus SCTP common-header details and DATA metadata with S1AP PPID recognition.

### 02_sctp_ipv6_data_s1ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv6 / SCTP / DATA chunk / S1AP-like payload bytes
- PPID: `18` / `S1AP`
- Expected future behavior: normal SCTP IPv6 flow plus the same PPID recognition as IPv4.

### 03_sctp_ipv4_data_m3ua.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / M3UA-like payload bytes
- PPID: `3` / `M3UA`
- Expected future behavior: SCTP DATA PPID recognition can show `MTP 3 User Adaptation Layer`.

### 04_sctp_ipv4_data_dua.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / DUA-like payload bytes
- PPID: `10` / `DUA`
- Expected future behavior: SCTP DATA PPID recognition shows `DUA`.

### 05_sctp_ipv4_data_nbap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / NBAP-like payload bytes
- PPID: `25` / `NBAP`
- Expected future behavior: SCTP DATA PPID recognition shows `NBAP`.

### 06_sctp_ipv4_data_x2ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / X2AP-like payload bytes
- PPID: `27` / `X2AP`
- Expected future behavior: SCTP DATA PPID recognition shows `X2AP`.

### 07_sctp_ipv4_data_diameter.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / Diameter-like payload bytes
- PPID: `46` / `Diameter`
- Expected future behavior: SCTP DATA PPID recognition shows `Diameter` without deep AVP parsing.

### 08_sctp_ipv4_data_ngap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / NGAP-like payload bytes
- PPID: `60` / `NGAP`
- Expected future behavior: SCTP DATA PPID recognition shows `NGAP`.

### 09_sctp_ipv4_data_unknown_ppid.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / unknown deterministic PPID
- PPID: `0x12345678`
- Expected future behavior: normal SCTP flow still works; PPID stays unknown and presentation remains generic SCTP payload.

### 10_sctp_ipv4_init.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / INIT chunk
- Expected future behavior: common-header parsing works without DATA; first-chunk metadata may later show `INIT`; no PPID pseudo-layer.

### 11_sctp_ipv4_sack.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / SACK chunk
- Expected future behavior: common-header parsing works for non-DATA chunks too; first-chunk metadata may later show `SACK`; no PPID pseudo-layer.

### 12_sctp_truncated_common_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / truncated SCTP common header
- Expected future behavior: no normal SCTP flow should be fabricated by strict import decode.

### 13_sctp_truncated_data_chunk_header.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / full SCTP common header / partial first chunk header
- Expected future behavior: strict flow extraction can still use the common header, but first-chunk parsing should be truncated and no PPID layer fabricated.

### 14_sctp_truncated_data_chunk_ppid.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / full SCTP common header / DATA chunk header / partial DATA fixed metadata before full PPID
- Expected future behavior: normal SCTP flow can still exist, but no PPID layer should be fabricated.

### 15_sctp_ipv4_bidirectional_flow.pcap

- Packets: 2
- Layer chain:
  - packet 1: Ethernet / IPv4 / SCTP / DATA chunk
  - packet 2: Ethernet / IPv4 / SCTP / SACK chunk
- Expected future behavior: one bidirectional SCTP flow with two packets.

### 16_sctp_vlan_ipv4_data_s1ap.pcap

- Packets: 1
- Layer chain: Ethernet / 802.1Q VLAN / IPv4 / SCTP / DATA chunk
- PPID: `18` / `S1AP`
- Expected future behavior: SCTP works behind existing VLAN shim support.

### 17_sctp_mpls_ipv4_data_s1ap.pcap

- Packets: 1
- Layer chain: Ethernet / MPLS / IPv4 / SCTP / DATA chunk
- PPID: `18` / `S1AP`
- Expected future behavior: SCTP works behind the existing direct-inner-IP MPLS path.

### 18_sctp_vxlan_inner_ipv4_data_s1ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / VXLAN / inner Ethernet / inner IPv4 / SCTP / DATA chunk
- PPID: `18` / `S1AP`
- Expected future behavior: later VXLAN inner tuple extraction should accept SCTP and key flows by the inner IPv4 + SCTP tuple.

### 19_sctp_geneve_inner_ipv4_data_m3ua.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / Geneve / inner Ethernet / inner IPv4 / SCTP / DATA chunk
- PPID: `3` / `M3UA`
- Expected future behavior: later Geneve inner tuple extraction should accept SCTP and preserve PPID recognition.

### 20_sctp_gtpu_inner_ipv4_data_s1ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / GTP-U / direct inner IPv4 / SCTP / DATA chunk
- PPID: `18` / `S1AP`
- Expected future behavior: later GTP-U direct-inner-IP tuple extraction should accept SCTP; TEID remains presentation metadata only.

### 21_non_sctp_negative.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / UDP / payload bytes that look SCTP-like
- Expected future behavior: no SCTP flow/details should be fabricated from payload bytes when IP protocol is not SCTP.

### 22_sctp_ipv4_data_m2ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / M2AP-like payload bytes
- PPID: `43` / `M2AP`
- Expected future behavior: SCTP DATA PPID recognition shows `M2AP`.

### 23_sctp_ipv4_data_m3ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / M3AP-like payload bytes
- PPID: `44` / `M3AP`
- Expected future behavior: SCTP DATA PPID recognition shows `M3AP`.

### 24_sctp_ipv4_data_f1ap.pcap

- Packets: 1
- Layer chain: Ethernet / IPv4 / SCTP / DATA chunk / F1AP-like payload bytes
- PPID: `62` / `F1AP`
- Expected future behavior: SCTP DATA PPID recognition shows `F1AP`.

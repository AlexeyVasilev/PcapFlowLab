Synthetic MACsec / IEEE 802.1AE fixtures that define the exact current
production decoder contract.

These fixtures remain the production-behavior source of truth. The shadow
dissector now mirrors that contract without changing current production
classification semantics.

No committed generator is kept for this directory. The `.pcap` files are
committed deterministic binaries.

## Current production scope

Production MACsec support is presentation-only and no-flow:
- entry is recognized only from Ethernet link-type parsing after:
  - direct Ethernet II EtherType `0x88e5`;
  - outer single VLAN `0x8100`;
  - outer QinQ / provider stacking `0x88a8` + inner `0x8100`;
  - outer legacy VLAN-like TPID `0x9100`;
- MACsec is not decoded from Linux cooked roots;
- MACsec does not continue through protected payload into IPv4, IPv6, ARP, TCP,
  or UDP;
- MACsec does not create a recognized flow;
- MACsec does not create a persistent ProtocolPath entry;
- MACsec metadata does not grow the ProtocolPath registry;
- all fixtures in this directory stay in the unrecognized-packet list.

Conservative unsupported parent contexts follow from the existing production
continuation helpers and are not separately implemented here:
- PBB inner Ethernet -> MACsec;
- GRE TEB / EoIP inner Ethernet -> MACsec;
- MPLS pseudowire inner Ethernet -> MACsec;
- nested MACsec;
- inner VLAN / PPPoE / MPLS / PBB / MACsec inside protected payload.

## Exact production SecTAG contract

Production consumes the MACsec envelope with:
- fixed base SecTAG size: `6` bytes;
- optional SCI size: `8` bytes, only when `SC=1`;
- fixed assumed ICV size: `16` bytes;
- packet number width: `32` bits, big-endian;
- no ICV validation;
- no decryption;
- no Short Length based payload bounding.

Exact base layout consumed by production:
- byte `0`: TCI/AN;
- byte `1`: Short Length;
- bytes `2..5`: Packet Number;
- optional bytes `6..13`: SCI when `SC=1`.

Exact TCI/AN mapping used by production:
- bit `7`: Version;
- bit `6`: ES;
- bit `5`: SC;
- bit `4`: SCB;
- bit `3`: E;
- bit `2`: C;
- bits `1..0`: AN.

Fields production retains for selected-packet presentation:
- Version / ES / SC / SCB / E / C / AN;
- Short Length when at least 2 base bytes are available;
- Packet Number only when the full 6-byte base SecTAG is available;
- SCI System ID when `SC=1` and at least 6 SCI bytes are available;
- SCI Port ID when `SC=1` and all 8 SCI bytes are available;
- opaque protected-payload preview;
- opaque ICV preview when a full 16-byte ICV is available.

Fields production does not use for identity or flow grouping:
- Version;
- ES / SC / SCB / E / C;
- AN;
- Short Length;
- Packet Number;
- SCI.

## Exact production payload / ICV behavior

After the base SecTAG and optional SCI:
- if fewer than `16` bytes remain, production reports `MACsec ICV truncated`;
- in that truncated-ICV case, all remaining bytes are treated as protected
  payload bytes;
- `ICV Length` stays `0` and no separate MACsec ICV layer is emitted;
- if at least `16` bytes remain, the final `16` bytes are treated as the ICV and
  everything before that is treated as protected payload;
- Short Length is presented but ignored for payload/ICV boundary calculation.

Special plaintext-like metadata behavior:
- only for complete frames with `E=0` and `C=0`;
- only when protected payload length is at least `2` bytes;
- the first two protected bytes may be surfaced as `Plain EtherType`;
- the remaining bytes may be surfaced as `Data Length` and `Raw`;
- no inner protocol decode is attempted even when those bytes look like IPv4,
  IPv6, or another known EtherType.

## Exact production outcomes

Complete MACsec frames:
- unrecognized packet;
- reason text: `MACsec protected payload not decrypted`.

Truncated base SecTAG with fewer than 2 available base bytes:
- unrecognized packet;
- reason text: `MACsec SecTAG truncated`.

Truncated packet number with 2-5 available base bytes:
- unrecognized packet;
- reason text: `MACsec packet number truncated`.

SCI flag set with fewer than 8 SCI bytes available:
- unrecognized packet;
- reason text: `MACsec SCI truncated`.

Fewer than 16 bytes remaining after base SecTAG and optional SCI:
- unrecognized packet;
- reason text: `MACsec ICV truncated`.

## Shared constants used by most fixtures

- outer destination MAC: `02:00:00:00:70:02`
- outer source MAC: `02:00:00:00:70:01`
- default SCI System ID: `02:00:00:00:71:01`
- default SCI Port ID: `0x0001`
- default Packet Number: `0x01020304`
- alternate Packet Number: `0x0a0b0c0d`
- default protected payload ASCII: `macsec-protected-payload`
- default ICV bytes:
  `a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af`

## Per-fixture contract

### 01_macsec_basic_no_sci.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: Version `0`, ES `0`, SC `0`, SCB `0`, E `1`, C `1`, AN `0`, SL `0`,
  PN `0x01020304`
- SCI: absent
- protected payload: opaque ASCII payload
- ICV: full 16 bytes
- capture/report boundary: complete capture
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- ProtocolId: none
- physical ProtocolPath: none persisted
- purpose: baseline complete MACsec envelope without SCI

### 02_macsec_sci_present.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: SC `1`, E `1`, C `1`, AN `0`, PN `0x01020304`
- SCI: `02:00:00:00:71:01:00:01`
- protected payload: opaque ASCII payload
- ICV: full 16 bytes
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: complete SCI presentation

### 03_macsec_an2_nonzero_pn_sci.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: SC `1`, E `1`, C `1`, AN `2`, PN `0x0a0b0c0d`
- SCI: `02:00:00:00:71:01:00:01`
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: non-default AN and PN metadata

### 04_macsec_integrity_only_cleartext_like_payload.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: E `0`, C `0`, AN `0`, PN `0x01020304`
- SCI: absent
- protected payload: starts with `45 00`, followed by IPv4-like cleartext bytes
- ICV: full 16 bytes
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: `Plain EtherType` metadata may be shown as `0x4500`, but no inner
  IPv4 / UDP decode occurs

### 05_macsec_short_length_nonzero.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: SL `32`, PN `0x01020304`
- SCI: absent
- protected payload: 32 bytes
- ICV: full 16 bytes
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: Short Length presentation when it happens to match payload size

### 06_vlan_macsec_sci.pcap
- outer encapsulation: Ethernet II -> VLAN `0x8100`, VID `700` -> MACsec
- SecTAG: SC `1`, PN `0x01020304`
- SCI: `02:00:00:00:71:01:00:01`
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: outer single-tag VLAN entry path

### 07_qinq_macsec_basic.pcap
- outer encapsulation: Ethernet II -> `0x88a8` VLAN `710` -> `0x8100` VLAN
  `720` -> MACsec
- SecTAG: no SCI, PN `0x01020304`
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: outer QinQ entry path

### 08_macsec_scb_flag.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: SCB `1`, E `1`, C `1`, PN `0x01020304`
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: SCB bit extraction

### 09_macsec_es_flag.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: ES `1`, E `1`, C `1`, PN `0x01020304`
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: ES bit extraction

### 10_macsec_truncated_base_sectag.pcap
- outer encapsulation: Ethernet II -> MACsec
- boundary shape: only 1 base SecTAG byte captured after EtherType
- expected production outcome: no-flow unrecognized packet,
  `MACsec SecTAG truncated`
- purpose: fewer than 2 base bytes

### 11_macsec_truncated_packet_number.pcap
- outer encapsulation: Ethernet II -> MACsec
- boundary shape: TCI/AN + Short Length + only 2 PN bytes captured
- expected production outcome: no-flow unrecognized packet,
  `MACsec packet number truncated`
- purpose: 2-5 available base bytes retain partial metadata but no PN

### 12_macsec_truncated_sci.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: SC `1`, complete base SecTAG, incomplete SCI
- SCI: only 1 byte captured
- expected production outcome: no-flow unrecognized packet,
  `MACsec SCI truncated`
- purpose: SCI truncation path

### 13_macsec_missing_icv_or_short_payload.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: complete base SecTAG, no SCI
- protected payload / ICV tail: only `15` bytes remain after the SecTAG
- expected production outcome: no-flow unrecognized packet,
  `MACsec ICV truncated`
- purpose: proves fewer than 16 remaining bytes are all counted as protected
  payload and no ICV layer is created

### 14_macsec_zero_packet_number.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: PN `0x00000000`
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: zero packet number presentation

### 15_macsec_protected_payload_ipv4_like_no_decode.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: complete base SecTAG, no SCI
- protected payload: bytes shaped like IPv4 + UDP + payload
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: proves IPv4-looking protected data remains opaque

### 16_macsec_legacy_vlan_9100.pcap
- outer encapsulation: Ethernet II -> legacy VLAN-like TPID `0x9100`, VID `730`
  -> MACsec
- SecTAG: complete base SecTAG, no SCI, PN `0x01020304`
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: proves outer `0x9100` VLAN entry reaches MACsec

### 17_macsec_version1_max_packet_number.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: Version `1`, AN `3`, PN `0xffffffff`
- SCI: absent
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: proves Version is metadata only and maximum PN is presented without
  changing classification

### 18_macsec_short_length_ignored_for_bounds.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: SL `4`, PN `0x01020304`
- SCI: absent
- protected payload: `de ad be ef ca fe ba be 11 22 33 44`
- ICV: full 16 bytes
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: proves Short Length is shown but ignored for protected-payload
  bounds

### 19_macsec_caplen_lt_origlen_partial_icv.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: complete base SecTAG, no SCI
- captured/original lengths: captured `32`, original `44`
- protected payload / ICV tail: captured bytes after the SecTAG are
  `6d 61 63 73 65 63 2d 38 a0 a1 a2 a3`
- expected production outcome: no-flow unrecognized packet,
  `MACsec ICV truncated`
- purpose: proves caplen-truncated partial ICV bytes are absorbed into protected
  payload preview and no ICV layer is emitted

### 20_macsec_plain_ether_type_one_byte_only.pcap
- outer encapsulation: Ethernet II -> MACsec
- SecTAG: E `0`, C `0`, PN `0x01020304`
- SCI: absent
- protected payload: single byte `45`
- ICV: full 16 bytes
- expected production outcome: no-flow unrecognized packet,
  `MACsec protected payload not decrypted`
- purpose: proves `Plain EtherType` requires at least 2 protected bytes even in
  complete `E=0` / `C=0` frames

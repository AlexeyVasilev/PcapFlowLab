Synthetic MACsec / IEEE 802.1AE parsing fixtures for regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- basic Ethernet `0x88e5` MACsec SecTAG presentation;
- optional outer VLAN / QinQ before MACsec;
- TCI/AN flag coverage;
- Packet Number and optional SCI presentation;
- Short Length presentation;
- bounded protected-payload / ICV preservation;
- malformed or truncated SecTAG / SCI / payload boundary cases;
- cleartext-looking protected payload that must not be decoded as IP in this scope.

Current shared support covers presentation-only MACsec handling.

Current committed behavior:
- MACsec EtherType `0x88e5` is recognized after outer Ethernet and optional outer VLAN / QinQ;
- SecTAG metadata is presented conservatively, including TCI/AN bits, Short Length, Packet Number, and optional SCI when available;
- protected payload bytes remain opaque and are shown only as bounded Data preview;
- ICV bytes are shown conservatively when enough bytes are present;
- all fixtures remain no-flow / unrecognized in this pass;
- no decryption, no ICV validation, and no flow recovery from protected payload are implied here.

## Local generation

Run from the repository root:

```bash
python tests/data/parsing/macsec/generate_macsec_pcaps.py --output-dir tests/data/parsing/macsec
```

To overwrite previously generated fixtures:

```bash
python tests/data/parsing/macsec/generate_macsec_pcaps.py --output-dir tests/data/parsing/macsec --force
```

Notes:
- The generator writes classic little-endian Ethernet `.pcap` files only.
- It does not send packets and does not require root/admin privileges.
- Manual bytes are used for outer Ethernet/VLAN framing, MACsec SecTAG bytes, protected payload bytes, ICV bytes, and malformed/truncated cases.
- No Scapy MACsec layer is required or assumed.

## Shared constants

- Secure A MAC: `02:00:00:00:70:01`
- Secure B MAC: `02:00:00:00:70:02`
- SCI System ID: `02:00:00:00:71:01`
- SCI Port ID: `0x0001`
- Outer VLAN ID: `700`
- Outer S-VLAN ID: `710`
- Outer C-VLAN ID: `720`
- Default Packet Number: `0x01020304`
- Alternate Packet Number: `0x0a0b0c0d`
- Zero Packet Number fixture value: `0x00000000`
- Default protected payload: ASCII bytes for `macsec-protected-payload`
- ICV length: `16` bytes
- ICV bytes: `a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af`

## MACsec / IEEE 802.1AE notes

This fixture set keeps the scope intentionally narrow:
- outer Ethernet plus optional outer VLAN / QinQ;
- EtherType `0x88e5`;
- MACsec SecTAG metadata only;
- protected payload bytes preserved as opaque bytes;
- ICV bytes preserved as opaque bytes.

Explicitly out of scope for this fixture-preparation pass:
- decryption;
- ICV / authentication validation;
- SAK / MKA / key-management handling;
- SecY / policy semantics;
- flow recovery from protected payload;
- inner IPv4 / IPv6 / TCP / UDP decode even when protected bytes look like cleartext.

## SecTAG layout notes

Common base SecTAG layout used by these fixtures:
- TCI/AN: `1` byte
- Short Length: `1` byte
- Packet Number: `4` bytes
- optional SCI: `8` bytes when the SC flag is set

SCI layout:
- System Identifier: `6` bytes
- Port Identifier: `2` bytes

## TCI/AN bit mapping

The generator constructs the TCI/AN byte from named fields using this mapping:

```text
bit 7: Version
bit 6: ES
bit 5: SC
bit 4: SCB
bit 3: E
bit 2: C
bits 1..0: AN
```

## Protected payload and ICV notes

- Protected payload bytes are deterministic explicit bytes.
- Some fixtures intentionally start protected payload with IPv4-like or EtherType-like bytes.
- Future parser behavior in this branch must still keep those bytes opaque and must not fabricate a normal IP flow from them.
- ICV bytes are deterministic explicit bytes and are not validated in this scope.

## Current support assumptions

Current supported presentation behavior:
- MACsec EtherType `0x88e5` recognized;
- SecTAG metadata shown conservatively:
  - TCI/AN flags
  - Short Length
  - Packet Number
  - optional SCI
- protected payload shown as bounded opaque Data;
- ICV bytes shown conservatively where practical.
- for complete `E=0` / `C=0` frames, the first two secured-data bytes may also be surfaced as `Plain EtherType` metadata while the remaining secured data stays opaque and no inner flow is recovered.

Current no-flow / safety behavior:
- all fixtures remain no-flow / unrecognized;
- outer Ethernet / VLAN envelope remains visible;
- protected payload is never decoded as inner IPv4 / IPv6 / ARP / TCP / UDP;
- malformed/truncated cases remain best-effort no-crash robustness fixtures.

## Per-file descriptions

### 01_macsec_basic_no_sci.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec EtherType / SecTAG without SCI / protected payload / ICV
- Fields:
  - Version `0`
  - ES `0`
  - SC `0`
  - SCB `0`
  - E `1`
  - C `1`
  - AN `0`
  - SL `0`
  - PN `0x01020304`
- Current behavior: basic SecTAG presentation without flow recovery.

### 02_macsec_sci_present.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG with SCI / protected payload / ICV
- Fields:
  - SC `1`
  - E `1`
  - C `1`
  - AN `0`
  - PN `0x01020304`
  - SCI `02:00:00:00:71:01:00:01`
- Current behavior: optional SCI presentation.

### 03_macsec_an2_nonzero_pn_sci.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG with SCI / protected payload / ICV
- Fields:
  - SC `1`
  - E `1`
  - C `1`
  - AN `2`
  - PN `0x0a0b0c0d`
- Current behavior: non-default association number and packet number presentation.

### 04_macsec_integrity_only_cleartext_like_payload.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG without SCI / cleartext-looking protected payload / ICV
- Fields:
  - E `0`
  - C `0`
  - AN `0`
  - PN `0x01020304`
  - first secured-data bytes `45 00`
- Current behavior: payload must still remain opaque MACsec protected data.
  The app may surface `0x4500` as plaintext EtherType metadata for manual inspection, but it must not decode inner IPv4/UDP or create a normal flow.

### 05_macsec_short_length_nonzero.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG / short protected payload / ICV
- Fields:
  - SL `32`
  - PN `0x01020304`
- Current behavior: Short Length field presentation.

### 06_vlan_macsec_sci.pcap

- Packets: 1
- Layer chain: outer Ethernet / VLAN / MACsec / SecTAG with SCI / protected payload / ICV
- Current behavior: outer VLAN remains visible and does not block MACsec metadata presentation.

### 07_qinq_macsec_basic.pcap

- Packets: 1
- Layer chain: outer Ethernet / QinQ / VLAN / MACsec / SecTAG without SCI / protected payload / ICV
- Current behavior: stacked VLAN before MACsec remains visible.

### 08_macsec_scb_flag.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG with SCB flag / protected payload / ICV
- Fields:
  - SCB `1`
  - E `1`
  - C `1`
- Current behavior: TCI flag coverage.

### 09_macsec_es_flag.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG with ES flag / protected payload / ICV
- Fields:
  - ES `1`
  - E `1`
  - C `1`
- Current behavior: TCI flag coverage.

### 10_macsec_truncated_base_sectag.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec EtherType / incomplete SecTAG base header
- Current conservative behavior: malformed/truncated no-crash case; no flow.

### 11_macsec_truncated_packet_number.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / TCI/AN + SL + partial PN
- Current conservative behavior: partial SecTAG handling without fabricating PN.

### 12_macsec_truncated_sci.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / complete base SecTAG / SC flag set / incomplete SCI
- Current conservative behavior: SCI truncation robustness; no flow.

### 13_macsec_missing_icv_or_short_payload.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / complete SecTAG / protected payload shorter than expected ICV boundary
- Current conservative behavior: protected payload / ICV boundary robustness; no flow.

### 14_macsec_zero_packet_number.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG / PN `0x00000000` / protected payload / ICV
- Current behavior: metadata robustness; Packet Number zero is shown conservatively.

### 15_macsec_protected_payload_ipv4_like_no_decode.pcap

- Packets: 1
- Layer chain: outer Ethernet / MACsec / SecTAG / protected payload bytes that look like IPv4/UDP / ICV
- Current behavior: payload remains opaque; no fake IPv4/UDP flow is created in this scope.

## Expected generated file list

- `01_macsec_basic_no_sci.pcap`
- `02_macsec_sci_present.pcap`
- `03_macsec_an2_nonzero_pn_sci.pcap`
- `04_macsec_integrity_only_cleartext_like_payload.pcap`
- `05_macsec_short_length_nonzero.pcap`
- `06_vlan_macsec_sci.pcap`
- `07_qinq_macsec_basic.pcap`
- `08_macsec_scb_flag.pcap`
- `09_macsec_es_flag.pcap`
- `10_macsec_truncated_base_sectag.pcap`
- `11_macsec_truncated_packet_number.pcap`
- `12_macsec_truncated_sci.pcap`
- `13_macsec_missing_icv_or_short_payload.pcap`
- `14_macsec_zero_packet_number.pcap`
- `15_macsec_protected_payload_ipv4_like_no_decode.pcap`

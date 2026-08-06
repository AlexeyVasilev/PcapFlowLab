# Packet Byte View Fixture Contracts

This directory contains deterministic classic-PCAP fixtures for selected-packet
`Bytes` fallback coverage.

Local regeneration:

```bash
python tests/data/parsing/packet_byte_views/generate_packet_byte_view_pcaps.py --output-dir tests/data/parsing/packet_byte_views --force
```

Notes:

- the generator is dependency-free and writes classic little-endian Ethernet `.pcap` files directly;
- the generated binaries are committed test assets and are opened from disk by tests;
- `Captured Packet` is a fallback for a packet record whose outer protocol unit cannot be safely decoded;
- rich decoded Packet Details may be unavailable while the fallback `Captured Packet` byte view remains available;
- classic-PCAP record headers are not part of the selected packet `Bytes` view;
- Linux SLL and SLL2 are intentionally out of scope for this directory;
- deeper PCAPNG container-byte inspection remains deferred to another feature pass.

Shared constants:

- Link type: Ethernet (`DLT_EN10MB`, `1`)
- Client MAC: `02:00:00:00:a0:01`
- Server MAC: `02:00:00:00:a0:02`
- Client IPv4: `192.0.2.10`
- Server IPv4: `198.51.100.20`
- Client UDP port: `53530`
- Server UDP port: `443`
- UDP payload: `PFL!`

## 01_ethernet_ipv4_udp.pcap

- Link type: Ethernet
- Packet structure: Ethernet II / IPv4 / UDP / payload
- Captured length: `46`
- Original length: `46`
- Why it exists: proves that an ordinary recognized outer unit suppresses the generic captured-packet fallback.
- Expected Summary behavior: normal Frame metadata plus decoded Ethernet / IPv4 / UDP layers.
- Expected Bytes descriptor behavior:
  - no visible `Captured Packet`;
  - no visible generic `Frame`;
  - root descriptor is `Ethernet II Frame`;
  - `Ethernet II Frame` starts at captured offset `0`;
  - `Ethernet II Frame` covers the complete captured packet bytes;
  - `IPv4 Packet` and `UDP Datagram` remain present.

## 02_truncated_ethernet_header.pcap

- Link type: Ethernet
- Packet structure: classic-PCAP packet record carrying only `10` captured Ethernet bytes
- Captured length: `10`
- Original length: `46`
- Why it exists: proves that selected-packet byte inspection remains usable when the outer Ethernet header cannot be safely decoded.
- Expected Summary behavior: Frame metadata remains honest about captured/original lengths; no fabricated Ethernet / IPv4 / UDP summary layer should be required for the fallback contract.
- Expected Bytes descriptor behavior:
  - fallback visible label is `Captured Packet`;
  - fallback stable id remains `frame:0:0`;
  - fallback starts at captured offset `0`;
  - fallback covers exactly the `10` captured bytes stored in the packet record;
  - no Ethernet II / IPv4 / UDP descriptor is fabricated.

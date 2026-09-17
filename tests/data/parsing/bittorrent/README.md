# BitTorrent Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab BitTorrent recognition behavior.

Current BitTorrent support is detection-only canonical BitTorrent peer-wire
handshake recognition. It lives in the application protocol hint path and
recognizes BitTorrent from an individual TCP transport payload when:

- payload size is at least `68` bytes;
- payload byte `0` is `19` / `0x13`;
- bytes `1..19` equal exactly `BitTorrent protocol`.

Recognition is not port-gated. Bytes after the first canonical 68-byte
handshake do not prevent detection. Successful detection produces Detected
Protocol `BitTorrent`; service hint remains empty.

PcapFlowLab does not currently validate reserved extension bits, interpret
`info_hash` as torrent identity, parse `peer_id`, parse tracker/torrent
metadata, parse length-prefixed peer-wire messages, or reconstruct a handshake
split across multiple TCP packets. It also does not expose dedicated
BitTorrent Packet Summary parsing, BitTorrent-specific Stream rows, or
BitTorrent Stream Item Data.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_bittorrent_pcaps.py --output-dir tests/data/parsing/bittorrent --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the six fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_bittorrent_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Canonical Handshake Layout

The canonical BitTorrent peer-wire handshake is `68` bytes:

- `pstrlen`: 1 byte, `19` / `0x13`
- protocol string: 19 bytes, `BitTorrent protocol`
- reserved bytes: 8 bytes
- `info_hash`: 20 bytes
- `peer_id`: 20 bytes

The fixtures use reserved bytes `00 00 00 00 00 00 00 00` and this
deterministic `info_hash`:

```text
00 01 02 03 04 05 06 07 08 09
0A 0B 0C 0D 0E 0F 10 11 12 13
```

Peer IDs:

- Peer A: `-PFL001-123456789012`
- Peer B: `-PFL002-ABCDEFGHIJKL`

## Shared Deterministic Network Values

- Peer A MAC: `02:00:00:00:43:01`
- Peer B MAC: `02:00:00:00:43:02`
- Peer A IPv4: `192.0.2.50`
- Peer B IPv4: `192.0.2.60`
- Typical/common Peer A port: `51413`
- Traditional/common Peer B port: `6881`
- Non-standard Peer A port: `53000`
- Non-standard Peer B port: `55000`
- Peer A initial sequence: `1000`
- Peer B initial sequence: `5000`

Port `6881` is traditional/common for BitTorrent traffic, not a protocol
requirement and not required by the current PcapFlowLab detector.

## Fixture Map

### `01_bittorrent_handshake_typical_ports.pcap`

- Packets: `1`
- Direction: Peer A to Peer B
- IPv4/TCP: `192.0.2.50:51413` -> `192.0.2.60:6881`
- Payload: exactly one canonical 68-byte handshake with Peer A peer ID
- Purpose: positive canonical-handshake baseline on common/traditional ports
- Expected current PFL behavior: one TCP Flow, Detected Protocol
  `BitTorrent`, empty service hint, no dedicated BitTorrent Summary or
  protocol-aware Stream behavior
- Wireshark note: should normally recognize the peer-wire handshake

### `02_bittorrent_bidirectional_nonstandard_ports.pcap`

- Packets: `2`
- Packet 1: Peer A `192.0.2.50:53000` -> Peer B `192.0.2.60:55000`
- Packet 2: Peer B `192.0.2.60:55000` -> Peer A `192.0.2.50:53000`
- Payloads: canonical 68-byte handshakes with the same `info_hash`, using Peer
  A and Peer B peer IDs respectively
- Purpose: positive baseline preserving current non-port-gated BitTorrent
  detection and one bidirectional user-facing Flow
- Expected current PFL behavior: one TCP Flow, packet count `2`, Detected
  Protocol `BitTorrent`, empty service hint
- Wireshark note: automatic BitTorrent dissection on arbitrary ports may vary
  by Wireshark configuration or heuristic behavior

### `03_bittorrent_handshake_plus_keepalive.pcap`

- Packets: `1`
- Direction: Peer A to Peer B
- IPv4/TCP: `192.0.2.50:51413` -> `192.0.2.60:6881`
- Payload: canonical 68-byte handshake followed by peer-wire keep-alive
  `00 00 00 00`
- Purpose: positive baseline proving current detection requires at least
  `68` bytes, not exactly `68` bytes
- Expected current PFL behavior: one TCP Flow, Detected Protocol
  `BitTorrent`, empty service hint
- Boundary: PcapFlowLab does not currently parse or identify the keep-alive

### `04_bittorrent_invalid_pstrlen.pcap`

- Packets: `1`
- Direction: Peer A to Peer B
- IPv4/TCP: `192.0.2.50:51413` -> `192.0.2.60:6881`
- Payload: 68-byte BitTorrent-like payload with first byte changed from
  `0x13` to `0x12`
- Purpose: negative pstrlen validation case
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `BitTorrent`, empty service hint, no crash

### `05_bittorrent_invalid_protocol_string.pcap`

- Packets: `1`
- Direction: Peer A to Peer B
- IPv4/TCP: `192.0.2.50:51413` -> `192.0.2.60:6881`
- Payload: 68-byte BitTorrent-like payload with `pstrlen = 19`, but protocol
  string `BitXorrent protocol`
- Purpose: negative exact protocol-name matching case
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `BitTorrent`, empty service hint

### `06_bittorrent_short_67_byte_handshake.pcap`

- Packets: `1`
- Direction: Peer A to Peer B
- IPv4/TCP: `192.0.2.50:51413` -> `192.0.2.60:6881`
- Payload: canonical handshake prefix truncated to exactly `67` TCP payload
  bytes by omitting the final peer ID byte
- Purpose: minimum-size boundary negative case
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `BitTorrent`, empty service hint, no crash
- Boundary: this is a valid TCP segment with a 67-byte payload, not snaplen
  truncation

## Future Parsing Boundary

These fixtures preserve current detection-only behavior. PcapFlowLab does not
currently parse choke/unchoke, interested/not interested, HAVE, BITFIELD,
REQUEST, PIECE, CANCEL, extended messaging, DHT metadata, or encrypted
BitTorrent handshakes.

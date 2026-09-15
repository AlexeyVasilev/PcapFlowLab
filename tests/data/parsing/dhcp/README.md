# DHCPv4 / BOOTP-DHCP Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab DHCPv4 recognition behavior.

Current PcapFlowLab DHCPv4 support is detection-only. It lives in the
application protocol hint path, not in structural DissectionEngine parsing.
The current detector recognizes DHCPv4 only when:

- transport is UDP;
- the endpoint ports are exactly `67` and `68` in either direction;
- the UDP payload is large enough to include the DHCP magic cookie;
- the DHCP magic cookie `63 82 53 63` appears at payload offset `236`.

The BOOTP fixed header is `236` bytes, so the magic cookie starts immediately
after that fixed area. PcapFlowLab does not currently expose dedicated DHCP
Packet Summary parsing, option parsing, message-type presentation,
protocol-aware DHCP Stream items, or DHCP Stream Item Data.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_dhcp_pcaps.py --output-dir tests/data/parsing/dhcp --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the six fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_dhcp_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:40:01`
- Server MAC: `02:00:00:00:40:fe`
- Broadcast MAC: `ff:ff:ff:ff:ff:ff`
- Client assigned IPv4: `192.0.2.100`
- Server IPv4: `192.0.2.1`
- Initial client IPv4: `0.0.0.0`
- Broadcast IPv4: `255.255.255.255`
- Transaction ID: `0x3903F326`
- DHCP client port: `68`
- DHCP server port: `67`

BOOTP uses `op = 1` for requests, `op = 2` for replies, `htype = 1`,
`hlen = 6`, and the fixed client MAC in `chaddr`.

## Fixture Map

### `01_dhcp_discover_broadcast.pcap`

- Packets: `1`
- Direction: client to broadcast
- Ethernet: `02:00:00:00:40:01` -> `ff:ff:ff:ff:ff:ff`
- IPv4: `0.0.0.0` -> `255.255.255.255`
- UDP: `68` -> `67`
- BOOTP/DHCP: BOOTREQUEST, broadcast flag, valid magic cookie, DHCP Message
  Type Discover, small Parameter Request List, End option
- Purpose: positive baseline for current DHCPv4 recognition on client-to-server
  ports
- Expected current PFL behavior: one normal UDP Flow, Detected Protocol
  `DHCP`, empty service hint, no dedicated DHCP Packet Summary or
  protocol-aware Stream behavior
- Wireshark note: should decode as BOOTP/DHCP

### `02_dhcp_offer_broadcast.pcap`

- Packets: `1`
- Direction: server to broadcast/client
- Ethernet: `02:00:00:00:40:fe` -> `ff:ff:ff:ff:ff:ff`
- IPv4: `192.0.2.1` -> `255.255.255.255`
- UDP: `67` -> `68`
- BOOTP/DHCP: BOOTREPLY, `yiaddr = 192.0.2.100`,
  `siaddr = 192.0.2.1`, valid magic cookie, DHCP Message Type Offer,
  Server Identifier, deterministic Lease Time, End option
- Purpose: positive baseline proving the detector accepts the reverse DHCP port
  direction
- Expected current PFL behavior: Detected Protocol `DHCP`, empty service hint,
  no deeper DHCP-specific presentation
- Wireshark note: should decode as BOOTP/DHCP

### `03_dhcp_request_ack_bidirectional.pcap`

- Packets: `2`
- Packet 1: client to server, `192.0.2.100:68` -> `192.0.2.1:67`,
  BOOTREQUEST, valid magic cookie, DHCP Message Type Request, Server Identifier
- Packet 2: server to client, `192.0.2.1:67` -> `192.0.2.100:68`,
  BOOTREPLY, valid magic cookie, DHCP Message Type ACK, Server Identifier,
  deterministic Lease Time
- Purpose: positive baseline for recognition inside one ordinary bidirectional
  UDP Flow
- Expected current PFL behavior: one user-facing UDP Flow, packet count `2`,
  Detected Protocol `DHCP`, empty service hint
- Wireshark note: should decode both packets as BOOTP/DHCP

### `04_dhcp_bad_magic_cookie.pcap`

- Packets: `1`
- Direction: client to broadcast
- IPv4/UDP: `0.0.0.0:68` -> `255.255.255.255:67`
- BOOTP/DHCP shape: Discover-like payload with enough bytes to reach the cookie
  location, but cookie bytes are `63 82 53 62`
- Purpose: negative baseline proving DHCP ports alone do not classify a Flow as
  DHCP
- Expected current PFL behavior: normal UDP Flow, Detected Protocol must not be
  `DHCP`, no crash
- Wireshark note: may decode conservatively as BOOTP or malformed/non-DHCP

### `05_dhcp_valid_payload_wrong_ports.pcap`

- Packets: `1`
- Direction: client to broadcast
- IPv4/UDP: `0.0.0.0:1068` -> `255.255.255.255:1067`
- Payload: structurally valid DHCP Discover payload with valid magic cookie and
  options
- Purpose: negative baseline preserving the current port-gated recognition
  contract
- Expected current PFL behavior: normal UDP Flow, Detected Protocol must not be
  `DHCP`, no crash
- Wireshark note: payload is DHCP-shaped, but PcapFlowLab intentionally does
  not classify it without ports `67`/`68`

### `06_dhcp_truncated_before_magic_cookie.pcap`

- Packets: `1`
- Direction: client to broadcast
- IPv4/UDP: `0.0.0.0:68` -> `255.255.255.255:67`
- Payload: exactly `239` UDP payload bytes, containing the full `236`-byte
  BOOTP fixed area plus only the first three bytes of the expected magic cookie
- Purpose: size-boundary negative case proving the detector does not read past
  available bytes
- Expected current PFL behavior: normal UDP Flow, Detected Protocol must not be
  `DHCP`, no crash
- Wireshark note: this is payload-short, not snaplen truncation

## Future Parsing Boundary

These fixtures preserve current detection-only behavior. Future DHCP work may
add deeper BOOTP/DHCP parsing, option presentation, message-type presentation,
or DHCP-specific Stream views, but that behavior is not implemented by the
current fixture contract.

# DHCPv4 / BOOTP-DHCP Parsing Fixtures

This directory contains the permanent PCAP fixture set for current PcapFlowLab
DHCPv4 recognition behavior and the first planned structured-inspection scope.

Current PcapFlowLab DHCPv4 support is detection-only. It lives in the
application protocol hint path, not in structural DissectionEngine parsing.
The current detector recognizes DHCPv4 only when:

- transport is UDP;
- the endpoint ports are exactly `67` and `68` in either direction;
- the UDP payload is at least `240` bytes;
- the DHCP magic cookie `63 82 53 63` appears at payload offset `236`.

The current detector does not require a valid BOOTP `op`, `htype`, `hlen`,
DHCP Message Type option, valid DHCP option list, End option, or semantic
consistency between addresses and options. The malformed-options fixture below
therefore remains a positive DHCP detection case even though a future deep
selected-packet parser should report its malformed option boundary.

PcapFlowLab does not currently expose dedicated DHCP Packet Summary parsing,
option parsing, message-type presentation, protocol-aware DHCP Stream items, or
DHCP Stream Item Data.

## Generation

The committed deterministic generator is:

```bash
python tests/data/parsing/dhcp/generate_dhcp_pcaps.py \
    --output-dir tests/data/parsing/dhcp \
    --force
```

Run the command from the repository root after installing Scapy locally. The
generator emits classic Ethernet `.pcap` files, prints generated paths, and
does not use network access, live DHCP, randomness, current time, hostname data,
or environment-derived values.

When `--force` is not supplied, existing fixture files are not overwritten.
Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the generator and regenerate the PCAPs.

Fixtures `01`-`06` are historical detector fixtures. Their generator path is
kept separate from the newer structured fixture helpers so future structured
changes do not silently alter the legacy bytes. After regeneration, verify
that `01`-`06` remain byte-for-byte clean in Git.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:40:01`
- Server MAC: `02:00:00:00:40:fe`
- Broadcast MAC: `ff:ff:ff:ff:ff:ff`
- Client assigned IPv4: `192.0.2.100`
- Server IPv4: `192.0.2.1`
- Initial client IPv4: `0.0.0.0`
- Broadcast IPv4: `255.255.255.255`
- Historical transaction ID: `0x3903F326`
- Structured Discover/Offer transaction ID: `0x3903F327`
- DHCP client port: `68`
- DHCP server port: `67`

BOOTP uses `op = 1` for requests, `op = 2` for replies, `htype = 1`,
`hlen = 6`, and the fixed client MAC in the meaningful prefix of `chaddr`.
Remaining `chaddr`, `sname`, and `file` bytes are deterministic zero padding
unless the fixture explicitly uses text or Option Overload.

## Planned First Structured Scope

The planned first structured DHCPv4 selected-packet pass should expose the
fixed BOOTP/DHCP fields:

- `op`;
- `htype`;
- `hlen`;
- `hops`;
- `xid`;
- `secs`;
- `flags` and the broadcast bit;
- `ciaddr`;
- `yiaddr`;
- `siaddr`;
- `giaddr`;
- `chaddr`;
- `sname` and `file` when they are not overloaded;
- DHCP magic cookie.

The planned first option parser should preserve ordered options and cover:

- Subnet Mask;
- Router;
- Domain Name Server;
- Host Name;
- Domain Name;
- Broadcast Address;
- Requested IP Address;
- IP Address Lease Time;
- Option Overload;
- DHCP Message Type;
- Server Identifier;
- Parameter Request List;
- Message;
- Maximum DHCP Message Size;
- Renewal Time Value;
- Rebinding Time Value;
- Vendor Class Identifier;
- Client Identifier;
- TFTP Server Name;
- Bootfile Name;
- generic unknown option preservation.

Structural behavior targets:

- ordered option preservation;
- Pad option support;
- End option termination;
- Option Overload option areas in the main options, `file`, and `sname`;
- malformed or truncated option preservation without over-read or crash;
- future selected-packet Bytes view named `DHCP Message`.

The planned first structured implementation does not include:

- Option 82 Relay Agent Information deep parsing;
- Option 119 Domain Search decoding or compression handling;
- Option 121 Classless Static Route decoding;
- Vendor-Specific Option 43 deep semantics;
- Vendor-Identifying Option 125 deep semantics;
- RFC3396 long-option concatenation;
- DHCP authentication;
- DHCPv6;
- DHCP-specific Stream rows;
- request/response transaction correlation by `xid`;
- lease/session lifecycle reconstruction;
- DHCP client/server state machine;
- service-hint extraction.

Unknown unsupported options should still be preserved generically.

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

### `07_dhcp_structured_discover.pcap`

- Packets: `1`
- Direction: client to broadcast
- Ethernet: `02:00:00:00:40:01` -> `ff:ff:ff:ff:ff:ff`
- IPv4/UDP: `0.0.0.0:68` -> `255.255.255.255:67`
- BOOTP: BOOTREQUEST, `htype = 1`, `hlen = 6`, `xid = 0x3903F327`,
  `secs = 7`, broadcast flag set, all address fields `0.0.0.0`, client MAC in
  `chaddr`, empty `sname`, empty `file`
- Options, in order: DHCP Message Type Discover, Host Name `pfl-client`,
  Requested IP Address `192.0.2.100`, Parameter Request List
  `[1, 3, 6, 15, 28, 51, 54, 58, 59]`, Client Identifier
  `01 02 00 00 00 40 01`, Maximum DHCP Message Size `1500`,
  Vendor Class Identifier `PFL-DHCP-Client`, End
- Purpose: target structured request-header, broadcast flag, `chaddr`, text
  option, single IPv4 option, PRL, Ethernet Client Identifier, uint16 option,
  and End handling
- Expected current PFL behavior: Detected Protocol `DHCP`, empty service hint,
  no dedicated DHCP Packet Summary or DHCP-specific Stream behavior
- Target structured behavior: expose fixed header fields, ordered options, and
  later a bounded `DHCP Message` byte view

### `08_dhcp_structured_offer.pcap`

- Packets: `1`
- Direction: server to broadcast/client
- Ethernet: `02:00:00:00:40:fe` -> `ff:ff:ff:ff:ff:ff`
- IPv4/UDP: `192.0.2.1:67` -> `255.255.255.255:68`
- BOOTP: BOOTREPLY, `xid = 0x3903F327`, broadcast flag set,
  `yiaddr = 192.0.2.100`, `siaddr = 192.0.2.1`, client MAC in `chaddr`,
  normal `sname = "dhcp-server"`, normal `file = "pxelinux.0"`
- Options, in order: DHCP Message Type Offer, Subnet Mask `255.255.255.0`,
  Router `192.0.2.1` and `192.0.2.254`, Domain Name Server `192.0.2.53` and
  `192.0.2.54`, Domain Name `example.test`, Broadcast Address
  `192.0.2.255`, Lease Time `3600`, Renewal Time `1800`, Rebinding Time
  `3150`, Server Identifier `192.0.2.1`, Message `PFL offer`, End
- Purpose: target BOOTREPLY fields, `yiaddr` / `siaddr`, non-overloaded
  `sname` / `file` text, IPv4-list options, lease/T1/T2 integers,
  domain/message text, and Server Identifier
- Expected current PFL behavior: Detected Protocol `DHCP`, empty service hint,
  no dedicated DHCP Packet Summary or DHCP-specific Stream behavior
- Target structured behavior: expose fixed reply fields, ordered options, text
  fields, and later a bounded `DHCP Message` byte view

### `09_dhcp_option_overload.pcap`

- Packets: `1`
- Direction: server to client
- Ethernet: `02:00:00:00:40:fe` -> `02:00:00:00:40:01`
- IPv4/UDP: `192.0.2.1:67` -> `192.0.2.100:68`
- BOOTP: BOOTREPLY, `xid = 0x3903F329`, `yiaddr = 192.0.2.100`,
  `siaddr = 192.0.2.1`, client MAC in `chaddr`
- Main options, in order: DHCP Message Type ACK, Option Overload `3`,
  Server Identifier `192.0.2.1`, End
- `file` field: overloaded option area containing Bootfile Name
  `bootx64.efi`, End, then zero-fill to `128` bytes
- `sname` field: overloaded option area containing TFTP Server Name
  `tftp.example.test`, End, then zero-fill to `64` bytes
- Purpose: target Option Overload semantics, main/file/sname option areas,
  fixed field sizes, and End behavior; prevents future parsing from treating
  overloaded binary option areas as ordinary BOOTP strings
- Expected current PFL behavior: Detected Protocol `DHCP`, empty service hint,
  no dedicated DHCP Packet Summary or DHCP-specific Stream behavior
- Target structured behavior: expose main options and overloaded `file` /
  `sname` option areas without expecting extra magic cookies in those fields

### `10_dhcp_padding_unknown_end.pcap`

- Packets: `1`
- Direction: client to server
- Ethernet: `02:00:00:00:40:01` -> `02:00:00:00:40:fe`
- IPv4/UDP: `192.0.2.100:68` -> `192.0.2.1:67`
- BOOTP: BOOTREQUEST, `xid = 0x3903F32A`, `ciaddr = 192.0.2.100`,
  client MAC in `chaddr`
- Options before End, in order: DHCP Message Type Request, Pad, Pad, unknown
  option `200` with value `12 34 56`, Host Name `pad-client`, End
- Intentional bytes after End: a plausible DHCP Message Type ACK TLV followed
  by Message `ignored-tail`; these bytes are deterministic tail data and must
  not be parsed as DHCP options
- Purpose: target Pad handling, unknown option preservation, exact
  unknown-length/value preservation, End termination, and no accidental parsing
  of tail bytes after End
- Expected current PFL behavior: Detected Protocol `DHCP`, empty service hint,
  no dedicated DHCP Packet Summary or DHCP-specific Stream behavior
- Target structured behavior: expose only the options before End and preserve
  or describe the post-End tail as non-option data

### `11_dhcp_malformed_option_length.pcap`

- Packets: `1`
- Direction: client to broadcast
- Ethernet: `02:00:00:00:40:01` -> `ff:ff:ff:ff:ff:ff`
- IPv4/UDP: `0.0.0.0:68` -> `255.255.255.255:67`
- BOOTP: BOOTREQUEST, `xid = 0x3903F32B`, broadcast flag set, client MAC in
  `chaddr`, valid DHCP magic cookie at offset `236`
- Options: DHCP Message Type Discover, then Host Name option code `12` with
  declared length `10` but only three bytes of value `bad`; no End option is
  appended and the UDP payload ends immediately after those three bytes
- Purpose: target distinction between cheap import-time DHCP recognition and
  deep selected-packet option validation; future Summary should preserve fixed
  header and already parsed options, report the malformed Host Name boundary,
  avoid over-read, and avoid crashing
- Expected current PFL behavior: Detected Protocol `DHCP`, empty service hint,
  no dedicated DHCP Packet Summary or DHCP-specific Stream behavior
- Target structured behavior: expose valid fixed header, valid cookie, valid
  earlier Message Type, malformed Host Name with declared length `10` and
  available value length `3`, and later a bounded `DHCP Message` byte view

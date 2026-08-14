# `packet-info`

`packet-info` inspects exactly one captured packet.

It supports two selection modes:

- a global packet number in the capture timeline;
- a packet position inside one canonical flow.

In the normal CLI workflow:

```text
summary
-> flows
-> flow-info
-> packet-info
```

But `packet-info` can also inspect a packet directly with `--packet-in-file`
when you already know the global packet number and do not need to pick a flow
first.

The examples below were captured from the 0.3.0 CLI using the repository
showcase raw capture and index. Shell-specific executable prefixes such as
`.\` are omitted.

## Inspect a packet by capture number

This is the best opening workflow because it shows the simplest direct packet
inspection path.

Command:

```text
pcap-flow-lab packet-info pcap_flow_lab_showcase.pcap --packet-in-file 1
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Packet 1

Packet
Packet in File: 1
Time: 2026-03-22 12:26:40.000000
Captured Length: 54 B
Original Length: 54 B

Summary

Frame: Packet 1 in file
  Packet number in file: 1
  Timestamp: 2026-03-22 12:26:40.000000
  Encapsulation Type: Ethernet
  Captured Length: 54 bytes
  Original Length: 54 bytes

Ethernet II, Src: 02:00:00:00:10:10, Dst: 02:00:00:00:10:20
  Source: 02:00:00:00:10:10
  Destination: 02:00:00:00:10:20
  Type: IPv4 (0x0800)

IPv4, Src: 192.0.2.10, Dst: 198.51.100.10
  Version: 4
  Internet Header Length: 20 bytes (5)
  Differentiated Services Field: 0x00
  Total Length: 40 bytes
  Identification: 0x0000
  Flags: 0x0
  Fragment Offset: 0
  TTL: 64
  Protocol: TCP (6)
  Header Checksum: 0x0000
  Source Address: 192.0.2.10
  Destination Address: 198.51.100.10

TCP, Src Port: 41000, Dst Port: 443
  Source Port: 41000
  Destination Port: 443
  Sequence Number (raw): 1000
  Acknowledgment Number (raw): 9000
  Header Length: 20 bytes (5)
  Flags: SYN
  Window: 16384
  Checksum: 0x0000
  Urgent Pointer: 0
  Payload Length: 0 bytes
```

What this shows:

- `--packet-in-file 1` selects the first captured packet globally;
- the report starts with packet metadata;
- `Summary` then walks the decoded protocol layers in order;
- this specific packet is a TCP SYN with no payload.

## Reading the packet report

The current CLI report is organized around:

- `Packet`
- `Summary`
- optional `Flow Context`
- optional `Bytes`

### Packet metadata

The `Packet` section gives the basic facts for the selected packet:

- `Packet in File`: the one-based packet number in the global capture
  timeline;
- `Time`: the packet timestamp;
- `Captured Length`: the captured packet length;
- `Original Length`: the original on-the-wire packet length.

This uses the same captured-vs-original terminology already used elsewhere in
the CLI.

### Structured Summary

`Summary` is structured protocol inspection, not just raw text dumping.

The structured summary uses the same packet-inspection model as the main
product surface. In practice that means:

- the top `Frame` layer gives packet-level metadata;
- protocol layers follow in decoded nesting order;
- each layer exposes labeled fields;
- child layers are rendered under their parent when the protocol stack is
  nested.

## Inspect a packet inside a flow

Use flow-scoped selection when you want the N-th packet inside one canonical
flow instead of the N-th packet in the whole capture.

Command:

```text
pcap-flow-lab packet-info pcap_flow_lab_showcase.pcap --flow-number 1 --packet-in-flow 4
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Flow 1 / Packet 4

Flow Context
Endpoints: 192.0.2.10:41000 <-> 198.51.100.10:443
Direction: A -> B

Packet
Packet in File: 4
Time: 2026-03-22 12:26:40.250000
Captured Length: 148 B
Original Length: 148 B

Summary

Frame: Packet 4 in Flow, Packet 4 in file
  Packet number in flow: 4
  Packet number in file: 4
  Timestamp: 2026-03-22 12:26:40.250000
  Encapsulation Type: Ethernet
  Captured Length: 148 bytes
  Original Length: 148 bytes

Ethernet II, Src: 02:00:00:00:10:10, Dst: 02:00:00:00:10:20
  Source: 02:00:00:00:10:10
  Destination: 02:00:00:00:10:20
  Type: IPv4 (0x0800)

IPv4, Src: 192.0.2.10, Dst: 198.51.100.10
  Version: 4
  Internet Header Length: 20 bytes (5)
  Differentiated Services Field: 0x00
  Total Length: 134 bytes
  Identification: 0x0000
  Flags: 0x0
  Fragment Offset: 0
  TTL: 64
  Protocol: TCP (6)
  Header Checksum: 0x0000
  Source Address: 192.0.2.10
  Destination Address: 198.51.100.10

TCP, Src Port: 41000, Dst Port: 443
  Source Port: 41000
  Destination Port: 443
  Sequence Number (raw): 1001
  Acknowledgment Number (raw): 9001
  Header Length: 20 bytes (5)
  Flags: ACK|PSH
  Window: 16384
  Checksum: 0x0000
  Urgent Pointer: 0
  Payload Length: 94 bytes

Transport Layer Security, ClientHello
  Record Type: Handshake
  Record Legacy Version: TLS 1.2 (0x0303)
  Record Length: 89
  Total Record Size: 94 bytes
  Handshake Type: ClientHello
  Handshake Length: 85
  ClientHello Legacy Version: TLS 1.2 (0x0303)
  Session ID Length: 0
  Session ID: <empty>
  Cipher Suite Count: 1
  Compression Method Count: 1
  Extension Count: 2
  SNI: bulk-download.example.test
  Supported TLS Versions: TLS 1.3 (0x0304)

  Cipher Suites (1)
    [0]: TLS_AES_128_GCM_SHA256 (0x1301)

  Compression Methods (1)
    [0]: null (0)

  Extensions (2)

    [0] server_name (0x0000), 31 bytes - bulk-download.example.test
      Type: 0 (0x0000)
      Length: 31
      Server Name [0]: bulk-download.example.test

    [1] supported_versions (0x002b), 3 bytes - TLS 1.3 (0x0304)
      Type: 43 (0x002b)
      Length: 3
      Version [0]: TLS 1.3 (0x0304)
```

This flow-scoped mode adds two useful things:

- `Flow Context` with the stored flow endpoints;
- `Direction` relative to the selected canonical flow's stored A/B
  orientation.

The `Direction` line should be read only as:

- packet traveling from Endpoint A toward Endpoint B; or
- packet traveling from Endpoint B toward Endpoint A.

It is not a client/server or request/response label.

This example also shows that `packet-info` can reach application-level
structured inspection. Here the packet reaches a TLS ClientHello and exposes
values such as:

- SNI: `bulk-download.example.test`
- supported TLS version: `TLS 1.3 (0x0304)`

### Packet in Flow vs Packet in File

These are different coordinate systems.

For the previous example:

- `Packet in Flow: 4`
- `Packet in File: 4`

That equality is incidental for this flow.

In the showcase GRE example below:

- `Packet in Flow: 4`
- `Packet in File: 392`

Current production behavior is:

- `--packet-in-file <N>` is global to the capture timeline;
- `--flow-number <F> --packet-in-flow <P>` is local to one canonical flow;
- flow-scoped packet numbering is one-based and follows the packet order of
  that selected canonical flow.

## Inspect nested protocol layers

The command is not limited to the terminal 5-tuple. It exposes nested
encapsulation and inner protocol layers too.

Command:

```text
pcap-flow-lab packet-info pcap_flow_lab_showcase.pcap --flow-number 2 --packet-in-flow 4
```

Verified relevant output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Flow 2 / Packet 4

Flow Context
Endpoints: 192.0.2.140:43000 <-> 198.51.100.140:443
Direction: A -> B

Packet
Packet in File: 392
Time: 2026-03-22 12:27:00.200000
Captured Length: 183 B
Original Length: 183 B

Summary

Frame: Packet 4 in Flow, Packet 392 in file
  Packet number in flow: 4
  Packet number in file: 392
  Timestamp: 2026-03-22 12:27:00.200000
  Encapsulation Type: Ethernet
  Captured Length: 183 bytes
  Original Length: 183 bytes

Ethernet II, Src: 02:00:00:00:40:10, Dst: 02:00:00:00:40:20
  Source: 02:00:00:00:40:10
  Destination: 02:00:00:00:40:20
  Type: 802.1Q VLAN (0x8100)

802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 320
  TPID: 802.1Q VLAN (0x8100)
  Priority: 0
  DEI: 0
  VLAN ID: 320
  Encapsulated EtherType: MPLS Unicast (0x8847)

MPLS Label, Label: 16010, TC: 0, BoS: 0, TTL: 64
  Label: 16010
  Traffic Class: 0
  Bottom of Stack: 0
  TTL: 64

MPLS Label, Label: 16011, TC: 0, BoS: 1, TTL: 64
  Label: 16011
  Traffic Class: 0
  Bottom of Stack: 1
  TTL: 64

IPv4, Src: 203.0.113.40, Dst: 198.51.100.40
  Version: 4
  Internet Header Length: 20 bytes (5)
  Differentiated Services Field: 0x00
  Total Length: 157 bytes
  Identification: 0x0000
  Flags: 0x0
  Fragment Offset: 0
  TTL: 64
  Protocol: 47
  Header Checksum: 0x0000
  Source Address: 203.0.113.40
  Destination Address: 198.51.100.40

GRE
  Flags / Version: 0x0000
  Version: 0
  Checksum Present: No
  Key Present: No
  Sequence Present: No
  Protocol Type: IPv4 (0x0800)
  Inner Payload: IPv4

Inner IPv4, Src: 192.0.2.140, Dst: 198.51.100.140
  Version: 4
  Internet Header Length: 20 bytes (5)
  Differentiated Services Field: 0x00
  Total Length: 133 bytes
  Identification: 0x0000
  Flags: 0x0
  Fragment Offset: 0
  TTL: 64
  Protocol: TCP (6)
  Header Checksum: 0x0000
  Source Address: 192.0.2.140
  Destination Address: 198.51.100.140

Inner TCP, Src Port: 43000, Dst Port: 443
  Source Port: 43000
  Destination Port: 443
  Sequence Number (raw): 3001
  Acknowledgment Number (raw): 8001
  Header Length: 20 bytes (5)
  Flags: ACK|PSH
  Window: 16384
  Checksum: 0x0000
  Urgent Pointer: 0
  Payload Length: 93 bytes

Transport Layer Security, ClientHello
  Record Type: Handshake
  Record Legacy Version: TLS 1.2 (0x0303)
  Record Length: 88
  Total Record Size: 93 bytes
  Handshake Type: ClientHello
  Handshake Length: 84
  ClientHello Legacy Version: TLS 1.2 (0x0303)
  Session ID Length: 0
  Session ID: <empty>
  Cipher Suite Count: 1
  Compression Method Count: 1
  Extension Count: 2
  SNI: gre-analysis.example.test
  Supported TLS Versions: TLS 1.3 (0x0304)

  ...
```

Here `...` marks documentation truncation, not literal CLI output.

The important part is the decoded nested stack:

```text
Ethernet II
-> VLAN
-> MPLS
-> MPLS
-> IPv4
-> GRE
-> Inner IPv4
-> Inner TCP
-> TLS ClientHello
```

Current nested-layer behavior is user-facing and explicit:

- inner encapsulated layers are rendered with labels such as `Inner IPv4` and
  `Inner TCP`;
- protocol layers are listed in decoded nesting order;
- the command can therefore expose both outer transport/encapsulation and inner
  application-facing details in one packet report.

## Show captured bytes

Use `--bytes` when you want the captured packet bytes in addition to the
structured summary.

Command:

```text
pcap-flow-lab packet-info pcap_flow_lab_showcase.pcap --flow-number 16 --packet-in-flow 1 --bytes
```

Verified output:

```text
Opening capture: 100% (728.9 KB / 728.9 KB)
Flow 16 / Packet 1

Flow Context
Endpoints: 192.0.2.50:53050 <-> 198.51.100.53:53
Direction: A -> B

Packet
Packet in File: 825
Time: 2026-03-22 12:27:20.000000
Captured Length: 77 B
Original Length: 77 B

Summary

Frame: Packet 1 in Flow, Packet 825 in file
  Packet number in flow: 1
  Packet number in file: 825
  Timestamp: 2026-03-22 12:27:20.000000
  Encapsulation Type: Ethernet
  Captured Length: 77 bytes
  Original Length: 77 bytes

Ethernet II, Src: 02:00:00:00:60:10, Dst: 02:00:00:00:60:20
  Source: 02:00:00:00:60:10
  Destination: 02:00:00:00:60:20
  Type: IPv4 (0x0800)

IPv4, Src: 192.0.2.50, Dst: 198.51.100.53
  Version: 4
  Internet Header Length: 20 bytes (5)
  Differentiated Services Field: 0x00
  Total Length: 63 bytes
  Identification: 0x0000
  Flags: 0x0
  Fragment Offset: 0
  TTL: 64
  Protocol: UDP (17)
  Header Checksum: 0x0000
  Source Address: 192.0.2.50
  Destination Address: 198.51.100.53

UDP, Src Port: 53050, Dst Port: 53
  Source Port: 53050
  Destination Port: 53
  Length: 43 bytes
  Checksum: 0x0000
  Payload Length: 35 bytes

Domain Name System, Query
  Message Type: Query
  Transaction ID: 0x2001
  Flags: 0x0100
  Opcode: Standard query (0)
  Authoritative Answer: No
  Truncated: No
  Recursion Desired: Yes
  Recursion Available: No
  Response Code: No error (0)
  Questions: 1
  Answers: 0
  Authority RRs: 0
  Additional RRs: 0
  QName: demo.example.test
  QType: A (1)

  Questions

    demo.example.test
      Type: A (1)
      Class: IN (1)


Bytes

Ethernet II Frame - 77 bytes

00000000  02 00 00 00 60 20 02 00 00 00 60 10 08 00 45 00  |....` ....`...E.|
00000010  00 3f 00 00 00 00 40 11 00 00 c0 00 02 32 c6 33  |.?....@......2.3|
00000020  64 35 cf 3a 00 35 00 2b 00 00 20 01 01 00 00 01  |d5.:.5.+.. .....|
00000030  00 00 00 00 00 00 04 64 65 6d 6f 07 65 78 61 6d  |.......demo.exam|
00000040  70 6c 65 04 74 65 73 74 00 00 01 00 01           |ple.test.....|
```

Current `--bytes` behavior is:

- the normal structured `Summary` is still shown;
- `--bytes` appends a separate `Bytes` section;
- the transcript includes a byte-owner label line for the selected bytes;
- the rendered bytes are the full captured packet bytes for the selected
  packet;
- the hex dump includes an offset column, hexadecimal bytes, and ASCII
  rendering.

The current public CLI surface exposes only `--bytes`.

## Inspect through an index

Packet inspection from an index can work too, but it depends on source capture
bytes being available.

Command:

```text
pcap-flow-lab packet-info showcase.idx --packet-in-file 1 --source-capture pcap_flow_lab_showcase.pcap
```

Verified output excerpt:

```text
Opening index: 100% (72.4 KB / 72.4 KB)
Packet 1

Packet
Packet in File: 1
Time: 2026-03-22 12:26:40.000000
Captured Length: 54 B
Original Length: 54 B

Summary

Frame: Packet 1 in file
  Packet number in file: 1
  Timestamp: 2026-03-22 12:26:40.000000
  Encapsulation Type: Ethernet
  Captured Length: 54 bytes
  Original Length: 54 bytes

...

TCP, Src Port: 41000, Dst Port: 443
  Source Port: 41000
  Destination Port: 443
  Sequence Number (raw): 1000
  Acknowledgment Number (raw): 9000
  Header Length: 20 bytes (5)
  Flags: SYN
  Window: 16384
  Checksum: 0x0000
  Urgent Pointer: 0
  Payload Length: 0 bytes
```

Here `...` again marks documentation truncation.

Current index behavior is:

- the index can identify the packet and its metadata;
- actual packet inspection still needs readable source capture data;
- if the index already points to an accessible source capture, packet
  inspection can work automatically;
- if the stored source capture is missing or unreadable, inspection fails and
  asks you to attach it with `--source-capture <path>`;
- raw capture input rejects `--source-capture`.

## Other useful workflows

### Use the explicit input form

You can replace positional input with:

```text
--input <path>
```

But positional input and `--input` are mutually exclusive input forms.

### Apply raw-capture import settings

`--settings <settings.json>` is valid only for raw capture input.

Current user-relevant contract is:

- settings are applied before raw-capture inspection;
- for flow-scoped selection, grouping settings can therefore affect canonical
  flow numbering and packet membership;
- index input rejects `--settings`.

For the accepted `settings.json` fields, defaults, and validation rules, see
[Capture processing settings](../reference/settings.md).

For direct global `--packet-in-file` selection, the packet number remains a
global capture coordinate, so grouping settings do not redefine that global
packet numbering.

### Control progress output

`--progress <auto|on|off>` controls progress reporting while the input is
opened.

The safe user-facing takeaway is simple:

- packet inspection reports open/import progress;
- packet report output itself goes to stdout;
- warnings and failures remain on stderr.

## Command reference

### Syntax

```text
pcap-flow-lab packet-info <input> --packet-in-file <N> [options]
pcap-flow-lab packet-info <input> --flow-number <F> --packet-in-flow <P> [options]
pcap-flow-lab packet-info --input <input> ...
```

### Supported inputs

- raw captures;
- Pcap Flow Lab indexes.

### Packet selection modes

| Selection | Meaning |
| --- | --- |
| `--packet-in-file <N>` | Select the N-th captured packet in the global capture timeline. |
| `--flow-number <F> --packet-in-flow <P>` | Select the P-th packet inside canonical flow F. |

Current rules:

- all user-facing packet and flow numbers here are one-based;
- `--flow-number` and `--packet-in-flow` must be supplied together;
- global and flow-scoped selection are mutually exclusive.

### Options

- `--input <path>`
- `--packet-in-file <N>`
- `--flow-number <F>`
- `--packet-in-flow <P>`
- `--source-capture <path>`
- `--settings <settings.json>`
- `--bytes`
- `--progress <auto|on|off>`
- `-h`
- `--help`

### Raw capture vs index

| Capability | Raw capture | Index |
| --- | --- | --- |
| Global packet selection | Yes | Yes |
| Flow-scoped packet selection | Yes | Yes |
| Structured Summary | Yes | Yes, when source packet bytes are available |
| `--bytes` | Yes | Yes, when source packet bytes are available |
| `--settings` | Yes | No |
| `--source-capture` | No | Yes |

## Invalid combinations and errors

The most important current rules are:

- missing input path is invalid;
- no packet selector is invalid;
- `--packet-in-file` together with flow-scoped selection is invalid;
- `--flow-number` without `--packet-in-flow` is invalid;
- `--packet-in-flow` without `--flow-number` is invalid;
- positional input together with `--input` is invalid;
- `--settings` with index input is invalid;
- `--source-capture` with raw capture input is invalid.

Important out-of-range failures are also explicit:

- out-of-range `--packet-in-file`;
- out-of-range `--flow-number`;
- out-of-range `--packet-in-flow` within the selected flow.

The current CLI also explicitly rejects unsupported options such
as:

- `--packet-number`
- `--packet-numbers`
- `--flow-numbers`
- `--byte-view`
- `--list-byte-views`
- `--bytes-layer`
- `--format`
- `--json`
- `--out`
- `--filter`
- `--sort`
- `--limit`

## Notes and limitations

- `packet-info` inspects exactly one packet at a time;
- flow-scoped selection adds `Flow Context`, but global packet selection does
  not;
- global packet selection can inspect recognized and unrecognized packets;
- the current public byte-presentation option is only `--bytes`;
- `--bytes` renders the complete captured packet, not uncaptured original bytes
  beyond the capture length;
- nested inner layers are exposed when the decode supports them.

## Related commands

- [summary](summary.md)
- [flows](flows.md)
- [flow-info](flow-info.md)
- [export-flows](export-flows.md)

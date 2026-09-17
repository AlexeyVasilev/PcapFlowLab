# AMQP Parsing Fixtures

This directory contains the permanent PCAP fixture set for the first
PcapFlowLab AMQP recognition behavior.

These PCAPs define the detection-only AMQP contract.

## Target First AMQP Support

The intended first AMQP support is detection-only. It should live in the
application protocol hint path and recognize AMQP only from one of the exact
supported protocol headers when that complete 8-byte header starts at offset
`0` of the examined TCP payload.

Target behavior:

- TCP only.
- Content-based recognition with no mandatory port requirement.
- The complete 8-byte AMQP protocol header must be present in one examined TCP
  payload.
- TCP/5672 alone does not imply AMQP.
- TCP/5671 alone does not imply AMQP.
- Ordinary TLS ClientHello traffic on TCP/5671 must remain TLS, not AMQP.
- No generic "starts with AMQP" recognition.
- No AMQP-specific TCP reassembly.
- A protocol header split across TCP packets may remain undetected initially.
- A capture that starts after AMQP protocol negotiation may remain plain TCP.
- No RabbitMQ-specific parsing.
- No container-id, virtual-host, or authentication-credential extraction into
  `service_hint`.
- No AMQP-specific Packet Summary, Stream rows, or byte views.

Successful AMQP detection produces Detected Protocol `AMQP` / protocol hint
`amqp`, while service hint remains empty.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_amqp_pcaps.py --output-dir tests/data/parsing/amqp --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the ten fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_amqp_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:48:01`
- Server MAC: `02:00:00:00:48:02`
- Client IPv4: `192.0.2.150`
- Server IPv4: `192.0.2.160`
- Client ephemeral TCP port: `58000`
- Normal AMQP server port: `5672`
- Non-standard AMQP test port: `35672`
- Client initial TCP sequence: `1000`
- Server initial TCP sequence: `5000`

All fixtures use deterministic Ethernet / IPv4 / TCP / Raw packets with `PA`
flags, stable ACK values, stable timestamps, and Scapy-generated IPv4/TCP
checksums. Full TCP handshakes are not required for these future
application-protocol recognition fixtures.

## Accepted Future Protocol Headers

The first AMQP recognizer should accept only these exact 8-byte protocol
headers:

AMQP 0-9-1:

```text
"AMQP" 00 00 09 01
```

AMQP 1.0 Core:

```text
"AMQP" 00 01 00 00
```

AMQP 1.0 TLS security-layer protocol header:

```text
"AMQP" 02 01 00 00
```

This is an explicit AMQP protocol negotiation header. It does not mean that
arbitrary TLS traffic is AMQP, and it does not mean that port `5671` implies
AMQP.

AMQP 1.0 SASL security-layer protocol header:

```text
"AMQP" 03 01 00 00
```

This is an explicit AMQP SASL protocol header. It does not mean that generic
SASL traffic is AMQP.

## Fixture Map

### `01_amqp091_header_port5672.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:5672`
- Payload: exactly `41 4D 51 50 00 00 09 01`
- Meaning: AMQP 0-9-1 protocol header
- Purpose: primary AMQP 0-9-1 positive baseline on standard TCP/5672
- Expected PFL behavior: one TCP Flow, Detected Protocol `AMQP`,
  protocol hint `amqp`, empty service hint

### `02_amqp091_header_nonstandard_port.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:35672`
- Payload: exactly `41 4D 51 50 00 00 09 01`
- Purpose: positive content-based AMQP 0-9-1 recognition without requiring
  TCP/5672
- Expected PFL behavior: Detected Protocol `AMQP`, empty service hint

### `03_amqp10_core_header_port5672.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:5672`
- Payload: exactly `41 4D 51 50 00 01 00 00`
- Meaning: AMQP 1.0 core protocol header, protocol-id `0`, version `1.0.0`
- Purpose: AMQP 1.0 core positive baseline
- Expected PFL behavior: Detected Protocol `AMQP`, empty service hint

### `04_amqp10_sasl_header_nonstandard_port.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:35672`
- Payload: exactly `41 4D 51 50 03 01 00 00`
- Meaning: AMQP 1.0 SASL protocol header, protocol-id `3`, version `1.0.0`
- Purpose: explicit AMQP SASL-layer positive case on a non-standard port
- Expected PFL behavior: Detected Protocol `AMQP`, empty service hint
- Boundary: this does not imply generic SASL traffic is AMQP.

### `05_amqp10_tls_header_nonstandard_port.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:35672`
- Payload: exactly `41 4D 51 50 02 01 00 00`
- Meaning: AMQP 1.0 TLS security-layer protocol header, protocol-id `2`,
  version `1.0.0`
- Purpose: explicit AMQP TLS negotiation header positive case without
  port-based AMQPS inference
- Expected PFL behavior: Detected Protocol `AMQP`, empty service hint
- Boundary: a real TLS ClientHello on TCP/5671 remains TLS, not AMQP.

### `06_amqp_garbage_port5672.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:5672`
- Payload: ASCII `PFL-NOT-AMQP\r\n`
- Purpose: negative case proving TCP/5672 alone is insufficient; the payload
  contains `AMQP` later, but not at offset `0`
- Expected PFL behavior: NOT AMQP

### `07_amqp091_wrong_version.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:5672`
- Payload: exactly `41 4D 51 50 00 00 09 00`
- Purpose: near-miss negative case proving exact AMQP 0-9-1 header matching
- Expected PFL behavior: NOT AMQP

### `08_amqp10_unsupported_protocol_id.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:5672`
- Payload: exactly `41 4D 51 50 01 01 00 00`
- Purpose: negative case proving the first implementation accepts only AMQP
  1.0 protocol IDs `0`, `2`, and `3`
- Expected PFL behavior: NOT AMQP

### `09_amqp10_wrong_revision.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:5672`
- Payload: exactly `41 4D 51 50 00 01 00 01`
- Purpose: negative case proving exact AMQP 1.0 version tuple validation
- Expected PFL behavior: NOT AMQP

### `10_amqp_truncated_header.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.150:58000` -> `192.0.2.160:5672`
- Payload: exactly seven bytes, `41 4D 51 50 00 01 00`
- Purpose: minimum-length boundary proving a valid-looking prefix is
  insufficient without the complete 8-byte protocol header
- Expected PFL behavior: NOT AMQP

## Intentionally Omitted Permanent Fixtures

This first fixture contract does not cover:

- arbitrary AMQP frame parsing;
- Connection.Start / Connection.Open semantic parsing;
- AMQP performatives;
- RabbitMQ extensions;
- container id;
- virtual host;
- authentication credentials;
- AMQP over WebSockets;
- AMQP-specific TCP reassembly;
- protocol header split across TCP packets;
- capture beginning after the AMQP protocol header;
- TLS ClientHello merely because it is on port `5671`;
- port-only recognition on `5672`;
- every historical AMQP version;
- unsupported AMQP 1.0 protocol IDs;
- Packet Summary;
- AMQP-specific Stream rows;
- AMQP-specific byte views.

No permanent trailing-bytes fixture is included. The eventual recognizer should
accept a complete supported AMQP protocol header even when additional bytes
follow in the same TCP payload, but that boundary is better protected by a
small synthetic unit test later.

No permanent TLS-on-5671 fixture is included. That remains existing TLS
recognition behavior, and AMQP recognition must be exact-content based rather
than port based.

These omissions are not bugs in the first detection-only contract.

## Manual Inspection Guidance

After generating the fixtures, useful manual checks include:

- For fixtures 01-05, verify the first 8 TCP payload bytes exactly match the
  documented accepted AMQP protocol headers.
- For fixtures 01-05, Wireshark may decode standard-port traffic
  automatically; non-standard ports may require Decode As.
- For fixtures 01-05, PcapFlowLab is expected to show Detected Protocol
  `AMQP` with an empty service hint.
- For fixtures 06-10, verify the malformed or near-miss payload bytes exactly.
- Wireshark behavior for the negative fixtures is informational only and does
  not define the PcapFlowLab detection contract.

## Future Parsing Boundary

Future AMQP work may add deeper parsing, protocol-aware Stream presentation,
or selected-packet Summary support. That work is intentionally outside this
fixture contract. The first implementation stays a cheap, bounded,
content-based protocol hint.

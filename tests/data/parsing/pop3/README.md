# POP3 Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab POP3 recognition behavior.

Current POP3 support is detection-only. It lives in the application protocol
hint path and recognizes POP3 from an individual TCP transport payload only
when:

- transport is TCP;
- either endpoint port is `110`;
- the payload begins exactly with one of `+OK`, `USER`, or `PASS`.

Matching is currently shallow and case-sensitive. The implementation uses
simple prefix matching and does not currently require a space after `+OK`,
`USER`, or `PASS`, nor complete POP3 command grammar or line termination.
Permanent positive fixtures intentionally use valid-looking POP3 lines rather
than accidental prefix matches such as `+OKAY`, `USERNAME`, or `PASSWORD`.

Successful detection produces Detected Protocol `POP3`; service hint remains
empty.

PcapFlowLab does not currently provide general POP3 command parsing, server
response parsing beyond shallow `+OK` recognition, authentication state,
mailbox/message state, `STAT`/`LIST`/`RETR`/`DELE`/`QUIT` parsing, multiline
response parsing, message/header/body parsing, dedicated POP3 Packet Summary,
POP3-specific Stream rows, or POP3 Stream Item Data. It also does not
reconstruct a POP3 command split across multiple TCP segments.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_pop3_pcaps.py --output-dir tests/data/parsing/pop3 --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the five fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_pop3_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:45:01`
- Server MAC: `02:00:00:00:45:02`
- Client IPv4: `192.0.2.90`
- Server IPv4: `192.0.2.100`
- Client ephemeral port: `55000`
- POP3 server port: `110`
- Unsupported-port fixture server port: `1110`
- Client initial TCP sequence: `1000`
- Server initial TCP sequence: `5000`

All fixtures use deterministic Ethernet / IPv4 / TCP / Raw packets with `PA`
flags, stable ACK values, CRLF line endings for normal POP3 text, and
Scapy-generated IPv4/TCP checksums. Full TCP handshakes are not required for
current application-protocol recognition.

## Fixture Map

### `01_pop3_greeting_user_port110.pcap`

- Packets: `2`
- Packet 1: server `192.0.2.100:110` -> client `192.0.2.90:55000`
- Packet 2: client `192.0.2.90:55000` -> server `192.0.2.100:110`
- Payloads: `+OK PFL POP3 server ready\r\n` and `USER alice\r\n`
- Purpose: positive baseline for common POP3 connection opening, covering both
  the `+OK` server prefix and `USER` client prefix inside one bidirectional
  TCP Flow
- Expected current PFL behavior: one bidirectional TCP Flow, packet count `2`,
  Detected Protocol `POP3`, empty service hint, no dedicated POP3 Summary
- Wireshark note: should normally be recognized as POP3

### `02_pop3_pass_port110.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.90:55000` -> `192.0.2.100:110`
- Payload: `PASS pfl-test-password\r\n`
- Purpose: positive baseline for the current `PASS` recognition prefix
- Expected current PFL behavior: one TCP Flow, Detected Protocol `POP3`,
  empty service hint
- Boundary: this deterministic synthetic credential does not imply
  authentication-state semantics

### `03_pop3_user_after_unmatched_payload.pcap`

- Packets: `2`
- Direction: client to server for both packets
- IPv4/TCP: `192.0.2.90:55000` -> `192.0.2.100:110`
- Packet 1 payload: `NOTICE\r\n`
- Packet 2 payload: `USER later-user\r\n`
- Purpose: positive baseline showing one unmatched payload does not
  permanently prevent later POP3 recognition in the same Flow
- Expected current PFL behavior: one TCP Flow, packet count `2`, final
  Detected Protocol `POP3`, empty service hint
- Boundary: this tests later independent payload recognition, not TCP
  reassembly; the second payload independently begins with `USER`

### `04_pop3_user_port1110_not_detected.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.90:55000` -> `192.0.2.100:1110`
- Payload: `USER alice\r\n`
- Purpose: negative baseline preserving the current TCP/110 port-gated
  detector contract
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `POP3`, empty service hint, no crash
- Boundary: TCP/1110 can carry POP3-like traffic in real deployments, but
  current PFL detection is intentionally limited to TCP/110; this fixture
  preserves current behavior and may be updated if detection policy is
  broadened later
- Wireshark note: recognition may differ depending on port/dissector settings

### `05_pop3_invalid_usxr_port110.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.90:55000` -> `192.0.2.100:110`
- Payload: `USXR alice\r\n`
- Purpose: negative exact-prefix case proving TCP/110 alone is insufficient
  and a visually similar command must not match `USER`
- Expected current PFL behavior: one TCP Flow, Detected Protocol must not be
  `POP3`, empty service hint, no crash
- Wireshark note: may still select the POP3 dissector because TCP/110 is
  present

## Future Parsing Boundary

These fixtures preserve current detection-only behavior. Future POP3 work may
add deeper command/reply parsing, authentication/mailbox state, multiline
response parsing, message presentation, or POP3-aware Stream views, but those
capabilities are not implemented by the current fixture contract.

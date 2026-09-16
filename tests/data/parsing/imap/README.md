# IMAP Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab IMAP recognition behavior.

Current IMAP support is detection-only. It lives in the application protocol
hint path and recognizes IMAP from an individual TCP transport payload only
when:

- transport is TCP;
- either endpoint port is `143`;
- the payload begins exactly with `* OK`; or
- the payload matches the current narrow tagged-command recognizer.

The current tagged-command recognizer is intentionally limited:

- the tag begins with uppercase `A`;
- the `A` is followed by one or more decimal digits;
- the numeric tag is followed by a space;
- the remaining command starts with `LOGIN `, starts with `CAPABILITY`, or
  equals exactly `LOGIN`.

Matching is currently case-sensitive. Real IMAP tags are more general than the
current `A<digits>` recognizer; this fixture set documents current useful
detection behavior, not the intended long-term IMAP grammar.

Successful detection produces Detected Protocol `IMAP`; service hint remains
empty.

PcapFlowLab does not currently provide general IMAP grammar parsing, arbitrary
IMAP tags, tagged `OK`/`NO`/`BAD` response parsing, untagged response parsing
beyond shallow `* OK` recognition, `SELECT`, `EXAMINE`, `FETCH`, `SEARCH`,
`STORE`, `COPY`, `UID`, `LIST`, `LSUB`, `STATUS`, `APPEND`, `IDLE`, `LOGOUT`,
`STARTTLS` state, authentication/session state, mailbox/message parsing,
dedicated IMAP Packet Summary, IMAP-specific Stream rows, or IMAP Stream Item
Data. It also does not reconstruct an IMAP command split across multiple TCP
segments.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_imap_pcaps.py --output-dir tests/data/parsing/imap --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the five fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_imap_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:46:01`
- Server MAC: `02:00:00:00:46:02`
- Client IPv4: `192.0.2.110`
- Server IPv4: `192.0.2.120`
- Client ephemeral port: `56000`
- IMAP server port: `143`
- Unsupported-port fixture server port: `1143`
- Client initial TCP sequence: `1000`
- Server initial TCP sequence: `5000`

All fixtures use deterministic Ethernet / IPv4 / TCP / Raw packets with `PA`
flags, stable ACK values, CRLF line endings for normal IMAP protocol text, and
Scapy-generated IPv4/TCP checksums. Full TCP handshakes are not required for
current application-protocol recognition.

## Fixture Map

### `01_imap_greeting_login_port143.pcap`

- Packets: `2`
- Packet 1: server `192.0.2.120:143` -> client `192.0.2.110:56000`
- Packet 2: client `192.0.2.110:56000` -> server `192.0.2.120:143`
- Payloads: `* OK PFL IMAP server ready\r\n` and
  `A001 LOGIN alice pfl-test-password\r\n`
- Purpose: positive baseline for common IMAP connection opening, covering both
  the `* OK` server prefix and current tagged `LOGIN ` client recognition
  inside one bidirectional TCP Flow
- Expected current PFL behavior: one bidirectional TCP Flow, packet count `2`,
  Detected Protocol `IMAP`, empty service hint, no dedicated IMAP Summary
- Boundary: the password is a deterministic synthetic fixture value only
- Wireshark note: should normally be recognized as IMAP

### `02_imap_capability_port143.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.110:56000` -> `192.0.2.120:143`
- Payload: `A002 CAPABILITY\r\n`
- Purpose: positive baseline for the current tagged `CAPABILITY` recognition
  path
- Expected current PFL behavior: one TCP Flow, Detected Protocol `IMAP`,
  empty service hint
- Boundary: this fixture does not imply capability-response parsing

### `03_imap_login_after_unmatched_payload.pcap`

- Packets: `2`
- Direction: client to server for both packets
- IPv4/TCP: `192.0.2.110:56000` -> `192.0.2.120:143`
- Packet 1 payload: `NOTICE\r\n`
- Packet 2 payload: `A123 LOGIN bob pfl-test-password\r\n`
- Purpose: positive baseline showing one unmatched payload does not
  permanently prevent later IMAP recognition in the same Flow
- Expected current PFL behavior: one TCP Flow, packet count `2`, final
  Detected Protocol `IMAP`, empty service hint
- Boundary: this tests later independent payload recognition, not TCP
  reassembly; packet 2 independently starts with a recognized tagged command

### `04_imap_login_port1143_not_detected.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.110:56000` -> `192.0.2.120:1143`
- Payload: `A001 LOGIN alice pfl-test-password\r\n`
- Purpose: negative baseline preserving the current TCP/143 port-gated
  detector contract
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `IMAP`, empty service hint, no crash
- Boundary: TCP/1143 can carry IMAP-like traffic in real deployments, but
  current PFL detection is intentionally limited to TCP/143; this fixture
  preserves current behavior and may be updated if detection policy is
  broadened later
- Wireshark note: recognition may differ depending on port/dissector settings

### `05_imap_missing_tag_command_separator_port143.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.110:56000` -> `192.0.2.120:143`
- Payload: `A001LOGIN alice pfl-test-password\r\n`
- Purpose: negative malformed near-miss proving TCP/143 alone is insufficient
  and the current tagged-command recognizer requires a separator after the
  numeric tag
- Expected current PFL behavior: one TCP Flow, Detected Protocol must not be
  `IMAP`, empty service hint, no crash
- Boundary: this payload is intentionally malformed because the tag/command
  separator is missing; it is not intended to restrict future support for
  legitimate non-`A<digits>` IMAP tags
- Wireshark note: may still select the IMAP dissector because TCP/143 is
  present

## Future Parsing Boundary

These fixtures preserve current detection-only behavior. Future IMAP work may
add deeper grammar parsing, broader tag support, additional command/response
recognition, session/mailbox state, message presentation, or IMAP-aware Stream
views, but those capabilities are not implemented by the current fixture
contract.

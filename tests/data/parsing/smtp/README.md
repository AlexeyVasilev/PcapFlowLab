# SMTP Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab SMTP recognition behavior.

Current SMTP support is detection-only. It lives in the application protocol
hint path and recognizes SMTP from an individual TCP transport payload only
when:

- transport is TCP;
- either endpoint port is `25` or `587`;
- the payload begins exactly with one of `220 `, `HELO `, `EHLO `, or
  `MAIL FROM:`.

Matching is currently shallow and case-sensitive. Successful detection
produces Detected Protocol `SMTP`; service hint remains empty.

PcapFlowLab does not currently provide general SMTP grammar parsing, reply-code
parsing beyond the `220 ` prefix, `RCPT TO` parsing, `DATA` parsing, `AUTH`
parsing, `STARTTLS` state tracking, message/header/body parsing, dedicated
SMTP Packet Summary parsing, SMTP-specific Stream rows, or SMTP Stream Item
Data.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_smtp_pcaps.py --output-dir tests/data/parsing/smtp --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the six fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_smtp_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:44:01`
- Server MAC: `02:00:00:00:44:02`
- Client IPv4: `192.0.2.70`
- Server IPv4: `192.0.2.80`
- Client ephemeral port: `54000`
- SMTP server port: `25`
- Submission port: `587`
- Unsupported-port fixture server port: `2525`
- Client initial TCP sequence: `1000`
- Server initial TCP sequence: `5000`

All fixtures use deterministic Ethernet / IPv4 / TCP / Raw packets with `PA`
flags, stable ACK values, CRLF line endings for normal SMTP text, and
Scapy-generated IPv4/TCP checksums. Full TCP handshakes are not required for
current application-protocol recognition.

## Fixture Map

### `01_smtp_greeting_ehlo_port25.pcap`

- Packets: `2`
- Packet 1: server `192.0.2.80:25` -> client `192.0.2.70:54000`
- Packet 2: client `192.0.2.70:54000` -> server `192.0.2.80:25`
- Payloads: `220 mail.example.test ESMTP PFL Test Server\r\n` and
  `EHLO client.example.test\r\n`
- Purpose: positive baseline for common SMTP connection opening, covering both
  the `220 ` server prefix and `EHLO ` client prefix inside one bidirectional
  TCP Flow
- Expected current PFL behavior: one bidirectional TCP Flow, packet count `2`,
  Detected Protocol `SMTP`, empty service hint, no dedicated SMTP Summary
- Wireshark note: should normally be recognized as SMTP

### `02_smtp_helo_port25.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.70:54000` -> `192.0.2.80:25`
- Payload: `HELO legacy-client.example.test\r\n`
- Purpose: positive baseline for the current `HELO ` recognition prefix
- Expected current PFL behavior: one TCP Flow, Detected Protocol `SMTP`,
  empty service hint

### `03_smtp_mail_from_port587.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.70:54000` -> `192.0.2.80:587`
- Payload: `MAIL FROM:<sender@example.test>\r\n`
- Purpose: positive baseline for current `MAIL FROM:` recognition and current
  TCP port `587` support
- Expected current PFL behavior: one TCP Flow, Detected Protocol `SMTP`,
  empty service hint
- Boundary: this fixture does not imply `STARTTLS` or `AUTH` support

### `04_smtp_ehlo_after_unmatched_payload.pcap`

- Packets: `2`
- Direction: client to server for both packets
- IPv4/TCP: `192.0.2.70:54000` -> `192.0.2.80:25`
- Packet 1 payload: `NOTICE\r\n`
- Packet 2 payload: `EHLO later.example.test\r\n`
- Purpose: positive baseline showing one unmatched payload does not
  permanently prevent later SMTP recognition in the same Flow
- Expected current PFL behavior: one TCP Flow, packet count `2`, final
  Detected Protocol `SMTP`, empty service hint
- Boundary: this tests later independent payload recognition, not TCP
  reassembly; the second payload independently begins with a recognized SMTP
  prefix

### `05_smtp_ehlo_port2525_not_detected.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.70:54000` -> `192.0.2.80:2525`
- Payload: `EHLO client.example.test\r\n`
- Purpose: negative baseline preserving the current port-gated detector
  contract
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `SMTP`, empty service hint, no crash
- Boundary: TCP/2525 can carry real SMTP in practice, but current PFL
  detection is intentionally limited to ports `25` and `587`; this fixture
  preserves current behavior and may be updated if detection policy is
  broadened later
- Wireshark note: recognition may differ depending on port/dissector settings

### `06_smtp_invalid_ehxlo_port25.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.70:54000` -> `192.0.2.80:25`
- Payload: `EHXLO client.example.test\r\n`
- Purpose: negative exact-prefix case proving port `25` alone is insufficient
  and a visually similar command prefix must not match `EHLO `
- Expected current PFL behavior: one TCP Flow, Detected Protocol must not be
  `SMTP`, empty service hint, no crash

## Future Parsing Boundary

These fixtures preserve current detection-only behavior. Future SMTP work may
add deeper command/reply parsing, `RCPT TO`, `DATA`, `AUTH`, `STARTTLS`,
message presentation, or SMTP-aware Stream views, but those capabilities are
not implemented by the current fixture contract.

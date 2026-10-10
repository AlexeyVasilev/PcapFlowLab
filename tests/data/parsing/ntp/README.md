# NTP Parsing Fixtures

This directory contains the permanent PCAP fixture set for conservative
PcapFlowLab NTP recognition behavior and the structured wire fixtures used by
selected-packet NTP Summary / byte-view tests.

## Current NTP Support

Current NTP support lives in the application protocol hint path and selected
packet presentation path. It recognizes and presents NTP only from a
conservative UDP/123-gated subset of classic NTP packets.

Current behavior:

- UDP only.
- NTP version `3` or `4` only.
- Ordinary client/server packet modes only:
  - mode `3`: client
  - mode `4`: server
- UDP payload size must be exactly `48` bytes.
- Client mode requires destination UDP port `123`.
- Server mode requires source UDP port `123`.
- Stratum must be `<= 16`.
- Leap Indicator `3` is not rejected; it represents an unsynchronized clock.
- Structured selected-packet Summary and byte-view support is intentionally
  limited to complete classic 48-byte NTPv3/NTPv4 basic headers.
- No NTP-specific Stream rows or Stream Item Data.
- No `service_hint`.
- No port-independent content recognition.
- No deep timestamp, poll, precision, extension-field, MAC, NTS, or daemon
  state validation.

Successful NTP detection produces Detected Protocol `NTP` /
protocol hint `ntp`, while service hint remains empty.

Fixtures 01-05 are recognized as NTP. Fixtures 06-10 remain ordinary UDP flows
with no NTP detected protocol because they are malformed for this recognition
contract or intentionally outside the first conservative automatic detector.
Fixtures 11-16 are structured-inspection inputs. They intentionally keep
the same conservative NTPv3/NTPv4 UDP/123 detection shape while adding richer
header-field coverage for Packet Summary / byte-view work.

## Fixture Generation

The authoritative generator is committed alongside these fixtures:

```bash
python tests/data/parsing/ntp/generate_ntp_pcaps.py --output-dir tests/data/parsing/ntp --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the sixteen fixture
files listed below when `--force` is supplied, emits classic Ethernet `.pcap`
files, and prints only the generated paths.

The fixtures are deterministic synthetic captures. The generator preserves the
historical detection fixture recipe for fixtures 01-10 and extends the same
fixture family with structured-inspection inputs 11-16. Regenerating with an
unchanged generator in the expected local environment should not change
existing fixture bytes; review generated `.pcap` diffs before committing.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tests/data/parsing/ntp/generate_ntp_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the committed generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:49:01`
- Server MAC: `02:00:00:00:49:02`
- Client IPv4: `192.0.2.170`
- Server IPv4: `192.0.2.180`
- Client ephemeral UDP port: `59000`
- NTP UDP port: `123`
- Non-standard negative-test server port: `30123`

All fixtures use deterministic Ethernet / IPv4 / UDP / Raw packets, stable
timestamps, and Scapy-generated IPv4/UDP checksums. No network access, live
NTP service, real clock, or external NTP library is required.

## NTP Basic Header Layout

All target positive fixtures use the classic 48-byte NTP basic header:

- byte `0`: Leap Indicator in bits `7..6`, Version in bits `5..3`, Mode in
  bits `2..0`
- byte `1`: Stratum
- byte `2`: Poll
- byte `3`: Precision
- bytes `4..7`: Root Delay
- bytes `8..11`: Root Dispersion
- bytes `12..15`: Reference ID
- bytes `16..23`: Reference Timestamp
- bytes `24..31`: Originate Timestamp
- bytes `32..39`: Receive Timestamp
- bytes `40..47`: Transmit Timestamp

Fields are encoded in big-endian/network byte order. The first detector should
not require client packets to have every non-mode field zero and should not
deeply validate timestamp semantics.

NTP timestamps carry only a 32-bit seconds field plus a 32-bit fraction field.
They do not carry an era number on the wire. Fixtures 11-16 therefore document
Era 0 raw timestamp values only. Era unfolding from capture time or local clock
context is future technical debt and is not part of the current fixture
contract.

Root Delay and Root Dispersion are retained as raw 32-bit wire fields. Summary
presentation interprets them by NTP version: NTPv3 uses signed 16.16 fixed
point, while NTPv4 uses unsigned NTP short format. Reference ID presentation is
also version/stratum/family aware: stratum `0`/`1` may show ASCII reference
identifiers, but stratum `> 1` over terminal IPv4 is shown as an IPv4 address;
IPv6 or unknown terminal family uses an opaque raw hex form.

## Fixture Map

### `01_ntpv4_client_request_port123.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.170:59000` -> `192.0.2.180:123`
- Payload: exactly `48` bytes
- Fields: LI `0`, VN `4`, Mode `3`, Stratum `0`
- Purpose: primary NTPv4 client request positive baseline with
  destination-port-123 recognition and an ephemeral client source port
- Current PFL behavior: Detected Protocol `NTP`, protocol hint `ntp`,
  empty service hint

### `02_ntpv4_server_response_port123.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: LI `0`, VN `4`, Mode `4`, Stratum `2`
- Purpose: normal NTPv4 server response positive baseline with
  source-port-123 recognition
- Current PFL behavior: Detected Protocol `NTP`, empty service hint

### `03_ntpv3_client_request_port123.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.170:59000` -> `192.0.2.180:123`
- Payload: exactly `48` bytes
- Fields: VN `3`, Mode `3`, Stratum `0`
- Purpose: explicit NTPv3 client positive coverage
- Current PFL behavior: Detected Protocol `NTP`, empty service hint

### `04_ntpv3_server_response_port123.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: VN `3`, Mode `4`, Stratum `3`
- Purpose: explicit NTPv3 server response positive coverage
- Current PFL behavior: Detected Protocol `NTP`, empty service hint

### `05_ntpv4_kod_rate_response.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: VN `4`, Mode `4`, Stratum `0`, Reference ID ASCII `RATE`
- Purpose: positive Kiss-o'-Death-style response proving stratum `0` is not
  rejected wholesale
- Current PFL behavior: Detected Protocol `NTP`, empty service hint
- Boundary: NTPv4 stratum-0 printable Reference ID also appears as `Kiss Code`;
  no service hint is expected

### `06_ntp_garbage_port123.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.170:59000` -> `192.0.2.180:123`
- Payload: exactly `48` deterministic bytes
- Malformed intent: byte `0` fails the supported VN/mode contract
- Purpose: negative case proving UDP/123 alone must not imply NTP
- Current PFL behavior: NOT NTP

### `07_ntpv4_client_wrong_ports.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.170:59000` -> `192.0.2.180:30123`
- Payload: otherwise valid 48-byte NTPv4 mode-3 client request
- Purpose: negative case proving NTP recognition is deliberately port-gated
  and valid-looking content alone on arbitrary UDP ports is insufficient
- Current PFL behavior: NOT NTP

### `08_ntpv2_client_port123.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.170:59000` -> `192.0.2.180:123`
- Payload: exactly `48` bytes
- Fields: VN `2`, Mode `3`, Stratum `0`
- Purpose: negative first-detector scope case; first PFL support accepts only
  NTPv3 and NTPv4
- Current PFL behavior: NOT NTP
- Boundary: NTPv2 is not described as intrinsically invalid protocol traffic;
  it is intentionally outside first PFL support

### `09_ntpv4_broadcast_mode5.pcap`

- Packets: `1`
- Direction: server-origin tuple
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: VN `4`, Mode `5`, Stratum `2`
- Purpose: negative first-detector scope case documenting intentionally narrow
  mode `3`/`4` support
- Current PFL behavior: NOT NTP in the first conservative detector
- Boundary: this is valid-family NTP behavior that is intentionally
  unsupported by the first automatic detector and may become positive in a
  future expansion

### `10_ntpv4_truncated_47_byte_header.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.170:59000` -> `192.0.2.180:123`
- Payload: exactly the first `47` bytes of an otherwise valid NTPv4 mode-3
  request
- Purpose: complete 48-byte basic-header boundary negative case
- Current PFL behavior: NOT NTP

### `11_ntpv4_structured_exchange.pcap`

- Packets: `2`
- Direction: bidirectional client/server exchange
- IPv4/UDP packet 1: `192.0.2.170:59000` -> `192.0.2.180:123`
- IPv4/UDP packet 2: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes in each packet
- Client fields: LI `0`, VN `4`, Mode `3`, Stratum `0`, Poll `6`,
  Precision `-20`, Root Delay `0`, Root Dispersion `0`
- Client Transmit Timestamp: Era 0 seconds for
  `2026-01-02 03:04:05 UTC`, fraction `0x40000000` (`.25`)
- Server fields: LI `0`, VN `4`, Mode `4`, Stratum `2`, Poll `6`,
  Precision `-20`, Root Delay `+0.125`, Root Dispersion `0.25`,
  Reference ID `192.0.2.1`
- Server Reference Timestamp: `2026-01-02 03:00:00.500000 UTC`
- Server Originate Timestamp: exactly the client Transmit Timestamp
- Server Receive Timestamp: `2026-01-02 03:04:05.375000 UTC`
- Server Transmit Timestamp: `2026-01-02 03:04:05.500000 UTC`
- Purpose: structured NTP client/server Summary and byte-view baseline
- Current PFL behavior: Detected Protocol `NTP`, protocol hint `ntp`, empty
  service hint; structured selected-packet Summary and NTP Message byte view
  are expected

### `12_ntpv3_structured_server_response.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: LI `0`, VN `3`, Mode `4`, Stratum `1`, Poll `4`,
  Precision `-18`, Reference ID ASCII `GPS\0`
- Root fields: deterministic nonzero Root Delay and Root Dispersion
- Timestamps: deterministic nonzero Era 0 Reference, Originate, Receive, and
  Transmit values
- Purpose: structured NTPv3 server-response presentation baseline
- Current PFL behavior: Detected Protocol `NTP`, empty service hint;
  structured selected-packet Summary and NTP Message byte view are expected

### `13_ntpv4_unsynchronized_stratum16.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: LI `3`, VN `4`, Mode `4`, Stratum `16`, Poll `4`,
  Precision `-18`, Reference ID raw bytes `53 54 45 50`
- Purpose: structured presentation coverage for the unsynchronized
  Leap Indicator, accepted stratum upper boundary, and stratum `> 1`
  Reference ID IPv4 interpretation
- Summary Reference ID: `83.84.69.80`; the printable raw bytes intentionally
  guard against treating all printable Reference IDs as ASCII.
- Current PFL behavior: Detected Protocol `NTP`, empty service hint; LI `3`
  and stratum `16` remain accepted by the conservative detector

### `14_ntpv4_large_root_delay.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: LI `0`, VN `4`, Mode `4`, Stratum `2`, Poll `4`,
  Precision `-30`
- Root Delay raw field: `0xffff8000`, interpreted as unsigned NTPv4 short
  format `65535.5 s`
- Root Dispersion raw field: `0x00018000`, interpreted as unsigned NTPv4
  short format `1.5 s`
- Timestamps: deterministic Era 0 values including exact `.5` fractions
- Purpose: structured presentation coverage for NTPv4 unsigned Root Delay and
  Root Dispersion fixed-point formatting
- Current PFL behavior: Detected Protocol `NTP`, empty service hint;
  structured selected-packet Summary and NTP Message byte view are expected

### `15_ntpv4_era0_last_second.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: LI `0`, VN `4`, Mode `4`, Stratum `2`, Poll `4`,
  Precision `-20`
- Transmit Timestamp raw fields: seconds `0xffffffff`, fraction `0x80000000`
- Interpreted within Era 0 only, this is
  `2036-02-07 06:28:15.500000 UTC`
- Purpose: structured presentation boundary for the final representable
  Era 0 second without adding Era 1 inference
- Current PFL behavior: Detected Protocol `NTP`, empty service hint; no era
  unfolding is expected

### `16_ntpv3_signed_root_delay.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.180:123` -> `192.0.2.170:59000`
- Payload: exactly `48` bytes
- Fields: LI `0`, VN `3`, Mode `4`, Stratum `2`, Poll `4`,
  Precision `-30`
- Root Delay raw field: `0xffff8000`, interpreted as signed NTPv3 16.16
  fixed point `-0.5 s`
- Root Dispersion raw field: `0x00018000`, interpreted as signed NTPv3 16.16
  fixed point `1.5 s`
- Timestamps: deterministic Era 0 values including exact `.5` fractions
- Purpose: structured presentation coverage for NTPv3 signed Root Delay /
  Root Dispersion fixed-point formatting
- Current PFL behavior: Detected Protocol `NTP`, empty service hint
- Wireshark note: this NTPv3 fixture uses Root Delay raw value `0xffff8000`.
  PcapFlowLab intentionally presents it as `-0.5 s` because NTPv3 Root Delay
  follows the signed 16.16 fixed-point semantics from RFC 1305. Current
  Wireshark versions may display the same raw NTPv3 field as `65535.5 s` using
  unsigned interpretation. This known difference is intentional; PFL must not
  be changed only to match that Wireshark presentation. Fixture 14 is the NTPv4
  counterpart where the high-bit-set field is intentionally interpreted as
  unsigned and displays `65535.5 s`.

## Intentionally Unsupported First-Version Forms

The first conservative detector intentionally does not recognize:

- NTPv1;
- NTPv2;
- symmetric active mode `1`;
- symmetric passive mode `2`;
- broadcast mode `5`;
- NTP control mode `6`;
- private/reserved mode `7`;
- otherwise NTP-looking payloads where neither direction matches UDP/123;
- NTP packets longer than `48` bytes;
- extension fields;
- authenticated NTP with a MAC;
- NTS;
- TCP;
- arbitrary non-standard-port NTP;
- packets shorter than the complete 48-byte basic header.

These are first-version limitations, not claims that those wire forms can
never be valid NTP. Extension fields, authentication MACs, NTS, NTPv2, and
broadcast mode are intentionally not frozen as universal invalid-protocol
contracts by these fixtures.

No permanent direction-mismatch fixture is included for mode/port combinations
such as client mode with only source port `123`; that boundary is better
protected later with small synthetic unit tests.

## Structured Inspection Expansion Boundary

Fixtures 11-16 are committed as packet-byte contracts for structured
selected-packet NTP presentation. Current structured support adds NTP Summary
fields and an NTP Message byte view; Stream/Stream Item Data labels remain
outside this fixture contract.

Fixture 05 remains the reusable KoD `RATE` coverage for stratum `0` /
Reference ID `RATE`. Fixture 10 remains the reusable truncated-header
negative boundary; it must not gain structured Summary output until truncated
NTP handling is explicitly designed.

## Manual Wireshark Guidance

Wireshark behavior is useful for visual wire verification, but it does not
define PcapFlowLab recognition semantics.

Useful manual checks include:

- For fixtures 01-05, Wireshark should normally decode standard UDP/123
  traffic as NTP.
- For fixtures 01-05, inspect Version, Mode, Stratum, and timestamps, and
  verify the UDP payload is exactly `48` bytes.
- For fixture 07, Wireshark may leave it as UDP because of the non-standard
  port; Decode As NTP can be useful for confirming the payload shape.
- For fixtures 08 and 09, Wireshark may correctly identify older or broadcast
  NTP-family traffic; that does not conflict with PcapFlowLab's intentionally
  narrower first automatic detector.
- For fixture 10, expect truncated or malformed presentation.
- For fixture 16, the Root Delay presentation difference described above is a
  known NTPv3 signed-fixed-point contract difference, not a PFL defect.

## Current Parsing Boundary

Future NTP work may add broader version support, extension-field handling,
authentication/NTS awareness, protocol-aware Stream presentation, or richer
clock-state reporting. That work is intentionally outside this fixture
contract. Current support remains cheap, bounded, and port-gated for
conservative NTPv3/NTPv4 client/server recognition, with selected-packet
structured Summary and a packet-local `NTP Message` byte view for complete
classic 48-byte messages.

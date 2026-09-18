# NTP Parsing Fixtures

This directory contains the permanent PCAP fixture set for the first
conservative PcapFlowLab NTP recognition behavior.

## Current First NTP Support

The first NTP support is detection-only. It lives in the
application protocol hint path and recognizes NTP only from a conservative
UDP/123-gated subset of classic NTP packets.

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
- No NTP-specific Packet Summary, Stream rows, Stream Item Data, or byte
  views.
- No `service_hint`.
- No port-independent content recognition.
- No deep timestamp, poll, precision, extension-field, MAC, NTS, or daemon
  state validation.

Successful NTP detection produces Detected Protocol `NTP` /
protocol hint `ntp`, while service hint remains empty.

Fixtures 01-05 are recognized as NTP. Fixtures 06-10 remain ordinary UDP flows
with no NTP detected protocol because they are malformed for this recognition
contract or intentionally outside the first conservative automatic detector.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_ntp_pcaps.py --output-dir tests/data/parsing/ntp --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the ten fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_ntp_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

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
- Boundary: no special KoD presentation or service hint is expected

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

## Future Parsing Boundary

Future NTP work may add broader version support, extension-field handling,
authentication/NTS awareness, protocol-aware Stream presentation, selected
packet Summary support, or richer clock-state reporting. That work is
intentionally outside this fixture contract. The first implementation stays a
cheap, bounded, port-gated protocol hint for conservative NTPv3/NTPv4
client/server packets.

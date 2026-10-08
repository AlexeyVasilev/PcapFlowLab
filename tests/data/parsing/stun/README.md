# STUN Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab STUN recognition behavior and future structured STUN presentation
coverage.

Current STUN support is detection-only. It lives in the application protocol
hint path and recognizes STUN from an individual UDP transport payload when:

- payload size is at least `20` bytes;
- the top two bits of the first byte are zero: `(payload[0] & 0xC0) == 0`;
- the 16-bit Message Length field at bytes `2..3` is divisible by `4`;
- UDP payload size is exactly `20 + Message Length`;
- the magic cookie at bytes `4..7` is `21 12 A4 42`.

Recognition is not port-gated. A valid STUN-shaped payload can be recognized
on UDP `3478` or on a non-standard UDP port. Successful detection produces
Detected Protocol `STUN`; service hint remains empty.

PcapFlowLab does not currently parse STUN methods/classes for presentation,
transaction IDs, attributes, TURN-specific data, ICE state, WebRTC sessions, or
protocol-aware STUN Stream rows. It also does not parse STUN attributes such as
`MAPPED-ADDRESS`, `XOR-MAPPED-ADDRESS`, `USERNAME`, `MESSAGE-INTEGRITY`,
`MESSAGE-INTEGRITY-SHA256`, `ERROR-CODE`, `REALM`, `NONCE`, `SOFTWARE`,
`FINGERPRINT`, `ICE-CONTROLLING`, `ICE-CONTROLLED`, `PRIORITY`, or
`USE-CANDIDATE`.

## Generation

The deterministic generator is committed beside these fixtures:

```bash
python tests/data/parsing/stun/generate_stun_pcaps.py --output-dir tests/data/parsing/stun --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the eleven fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths. Fixtures `01`-`06` preserve the historical
detection-only recipe; fixtures `07`-`11` are structured-inspection targets for
future STUN parsing work.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tests/data/parsing/stun/generate_stun_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the committed generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:42:01`
- Server MAC: `02:00:00:00:42:02`
- Client IPv4: `192.0.2.30`
- Server IPv4: `192.0.2.40`
- Client IPv6: `2001:db8:1::30`
- Server IPv6: `2001:db8:1::40`
- Client UDP port: `51000`
- Standard STUN server port: `3478`
- Non-standard server port: `45678`
- Magic cookie: `21 12 A4 42`
- Transaction ID: `10 11 12 13 20 21 22 23 30 31 32 33`

The STUN header is `20` bytes:

- Message Type: 2 bytes
- Message Length: 2 bytes
- Magic Cookie: 4 bytes
- Transaction ID: 12 bytes

Fixtures `01`-`06` use the historical fixed transaction ID above. Structured
fixtures `07`-`11` use fixture-specific repeated-byte transaction IDs to keep
attribute encoding deterministic and easy to inspect.

For `XOR-MAPPED-ADDRESS`, IPv4 addresses are XORed with the magic cookie and
IPv6 addresses are XORed with `Magic Cookie || Transaction ID`. Ports are XORed
with the upper 16 bits of the magic cookie. `FINGERPRINT` attributes use the
standard STUN CRC-32 over the message with the final attribute length included,
then XOR the CRC with `0x5354554E`.

## Fixture Map

### `01_stun_binding_request_3478.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.30:51000` -> `192.0.2.40:3478`
- STUN: Binding Request `0x0001`, Message Length `0`, valid magic cookie,
  deterministic transaction ID
- Purpose: positive baseline for common STUN Binding Request recognition on
  the standard STUN port
- Expected current PFL behavior: one UDP Flow, Detected Protocol `STUN`, empty
  service hint, no dedicated STUN Summary
- Wireshark note: should decode as STUN

### `02_stun_binding_request_response.pcap`

- Packets: `2`
- Packet 1: client `51000` -> server `3478`, Binding Request `0x0001`
- Packet 2: server `3478` -> client `51000`, Binding Success Response
  `0x0101`
- STUN: both packets use Message Length `0`, valid magic cookie, same
  deterministic transaction ID
- Purpose: positive bidirectional Flow baseline showing method/class
  differences do not split the user-facing Flow
- Expected current PFL behavior: one bidirectional UDP Flow, packet count `2`,
  Detected Protocol `STUN`, empty service hint
- Boundary: PcapFlowLab does not currently associate transaction IDs
  semantically

### `03_stun_binding_request_nonstandard_port.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.30:51000` -> `192.0.2.40:45678`
- STUN: valid Binding Request, Message Length `0`, valid cookie, deterministic
  transaction ID
- Purpose: positive baseline preserving current non-port-gated STUN detection
- Expected current PFL behavior: one UDP Flow, Detected Protocol `STUN`, empty
  service hint
- Wireshark note: automatic STUN dissection on non-standard ports may vary by
  Wireshark configuration or heuristic behavior

### `04_stun_bad_magic_cookie.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.30:51000` -> `192.0.2.40:3478`
- STUN-like payload: Binding Request with Message Length `0`, but cookie
  `21 12 A4 43`
- Purpose: negative magic-cookie validation case proving port `3478` plus
  STUN-like shape is insufficient
- Expected current PFL behavior: one normal UDP Flow, Detected Protocol must
  not be `STUN`, empty service hint, no crash

### `05_stun_invalid_top_bits.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.30:51000` -> `192.0.2.40:3478`
- STUN-like payload: first byte has bit 7 set, Message Length `0`, valid
  magic cookie, deterministic transaction ID
- Purpose: negative first-two-bits validation case proving cookie alone does
  not trigger STUN
- Expected current PFL behavior: one normal UDP Flow, Detected Protocol must
  not be `STUN`, empty service hint

### `06_stun_declared_length_mismatch.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.30:51000` -> `192.0.2.40:3478`
- STUN-like payload: exactly `20` bytes, Message Length `4`, valid cookie,
  deterministic transaction ID
- Purpose: negative declared-length boundary case proving exact total-length
  validation and safe handling when the declared message length exceeds
  available payload bytes
- Expected current PFL behavior: one normal UDP Flow, Detected Protocol must
  not be `STUN`, empty service hint, no crash
- Wireshark note: may decode as malformed/truncated STUN; PcapFlowLab requires
  a structurally complete message for confirmed detection

### `07_stun_binding_ice_exchange.pcap`

- Packets: `2`
- Packet 1: client `51000` -> server `3478`, Binding Request `0x0001`
- Packet 2: server `3478` -> client `51000`, Binding Success Response
  `0x0101`
- Transaction ID: fixture-specific deterministic ID reused by request and
  response
- Request attributes: `USERNAME` value `remote:local`, `PRIORITY`
  `1845501695`, `ICE-CONTROLLING` `0x1122334455667788`, zero-length
  `USE-CANDIDATE`, deterministic `MESSAGE-INTEGRITY`, valid `FINGERPRINT`
- Response attributes: IPv4 `XOR-MAPPED-ADDRESS` for
  `203.0.113.25:54321`, `SOFTWARE` value `PFL STUN fixture`,
  deterministic `MESSAGE-INTEGRITY-SHA256`, valid `FINGERPRINT`
- Purpose: future structured STUN/ICE attribute presentation coverage while
  preserving current detection-only behavior
- Expected current PFL behavior: one bidirectional UDP Flow, packet count `2`,
  Detected Protocol `STUN`, empty service hint, no dedicated STUN Summary

### `08_stun_binding_success_xor_mapped_ipv6.pcap`

- Packets: `1`
- Direction: IPv6 server to client
- IPv6/UDP: `2001:db8:1::40:3478` -> `2001:db8:1::30:51000`
- STUN: Binding Success Response `0x0101`
- Attributes: IPv6 `XOR-MAPPED-ADDRESS` for
  `2001:db8:ffff::25:54321`, IPv6 `MAPPED-ADDRESS` for
  `2001:db8:ffff::26:54322`
- Purpose: future IPv6 address-family coverage for mapped-address attribute
  decoding
- Expected current PFL behavior: one UDP Flow, Detected Protocol `STUN`, empty
  service hint, no dedicated STUN Summary

### `09_stun_binding_error_response.pcap`

- Packets: `1`
- Direction: server to client
- IPv4/UDP: `192.0.2.40:3478` -> `192.0.2.30:51000`
- STUN: Binding Error Response `0x0111`
- Attributes: `ERROR-CODE` `401 Unauthorized`, `REALM` value `example.org`,
  `NONCE` value `pfl-stun-nonce-0001`, `SOFTWARE` value `PFL STUN fixture`
- Purpose: future structured error-response and text-attribute coverage
- Expected current PFL behavior: one UDP Flow, Detected Protocol `STUN`, empty
  service hint, no dedicated STUN Summary

### `10_stun_attribute_padding_and_unknown.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.30:51000` -> `192.0.2.40:3478`
- STUN: Binding Request `0x0001`
- Attributes: `USERNAME` value `pad-nine!` with 9-byte value and 3 bytes of
  zero padding, `ICE-CONTROLLED` `0x8877665544332211`, unknown required
  attribute `0x1234`, unknown optional attribute `0x8123` with 3-byte value and
  1 byte of zero padding
- Purpose: future attribute padding, alignment, and unknown-attribute
  preservation coverage
- Expected current PFL behavior: one UDP Flow, Detected Protocol `STUN`, empty
  service hint, no dedicated STUN Summary

### `11_stun_malformed_attribute_length.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/UDP: `192.0.2.30:51000` -> `192.0.2.40:3478`
- STUN: Binding Request `0x0001` with a structurally valid outer STUN envelope
- Malformed body: Message Length is `8`; the single `USERNAME` attribute
  declares Length `8` but only 4 value bytes are present after the attribute
  header
- Purpose: future parser robustness coverage for malformed inner attributes
  without weakening the current outer-envelope detector
- Expected current PFL behavior: one UDP Flow, Detected Protocol `STUN`, empty
  service hint, no dedicated STUN Summary, no crash

## Future Parsing Boundary

These fixtures preserve current detection-only behavior while documenting the
target shape for future structured STUN support.

A future STUN parser should expose the header fields `Message Type`, `Method`,
`Class`, `Message Length`, `Magic Cookie`, and `Transaction ID`, and should
present the attributes covered by fixtures `07`-`11` safely. That future parser
should not imply HMAC validation, FINGERPRINT CRC validation, TURN allocation
state, STUN over TCP/TLS/DTLS support, request/response correlation, ICE state
machine reconstruction, WebRTC session reconstruction, specialized STUN Stream
rows, or a service hint unless those capabilities are explicitly implemented.

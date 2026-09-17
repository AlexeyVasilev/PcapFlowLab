# STUN Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab STUN recognition behavior.

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
`XOR-MAPPED-ADDRESS`, `USERNAME`, `MESSAGE-INTEGRITY`, `FINGERPRINT`,
`ICE-CONTROLLING`, `ICE-CONTROLLED`, or `PRIORITY`.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_stun_pcaps.py --output-dir tests/data/parsing/stun --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the six fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_stun_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:42:01`
- Server MAC: `02:00:00:00:42:02`
- Client IPv4: `192.0.2.30`
- Server IPv4: `192.0.2.40`
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

All normal positive fixtures use zero-attribute STUN messages with Message
Length `0`, so the UDP payload length is exactly `20` bytes.

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

## Future Parsing Boundary

These fixtures preserve current detection-only behavior. Future STUN, TURN,
ICE, or WebRTC-related parsing may add deeper presentation, but those
capabilities are not implemented by the current fixture contract.

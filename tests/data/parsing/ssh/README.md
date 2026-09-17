# SSH Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for current
PcapFlowLab SSH recognition behavior.

Current SSH support is detection-only. It lives in the application protocol
hint path and recognizes SSH when an individual TCP transport payload:

- contains at least four bytes;
- begins exactly with `SSH-`.

Current recognition is not port-gated. A plausible SSH identification banner
can be recognized on TCP port `22` or on a non-standard TCP port when that
payload itself begins with `SSH-`.

PcapFlowLab does not currently validate SSH protocol-version syntax, software
version syntax, line termination, the complete identification exchange, binary
SSH packet framing, key exchange, host keys, encryption algorithms, encrypted
SSH packets, or a banner split across multiple packets. It also does not expose
dedicated SSH Packet Summary parsing, SSH-specific Stream rows, or SSH Stream
Item Data.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_ssh_pcaps.py --output-dir tests/data/parsing/ssh --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the five fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_ssh_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:41:01`
- Server MAC: `02:00:00:00:41:02`
- Client IPv4: `192.0.2.10`
- Server IPv4: `192.0.2.20`
- Client ephemeral port: `53022`
- Standard SSH server port: `22`
- Non-standard SSH server port: `2222`
- Client initial sequence: `1000`
- Server initial sequence: `5000`
- Normal server identification string: `SSH-2.0-OpenSSH_9.6\r\n`
- Normal client identification string: `SSH-2.0-PFL_Test_Client_1.0\r\n`

All fixtures use deterministic Ethernet / IPv4 / TCP / Raw packets with `PA`
flags, stable ACK values, and Scapy-generated IPv4/TCP checksums.

## Fixture Map

### `01_ssh_server_banner_port22.pcap`

- Packets: `1`
- Direction: server to client
- Ethernet: `02:00:00:00:41:02` -> `02:00:00:00:41:01`
- IPv4/TCP: `192.0.2.20:22` -> `192.0.2.10:53022`
- Payload: `SSH-2.0-OpenSSH_9.6\r\n`
- Purpose: positive baseline for content-based SSH recognition on the standard
  server port
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol `SSH`,
  empty service hint, no dedicated SSH Packet Summary or protocol-aware Stream
  behavior
- Wireshark note: should normally be recognized as SSH traffic

### `02_ssh_client_banner_port2222.pcap`

- Packets: `1`
- Direction: client to server
- Ethernet: `02:00:00:00:41:01` -> `02:00:00:00:41:02`
- IPv4/TCP: `192.0.2.10:53022` -> `192.0.2.20:2222`
- Payload: `SSH-2.0-PFL_Test_Client_1.0\r\n`
- Purpose: positive baseline preserving current non-port-gated SSH detection
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol `SSH`,
  empty service hint
- Wireshark note: automatic SSH dissection on non-standard ports may vary by
  Wireshark configuration or heuristic behavior

### `03_ssh_banner_after_unmatched_payload.pcap`

- Packets: `2`
- Direction: server to client for both packets
- IPv4/TCP: `192.0.2.20:22` -> `192.0.2.10:53022`
- Packet 1 payload: `NOTICE\r\n`
- Packet 2 payload: `SSH-2.0-OpenSSH_9.6\r\n`
- Purpose: positive baseline showing a later independent payload-bearing packet
  in the same Flow can settle SSH detection after an earlier unmatched payload
- Expected current PFL behavior: one user-facing TCP Flow, packet count `2`,
  final Detected Protocol `SSH`, empty service hint
- Boundary: this does not test SSH banner reconstruction across packets; the
  second payload independently begins with `SSH-`

### `04_ssh_invalid_ssx_prefix_port22.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.10:53022` -> `192.0.2.20:22`
- Payload: `SSX-2.0-OpenSSH_9.6\r\n`
- Purpose: negative baseline proving TCP port `22` alone does not classify a
  Flow as SSH and a near-miss prefix does not match
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `SSH`, empty service hint, no crash

### `05_ssh_short_prefix_three_bytes.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.10:53022` -> `192.0.2.20:22`
- Payload: exactly three bytes, `SSH`
- Purpose: negative boundary-safety case proving the detector requires at
  least four bytes before matching `SSH-`
- Expected current PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `SSH`, empty service hint, no crash
- Boundary: this is a valid TCP segment carrying a short payload, not snaplen
  truncation

## Future Parsing Boundary

These fixtures preserve current detection-only behavior. Future SSH work may
add deeper protocol parsing or SSH-aware Stream presentation, but those
capabilities are not implemented by the current fixture contract.

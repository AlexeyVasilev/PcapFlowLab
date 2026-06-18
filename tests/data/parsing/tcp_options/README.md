Synthetic TCP options parsing fixtures for future regression tests.

This directory is intended for tiny deterministic `.pcap` fixtures that exercise:
- TCP packets without options;
- common TCP SYN option layouts;
- SACK and timestamp variants;
- unknown but valid TCP options;
- boundary and maximum-header cases;
- malformed TCP option encodings;
- snaplen-truncated TCP header/options captures;
- IPv4-options plus TCP-options offset handling.

The local helper script that generates these pcaps is intentionally **not** committed.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python3 tmp/generate_tcp_options_pcaps.py tests/data/parsing/tcp_options
```

Notes:
- The script is a local helper only and should **not** be committed.
- The generated `.pcap` files from this directory are intended to be reviewed locally before commit.
- The script uses deterministic MAC/IP/port/sequence values and classic little-endian `.pcap` output.

## Shared constants

- Client MAC: `02:00:00:00:00:01`
- Server MAC: `02:00:00:00:00:02`
- Client IP: `192.0.2.10`
- Server IP: `198.51.100.20`
- Client port: `49152`
- Server port: `443`

## Current Summary expectations before dedicated TCP options parsing

Unless a packet is intentionally malformed or snaplen-truncated:
- TCP layer should still be present.
- TCP layer title should remain in the form `TCP, Src Port: 49152, Dst Port: 443` or the reverse direction variant.
- TCP fields should continue to show `Header Length` correctly.
- No structured TCP option subfields are expected yet.

Malformed or truncated cases should behave conservatively:
- no crash;
- no read past the captured bytes or declared TCP header size;
- warnings or absence of deeper TCP decoding are acceptable if they match the current decoder policy.

---

### 01_tcp_syn_no_options.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 20 bytes
- Options bytes: none

Current expected Summary:
- TCP layer is present.
- No structured `Options` field is expected.

Future TCP Options parser expected behavior:
- No TCP options should be reported.

### 02_tcp_ack_payload_no_options.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: ACK|PSH
- Header Length: 20 bytes
- Payload Length: non-zero
- Options bytes: none

Current expected Summary:
- TCP layer is present.
- Payload Length is non-zero.
- No structured `Options` field is expected.

Future TCP Options parser expected behavior:
- No TCP options should be reported.

### 03_tcp_syn_mss.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 24 bytes
- Options bytes: `02 04 05 b4`
- Options semantics:
  - MSS 1460

Current expected Summary:
- TCP layer is present.
- Header Length is 24 bytes.

Future TCP Options parser expected behavior:
- Recognize MSS and value `1460`.

### 04_tcp_syn_mss_window_scale_sack_timestamp.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 40 bytes
- Options bytes:
  - `02 04 05 b4` MSS 1460
  - `04 02` SACK Permitted
  - `08 0a 01 02 03 04 05 06 07 08` Timestamp
  - `01` NOP
  - `03 03 07` Window Scale 7
- Expected padding may be present for 32-bit alignment.

Current expected Summary:
- TCP layer is present.
- Header Length is 40 bytes.

Future TCP Options parser expected behavior:
- Recognize MSS, SACK Permitted, Timestamp, Window Scale, and any NOP padding.

### 05_tcp_syn_common_options_with_eol_padding.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 32 bytes
- Options bytes:
  - MSS 1460
  - SACK Permitted
  - End of Option List
  - zero padding after EOL

Current expected Summary:
- TCP layer is present.
- Header Length reflects the padded header.

Future TCP Options parser expected behavior:
- Recognize EOL.
- Ignore zero padding after EOL instead of producing fake options.

### 06_tcp_syn_nop_padding.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 32 bytes
- Options bytes:
  - MSS 1460
  - multiple NOPs
  - Window Scale 7
  - SACK Permitted

Current expected Summary:
- TCP layer is present.

Future TCP Options parser expected behavior:
- Recognize each NOP.
- Parse following options at the correct boundaries.

### 07_tcp_ack_sack_blocks.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: ACK
- Header Length: 40 bytes
- Options bytes:
  - `05 12 00 00 03 e8 00 00 07 d0 00 00 0b b8 00 00 0f a0`
- Options semantics:
  - SACK with two blocks:
    - `1000-2000`
    - `3000-4000`

Current expected Summary:
- TCP layer is present.

Future TCP Options parser expected behavior:
- Recognize SACK option and expose both block ranges.

### 08_tcp_ack_timestamp_only.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: ACK
- Header Length: 32 bytes
- Options bytes:
  - `01 01` NOP padding
  - `08 0a 11 22 33 44 55 66 77 88`
- Options semantics:
  - Timestamp TSval=`0x11223344`
  - TSecr=`0x55667788`

Current expected Summary:
- TCP layer is present.

Future TCP Options parser expected behavior:
- Recognize Timestamp and expose TSval/TSecr.

### 09_tcp_syn_unknown_valid_option.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 24 bytes
- Options bytes:
  - `1e 04 aa bb`
- Options semantics:
  - unknown kind `30`
  - valid length `4`
  - raw data `aa bb`

Current expected Summary:
- TCP layer is present.

Future TCP Options parser expected behavior:
- Preserve unknown option kind/length/data without crashing.

### 10_tcp_syn_multiple_unknown_valid_options.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 32 bytes
- Options bytes:
  - `1e 04 aa bb`
  - `1f 05 cc dd ee`
  - `01` NOP
  - `20 06 12 34 56 78`

Current expected Summary:
- TCP layer is present.

Future TCP Options parser expected behavior:
- Represent each unknown option separately with preserved raw bytes.

### 11_tcp_syn_max_header_60_bytes.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 60 bytes
- Options length: 40 bytes
- Options area filled with valid options, NOPs, and alignment-safe padding

Current expected Summary:
- TCP layer is present.
- Header Length is 60 bytes.

Future TCP Options parser expected behavior:
- Parse or preserve the full 40-byte option area with no overrun.

### 12_tcp_syn_options_exact_padding.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 28 bytes
- Options bytes intentionally require exact 32-bit padding

Current expected Summary:
- TCP layer is present.

Future TCP Options parser expected behavior:
- Handle alignment and pad bytes correctly.

### 13_tcp_option_length_zero_malformed.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 24 bytes
- Malformed options bytes:
  - `1e 00 00 00`
- Malformation:
  - option kind `30` declares invalid length `0`

Current expected Summary:
- TCP layer may still be present.
- Conservative malformed/truncated handling is acceptable.

Future TCP Options parser expected behavior:
- Report malformed option length `0`.
- No crash.

### 14_tcp_option_length_one_malformed.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 24 bytes
- Malformed options bytes:
  - `1e 01 00 00`
- Malformation:
  - option kind `30` declares invalid length `1`

Current expected Summary:
- TCP layer may still be present.

Future TCP Options parser expected behavior:
- Report malformed option length `1`.
- No crash.

### 15_tcp_option_length_past_header_malformed.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 24 bytes
- Malformed options bytes:
  - `1e 08 aa bb`
- Malformation:
  - option length claims `8` bytes while only `4` bytes of option area exist

Current expected Summary:
- TCP layer may still be present.

Future TCP Options parser expected behavior:
- Report option length extending past TCP header bounds.
- No read past header.

### 16_tcp_option_truncated_timestamp_malformed.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 24 bytes
- Malformed options bytes:
  - `08 0a 00 01`
- Malformation:
  - Timestamp kind/length present but payload is incomplete inside the declared header

Current expected Summary:
- TCP layer may still be present.

Future TCP Options parser expected behavior:
- Report malformed or truncated Timestamp option.

### 17_tcp_option_eol_then_nonzero_padding.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Header Length: 28 bytes
- Options bytes:
  - `02 04 05 b4 00 aa bb cc`
- Semantics:
  - MSS 1460
  - EOL
  - non-zero bytes after EOL

Current expected Summary:
- TCP layer is present.

Future TCP Options parser expected behavior:
- Recognize EOL.
- Preserve or warn about suspicious non-zero bytes after EOL according to future policy.

### 18_tcp_syn_options_snaplen_truncated.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- TCP

TCP:
- Flags: SYN
- Original packet includes TCP options
- Captured length cuts off part of the TCP option area

Current expected Summary:
- Packet should be recognized as capture-truncated.
- Conservative warning behavior is expected.

Future TCP Options parser expected behavior:
- Never read past captured bytes.
- Report truncated TCP options availability conservatively.

### 19_tcp_syn_tcp_header_snaplen_truncated.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4
- partial TCP

TCP:
- Flags: SYN in original packet
- Captured length cuts off inside the fixed TCP header

Current expected Summary:
- Frame/Ethernet/IPv4 should still decode where possible.
- TCP layer may be missing or warning-only depending current policy.

Future TCP Options parser expected behavior:
- No crash.
- No attempt to parse incomplete fixed TCP header as full options.

### 20_tcp_syn_ipv4_options_and_tcp_options.pcap

Packets: 1

Layers:
- Ethernet II
- IPv4 with IPv4 options
- TCP with TCP options

TCP:
- Flags: SYN
- Header Length: non-zero options area
- IPv4 header length is greater than 20 bytes

Current expected Summary:
- IPv4 layer is present.
- TCP layer should still be found at the correct offset.

Future TCP Options parser expected behavior:
- Use the actual IPv4 header length instead of assuming a fixed 20-byte IPv4 header.

## Expected generated file list

- `01_tcp_syn_no_options.pcap`
- `02_tcp_ack_payload_no_options.pcap`
- `03_tcp_syn_mss.pcap`
- `04_tcp_syn_mss_window_scale_sack_timestamp.pcap`
- `05_tcp_syn_common_options_with_eol_padding.pcap`
- `06_tcp_syn_nop_padding.pcap`
- `07_tcp_ack_sack_blocks.pcap`
- `08_tcp_ack_timestamp_only.pcap`
- `09_tcp_syn_unknown_valid_option.pcap`
- `10_tcp_syn_multiple_unknown_valid_options.pcap`
- `11_tcp_syn_max_header_60_bytes.pcap`
- `12_tcp_syn_options_exact_padding.pcap`
- `13_tcp_option_length_zero_malformed.pcap`
- `14_tcp_option_length_one_malformed.pcap`
- `15_tcp_option_length_past_header_malformed.pcap`
- `16_tcp_option_truncated_timestamp_malformed.pcap`
- `17_tcp_option_eol_then_nonzero_padding.pcap`
- `18_tcp_syn_options_snaplen_truncated.pcap`
- `19_tcp_syn_tcp_header_snaplen_truncated.pcap`
- `20_tcp_syn_ipv4_options_and_tcp_options.pcap`

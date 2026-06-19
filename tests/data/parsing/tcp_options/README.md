Synthetic TCP options parsing fixtures for selected-packet Summary regression tests.

This directory contains tiny deterministic `.pcap` fixtures that exercise:
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
- the script is a local helper only and should **not** be committed;
- generated `.pcap` files from this directory are intended to be reviewed locally before commit;
- the generator uses deterministic MAC/IP/port/sequence values and classic little-endian `.pcap` output.

## Shared constants

- Client MAC: `02:00:00:00:00:01`
- Server MAC: `02:00:00:00:00:02`
- Client IP: `192.0.2.10`
- Server IP: `198.51.100.20`
- Client port: `49152`
- Server port: `443`

## Current Summary expectations

Selected-packet Summary now parses TCP options on demand and nests them under the top-level TCP layer.

Expected shared model shape:

- top-level TCP layer id remains `tcp`;
- when options are present, TCP contains a child layer:
  - id: `tcp_options`
  - title: `TCP Options (N bytes)`
- individual options are represented as nested child nodes under `tcp_options`;
- the raw option byte list remains visible in the `tcp_options` block;
- packets without options do **not** create a `tcp_options` child;
- malformed options are reported conservatively through `tcp_option_malformed` warning children;
- the parser never reads past the declared/captured TCP option area.

Supported option kinds in this first pass:
- `0` End of Option List (EOL)
- `1` No-Operation (NOP)
- `2` Maximum Segment Size (MSS)
- `3` Window Scale
- `4` SACK Permitted
- `5` SACK
- `8` Timestamps
- unknown valid options with preserved kind/length/raw bytes

Malformed handling in this first pass:
- invalid length `0` / `1` for non-EOL/NOP options;
- declared length extending past the available TCP option area;
- invalid known-option lengths;
- invalid SACK length;
- truncated Timestamp payload;
- non-zero padding after EOL.

Malformed handling is intentionally conservative:
- no crash;
- no out-of-bounds read;
- the TCP layer still remains available when enough fixed-header decoding succeeded.

## Fixture map

### Control / no options

- `01_tcp_syn_no_options.pcap`
  - SYN with 20-byte TCP header and no options.
  - Expected Summary: TCP layer present, no `tcp_options` child.

- `02_tcp_ack_payload_no_options.pcap`
  - ACK|PSH with payload and no options.
  - Expected Summary: TCP layer present, payload length non-zero, no `tcp_options` child.

### Common TCP options

- `03_tcp_syn_mss.pcap`
  - MSS-only SYN.
  - Expected Summary: `tcp_options` contains `tcp_option_mss` with MSS `1460 bytes`.

- `04_tcp_syn_mss_window_scale_sack_timestamp.pcap`
  - Common SYN layout with MSS, SACK Permitted, Timestamp, NOP, Window Scale.
  - Expected Summary: `tcp_options` contains MSS, SACK Permitted, Timestamp, Window Scale, and NOP nodes.

- `05_tcp_syn_common_options_with_eol_padding.pcap`
  - Common options followed by EOL and zero padding.
  - Expected Summary: EOL is represented; zero padding after EOL does not create fake options.

- `06_tcp_syn_nop_padding.pcap`
  - Multiple NOPs used as alignment between real options.
  - Expected Summary: each NOP is represented separately and later options still parse correctly.

### SACK / timestamp

- `07_tcp_ack_sack_blocks.pcap`
  - ACK with SACK option containing two blocks.
  - Expected Summary: `tcp_option_sack` exposes both left/right block edges.

- `08_tcp_ack_timestamp_only.pcap`
  - ACK with Timestamp option and NOP padding.
  - Expected Summary: `tcp_option_timestamp` exposes `Timestamp value` and `Timestamp echo reply`.

### Unknown valid options

- `09_tcp_syn_unknown_valid_option.pcap`
  - Single unknown option with valid length.
  - Expected Summary: `tcp_option_unknown` preserves kind, length, and raw bytes.

- `10_tcp_syn_multiple_unknown_valid_options.pcap`
  - Several unknown options plus alignment.
  - Expected Summary: each unknown option becomes its own child node.

### Boundary / maximum header

- `11_tcp_syn_max_header_60_bytes.pcap`
  - Maximum legal 60-byte TCP header.
  - Expected Summary: TCP Header Length is `60 bytes (15)` and full 40-byte option area remains parseable/preserved.

- `12_tcp_syn_options_exact_padding.pcap`
  - Options area that requires exact 32-bit alignment handling.
  - Expected Summary: options parse at the correct boundaries with no fabricated extra option.

### Malformed option encodings

- `13_tcp_option_length_zero_malformed.pcap`
  - Invalid non-EOL/NOP option length `0`.
  - Expected Summary: warning child `tcp_option_malformed`; no crash.

- `14_tcp_option_length_one_malformed.pcap`
  - Invalid non-EOL/NOP option length `1`.
  - Expected Summary: warning child `tcp_option_malformed`; no crash.

- `15_tcp_option_length_past_header_malformed.pcap`
  - Declared option length extends beyond available option bytes.
  - Expected Summary: warning child about length extending past the TCP header.

- `16_tcp_option_truncated_timestamp_malformed.pcap`
  - Timestamp kind/length is present but payload bytes are incomplete.
  - Expected Summary: malformed timestamp warning child.

- `17_tcp_option_eol_then_nonzero_padding.pcap`
  - EOL followed by non-zero bytes.
  - Expected Summary: EOL node plus warning child for suspicious non-zero padding after EOL.

### Truncation / offset handling

- `18_tcp_syn_options_snaplen_truncated.pcap`
  - Captured bytes end inside the TCP options area.
  - Expected Summary: conservative best-effort behavior only; never read past captured bytes.

- `19_tcp_syn_tcp_header_snaplen_truncated.pcap`
  - Captured bytes end inside the fixed TCP header.
  - Expected Summary: Frame/Ethernet/IPv4 can still appear, but TCP options are not parsed from an incomplete header.

- `20_tcp_syn_ipv4_options_and_tcp_options.pcap`
  - IPv4 header includes IPv4 options and TCP also includes TCP options.
  - Expected Summary: TCP is found using the actual IPv4 header length and `tcp_options` still parses correctly.

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

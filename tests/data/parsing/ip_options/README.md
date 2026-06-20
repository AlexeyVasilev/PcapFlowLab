Synthetic IPv4 Options parsing fixtures for current IHL-aware packet handling and future detailed IPv4 Options presentation.

This directory is intended to contain tiny deterministic `.pcap` fixtures for:
- IPv4 packets without options as a control case;
- IPv4 Router Alert handling with IGMP and UDP payloads;
- common IPv4 option kinds such as RR, Timestamp, LSRR, SSRR, EOL, and NOP;
- unknown-but-valid IPv4 options;
- multiple-option ordering and max-header-length cases;
- fragmentation interaction with IPv4 options;
- malformed option encodings and boundary violations;
- true snaplen-truncated captures inside IPv4 options or before the next header.

The local helper script that generates these pcaps is intentionally **not** committed.

## Local generation

Run from the repository root:

```bash
python3 tmp/generate_ipv4_options_pcaps.py tests/data/parsing/ip_options
```

Notes:
- the script is a local helper only and should **not** be committed;
- generated `.pcap` files from this directory are intended to be reviewed locally before commit;
- the generator writes classic little-endian `.pcap` records directly;
- no production parser code depends on this helper;
- true snaplen-truncated fixtures use packet-record included length smaller than original wire length.

## IPv4 Options basics

- IPv4 options are controlled by the IPv4 IHL field.
- Minimum IPv4 header length is `20` bytes.
- Maximum IPv4 header length is `60` bytes.
- Options area length is `IHL * 4 - 20`.
- Options must be parsed only within the IPv4 header bounds.
- The next protocol starts after the full IPv4 header, not after a fixed 20-byte offset.
- EOL and NOP are special single-byte options used for termination and padding.

Common option kinds covered or referenced here:
- `0` End of Options List / EOL
- `1` No-Operation / NOP
- `7` Record Route / RR
- `68` Timestamp
- `131` Loose Source Route / LSRR
- `137` Strict Source Route / SSRR
- `148` Router Alert

Unknown valid option types should preserve Type / Length / Raw bytes when a future parser is added.
Security and other historical/rare options can remain deferred unless represented as raw/unknown entries.

## Shared constants

- Host A MAC: `02:00:00:00:30:01`
- Host B MAC: `02:00:00:00:30:02`
- Router MAC: `02:00:00:00:30:fe`
- Host A IPv4: `198.51.100.10`
- Host B IPv4: `198.51.100.20`
- Router IPv4: `198.51.100.1`
- Multicast group: `224.0.0.251`
- UDP source port: `12345`
- UDP destination port: `54321`
- TCP source port: `40000`
- TCP destination port: `443`

## Expected current behavior

Current shared selected-packet behavior:
- valid packets can still form normal TCP/UDP/IGMP flows because next-protocol parsing uses the actual IPv4 IHL;
- Summary should contain a nested `IPv4 Options (N bytes)` block when options are present;
- option entries should be shown in wire order;
- `EOL` and `NOP` should be handled specially;
- known options should show safe parsed fields plus raw bytes where useful;
- unknown valid options should preserve Type / Length / Raw;
- malformed and truncated option packets should stay safe, preserve partial IPv4 details where possible, and surface warning entries such as invalid length, missing length, or truncated options;
- malformed option semantics inside a bounded IPv4 header should not by themselves force the decoder to lose a safely reachable UDP/TCP/IGMP next header.

## Fixture map

### A. Baseline and simple offset cases

- `01_ipv4_udp_no_options_control.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `20 bytes`
  - Options: none
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow, no detailed IPv4 Options block
  - Expected future behavior: no IPv4 Options block in Summary

- `02_ipv4_router_alert_igmpv2_report.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / IGMP`
  - IPv4 source/destination: `198.51.100.1` -> `224.0.0.251`
  - IPv4 IHL / header length: `24 bytes`
  - Options: Router Alert
  - Next protocol after IPv4: IGMPv2 Membership Report
  - Expected current behavior: normal IGMP flow because IPv4 IHL handling already reaches IGMP correctly
  - Expected future behavior: IPv4 Options block shows Router Alert and IGMP still appears after IPv4

- `03_ipv4_router_alert_udp_payload.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: Router Alert
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow, proving IHL-aware UDP offset handling
  - Expected future behavior: IPv4 Options block shows Router Alert and UDP ports remain correct

- `04_ipv4_nop_eol_padding_tcp_syn.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / TCP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: NOP, NOP, EOL, zero padding
  - Next protocol after IPv4: TCP SYN
  - Expected current behavior: normal TCP flow
  - Expected future behavior: IPv4 Options block shows NOP / NOP / EOL and TCP remains correctly offset

### B. Common IPv4 option types

- `05_ipv4_record_route_udp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `28 bytes`
  - Options: Record Route with one route slot populated
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow
  - Expected future behavior: IPv4 Options block shows RR type/length/pointer/route data

- `06_ipv4_timestamp_udp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `28 bytes`
  - Options: Timestamp with one timestamp entry
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow
  - Expected future behavior: IPv4 Options block shows Timestamp and safe parsed/raw timestamp fields

- `07_ipv4_loose_source_route_udp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `28 bytes`
  - Options: Loose Source Route with one route address
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow
  - Expected future behavior: IPv4 Options block shows LSRR pointer/route data/raw bytes

- `08_ipv4_strict_source_route_udp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `28 bytes`
  - Options: Strict Source Route with one route address
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow
  - Expected future behavior: IPv4 Options block shows SSRR pointer/route data/raw bytes

- `09_ipv4_unknown_valid_option_udp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `28 bytes`
  - Options: unknown valid option with explicit length and raw bytes
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow
  - Expected future behavior: IPv4 Options block shows Unknown Option with Type / Length / Raw

- `10_ipv4_multiple_options_udp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `36 bytes`
  - Options: NOP, Router Alert, Record Route, EOL, padding
  - Next protocol after IPv4: UDP
  - Expected current behavior: normal UDP flow
  - Expected future behavior: multiple IPv4 option entries appear in order before UDP

- `11_ipv4_max_header_options_tcp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / TCP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `60 bytes`
  - Options: max-size 40-byte option area using NOP padding and EOL termination
  - Next protocol after IPv4: TCP SYN
  - Expected current behavior: normal TCP flow if the parser truly honors full IHL
  - Expected future behavior: IPv4 Options block safely handles the maximum option area

### C. Fragmentation interaction

- `12_ipv4_first_fragment_with_options_udp.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / first UDP fragment`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: Router Alert
  - Next protocol after IPv4: partial UDP first fragment
  - Expected current behavior: fragmentation behavior should follow existing first-fragment policy without losing the IPv4 header facts
  - Expected future behavior: IPv4 Options block parses Router Alert while fragment policy remains unchanged

- `13_ipv4_noninitial_fragment_with_options.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / non-initial fragment payload`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: Router Alert
  - Next protocol after IPv4: no safe transport header at this fragment offset
  - Expected current behavior: no unsafe TCP/UDP parsing from a non-initial fragment
  - Expected future behavior: IPv4 Options still render while next-header parsing stays conservative

### D. Malformed option cases

- `14_ipv4_option_length_zero_malformed.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / malformed IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: unknown option with length byte `0`
  - Next protocol after IPv4: UDP on wire, but parser should become conservative
  - Expected current behavior: no crash
  - Expected future behavior: invalid option length warning or conservative stop

- `15_ipv4_option_length_one_malformed.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / malformed IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: unknown option with length byte `1`
  - Next protocol after IPv4: UDP on wire, but parser should become conservative
  - Expected current behavior: no crash
  - Expected future behavior: invalid option length warning

- `16_ipv4_option_length_past_ihl_malformed.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / malformed IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: length field extends beyond the declared options area
  - Next protocol after IPv4: UDP on wire
  - Expected current behavior: no crash
  - Expected future behavior: warning such as `IPv4 option length exceeds header`

- `17_ipv4_options_missing_length_byte_malformed.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / malformed IPv4(options)`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: an option type that requires a length byte appears, but packet bytes end before the length byte exists
  - Next protocol after IPv4: none safely reachable
  - Expected current behavior: no crash
  - Expected future behavior: warning such as `IPv4 option length field missing`

- `18_ipv4_eol_then_nonzero_padding.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / UDP`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `24 bytes`
  - Options: EOL followed by non-zero bytes in remaining option area
  - Next protocol after IPv4: UDP
  - Expected current behavior: no crash
  - Expected future behavior: EOL stops option parsing; non-zero bytes after EOL are preserved or warned about

### E. Packet/header truncation cases

- `19_ipv4_snaplen_truncated_inside_options.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / snaplen-truncated IPv4(options)`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `32 bytes` on original wire
  - Options: begins with NOP + Record Route, but captured bytes end inside the options area
  - Next protocol after IPv4: UDP on original wire, not safely reachable from captured bytes
  - Expected current behavior: no crash, capture truncation preserved, packet may be partial/unrecognized
  - Expected future behavior: partial IPv4/options details where safe; normal flow should not require unsafe fixed-offset parsing
  - Relies on true snaplen truncation: yes

- `20_ipv4_snaplen_truncated_before_next_header.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / partially captured next header`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: `28 bytes`
  - Options: Router Alert + NOP + EOL
  - Next protocol after IPv4: UDP on original wire, but captured bytes end before a complete next header is available
  - Expected current behavior: no crash, capture truncation preserved
  - Expected future behavior: IPv4 Options may be shown while next-header behavior stays conservative
  - Relies on true snaplen truncation: yes

- `21_ipv4_ihl_exceeds_packet_length.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / malformed IPv4`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: claims `28 bytes`, fewer bytes actually present
  - Options: implied by IHL but unavailable in packet bytes
  - Next protocol after IPv4: none safely reachable
  - Expected current behavior: no crash, packet rejected or marked partial/unrecognized
  - Expected future behavior: reason such as `IPv4 header truncated` or `IPv4 options truncated`

- `22_ipv4_invalid_ihl_too_small.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / malformed IPv4`
  - IPv4 source/destination: `198.51.100.10` -> `198.51.100.20`
  - IPv4 IHL / header length: invalid, smaller than `20 bytes`
  - Options: none valid
  - Next protocol after IPv4: not safely parseable
  - Expected current behavior: no crash, packet rejected or marked unrecognized
  - Expected future behavior: useful invalid-IHL warning

## Cases requiring true classic-pcap truncation semantics

These fixtures rely on packet-record included length smaller than original wire length:
- `19_ipv4_snaplen_truncated_inside_options.pcap`
- `20_ipv4_snaplen_truncated_before_next_header.pcap`

These malformed-on-wire fixtures are not snaplen-truncated and should remain distinct:
- `21_ipv4_ihl_exceeds_packet_length.pcap`
- `22_ipv4_invalid_ihl_too_small.pcap`

## Expected generated file list

- `01_ipv4_udp_no_options_control.pcap`
- `02_ipv4_router_alert_igmpv2_report.pcap`
- `03_ipv4_router_alert_udp_payload.pcap`
- `04_ipv4_nop_eol_padding_tcp_syn.pcap`
- `05_ipv4_record_route_udp.pcap`
- `06_ipv4_timestamp_udp.pcap`
- `07_ipv4_loose_source_route_udp.pcap`
- `08_ipv4_strict_source_route_udp.pcap`
- `09_ipv4_unknown_valid_option_udp.pcap`
- `10_ipv4_multiple_options_udp.pcap`
- `11_ipv4_max_header_options_tcp.pcap`
- `12_ipv4_first_fragment_with_options_udp.pcap`
- `13_ipv4_noninitial_fragment_with_options.pcap`
- `14_ipv4_option_length_zero_malformed.pcap`
- `15_ipv4_option_length_one_malformed.pcap`
- `16_ipv4_option_length_past_ihl_malformed.pcap`
- `17_ipv4_options_missing_length_byte_malformed.pcap`
- `18_ipv4_eol_then_nonzero_padding.pcap`
- `19_ipv4_snaplen_truncated_inside_options.pcap`
- `20_ipv4_snaplen_truncated_before_next_header.pcap`
- `21_ipv4_ihl_exceeds_packet_length.pcap`
- `22_ipv4_invalid_ihl_too_small.pcap`

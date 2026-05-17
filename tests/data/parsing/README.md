# Parsing Fixture Catalog

This catalog documents synthetic parsing fixtures that were added for targeted regression coverage. Update this file when new `pcap` fixtures are added under `tests/data/parsing/`.

## TCP

`tcp/ipv4_tcp_valid_checksum_1.pcap`
- Purpose: clean IPv4/TCP checksum baseline.
- Used by: checksum UI regression covering valid IPv4 and TCP checksum reporting.

`tcp/ipv4_tcp_bad_checksum_1.pcap`
- Purpose: IPv4/TCP packet with an invalid TCP checksum.
- Used by: checksum UI regression covering invalid TCP checksum reporting.

`tcp/ipv4_bad_ip_checksum_1.pcap`
- Purpose: IPv4/TCP packet with an invalid IPv4 header checksum.
- Used by: checksum UI regression covering invalid IPv4 checksum reporting.

`tcp/ipv4_pre_offload_like_tcp_1.pcap`
- Purpose: IPv4/TCP packet shaped like a pre-offload capture where IPv4 total length must be interpreted conservatively.
- Used by: import visibility regression and UI checksum/details regression for pre-offload warnings.

## UDP

`udp/ipv4_udp_valid_checksum_1.pcap`
- Purpose: clean IPv4/UDP checksum baseline.
- Used by: checksum UI regression covering valid IPv4 and UDP checksum reporting.

`udp/ipv4_udp_bad_checksum_1.pcap`
- Purpose: IPv4/UDP packet with an invalid UDP checksum.
- Used by: checksum UI regression covering invalid IPv4 UDP checksum reporting.

`udp/ipv4_udp_checksum_zero_1.pcap`
- Purpose: IPv4/UDP packet with checksum field set to zero.
- Used by: checksum UI regression covering IPv4 UDP "not checked" semantics.

`udp/ipv6_udp_bad_checksum_1.pcap`
- Purpose: IPv6/UDP packet with an invalid UDP checksum.
- Used by: checksum UI regression covering invalid IPv6 UDP checksum reporting.

`udp/ipv6_udp_checksum_zero_1.pcap`
- Purpose: IPv6/UDP packet with checksum field set to zero.
- Used by: checksum UI regression covering the "checksum required for IPv6" case.

`udp/udp_truncated_manual_1.pcap`
- Purpose: truly truncated UDP packet with preserved captured/original packet lengths.
- Used by: import visibility regression and UI checksum/details regression for conservative truncation handling.

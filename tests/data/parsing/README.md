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

## GRE

`gre/01_gre_ipv4_tcp.pcap`
- Purpose: outer IPv4 GRE version 0 carrying inner IPv4/TCP.

`gre/02_gre_ipv4_udp.pcap`
- Purpose: outer IPv4 GRE version 0 carrying inner IPv4/UDP.

`gre/03_gre_ipv6_tcp.pcap`
- Purpose: outer IPv4 GRE version 0 carrying inner IPv6/TCP.

`gre/04_gre_ipv6_udp.pcap`
- Purpose: outer IPv4 GRE version 0 carrying inner IPv6/UDP.

`gre/05_ipv6_outer_gre_ipv4_tcp.pcap`
- Purpose: outer IPv6 GRE carriage for inner IPv4/TCP.

`gre/06_ipv6_outer_gre_ipv6_udp.pcap`
- Purpose: outer IPv6 GRE carriage for inner IPv6/UDP.

`gre/07_gre_key_ipv4_udp.pcap`
- Purpose: GRE key-present coverage with inner IPv4/UDP.

`gre/08_gre_sequence_ipv4_tcp.pcap`
- Purpose: GRE sequence-present coverage with inner IPv4/TCP.

`gre/09_gre_checksum_ipv4_udp.pcap`
- Purpose: GRE checksum-present coverage with inner IPv4/UDP.

`gre/10_gre_checksum_key_sequence_ipv4_udp.pcap`
- Purpose: combined GRE checksum/key/sequence optional-field ordering coverage.

`gre/11_gre_teb_ethernet_ipv4_tcp.pcap`
- Purpose: Transparent Ethernet Bridging payload carrying inner Ethernet/IPv4/TCP.

`gre/12_gre_teb_ethernet_vlan_ipv4_udp.pcap`
- Purpose: GRE TEB plus inner VLAN continuation coverage.

`gre/13_outer_vlan_gre_ipv4_udp.pcap`
- Purpose: outer VLAN preserved before GRE/inner IPv4/UDP.

`gre/14_outer_qinq_gre_ipv4_tcp.pcap`
- Purpose: outer QinQ preserved before GRE/inner IPv4/TCP.

`gre/15_gre_mpls_ipv4_udp.pcap`
- Purpose: staged GRE payload protocol type `0x8847` MPLS coverage with inner IPv4/UDP.

`gre/16_gre_unknown_protocol_type.pcap`
- Purpose: GRE unknown payload protocol type robustness without fabricating an inner flow.

`gre/17_gre_version1_pptp_like_unsupported.pcap`
- Purpose: GRE version 1 / PPTP-like unsupported coverage.

`gre/18_gre_truncated_base_header.pcap`
- Purpose: truncated GRE base-header robustness.

`gre/19_gre_truncated_key_field.pcap`
- Purpose: truncated GRE optional key-field robustness.

`gre/20_gre_truncated_inner_ipv4.pcap`
- Purpose: snaplen-truncated inner IPv4 payload behind a complete GRE header.

`gre/21_gre_same_inner_tuple_different_keys.pcap`
- Purpose: namespace-collision staging where identical inner tuples differ only by GRE key.

`gre/22_gre_same_inner_tuple_same_key_two_packets.pcap`
- Purpose: same-key, same-inner-tuple two-packet grouping baseline for future GRE tests.

## ESP

`esp/01_ipv4_esp_basic.pcap`
- Purpose: outer IPv4 ESP baseline with deterministic SPI and Sequence Number.

`esp/02_ipv6_esp_basic.pcap`
- Purpose: outer IPv6 ESP baseline with deterministic SPI and Sequence Number.

`esp/03_ipv4_esp_same_hosts_different_spi.pcap`
- Purpose: same IPv4 endpoints but different SPI values for future SPI-aware identity coverage.

`esp/04_ipv4_esp_same_spi_two_packets.pcap`
- Purpose: same SPI two-packet grouping baseline with sequence-only variation.

`esp/05_ipv6_esp_same_hosts_different_spi.pcap`
- Purpose: IPv6 analogue of same-endpoint different-SPI coverage.

`esp/06_outer_vlan_ipv4_esp.pcap`
- Purpose: outer VLAN preserved before IPv4 ESP.

`esp/07_outer_qinq_ipv4_esp.pcap`
- Purpose: outer QinQ preserved before IPv4 ESP.

`esp/08_ipv4_esp_large_opaque_payload.pcap`
- Purpose: larger opaque ESP payload that should remain undecoded.

`esp/09_ipv4_esp_minimal_header_only.pcap`
- Purpose: exactly 8 ESP bytes with no opaque payload after the lead-in header.

`esp/10_ipv4_esp_truncated_header.pcap`
- Purpose: truncated IPv4 ESP header robustness with fewer than 8 bytes after the IP header.

`esp/11_ipv4_esp_truncated_spi_only.pcap`
- Purpose: partial-SPI robustness with exactly 4 ESP bytes captured.

`esp/12_ipv6_esp_truncated_header.pcap`
- Purpose: truncated IPv6 ESP header robustness with fewer than 8 bytes after the IPv6 header.

`esp/13_ipv4_esp_zero_spi.pcap`
- Purpose: SPI zero boundary-value coverage.

`esp/14_ipv4_esp_high_spi_value.pcap`
- Purpose: full-range `0xffffffff` SPI formatting coverage.

`esp/15_ipv4_esp_sequence_wrapish_values.pcap`
- Purpose: high-range sequence-number coverage without changing SPI.

`esp/16_udp4500_nat_t_esp_non_ike_marker.pcap`
- Purpose: staged UDP/4500 NAT-T ESP-like payload with no Non-ESP Marker.

`esp/17_udp4500_nat_t_ike_marker_staged.pcap`
- Purpose: staged UDP/4500 Non-ESP Marker negative control for future NAT-T detection.

`esp/18_ipv4_esp_two_directions_different_spi.pcap`
- Purpose: opposite-direction ESP packets with different SPI values for future directional identity coverage.

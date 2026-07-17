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

## AH

`ah/01_ipv4_ah_tcp.pcap`
- Purpose: direct IPv4 AH baseline carrying TCP.

`ah/02_ipv4_ah_udp.pcap`
- Purpose: direct IPv4 AH baseline carrying UDP.

`ah/03_ipv6_ah_tcp.pcap`
- Purpose: direct IPv6 AH baseline carrying TCP.

`ah/04_ipv6_ah_udp.pcap`
- Purpose: direct IPv6 AH baseline carrying UDP.

`ah/05_ipv4_ah_same_tuple_different_spi.pcap`
- Purpose: same IPv4 tuple with different AH SPI values for SPI-aware identity coverage.

`ah/06_ipv4_ah_same_spi_two_packets.pcap`
- Purpose: same-SPI repeated two-packet grouping baseline.

`ah/07_ipv6_ah_same_tuple_different_spi.pcap`
- Purpose: IPv6 analogue of same-tuple different-SPI coverage.

`ah/08_ipv4_ah_same_spi_different_sequence.pcap`
- Purpose: same-SPI sequence variation baseline for details-only sequence handling.

`ah/09_outer_vlan_ipv4_ah_udp.pcap`
- Purpose: outer VLAN preserved before IPv4 AH.

`ah/10_outer_qinq_ipv4_ah_tcp.pcap`
- Purpose: valid QinQ preserved before IPv4 AH.

`ah/11_ipv6_hop_by_hop_ah_udp.pcap`
- Purpose: IPv6 Hop-by-Hop placement immediately before AH.

`ah/12_ipv4_ah_inner_ipv4_udp.pcap`
- Purpose: tunnel-mode IPv4 AH carrying inner IPv4 / UDP.

`ah/13_ipv4_ah_inner_ipv6_tcp.pcap`
- Purpose: tunnel-mode IPv4 AH carrying inner IPv6 / TCP.

`ah/14_ipv6_ah_inner_ipv4_udp.pcap`
- Purpose: tunnel-mode IPv6 AH carrying inner IPv4 / UDP.

`ah/15_ipv6_ah_inner_ipv6_tcp.pcap`
- Purpose: tunnel-mode IPv6 AH carrying inner IPv6 / TCP.

`ah/16_ah_truncated_fixed_header.pcap`
- Purpose: snaplen-style truncation before the full 12-byte AH fixed header is available.

`ah/17_ah_invalid_payload_length_too_small.pcap`
- Purpose: malformed AH with a payload-length field below the minimum valid size.

`ah/18_ah_payload_length_exceeds_packet.pcap`
- Purpose: malformed AH with a payload-length field that exceeds packet bytes.

`ah/19_ah_truncated_icv.pcap`
- Purpose: malformed AH with bytes ending inside the declared ICV.

`ah/20_ah_unsupported_next_header.pcap`
- Purpose: unsupported AH next-header value with otherwise well-formed AH structure.

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
- Purpose: GRE payload protocol type `0x8847` MPLS coverage with inner IPv4/UDP.

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
- Purpose: same-inner-tuple GRE-key identity split coverage.

`gre/22_gre_same_inner_tuple_same_key_two_packets.pcap`
- Purpose: same-key, same-inner-tuple two-packet grouping baseline.

## ESP

`esp/01_ipv4_esp_basic.pcap`
- Purpose: outer IPv4 ESP baseline with deterministic SPI and Sequence Number.

`esp/02_ipv6_esp_basic.pcap`
- Purpose: outer IPv6 ESP baseline with deterministic SPI and Sequence Number.

`esp/03_ipv4_esp_same_hosts_different_spi.pcap`
- Purpose: same IPv4 endpoints but different SPI values for SPI-aware identity coverage.

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
- Purpose: opposite-direction ESP packets with different SPI values for directional SPI-aware identity coverage.

## EoIP

`eoip/01_ipv4_eoip_inner_ipv4_udp.pcap`
- Purpose: baseline EoIP over outer IPv4 carrying inner Ethernet / IPv4 / UDP.

`eoip/02_ipv4_eoip_inner_ipv4_tcp.pcap`
- Purpose: baseline EoIP over outer IPv4 carrying inner Ethernet / IPv4 / TCP.

`eoip/03_ipv4_eoip_inner_ipv6_udp.pcap`
- Purpose: EoIP carrying inner Ethernet / IPv6 / UDP.

`eoip/04_ipv4_eoip_inner_vlan_ipv4_udp.pcap`
- Purpose: EoIP carrying inner Ethernet / VLAN / IPv4 / UDP.

`eoip/05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap`
- Purpose: EoIP carrying inner Ethernet / QinQ / IPv6 / TCP.

`eoip/06_outer_vlan_ipv4_eoip_inner_ipv4_udp.pcap`
- Purpose: outer VLAN preserved before outer IPv4 / GRE / EoIP.

`eoip/07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap`
- Purpose: deterministic real-shape coverage for outer VLAN + two MPLS labels before outer IPv4 / EoIP plus inner VLAN / IPv4 / UDP.

`eoip/08_same_inner_tuple_different_tunnel_ids.pcap`
- Purpose: tunnel-ID identity split baseline for the same inner tuple through tunnel IDs `6400` and `6401`.

`eoip/09_same_tunnel_id_different_inner_payload_lengths.pcap`
- Purpose: payload-length normalization baseline proving packet-dependent EoIP payload length must not split identity.

`eoip/10_same_tunnel_id_two_packets.pcap`
- Purpose: same-tunnel two-packet grouping baseline.

`eoip/11_max_tunnel_id.pcap`
- Purpose: `65535` tunnel-ID boundary-value coverage.

`eoip/12_truncated_eoip_key_word.pcap`
- Purpose: truncated EoIP payload-length / tunnel-ID word robustness.

`eoip/13_eoip_payload_length_exceeds_available.pcap`
- Purpose: declared EoIP payload length exceeds available inner Ethernet bytes.

`eoip/14_eoip_payload_length_smaller_than_inner_frame.pcap`
- Purpose: declared EoIP payload length is shorter than the following bytes and must bound future parsing.

`eoip/15_eoip_missing_key_bit.pcap`
- Purpose: GRE version-1 negative control with protocol type `0x6400` but GRE K bit clear.

`eoip/16_gre_v1_unsupported_protocol_type.pcap`
- Purpose: GRE version-1 unsupported-protocol negative control with protocol type `0x1234`.

`eoip/17_eoip_truncated_inner_ethernet.pcap`
- Purpose: valid EoIP header followed by fewer than 14 bytes of inner Ethernet.

`eoip/18_eoip_truncated_inner_vlan.pcap`
- Purpose: valid EoIP header plus inner Ethernet addresses and a truncated inner VLAN header.

## IP Encapsulation

`ip_encapsulation/01_ipv4_in_ipv4_tcp.pcap`
- Purpose: outer IPv4 protocol `4` carrying inner IPv4/TCP.

`ip_encapsulation/02_ipv4_in_ipv4_udp.pcap`
- Purpose: outer IPv4 protocol `4` carrying inner IPv4/UDP.

`ip_encapsulation/03_ipv6_in_ipv4_tcp.pcap`
- Purpose: outer IPv4 protocol `41` carrying inner IPv6/TCP.

`ip_encapsulation/04_ipv6_in_ipv4_udp.pcap`
- Purpose: outer IPv4 protocol `41` carrying inner IPv6/UDP.

`ip_encapsulation/05_ipv4_in_ipv6_tcp.pcap`
- Purpose: outer IPv6 next-header `4` carrying inner IPv4/TCP.

`ip_encapsulation/06_ipv4_in_ipv6_udp.pcap`
- Purpose: outer IPv6 next-header `4` carrying inner IPv4/UDP.

`ip_encapsulation/07_ipv6_in_ipv6_tcp.pcap`
- Purpose: outer IPv6 next-header `41` carrying inner IPv6/TCP.

`ip_encapsulation/08_ipv6_in_ipv6_udp.pcap`
- Purpose: outer IPv6 next-header `41` carrying inner IPv6/UDP.

`ip_encapsulation/09_outer_vlan_ipv4_in_ipv4_udp.pcap`
- Purpose: outer VLAN preserved before outer IPv4 protocol `4` and inner IPv4/UDP.

`ip_encapsulation/10_outer_qinq_ipv6_in_ipv4_tcp.pcap`
- Purpose: outer QinQ preserved before outer IPv4 protocol `41` and inner IPv6/TCP.

`ip_encapsulation/11_outer_vlan_ipv4_in_ipv6_udp.pcap`
- Purpose: outer VLAN preserved before outer IPv6 next-header `4` and inner IPv4/UDP.

`ip_encapsulation/12_nested_ipv4_in_ipv4_in_ipv4_udp.pcap`
- Purpose: repeated nested IPv4 layers for implemented bounded positional protocol-path coverage.

`ip_encapsulation/13_same_inner_tuple_different_outer_ipv4_tunnels.pcap`
- Purpose: same inner IPv4/UDP tuple through two different outer IPv4 tunnel endpoint pairs to document the accepted v1 merge tradeoff.

`ip_encapsulation/14_same_inner_tuple_same_outer_ipv4_two_packets.pcap`
- Purpose: same outer and inner IPv4/UDP tuple repeated twice as a one-flow/two-packet baseline.

`ip_encapsulation/15_ipv4_in_ipv4_inner_icmp.pcap`
- Purpose: outer IPv4 protocol `4` carrying inner IPv4 ICMP echo request.

`ip_encapsulation/16_ipv6_in_ipv4_inner_icmpv6.pcap`
- Purpose: outer IPv4 protocol `41` carrying inner IPv6 ICMPv6 echo request.

`ip_encapsulation/17_truncated_inner_ipv4_header.pcap`
- Purpose: outer IPv4 protocol `4` with a snaplen-truncated inner IPv4 header.

`ip_encapsulation/18_truncated_inner_ipv6_header.pcap`
- Purpose: outer IPv4 protocol `41` with a snaplen-truncated inner IPv6 header.

`ip_encapsulation/19_outer_ipv4_proto4_payload_too_short.pcap`
- Purpose: outer IPv4 protocol `4` with too-short payload that must not fabricate an inner flow.

`ip_encapsulation/20_ipv6_next41_payload_too_short.pcap`
- Purpose: outer IPv6 next-header `41` with too-short payload that must not fabricate an inner flow.

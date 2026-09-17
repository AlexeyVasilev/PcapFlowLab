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

## DHCPv4

`dhcp/01_dhcp_discover_broadcast.pcap`
- Purpose: positive DHCPv4 Discover recognition baseline on UDP 68 -> 67.

`dhcp/02_dhcp_offer_broadcast.pcap`
- Purpose: positive DHCPv4 Offer recognition baseline on reverse UDP 67 -> 68.

`dhcp/03_dhcp_request_ack_bidirectional.pcap`
- Purpose: DHCPv4 Request/ACK bidirectional grouping baseline in one UDP flow.

`dhcp/04_dhcp_bad_magic_cookie.pcap`
- Purpose: negative DHCPv4 case showing ports 67/68 alone are insufficient without the valid magic cookie.

`dhcp/05_dhcp_valid_payload_wrong_ports.pcap`
- Purpose: negative DHCPv4 case showing a valid DHCP-looking payload is not recognized on non-DHCP ports.

`dhcp/06_dhcp_truncated_before_magic_cookie.pcap`
- Purpose: negative DHCPv4 boundary case where the payload ends before the complete magic cookie is available.

## SSH

`ssh/01_ssh_server_banner_port22.pcap`
- Purpose: standard TCP/22 SSH server identification baseline.

`ssh/02_ssh_client_banner_port2222.pcap`
- Purpose: content-based SSH recognition on a non-standard port.

`ssh/03_ssh_banner_after_unmatched_payload.pcap`
- Purpose: later payload recognition within one TCP Flow.

`ssh/04_ssh_invalid_ssx_prefix_port22.pcap`
- Purpose: near-miss prefix negative case proving TCP port 22 alone is insufficient.

`ssh/05_ssh_short_prefix_three_bytes.pcap`
- Purpose: payload-length boundary negative case.

## STUN

`stun/01_stun_binding_request_3478.pcap`
- Purpose: standard positive STUN Binding Request baseline.

`stun/02_stun_binding_request_response.pcap`
- Purpose: bidirectional STUN request/response Flow baseline.

`stun/03_stun_binding_request_nonstandard_port.pcap`
- Purpose: content-based STUN recognition on a non-standard UDP port.

`stun/04_stun_bad_magic_cookie.pcap`
- Purpose: invalid-cookie negative case.

`stun/05_stun_invalid_top_bits.pcap`
- Purpose: STUN first-two-bits invariant negative case.

`stun/06_stun_declared_length_mismatch.pcap`
- Purpose: exact declared-length boundary negative case.

## BitTorrent

`bittorrent/01_bittorrent_handshake_typical_ports.pcap`
- Purpose: canonical 68-byte peer-wire handshake positive baseline.

`bittorrent/02_bittorrent_bidirectional_nonstandard_ports.pcap`
- Purpose: bidirectional canonical handshakes on non-standard ports.

`bittorrent/03_bittorrent_handshake_plus_keepalive.pcap`
- Purpose: handshake followed by additional peer-wire bytes in one TCP payload.

`bittorrent/04_bittorrent_invalid_pstrlen.pcap`
- Purpose: invalid pstrlen negative case.

`bittorrent/05_bittorrent_invalid_protocol_string.pcap`
- Purpose: exact protocol-string negative case.

`bittorrent/06_bittorrent_short_67_byte_handshake.pcap`
- Purpose: minimum handshake-size boundary negative case.

## SMTP

`smtp/01_smtp_greeting_ehlo_port25.pcap`
- Purpose: bidirectional SMTP greeting/EHLO positive baseline on TCP/25.

`smtp/02_smtp_helo_port25.pcap`
- Purpose: HELO recognition positive baseline.

`smtp/03_smtp_mail_from_port587.pcap`
- Purpose: MAIL FROM recognition on supported submission port 587.

`smtp/04_smtp_ehlo_after_unmatched_payload.pcap`
- Purpose: later independent payload recognition in one TCP Flow.

`smtp/05_smtp_ehlo_port2525_not_detected.pcap`
- Purpose: valid recognized SMTP prefix on unsupported port negative case.

`smtp/06_smtp_invalid_ehxlo_port25.pcap`
- Purpose: port-25 near-miss command prefix negative case.

## POP3

`pop3/01_pop3_greeting_user_port110.pcap`
- Purpose: bidirectional server greeting + USER positive baseline.

`pop3/02_pop3_pass_port110.pcap`
- Purpose: PASS command positive baseline.

`pop3/03_pop3_user_after_unmatched_payload.pcap`
- Purpose: later independent payload recognition in one TCP Flow.

`pop3/04_pop3_user_port1110_not_detected.pcap`
- Purpose: recognized USER prefix on unsupported port negative case.

`pop3/05_pop3_invalid_usxr_port110.pcap`
- Purpose: TCP/110 near-miss prefix negative case.

## IMAP

`imap/01_imap_greeting_login_port143.pcap`
- Purpose: bidirectional server greeting + tagged LOGIN positive baseline.

`imap/02_imap_capability_port143.pcap`
- Purpose: tagged CAPABILITY positive baseline.

`imap/03_imap_login_after_unmatched_payload.pcap`
- Purpose: later independent payload recognition within one TCP Flow.

`imap/04_imap_login_port1143_not_detected.pcap`
- Purpose: recognizable current LOGIN form on unsupported port negative case.

`imap/05_imap_missing_tag_command_separator_port143.pcap`
- Purpose: malformed tagged-command separator negative case.

## MQTT

These fixtures define the target MQTT detection-only behavior. MQTT support is
implemented as core CONNECT-based recognition; fixtures 01-04 are MQTT
positive cases and fixtures 05-10 are MQTT negative cases.

`mqtt/01_mqtt311_connect_port1883.pcap`
- Purpose: MQTT 3.1.1 CONNECT positive baseline on TCP/1883.

`mqtt/02_mqtt5_rich_connect_nonstandard_port.pcap`
- Purpose: rich MQTT 5 CONNECT on a non-standard port; content-based positive case.

`mqtt/03_mqtt31_connect_port1883.pcap`
- Purpose: MQTT 3.1 `MQIsdp` / level-3 positive baseline.

`mqtt/04_mqtt311_connect_plus_pingreq_same_payload.pcap`
- Purpose: CONNECT plus PINGREQ in one TCP payload positive coalescing case.

`mqtt/05_mqtt_garbage_port1883.pcap`
- Purpose: non-MQTT data on TCP/1883 negative case.

`mqtt/06_mqtt_invalid_fixed_header_flags.pcap`
- Purpose: invalid CONNECT fixed-header flags negative case.

`mqtt/07_mqtt_protocol_name_level_mismatch.pcap`
- Purpose: protocol-name / protocol-level mismatch negative case.

`mqtt/08_mqtt_invalid_connect_flags_reserved_bit.pcap`
- Purpose: invalid reserved bit in CONNECT Flags negative case.

`mqtt/09_mqtt_declared_remaining_length_too_large.pcap`
- Purpose: declared Remaining Length exceeds available TCP bytes negative case.

`mqtt/10_mqtt_client_id_length_exceeds_frame.pcap`
- Purpose: inner Client Identifier length exceeds CONNECT frame negative case.

## AMQP

These fixtures define the target first AMQP detection-only behavior before the
recognizer exists. Fixtures 01-05 are future AMQP positive cases and fixtures
06-10 are future AMQP negative cases; current pre-implementation behavior is
ordinary TCP with no AMQP detected protocol.

`amqp/01_amqp091_header_port5672.pcap`
- Purpose: AMQP 0-9-1 exact protocol-header positive baseline on TCP/5672.

`amqp/02_amqp091_header_nonstandard_port.pcap`
- Purpose: AMQP 0-9-1 exact protocol-header positive case on a non-standard port.

`amqp/03_amqp10_core_header_port5672.pcap`
- Purpose: AMQP 1.0 core exact protocol-header positive baseline.

`amqp/04_amqp10_sasl_header_nonstandard_port.pcap`
- Purpose: explicit AMQP 1.0 SASL protocol-header positive case on a non-standard port.

`amqp/05_amqp10_tls_header_nonstandard_port.pcap`
- Purpose: explicit AMQP 1.0 TLS protocol-header positive case, not generic TLS/port inference.

`amqp/06_amqp_garbage_port5672.pcap`
- Purpose: non-AMQP data on TCP/5672 negative case with `AMQP` not at payload offset 0.

`amqp/07_amqp091_wrong_version.pcap`
- Purpose: AMQP 0-9-1 near-miss wrong-version negative case.

`amqp/08_amqp10_unsupported_protocol_id.pcap`
- Purpose: unsupported AMQP 1.0 protocol-id negative case.

`amqp/09_amqp10_wrong_revision.pcap`
- Purpose: AMQP 1.0 wrong revision negative case.

`amqp/10_amqp_truncated_header.pcap`
- Purpose: seven-byte AMQP-looking prefix negative case.

## ICMP

`icmp/01_icmp_echo_request.pcap`
- Purpose: deterministic ICMPv4 Echo Request baseline.
- Used by: fixture-first regression coverage for current ICMP flow recognition, Summary, and Packet Bytes behavior.

`icmp/02_icmp_echo_reply.pcap`
- Purpose: deterministic ICMPv4 Echo Reply baseline.
- Used by: fixture-first regression coverage for current ICMP details decoding.

`icmp/03_icmp_dest_unreachable_network.pcap`
- Purpose: Destination Unreachable / Network Unreachable with realistic quoted IPv4+UDP bytes.

`icmp/04_icmp_dest_unreachable_host.pcap`
- Purpose: Destination Unreachable / Host Unreachable with realistic quoted IPv4+UDP bytes.

`icmp/05_icmp_dest_unreachable_port.pcap`
- Purpose: Destination Unreachable / Port Unreachable with realistic quoted IPv4+UDP bytes.

`icmp/06_icmp_dest_unreachable_frag_needed_mtu_1400.pcap`
- Purpose: Destination Unreachable / Fragmentation Needed with deterministic Next-Hop MTU value.

`icmp/07_icmp_time_exceeded_ttl.pcap`
- Purpose: Time Exceeded / TTL exceeded in transit with quoted IPv4+UDP bytes.

`icmp/08_icmp_time_exceeded_reassembly.pcap`
- Purpose: Time Exceeded / fragment reassembly timeout with quoted IPv4+UDP bytes.

`icmp/09_icmp_redirect_host_gateway.pcap`
- Purpose: Redirect / host redirect with deterministic gateway address and quoted original datagram bytes.

`icmp/10_icmp_parameter_problem_pointer_5.pcap`
- Purpose: Parameter Problem with deterministic pointer value and quoted IPv4+TCP bytes.

`icmp/11_icmp_unknown_type_99.pcap`
- Purpose: unknown numeric ICMP Type baseline that remains structurally long enough for current common-header decoding.

`icmp/12_icmp_echo_request_unknown_code_7.pcap`
- Purpose: known Echo Request Type with uncommon numeric Code preserved on wire.

`icmp/13_icmp_truncated_common_header_3_bytes.pcap`
- Purpose: outer Ethernet/IPv4 remains valid while ICMP common header is truncated below 4 bytes.

`icmp/14_icmp_truncated_echo_body.pcap`
- Purpose: common header present but Echo Identifier/Sequence body intentionally incomplete.

`icmp/15_icmp_truncated_error_quote.pcap`
- Purpose: error-message header present with intentionally incomplete quoted/original data.

`icmp/16_icmp_same_endpoints_different_identifiers.pcap`
- Purpose: flow-identity regression showing that differing Echo Identifier/Sequence values do not split the current endpoint-based ICMP flow key.

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

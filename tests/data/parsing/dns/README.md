# DNS Fixture Contracts

This directory contains classic PCAP fixtures for current DNS hinting/presentation baselines and for the shared backend `DnsInspectionParser` packet and stream presentation contracts.

Current behavior already covered elsewhere in default-on tests:
- DNS hint detection on known request/response fixtures;
- QNAME-based service hinting where already supported;
- structured selected-packet DNS Summary plus existing Packet Bytes behavior;
- packet-local structured DNS Stream item Summary using the shared `DnsMessage` model.

Current backend parser/model, selected-packet Summary coverage, and packet-local Stream coverage are now default-on:
- `DNS payload -> DnsInspectionParser -> DnsMessage(header, questions, answers, authorities, additionals)`

## Scenario Matrix

| Fixture | Transport | Msg | Structure | Compression | RR types | Malformed | Current behavior | Planned contract |
|---|---|---|---|---|---|---|---|---|
| `dns_request_1.pcap` | IPv4 UDP | Query | one question | unknown/manual baseline | HTTPS query | none | existing baseline fixture; DNS hint + service already asserted | retain as current baseline only |
| `dns_response_2.pcap` | IPv4 UDP | Response | question + answer set | existing compressed real fixture | mixed real-world answer set | none | existing baseline fixture; DNS hint + service already asserted | retain as current baseline only |
| `03_dns_ipv4_a_query.pcap` | IPv4 UDP | Query | one question | none | A | none | structured packet-local DNS query | baseline A-query packet/stream contract |
| `04_dns_ipv4_a_response_compressed.pcap` | IPv4 UDP | Response | one question, one answer | answer owner compressed to question name | A | none | structured packet-local DNS response | compressed-owner packet/stream contract |
| `05_dns_ipv6_aaaa_query.pcap` | IPv6 UDP | Query | one question | none | AAAA | none | structured packet-local DNS query | IPv6 AAAA-query contract |
| `06_dns_ipv6_aaaa_response.pcap` | IPv6 UDP | Response | one question, one answer | answer owner compressed to question name | AAAA | none | structured packet-local DNS response | IPv6 AAAA-answer contract |
| `07_dns_ipv4_cname_response_compressed.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner plus compressed target suffix | CNAME | none | structured packet-local DNS response | bounded compression-name decoding contract |
| `08_dns_ipv4_multiple_answers_response.pcap` | IPv4 UDP | Response | one question, two answers | compressed owners | A | none | structured packet-local DNS response | multiple-answer packet/stream contract |
| `09_dns_ipv4_nxdomain_response.pcap` | IPv4 UDP | Response | one question, zero answers | none | none | NXDOMAIN | structured packet-local DNS response | non-zero RCODE contract with no fabricated answers |
| `10_dns_ipv4_https_query.pcap` | IPv4 UDP | Query | one question | none | HTTPS (65) query | none | structured packet-local DNS query | RR-type naming contract for HTTPS / 65 |
| `11_dns_ipv4_ptr_query.pcap` | IPv4 UDP | Query | one question | none | PTR | none | structured packet-local DNS query | ordinary PTR question contract |
| `12_dns_ipv4_srv_response.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner | SRV | none | structured packet-local DNS response | SRV priority/weight/port/target contract |
| `13_dns_ipv4_txt_response.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner | TXT | none | structured packet-local DNS response | bounded TXT-string contract |
| `14_dns_ipv4_truncated_message.pcap` | IPv4 UDP | Query-like | DNS header plus partial question bytes | none | none | structurally truncated message | structured warning with bounded header retention | bounded truncation diagnostics contract |
| `15_dns_ipv4_malformed_pointer_oob.pcap` | IPv4 UDP | Query-like | one question | pointer outside message bounds | none | malformed compression target | structured warning with bounded header retention | out-of-bounds compression diagnostic contract |
| `16_dns_ipv4_malformed_pointer_loop.pcap` | IPv4 UDP | Query-like | one question | self-referential pointer loop | none | malformed compression loop | structured warning with bounded header retention | bounded pointer-loop diagnostic contract |
| `17_dns_ipv4_unknown_rr_response.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner | unknown type `65280` | none | structured packet-local DNS response | raw-type / raw-RDLENGTH preservation contract |

## Notes

- All fixtures in this directory are classic PCAP, not PCAPNG.
- Outer Ethernet / IP / UDP framing is intentionally valid even when the DNS payload is malformed.
- Compression-focused fixtures are deterministic and self-contained; no runtime Wireshark behavior is required to interpret them.
- Future v1 RR parsing priority for guarded tests is: `A`, `AAAA`, `CNAME`, `PTR`, `SRV`, `TXT`.

# DNS Fixture Contracts

This directory contains classic PCAP fixtures for current DNS hinting/presentation baselines, for the now-implemented shared backend `DnsInspectionParser`, and for future guarded DNS presentation contracts.

Current behavior already covered elsewhere in default-on tests:
- DNS hint detection on known request/response fixtures;
- QNAME-based service hinting where already supported;
- basic packet-local DNS Summary / Packet Bytes behavior.

Current backend parser/model coverage is now default-on:
- `DNS payload -> DnsInspectionParser -> DnsMessage(header, questions, answers, authorities, additionals)`

Future Packet Summary / Stream presentation contracts should remain guarded behind:
- `PFL_ENABLE_PENDING_DNS_INSPECTION_TESTS`

## Scenario Matrix

| Fixture | Transport | Msg | Structure | Compression | RR types | Malformed | Current behavior | Planned contract |
|---|---|---|---|---|---|---|---|---|
| `dns_request_1.pcap` | IPv4 UDP | Query | one question | unknown/manual baseline | HTTPS query | none | existing baseline fixture; DNS hint + service already asserted | retain as current baseline only |
| `dns_response_2.pcap` | IPv4 UDP | Response | question + answer set | existing compressed real fixture | mixed real-world answer set | none | existing baseline fixture; DNS hint + service already asserted | retain as current baseline only |
| `03_dns_ipv4_a_query.pcap` | IPv4 UDP | Query | one question | none | A | none | should remain a basic DNS packet | future header/question contract for uncompressed A query |
| `04_dns_ipv4_a_response_compressed.pcap` | IPv4 UDP | Response | one question, one answer | answer owner compressed to question name | A | none | packet remains structurally valid | future compressed-owner A-answer contract |
| `05_dns_ipv6_aaaa_query.pcap` | IPv6 UDP | Query | one question | none | AAAA | none | packet remains structurally valid | future IPv6 transport AAAA-query contract |
| `06_dns_ipv6_aaaa_response.pcap` | IPv6 UDP | Response | one question, one answer | answer owner compressed to question name | AAAA | none | packet remains structurally valid | future IPv6 transport AAAA-answer contract |
| `07_dns_ipv4_cname_response_compressed.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner plus compressed target suffix | CNAME | none | packet remains structurally valid | future bounded compression-name decoding contract |
| `08_dns_ipv4_multiple_answers_response.pcap` | IPv4 UDP | Response | one question, two answers | compressed owners | A | none | packet remains structurally valid | future section-count / multiple-answer contract |
| `09_dns_ipv4_nxdomain_response.pcap` | IPv4 UDP | Response | one question, zero answers | none | none | NXDOMAIN | packet remains structurally valid | future non-zero RCODE contract with no fabricated answers |
| `10_dns_ipv4_https_query.pcap` | IPv4 UDP | Query | one question | none | HTTPS (65) query | none | packet remains structurally valid | future RR-type naming contract for HTTPS / 65 |
| `11_dns_ipv4_ptr_query.pcap` | IPv4 UDP | Query | one question | none | PTR | none | packet remains structurally valid | future ordinary PTR question contract |
| `12_dns_ipv4_srv_response.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner | SRV | none | packet remains structurally valid | future SRV priority/weight/port/target contract |
| `13_dns_ipv4_txt_response.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner | TXT | none | packet remains structurally valid | future bounded TXT-string contract |
| `14_dns_ipv4_truncated_message.pcap` | IPv4 UDP | Query-like | DNS header plus partial question bytes | none | none | structurally truncated message | outer Ethernet/IP/UDP remain valid | future bounded truncation diagnostics contract |
| `15_dns_ipv4_malformed_pointer_oob.pcap` | IPv4 UDP | Query-like | one question | pointer outside message bounds | none | malformed compression target | outer Ethernet/IP/UDP remain valid | future out-of-bounds compression diagnostic contract |
| `16_dns_ipv4_malformed_pointer_loop.pcap` | IPv4 UDP | Query-like | one question | self-referential pointer loop | none | malformed compression loop | outer Ethernet/IP/UDP remain valid | future bounded pointer-loop diagnostic contract |
| `17_dns_ipv4_unknown_rr_response.pcap` | IPv4 UDP | Response | one question, one answer | compressed owner | unknown type `65280` | none | packet remains structurally valid | future raw-type / raw-RDLENGTH preservation contract |

## Notes

- All fixtures in this directory are classic PCAP, not PCAPNG.
- Outer Ethernet / IP / UDP framing is intentionally valid even when the DNS payload is malformed.
- Compression-focused fixtures are deterministic and self-contained; no runtime Wireshark behavior is required to interpret them.
- Future v1 RR parsing priority for guarded tests is: `A`, `AAAA`, `CNAME`, `PTR`, `SRV`, `TXT`.

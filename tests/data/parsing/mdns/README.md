# mDNS Fixture Contracts

This directory contains classic PCAP fixtures for current mDNS detector-scope regressions and for the shared backend `DnsInspectionParser` packet and stream presentation contracts.

Current production behavior intentionally remains limited in this stage:
- mDNS hint detection depends on UDP/5353 plus the common multicast destination path;
- selected-packet Summary now uses the shared structured DNS wire model with an mDNS-specific layer title and class-bit presentation;
- selected-flow Stream now uses the same shared structured DNS wire model for packet-local mDNS items;
- flow-level Service now uses a bounded best-effort name hint:
  1. first meaningful Question name;
  2. otherwise first meaningful PTR owner name;
  3. otherwise first meaningful RR owner name;
  4. otherwise empty;
- user-facing detected text now appears as `mDNS`.

Current backend parser/model coverage is now default-on for shared DNS wire parsing, selected-packet Summary mapping, and packet-local mDNS Stream presentation.

## Scenario Matrix

| Fixture | Transport | Msg | Structure | Compression | RR types | Malformed / detector note | Current behavior | Planned contract |
|---|---|---|---|---|---|---|---|---|
| `01_mdns_ipv4_ptr_query.pcap` | IPv4 UDP/5353 to `224.0.0.251` | Query | one question | none | PTR | none | structured packet-local mDNS query; Service = `_demo-service._tcp.local` | structured mDNS PTR-query contract |
| `02_mdns_ipv6_ptr_query.pcap` | IPv6 UDP/5353 to `ff02::fb` | Query | one question | none | PTR | none | structured packet-local mDNS query; Service = `_demo-service._tcp.local` | IPv6 mDNS PTR-query contract |
| `03_mdns_ipv4_ptr_response.pcap` | IPv4 UDP/5353 multicast | Response | one answer | none | PTR | none | structured packet-local mDNS response | PTR owner/instance contract |
| `04_mdns_ipv4_dns_sd_response.pcap` | IPv4 UDP/5353 multicast | Response | answer + additionals | none | PTR, SRV, TXT, A | none | structured packet-local mDNS response | DNS-SD multi-record contract |
| `05_mdns_ipv6_dns_sd_response_aaaa.pcap` | IPv6 UDP/5353 multicast | Response | answer + additionals | none | PTR, SRV, TXT, AAAA | none | structured packet-local mDNS response | IPv6 DNS-SD additional AAAA contract |
| `06_mdns_ipv4_multiple_questions.pcap` | IPv4 UDP/5353 multicast | Query | two questions | none | PTR, A | none | structured packet-local mDNS query | multi-question section contract |
| `07_mdns_ipv4_multiple_answers.pcap` | IPv4 UDP/5353 multicast | Response | two answers | none | PTR | none | structured packet-local mDNS response | multi-answer section contract |
| `08_mdns_ipv4_cache_flush_response.pcap` | IPv4 UDP/5353 multicast | Response | one answer | none | A | RR class high bit set (`cache-flush`) | structured packet-local mDNS response | raw-class + cache-flush interpretation contract |
| `09_mdns_ipv4_qu_question.pcap` | IPv4 UDP/5353 multicast | Query | one question | none | PTR | question class high bit set (`QU`) | structured packet-local mDNS query | raw-class + QU interpretation contract |
| `10_mdns_ipv4_truncated_message.pcap` | IPv4 UDP/5353 multicast | Query-like | DNS header plus partial question bytes | none | none | structurally truncated message | structured warning with bounded header retention | bounded truncation diagnostic contract |
| `11_mdns_ipv4_malformed_pointer.pcap` | IPv4 UDP/5353 multicast | Query-like | one question | malformed out-of-bounds pointer | none | malformed compression | structured warning with bounded header retention | malformed-compression contract |
| `12_mdns_wrong_port_negative.pcap` | IPv4 UDP/5354 to `224.0.0.251` | Query-like | one question | none | PTR | wrong port | must remain generic UDP Stream / no mDNS hint | documents current detector scope |
| `13_mdns_wrong_multicast_destination_negative.pcap` | IPv4 UDP/5353 to `224.0.0.252` | Query-like | one question | none | PTR | wrong destination | must remain generic UDP Stream / no mDNS hint | documents current detector scope |

## Notes

- All fixtures in this directory are classic PCAP, not PCAPNG.
- The deterministic DNS-SD example used here is:
  - service type: `_demo-service._tcp.local`
  - instance: `Example Device._demo-service._tcp.local`
  - host: `example-device.local` / `example-device-v6.local`
- Implemented best-effort mDNS service-hint rule:
  1. first meaningful Question name;
  2. otherwise first meaningful PTR owner name;
  3. otherwise first meaningful RR owner name;
  4. otherwise empty.
- User-facing detected terminology is `mDNS`.

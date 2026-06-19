Synthetic IGMP parsing fixtures for current IGMP flow recognition, grouping, and safe malformed-packet handling.

This directory is intended to contain tiny deterministic `.pcap` fixtures for:
- IGMPv1/v2 Membership Reports and Queries;
- IGMP grouping behavior across source hosts and multicast groups;
- IPv4 Router Alert option handling;
- unknown, partial, malformed, and snaplen-truncated IGMP packets.

The local helper script that generates these pcaps is intentionally **not** committed.

## Local generation

Run from the repository root after installing Scapy locally:

```bash
python3 tmp/generate_igmp_pcaps.py tests/data/parsing/igmp
```

Notes:
- the script is a local helper only and should **not** be committed;
- generated `.pcap` files from this directory are intended to be reviewed locally before commit;
- the generator uses deterministic MAC/IP values and classic little-endian `.pcap` output;
- true snaplen-truncated captures are written with classic `.pcap` records whose included length is smaller than the original wire length.

## IGMP basics

- IGMP uses IPv4 protocol number `2`.
- The common layer chain is `Ethernet / IPv4 / IGMP`.
- IGMP does not use TCP/UDP ports.
- Typical TTL is `1`.
- Many IGMP packets include the IPv4 Router Alert option.
- Basic IGMPv1/v2-style headers are 8 bytes:
  - Type
  - Max Resp Time / Code
  - Checksum
  - Group Address

Common message types:
- `0x11` Membership Query
- `0x12` IGMPv1 Membership Report
- `0x16` IGMPv2 Membership Report
- `0x17` IGMPv2 Leave Group
- `0x22` IGMPv3 Membership Report

## Shared constants

- Host A MAC: `02:00:00:00:20:01`
- Host B MAC: `02:00:00:00:20:02`
- Router MAC: `02:00:00:00:20:fe`
- Host A IPv4: `192.0.2.10`
- Host B IPv4: `192.0.2.11`
- Router IPv4: `192.0.2.1`
- mDNS multicast group: `224.0.0.251`
- all-systems group: `224.0.0.1`
- all-routers group: `224.0.0.2`
- test multicast group: `239.1.2.3`

IPv4 multicast destination MAC mapping used where practical:
- `224.0.0.251` -> `01:00:5e:00:00:fb`
- `224.0.0.1` -> `01:00:5e:00:00:01`
- `224.0.0.2` -> `01:00:5e:00:00:02`
- `239.1.2.3` -> `01:00:5e:01:02:03`

## Current behavior

Current IGMP support uses the following flow-key semantics:
- protocol = `IGMP`
- source address = IPv4 source address
- destination/group key = IGMP group address when non-zero
- for General Query with group `0.0.0.0`, use the IPv4 destination address as the effective group key
- source port = `0` internally / empty in UI
- destination port = `0` internally / empty in UI
- IGMP message type is **not** part of the flow key

Current presentation behavior:
- valid IGMP packets appear as normal `IGMP` flows, not in the unrecognized list;
- Summary includes an IGMP layer after IPv4;
- Hint/Service describe IGMP version and message type without splitting flows;
- Raw remains available;
- detailed IGMPv3 group-record parsing remains deferred;
- malformed/truncated IGMP packets stay safe and may remain in the unrecognized list with explicit reason text.

## Current flow grouping behavior

IGMP grouping behavior is intentionally:
- same source host + same multicast group => one user-facing IGMP flow, even if message type changes;
- same group but different sources => different flows;
- same source but different multicast groups => different flows;
- General Query with IGMP group `0.0.0.0` should use the IPv4 destination as the effective group key.

This means, for example:
- a Membership Report followed by Leave Group for `192.0.2.10` + `224.0.0.251` should stay in one flow;
- two hosts both reporting `224.0.0.251` should become two flows;
- one host reporting `224.0.0.251` and `239.1.2.3` should become two flows.

## Fixture map

### A. Basic IGMPv1/v2 messages

- `01_igmpv1_membership_report_mdns_group.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: IGMPv1 Membership Report (`0x12`)
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.251`
  - IGMP group address: `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: normal IGMP flow, Hint `IGMPv1`, Service `Membership Report 224.0.0.251`

- `02_igmpv2_membership_report_mdns_group.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: IGMPv2 Membership Report (`0x16`)
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.251`
  - IGMP group address: `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: normal IGMP flow, Hint `IGMPv2`, Service `Membership Report 224.0.0.251`

- `03_igmpv2_leave_group_mdns_group.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: IGMPv2 Leave Group (`0x17`)
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.2`
  - IGMP group address: `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: grouped by Host A + group `224.0.0.251`, Service `Leave Group 224.0.0.251`

- `04_igmpv2_general_query.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: Membership Query (`0x11`), general query
  - IPv4 source/destination: `192.0.2.1` -> `224.0.0.1`
  - IGMP group address: `0.0.0.0`
  - IPv4 Router Alert: `no`
  - Expected behavior: normal IGMP flow keyed by source `192.0.2.1` + effective group key `224.0.0.1`, Service `General Query`

- `05_igmpv2_group_specific_query.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: Membership Query (`0x11`), group-specific query
  - IPv4 source/destination: `192.0.2.1` -> `239.1.2.3`
  - IGMP group address: `239.1.2.3`
  - IPv4 Router Alert: `no`
  - Expected behavior: normal IGMP flow, Service `Group-Specific Query 239.1.2.3`

### B. Grouping behavior

- `06_igmp_same_source_group_report_then_leave.pcap`
  - Packets: `2`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - Packet 1: Host A IGMPv2 Membership Report for `224.0.0.251`
  - Packet 2: Host A IGMPv2 Leave Group for `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: one IGMP flow with two packets because message type is not part of the key

- `07_igmp_two_sources_same_group.pcap`
  - Packets: `2`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - Packet 1: Host A report for `224.0.0.251`
  - Packet 2: Host B report for `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: two IGMP flows because source host differs

- `08_igmp_same_source_two_groups.pcap`
  - Packets: `2`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - Packet 1: Host A report for `224.0.0.251`
  - Packet 2: Host A report for `239.1.2.3`
  - IPv4 Router Alert: `no`
  - Expected behavior: two IGMP flows because group key differs

### C. IPv4 options / Router Alert

- `09_igmpv2_report_with_router_alert.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / IGMP`
  - IGMP message: IGMPv2 Membership Report (`0x16`)
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.251`
  - IGMP group address: `224.0.0.251`
  - IPv4 Router Alert: `yes`
  - Expected behavior: IGMP parser uses correct IPv4 IHL and places IGMP after IPv4 with no offset bug

- `10_igmpv2_general_query_with_router_alert.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / IGMP`
  - IGMP message: General Query (`0x11`)
  - IPv4 source/destination: `192.0.2.1` -> `224.0.0.1`
  - IGMP group address: `0.0.0.0`
  - IPv4 Router Alert: `yes`
  - Expected behavior: normal IGMP flow, IPv4 IHL displayed correctly, IGMP offset correct

### D. Unknown / partial cases

- `11_igmp_unknown_type.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: unknown/reserved type (`0x99`)
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.251`
  - IGMP group address: `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: unknown IGMP type shown safely, no crash, grouping still uses source + group

- `12_igmpv3_membership_report_minimal.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4(options) / IGMPv3`
  - IGMP message: IGMPv3 Membership Report (`0x22`), minimal zero-record form
  - IPv4 source/destination: `192.0.2.1` -> `239.1.2.3`
  - IGMP group address: not a v1/v2 group field; minimal IGMPv3 report body only
  - IPv4 Router Alert: `yes`
  - Expected behavior: IGMPv3 is recognized safely with partial details; detailed group-record parsing remains deferred

### E. Malformed / truncated cases

- `13_igmp_truncated_header.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / partial IGMP`
  - IGMP message: intended IGMPv2 Membership Report but fewer than 8 bytes are present on wire
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.251`
  - IGMP group address: incomplete/truncated in payload
  - IPv4 Router Alert: `no`
  - Expected behavior: safe unrecognized packet or partial IGMP details with reason such as `IGMP header truncated`

- `14_igmp_snaplen_truncated_header.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: full IGMPv2 Membership Report on original wire, but captured bytes end inside the IGMP header
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.251`
  - IGMP group address: `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: partial IGMP details where safe, capture truncation warning preserved

- `15_igmp_bad_checksum.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4 / IGMP`
  - IGMP message: structurally valid IGMPv2 Membership Report with intentionally wrong checksum
  - IPv4 source/destination: `192.0.2.10` -> `224.0.0.251`
  - IGMP group address: `224.0.0.251`
  - IPv4 Router Alert: `no`
  - Expected behavior: checksum value shown, checksum validation remains deferred, grouping still works

- `16_ipv4_protocol_igmp_no_payload.pcap`
  - Packets: `1`
  - Layer chain: `Ethernet / IPv4`
  - IGMP message: none; IPv4 protocol is `2` but there is no payload after the IPv4 header
  - IPv4 source/destination: `192.0.2.1` -> `224.0.0.1`
  - IGMP group address: none
  - IPv4 Router Alert: `no`
  - Expected behavior: unrecognized packet with reason such as `Missing IGMP payload`, no crash

## Cases that require manual classic pcap writing semantics

The generator writes classic `.pcap` records directly for all fixtures, but these cases specifically rely on manual included-length/original-length control:
- `14_igmp_snaplen_truncated_header.pcap`
  - included/captured length is smaller than original wire length
  - used to model true snaplen truncation inside the IGMP header

These malformed-but-not-snaplen cases only need shorter actual payload bytes and do not require special original-length handling:
- `13_igmp_truncated_header.pcap`
- `16_ipv4_protocol_igmp_no_payload.pcap`

## Expected generated file list

- `01_igmpv1_membership_report_mdns_group.pcap`
- `02_igmpv2_membership_report_mdns_group.pcap`
- `03_igmpv2_leave_group_mdns_group.pcap`
- `04_igmpv2_general_query.pcap`
- `05_igmpv2_group_specific_query.pcap`
- `06_igmp_same_source_group_report_then_leave.pcap`
- `07_igmp_two_sources_same_group.pcap`
- `08_igmp_same_source_two_groups.pcap`
- `09_igmpv2_report_with_router_alert.pcap`
- `10_igmpv2_general_query_with_router_alert.pcap`
- `11_igmp_unknown_type.pcap`
- `12_igmpv3_membership_report_minimal.pcap`
- `13_igmp_truncated_header.pcap`
- `14_igmp_snaplen_truncated_header.pcap`
- `15_igmp_bad_checksum.pcap`
- `16_ipv4_protocol_igmp_no_payload.pcap`

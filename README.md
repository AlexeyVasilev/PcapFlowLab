# Pcap Flow Lab

Flow-centric PCAP analyzer for large network captures.

Pcap Flow Lab is a new open-source C++ project focused on flow-first analysis of packet captures. The current import/decode path supports classic PCAP with Ethernet II frames, up to two VLAN tags, IPv4/IPv6, and TCP/UDP.

## Project status

Architecture bootstrap in progress.

## CLI

Examples:

`pcap-flow-lab summary sample.pcap`

`pcap-flow-lab flows sample.pcap`

`pcap-flow-lab inspect-packet sample.pcap --packet-index 0`

`pcap-flow-lab hex sample.pcap --packet-index 0`

`pcap-flow-lab export-flow sample.pcap --flow-index 0 --out selected-flow.pcap`

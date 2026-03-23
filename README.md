# Pcap Flow Lab

Flow-centric PCAP analyzer for large network captures.

Pcap Flow Lab is a new open-source C++ project focused on flow-first analysis of packet captures. The current import path auto-detects classic PCAP and initial PCAPNG, and the current decode path supports Ethernet II frames, up to two VLAN tags, IPv4/IPv6, and TCP/UDP.

## Project status

Architecture bootstrap in progress.

## CLI

The main read/query commands accept either a capture file or a saved analysis index.

Examples:

`pcap-flow-lab summary sample.pcap`

`pcap-flow-lab summary sample.idx`

`pcap-flow-lab flows sample.pcapng`

`pcap-flow-lab flows sample.idx`

`pcap-flow-lab inspect-packet sample.idx --packet-index 0`

`pcap-flow-lab hex sample.pcapng --packet-index 0`

`pcap-flow-lab export-flow sample.idx --flow-index 0 --out selected-flow.pcap`

`pcap-flow-lab save-index sample.pcapng --out sample.idx`

`pcap-flow-lab load-index-summary sample.idx`

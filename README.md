# Pcap Flow Lab

Flow-centric PCAP analyzer for large network captures.

Pcap Flow Lab is a new open-source C++ project focused on flow-first analysis of packet captures. The current import path auto-detects classic PCAP and initial PCAPNG, and the current decode path supports Ethernet II frames, up to two VLAN tags, ARP, IPv4/IPv6, ICMP, ICMPv6, TCP/UDP, and safe traversal of common IPv6 extension headers.

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

`pcap-flow-lab chunked-import sample.pcap --checkpoint sample.ckp --max-packets 100000`

`pcap-flow-lab resume-import --checkpoint sample.ckp --max-packets 100000`

`pcap-flow-lab finalize-import --checkpoint sample.ckp --out sample.idx`

## Desktop UI

The CLI remains the primary interface today. The Qt Quick desktop UI can already open captures or indexes via native file dialogs, show summary data, show protocol and top-talker statistics on a dedicated Statistics tab, drill down from top endpoints and top ports into the Flow tab by reusing the existing flow filter, browse flows with separate address and port columns plus protocol and service hints when available, apply basic flow filtering and sorting, browse packets for the selected flow, inspect packet details in a Summary view plus a Raw view that combines Hex and transport Payload sub-tabs, and show transport payload length and TCP flags directly in the packet list. The Packet Details structure is also prepared for future protocol-aware decoding.






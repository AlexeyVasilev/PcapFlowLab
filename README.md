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

The CLI remains the primary interface today. A first Qt Quick desktop UI skeleton now exists, and the desktop shell can already open captures or indexes, including via native file dialogs, show summary data, browse flows, apply basic flow filtering and sorting, browse packets for the selected flow, and inspect packet details with a hex dump. Packet browsing and inspection formatting was also cleaned up for better readability.

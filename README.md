# Pcap Flow Lab

Flow-centric PCAP analyzer for large network captures.

Pcap Flow Lab is a new open-source C++ project focused on flow-first analysis of packet captures. The current import path auto-detects classic PCAP and initial PCAPNG, and the current decode path supports Ethernet II frames, Linux cooked captures (SLL and SLL2), up to two VLAN tags, ARP, IPv4/IPv6, ICMP, ICMPv6, TCP/UDP, conservative traversal of common IPv6 extension headers, and always-on IP fragmentation detection as diagnostic metadata.

## Project status

Architecture bootstrap in progress.

## CLI

The main read/query commands accept either a capture file or a saved analysis index.

Examples:

`pcap-flow-lab summary sample.pcap --mode fast`

`pcap-flow-lab summary sample.idx`

`pcap-flow-lab flows sample.pcapng --mode deep`

`pcap-flow-lab flows sample.idx`

`pcap-flow-lab inspect-packet sample.idx --packet-index 0`

`pcap-flow-lab hex sample.pcapng --packet-index 0`

`pcap-flow-lab export-flow sample.idx --flow-index 0 --out selected-flow.pcap`

`pcap-flow-lab save-index sample.pcapng --out sample.idx --mode deep`

`pcap-flow-lab load-index-summary sample.idx`

`pcap-flow-lab chunked-import sample.pcap --checkpoint sample.ckp --max-packets 100000`

`pcap-flow-lab resume-import --checkpoint sample.ckp --max-packets 100000`

`pcap-flow-lab finalize-import --checkpoint sample.ckp --out sample.idx`

## Desktop UI

The CLI remains the primary interface today. The Qt Quick desktop UI can already open captures or analysis indexes via native file dialogs, save the current analysis state back to an index, export the currently selected flow to classic PCAP, choose `Fast` or `Deep` mode when opening captures, show summary data, show protocol and top-talker statistics on a dedicated Statistics tab, drill down from top endpoints and top ports into the Flow tab by reusing the existing flow filter, browse flows with separate address and port columns plus protocol and service hints when available, show fragmented-packet counts in a compact `Frag` flow column with subtle warning highlighting, apply basic flow filtering and sorting, browse packets for the selected flow, switch between a packet-level Packets tab and a higher-level payload-oriented Stream tab for the selected flow, inspect packet details in a Summary view plus a Raw view that combines Hex and transport Payload sub-tabs, and show local packet numbering within the selected flow, packet direction, transport payload length, and TCP flags directly in the packet list, with fragmented packets softly highlighted in the packet list and truncated or IP-fragmented packets grouped in a warning block inside packet details. In Deep mode, the Protocol tab now shows richer single-packet TLS, DNS, HTTP, ARP, ICMP, and ICMPv6 details when they are available. A temporary Settings tab now exposes the first analysis setting: falling back to the HTTP request path as a service hint when the Host header is missing. Analysis indexes can also be opened without the original capture, with explicit index-only UI feedback and a follow-up action to attach the matching source capture later and restore raw packet features. The Packet Details structure is also prepared for future protocol-aware decoding. The current Stream tab is intentionally conservative and does not yet perform full application-message reconstruction. Stream items are selectable and can be inspected through the existing details pane.








Deep mode already exists as a separate import path, but Fast mode remains optimized for quick browsing. Deep mode currently exposes richer TLS, DNS, and HTTP packet-level details in the Protocol tab when they are available from a single packet.















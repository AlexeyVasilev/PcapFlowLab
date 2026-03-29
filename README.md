# Pcap Flow Lab

Flow-centric PCAP analyzer for large network captures.

Pcap Flow Lab is an open-source C++ project focused on flow-first analysis of packet captures. The current import path auto-detects classic PCAP and current PCAPNG support, and the decode path supports Ethernet II, Linux cooked captures (SLL and SLL2), up to two VLAN tags, ARP, IPv4/IPv6, ICMP, ICMPv6, TCP/UDP, conservative traversal of common IPv6 extension headers, and always-on IP fragmentation detection as diagnostic metadata.

## Project status

Usable prototype with flow browsing, packet inspection, saved analysis indexes, and on-demand Stream analysis for selected flows.

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

The Qt Quick desktop UI can:

- open captures and analysis indexes via native file dialogs
- save the current analysis state back to an index
- export the currently selected flow to classic PCAP
- browse flows, packets, protocol statistics, top endpoints, and top ports
- show fragmented packets and flows as diagnostic metadata
- open indexes in explicit index-only mode and attach the matching source capture later
- inspect packet details in Summary, Raw, and Protocol views
- show a payload-oriented Stream tab for the selected flow

### Stream tab

The Stream tab is on-demand, flow-local, and ephemeral.

- It runs only for the currently selected flow.
- It requires source capture access because raw packet bytes are still read lazily from the original capture.
- It does not store stream items in indexes or checkpoints.
- TLS parsing uses bounded directional reassembly, so TLS records spanning multiple TCP packets can appear as one logical stream item when enough bytes are available.
- HTTP parsing uses bounded directional reassembly for complete request/response header blocks.
- This remains heuristic analysis, not full TCP-correct stream reconstruction.

Deep mode remains available as a separate open path for richer packet-level protocol details. Fast mode remains the default browsing path and does not perform global reassembly during open.

## Developer note

Creating `perf-open.enabled` next to the executable or in the current working directory enables append-only open-time CSV logging to `perf_open_log.csv` for `capture_fast`, `capture_deep`, and `index_load` operations. This is intended only for local regression tracking during development and has no effect in normal usage.

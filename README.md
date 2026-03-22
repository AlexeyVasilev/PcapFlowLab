# Pcap Flow Lab

Flow-centric PCAP analyzer for large network captures.

Pcap Flow Lab is a new open-source C++ project focused on flow-first analysis of packet captures. The initial work in this repository establishes the project layout, domain model skeleton, and test baseline for future packet I/O, indexing, decoding, and application layers.

## Project status

Architecture bootstrap in progress.

## CLI

Examples:

`pcap-flow-lab summary sample.pcap`

`pcap-flow-lab flows sample.pcap`

`pcap-flow-lab inspect-packet sample.pcap --packet-index 0`

`pcap-flow-lab hex sample.pcap --packet-index 0`

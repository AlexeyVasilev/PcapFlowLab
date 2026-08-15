# Pcap Flow Lab 0.3.0

Pcap Flow Lab is a flow-based PCAP analyzer.

This archive contains:

- one desktop frontend, identified by the archive filename;
- the `pcap-flow-lab` command-line interface for the same platform;
- required runtime files;
- license information.

Qt packages contain the primary desktop UI. Tauri packages contain the
experimental alternative desktop frontend. Tauri is not guaranteed to match
every Qt workflow perfectly.

## Quick start

1. Launch the desktop application included in the archive.
2. Open a `PCAP` or `PCAPNG` capture.
3. Start with the `Flows` workspace.
4. Select a flow for packet, Stream, or Analysis inspection.

## CLI

```sh
pcap-flow-lab summary capture.pcap
pcap-flow-lab flows capture.pcap --filter TLS --sort bytes:desc
```

## Try the showcase capture

The 0.3.0 release publishes the showcase capture separately as:

- `pcap_flow_lab_showcase.pcap`

You can download it from the `0.3.0` GitHub Release or from the project
repository, then open it directly in the desktop application or use it with the
CLI.

Useful links:

- [Pcap Flow Lab repository](https://github.com/AlexeyVasilev/PcapFlowLab)
- [Pcap Flow Lab releases](https://github.com/AlexeyVasilev/PcapFlowLab/releases)

## Documentation

For product overview, user guides, and source-build information:

- [Pcap Flow Lab repository](https://github.com/AlexeyVasilev/PcapFlowLab)
- [Pcap Flow Lab releases](https://github.com/AlexeyVasilev/PcapFlowLab/releases)

## License

Pcap Flow Lab is licensed under the Apache License 2.0. This archive includes
`LICENSE`.

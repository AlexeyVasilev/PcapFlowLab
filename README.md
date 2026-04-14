# Pcap Flow Lab

Flow-first PCAP analyzer for large network captures.

Pcap Flow Lab is an open-source C++20 project with a CLI and an optional Qt Quick desktop UI. The project is built around three constraints:

- open captures quickly with a packet-oriented fast path
- persist reusable analysis indexes so large captures do not need to be re-imported every time
- keep richer work bounded and selected-flow-only instead of doing global stream reconstruction during open

This is the product direction for the first public release. The goal is not to be a Wireshark replacement. The goal is to be a practical flow-oriented tool that stays useful, predictable, and honest about limits.

## Current status

The project is approaching `v0.1.0` as a first public release.

Today it is already useful for:

- opening PCAP and PCAPNG captures
- browsing flows, packets, top endpoints, top ports, and protocol statistics
- saving and reopening analysis indexes
- opening an index in index-only mode and attaching the source capture later when needed
- selected-flow Analysis views built from metadata only
- selected-flow Stream inspection for practical TCP, TLS, HTTP, and narrow QUIC cases
- conservative handling of imperfect or partially readable captures

The roadmap is still focused on reliability, Stream correctness, bounded analysis, and incremental protocol enrichment rather than broad protocol coverage.

## What the tool supports

Current decode and import support includes:

- classic PCAP and current PCAPNG
- Ethernet II
- Linux cooked captures `SLL` and `SLL2`
- up to two VLAN tags
- ARP
- IPv4 and IPv6
- ICMP and ICMPv6
- TCP and UDP
- conservative traversal of common IPv6 extension headers
- always-on IP fragmentation detection as diagnostic metadata

Current desktop and analysis workflows include:

- fast capture open with non-modal progress and cooperative cancellation
- saved index reopen workflows for large captures
- packet details in Summary, Raw, and Protocol views
- selected-flow Analysis with Sequence Preview, Timeline, Packet Size Histogram, Inter-arrival Histogram, Derived Metrics, Directional Ratio, and Flow Rate graph
- selected-flow Stream with bounded initial materialization and explicit `Load more` continuation for heavy flows
- flow export to classic PCAP
- selected-flow sequence export to CSV from metadata only
- optional weak-hint buckets for `Possible TLS` and `Possible QUIC` on unresolved port 443 flows

## Analysis model

The project is intentionally flow-first and bounded.

- `fast` mode is the default open path and keeps work packet-oriented and predictable.
- `deep` mode remains available as a separate open path for richer packet-level details.
- Indexes store metadata, packet references, and source metadata, but not raw packet bytes.
- Selected-flow Stream and byte-dependent packet details still require source capture access.
- Opening an index without the original capture is supported, but raw-byte features become available only after the matching source capture is attached and validated.

This separation is deliberate. Stream analysis is on-demand, flow-local, and ephemeral.

## Current protocol behavior

The most useful protocol-aware paths today are:

- HTTP request and response header-block recognition with bounded directional reassembly
- TLS record-oriented Stream parsing with bounded directional reassembly
- narrow TLS detail exposure for complete `ClientHello`, `ServerHello`, and `Certificate` cases
- narrow selected-flow QUIC labeling for practical packet-aware cases such as `Initial`, `Handshake`, `Retry`, `Version Negotiation`, `CRYPTO`, `ACK`, and protected payload fallback

## Known limitations

The current release direction explicitly accepts these limits:

- no full TCP-correct stream reconstruction
- no deep TCP recovery after gaps, major reordering, or loss
- Stream results are heuristic and can differ from Wireshark on difficult captures
- retransmission handling is still narrow and currently centered on exact duplicate suppression for selected-flow analysis
- HTTP Stream parsing is focused on header blocks, not full body reconstruction
- QUIC handling is intentionally narrow and does not attempt full session reconstruction or decryption-backed analysis
- packet details remain intentionally shallower than Wireshark
- index and checkpoint loading currently follow an exact-version policy

If the core workflows are solid and these limits are made explicit, the tool is behaving as intended.

## Build

Requirements:

- CMake `3.24+`
- a C++20 compiler
- Qt `6.8+` with `Quick`, `Qml`, `QuickControls2`, and `Widgets` for the desktop UI

The CLI and core library can build without Qt. If Qt 6 is not found, the UI target is skipped.

Example configure and build steps:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

If `BUILD_TESTING` is enabled, the repository defines:

- `pcap_flow_lab_core_tests`
- `pcap_flow_lab_ui_tests` when the Qt UI target is available

Example test command:

```sh
ctest --test-dir build --output-on-failure --build-config Release
```

## Run

CLI examples:

```sh
pcap-flow-lab summary sample.pcap --mode fast
pcap-flow-lab flows sample.pcapng --mode deep
pcap-flow-lab summary sample.idx
pcap-flow-lab inspect-packet sample.idx --packet-index 0
pcap-flow-lab export-flow sample.idx --flow-index 0 --out selected-flow.pcap
pcap-flow-lab save-index sample.pcapng --out sample.idx --mode deep
pcap-flow-lab load-index-summary sample.idx
pcap-flow-lab chunked-import sample.pcap --checkpoint sample.ckp --max-packets 100000
pcap-flow-lab resume-import --checkpoint sample.ckp --max-packets 100000
pcap-flow-lab finalize-import --checkpoint sample.ckp --out sample.idx
```

If the Qt UI target is built, run:

```sh
pcap-flow-lab-ui
```

## Platform note

The repository currently shows an actively used Windows workflow, and some code paths are Windows-specific. Treat broader platform support as best-effort unless a release note explicitly says a platform or workflow was checked for that release.

## Repository guide

Key documents:

- [docs/architecture.md](docs/architecture.md): architecture, persistence boundaries, and runtime paths
- [docs/current-state.md](docs/current-state.md): implemented behavior and current gaps
- [docs/roadmap.md](docs/roadmap.md): practical engineering roadmap
- [docs/release-checklist-v0.1.0.md](docs/release-checklist-v0.1.0.md): first public release readiness checklist
- [docs/contributing.md](docs/contributing.md): contribution expectations

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## Developer note

Creating `perf-open.enabled` next to the executable or in the current working directory enables append-only open-time CSV logging to `perf_open_log.csv` for `capture_fast`, `capture_deep`, and `index_load` operations. This is developer-only instrumentation for local regression tracking and has no effect in normal usage.










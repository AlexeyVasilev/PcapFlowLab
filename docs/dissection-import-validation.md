# Unified Import Validation

Date: 2026-07-22
Branch: `feature/unified-packet-dissection`

This document describes the developer-only validation executable used to compare
legacy import against unified shadow import on arbitrary local captures.

Production runtime import remains legacy `PacketDecoder`.

## Tool

Developer executable:

- `pcap_flow_lab_import_validation`

Supported modes:

- `compare <capture>`
- `diagnose <capture>`
- `legacy <capture>`
- `unified <capture>`

Supported formats:

- classic PCAP
- PCAPNG

Useful options:

- `--max-packets N`
- `--packet-index N`
- `--max-mismatches N`
- `--no-hints`
- `--json <output-file>`

`--no-hints` disables hint comparison in the canonical snapshot. It does not
change import semantics, parser behavior, or production-style hint execution.

## Commands

Windows PowerShell:

```powershell
.\build\pcap_flow_lab_import_validation.exe compare .\path\to\capture.pcap
.\build\pcap_flow_lab_import_validation.exe diagnose .\path\to\capture.pcap
.\build\pcap_flow_lab_import_validation.exe legacy .\path\to\capture.pcap
.\build\pcap_flow_lab_import_validation.exe unified .\path\to\capture.pcap
.\build\pcap_flow_lab_import_validation.exe compare .\path\to\capture.pcap --json .\validation.json
.\build\pcap_flow_lab_import_validation.exe diagnose .\path\to\capture.pcap --packet-index 3876
```

Linux shell:

```bash
./build/pcap_flow_lab_import_validation compare ./path/to/capture.pcap
./build/pcap_flow_lab_import_validation diagnose ./path/to/capture.pcap
./build/pcap_flow_lab_import_validation legacy ./path/to/capture.pcap
./build/pcap_flow_lab_import_validation unified ./path/to/capture.pcap
./build/pcap_flow_lab_import_validation compare ./path/to/capture.pcap --json ./validation.json
./build/pcap_flow_lab_import_validation diagnose ./path/to/capture.pcap --packet-index 3876
```

For peak-memory comparison, run `legacy` and `unified` as separate processes.
That is the intended measurement mode.

## Compare Mode

`compare` runs legacy import and unified import sequentially on the same
capture, builds deterministic canonical snapshots, releases the first import
state, then compares:

- capture summary accounting;
- connection grouping;
- flow grouping;
- structural protocol-path registry contents;
- `PacketRef` contents and per-flow packet order;
- unrecognized packet records and reason text;
- persisted hint state when hint comparison is enabled.

Structural comparison uses resolved `ProtocolPath` values rather than raw
`protocol_path_id`. Registry reporting now separates:

- structural added/removed paths;
- shared structural paths;
- numeric ID drift caused by a real import-order difference.

Peak memory is intentionally not compared in `compare` mode because both paths
run in the same process.

## Diagnose Mode

`diagnose` keeps the existing whole-session comparison as the final parity
oracle, but adds packet-level attribution so session-level cascades can be
reduced to their primary causes.

It compares per-packet legacy and unified import observations before flow and
registry grouping hides the original source of divergence.

Packet-level mismatch categories include:

- classification;
- address family;
- addresses;
- ports;
- protocol;
- captured transport payload length;
- TCP flags;
- fragmentation;
- structural physical path;
- parse status;
- stop reason;
- unrecognized reason.

Repeated packet-level mismatches are grouped by a stable structural signature.
This is intended to collapse recurring patterns such as repeated
payload-length deltas into a single grouped diagnostic.

`diagnose <capture> --packet-index N` prints exactly one packet's legacy and
unified observations and does not require locating the packet through the UI.

`--max-mismatches N` bounds stored mismatch rows and grouped signatures in both
`compare` and `diagnose` output.

## Single-Mode Metrics

`legacy` and `unified` each report:

- file size;
- packet count;
- captured bytes;
- flow count;
- connection count;
- unrecognized count;
- protocol-path registry size;
- elapsed wall-clock time;
- packets per second;
- MiB per second;
- peak process memory when supported by platform APIs.

Timing is end-to-end import timing, including capture opening and capture
reading.

Peak memory:

- Windows: process peak working set
- Linux: `getrusage(RUSAGE_SELF)` normalized to bytes
- unsupported platforms: reported as unavailable without failing validation

## Recommended Validation Corpus

Run all three commands on a representative local corpus:

- small mixed-protocol capture
- large TCP-heavy capture
- large UDP-heavy capture
- overlay-heavy capture
- fragment-heavy capture
- malformed/truncated capture
- representative 10+ GB capture
- largest locally available capture

Do not commit private capture paths.

For each capture, record:

- capture size
- packet count
- parity result
- legacy elapsed time
- unified elapsed time
- legacy packets/s
- unified packets/s
- legacy MiB/s
- unified MiB/s
- legacy peak memory
- unified peak memory

## Provisional Acceptance Criteria

Correctness:

- zero structural mismatches on the selected real-capture corpus
- zero committed fixture-session parity regressions
- no additional unrecognized packets
- identical structural protocol-path registry contents
- identical persisted `PacketRef` facts
- identical persisted hints when hint comparison is enabled

Performance:

- measure first, then review deltas
- investigate if unified import is more than approximately 5-10% slower on representative large captures
- investigate any material peak-memory increase on representative large captures

These are review thresholds, not automatic pass/fail gates.

## Current Status

Implemented:

- developer-only validation executable
- sequential legacy-versus-unified comparison core
- packet-level diagnose mode with grouped mismatch attribution
- classic-PCAP staged-prefix parity coverage
- PCAPNG validation coverage

Still pending before any production cutover claim:

- real-capture validation runs
- review of measured throughput and peak-memory deltas
- explicit production import cutover change

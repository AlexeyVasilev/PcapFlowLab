# Pcap Flow Lab 0.4.0

Pcap Flow Lab 0.4.0 is the next release after the published `v0.3.0` tag. It
keeps the same positioning: **a flow-based PCAP analyzer** that complements
Wireshark rather than replacing deep packet-by-packet dissection.

This release focuses on structured flow filtering, broader whole-capture
Statistics, reusable report output, newer index metadata, expanded protocol
recognition, ERF Ethernet capture input, and parity hardening across Qt, Tauri,
and CLI.

## Highlights Since v0.3.0

- Structured Advanced Flow Filter workflows across the shared backend, Qt,
  Tauri, CLI, and reusable `.filter` documents.
- Expanded capture/index-wide Statistics, including richer packet and flow
  distributions, IP fragmentation, Protocol Path statistics, protocol hints,
  QUIC/TLS summaries, top flows, endpoints, and ports.
- Whole-session Statistics report export as HTML or Markdown from desktop and
  CLI.
- Stable revision-19 indexes with persisted Statistics/import provenance and
  metadata-backed reopen workflows.
- Expanded recognition for application protocols such as MQTT, AMQP, NTP, and
  mail-protocol hints, with support depth documented explicitly.
- ERF Ethernet capture/link-layer input support for classic PCAP and PCAPNG
  `LINKTYPE_ERF` captures.
- CLI documentation and examples refreshed against the current showcase,
  including Advanced Filter, Statistics export, per-Flow export, and
  unrecognized-packet export workflows.
- Runtime and selected-flow hardening for byte ownership, Packet Details,
  Stream Item Data, QUIC/TLS presentation, and malformed/truncated input.

## Advanced Flow Filter

0.4.0 adds a structured Advanced Flow Filter workflow on top of the existing
flow model. Users can combine protocol, endpoint, service, time, traffic,
Protocol Path, and contained-layer predicates, then save and reopen those
filters as `.filter` documents.

The parser, formatter, compiler, evaluator, Qt editor, Tauri editor, CLI
integration, and Smart Export path now share the same backend semantics.

## Statistics and Reports

Statistics is substantially broader than in the released `v0.3.0` baseline.
Current Statistics includes representative areas such as:

- capture overview and capture time
- transport and IP-family summary
- Unrecognized Packets tracking
- packet size distribution
- flows by packet count, duration, and data size
- IP fragmentation
- Protocol Path tree/statistics
- detected protocol hints
- capture metrics and flow characteristics
- direction distribution and TCP flags
- QUIC and TLS summaries
- top flows by original bytes
- top endpoints and ports

Statistics can also be exported as complete whole-session reports:

- desktop: `Statistics -> Export Statistics as HTML...` and
  `Statistics -> Export Statistics as Markdown...`
- CLI: `summary --out-statistics-html <path>` and
  `summary --out-statistics-markdown <path>`

The report path uses the shared Statistics/report model and is available for
raw captures and compatible indexes.

## CLI and Export

The public CLI command set remains:

- `summary`
- `flows`
- `export-flows`
- `flow-info`
- `packet-info`

0.4.0 expands the documented CLI workflows around raw captures and compatible
indexes, filtering and sorting, `flows --adv-filter`, Statistics HTML/Markdown
report export through `summary`, per-Flow export, and unrecognized-packet
export.

Each prebuilt desktop archive also includes the `pcap-flow-lab` CLI and a short
package-oriented `README.md`.

## Protocol and Capture Support

Protocol support remains intentionally explicit about depth. Recognition, flow
identity, selected-packet Summary, Stream semantics, Service hints, and byte
views are not identical for every protocol family.

Notable post-`v0.3.0` additions and expansions include recognition-oriented
support for MQTT, AMQP, SSH, BitTorrent, SMTP, POP3, and IMAP, structured
selected-packet coverage for NTP, STUN, and DHCPv4, plus continued hardening
for TLS, QUIC, DNS/mDNS, HTTP, overlays, and encapsulation handling.

MQTT, AMQP, mail protocols, SSH, and BitTorrent remain recognition-oriented
unless the current protocol catalog states deeper support. NTP, STUN, and
DHCPv4 now have selected-packet Summary/Bytes support. DHCPv4 also adds
packet-local DHCP Stream rows with selected Stream Summary/Data backed by the
terminal UDP payload as `DHCP Message`. DHCP transaction reconstruction,
XID/session modeling, and lease-state tracking remain out of scope. Do not
infer full selected-packet or Stream parsing from recognition alone.

ERF Ethernet support is capture/link-layer input support, not an application
protocol. The first supported scope is deliberately narrow: `LINKTYPE_ERF`
records carrying Ethernet traffic, including the PCAPNG ERF case.

For the authoritative protocol capability matrix, see:

- [`docs/protocols/protocol_support.md`](protocols/protocol_support.md)

## Index Compatibility

The application release version is `0.4.0`; the current stable index revision
is still `19`.

Pcap Flow Lab uses exact-version index loading. Revision 18 and older full
indexes require rebuild from the original PCAP or PCAPNG for full load. When an
older index is rejected, rebuild it from the source capture rather than
expecting automatic migration.

Indexes are metadata-backed. Byte-backed inspection, Stream reconstruction, and
packet-writing export still require readable source capture bytes where those
features need packet data.

## Showcase Capture

The versioned showcase capture:

- [`examples/showcase/pcap_flow_lab_showcase.pcap`](../examples/showcase/pcap_flow_lab_showcase.pcap)

has been expanded to exercise current 0.4.0 scenarios, including Advanced Flow
Filter, Statistics, Protocol Path identity, tunnels, recognition-only
protocols, Stream inspection, and edge cases.

Suggested scenarios and stable scenario IDs are documented in:

- [`examples/showcase/README.md`](../examples/showcase/README.md)

## Platform Availability

Pcap Flow Lab 0.4.0 is planned to publish four prebuilt application archives:

- `PcapFlowLab-0.4.0-windows-x64-qt.zip`
- `PcapFlowLab-0.4.0-windows-x64-tauri.zip`
- `PcapFlowLab-0.4.0-ubuntu-x64-qt.tar.gz`
- `PcapFlowLab-0.4.0-ubuntu-x64-tauri.tar.gz`

In addition, the release publishes one separate sample asset:

- `pcap_flow_lab_showcase.pcap`

Windows and Ubuntu have prebuilt Qt and Tauri applications. Qt remains the
primary desktop UI. Tauri remains an experimental alternative frontend over the
shared backend model.

macOS is source-build-only for this release. Linux distributions other than the
published Ubuntu target are source-build-only.

Release artifacts remain manually assembled and manually verified.

## Current Limitations

- Pcap Flow Lab does not provide full TCP recovery or reassembly under adverse
  capture conditions.
- Selected-flow Stream inspection is bounded and practical rather than a full
  forensic TCP/session reconstruction engine.
- QUIC inspection does not attempt complete session reconstruction or general
  application-data decryption.
- Tauri remains experimental and is not guaranteed to match every Qt workflow
  perfectly.
- Protocol support depth varies by protocol and should be read from the
  protocol-support catalog rather than inferred from a detection label.
- Packet-detail breadth remains intentionally below Wireshark.
- Malformed and truncated data is handled conservatively.

## Download / Source-Build Guidance

Release assets will be published through the GitHub release page for `v0.4.0`.
Users who need source-build instructions can use:

- [`README.md`](../README.md)
- [`user_docs/build-from-source.md`](../user_docs/build-from-source.md)

## Suggested GitHub Release Summary

Pcap Flow Lab 0.4.0 is the next release after `v0.3.0`. It adds structured
Advanced Flow Filter workflows, expanded capture/index-wide Statistics with
HTML/Markdown report export, revision-19 index metadata/provenance,
recognition for more application protocols, ERF Ethernet capture input, a
refreshed CLI/export workflow set, and the current showcase capture. Pcap Flow
Lab remains a flow-based PCAP analyzer that complements Wireshark and stays
explicit about bounded Stream behavior, protocol-support depth, and QUIC/TLS
limits.

## Repository Metadata Suggestion

Recommended repository description:

Flow-based PCAP analyzer with protocol-aware Stream inspection, Analysis,
Statistics, reusable indexes, and CLI.

Recommended GitHub topics:

- pcap
- pcapng
- packet-analysis
- network-analysis
- network-forensics
- qt
- qt-quick
- qml
- cpp
- cmake
- traffic-analysis

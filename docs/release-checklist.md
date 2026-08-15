# Release Checklist

## 1. Release goal

Pcap Flow Lab 0.3.0 should publish the project as a practical flow-based PCAP
analyzer with:

- flow-based exploration
- Protocol Path-aware identity and presentation
- structured Packet Details `Summary` / `Bytes`
- bounded selected-flow Stream inspection
- selected-flow Analysis
- capture/index-wide Statistics
- reusable indexes
- modern CLI and practical export workflows

The release should be honest about scope and limits. It should not present
Pcap Flow Lab as a Wireshark replacement, a full TCP recovery engine, or a
universal protocol-forensics suite.

## 2. Planned release artifacts

All four planned application archives must be treated as independent release
targets:

- [ ] `PcapFlowLab-0.3.0-windows-x64-qt.zip`
- [ ] `PcapFlowLab-0.3.0-windows-x64-tauri.zip`
- [ ] `PcapFlowLab-0.3.0-ubuntu-x64-qt.tar.gz`
- [ ] `PcapFlowLab-0.3.0-ubuntu-x64-tauri.tar.gz`
- [ ] `pcap_flow_lab_showcase.pcap`

Release artifacts are manually assembled and manually verified.

## 3. Core product checks

- [ ] Open representative PCAP and PCAPNG captures successfully.
- [ ] Save an index successfully.
- [ ] Reopen a saved index successfully.
- [ ] Index-only open plus later source-capture attach behaves clearly and
      honestly.
- [ ] Selected packet `Summary` works on representative normal traffic.
- [ ] Selected packet `Bytes` works on representative normal traffic.
- [ ] Selected-flow Stream is useful on representative supported flows.
- [ ] Selected-flow Analysis is useful on representative supported flows.
- [ ] Statistics opens and the major sections populate correctly.
- [ ] Protocol Path tree can be opened and is usable on representative
      identity-bearing traffic.
- [ ] Normal export workflow is usable where supported.
- [ ] Partial, malformed, and truncated data still behaves conservatively.

## 4. Preferred deterministic smoke input

- [ ] Use the showcase capture as the preferred deterministic smoke input:
      [`examples/showcase/pcap_flow_lab_showcase.pcap`](../examples/showcase/pcap_flow_lab_showcase.pcap)
- [ ] Use the showcase guide for suggested scenarios:
      [`examples/showcase/README.md`](../examples/showcase/README.md)
- [ ] Representative real captures may still be used for additional large-file
      or broader coverage checks.

## 5. Windows Qt smoke checks

- [ ] Application launches normally.
- [ ] Showcase capture opens successfully.
- [ ] Flows workspace is usable.
- [ ] Selected packet `Summary` and `Bytes` work.
- [ ] Stream works on a representative supported flow.
- [ ] Analysis works on a representative selected flow.
- [ ] Statistics works on the opened capture.
- [ ] Protocol Path tree can be opened.
- [ ] Normal export and index workflow is usable where supported.

## 6. Windows Tauri smoke checks

- [ ] Application launches normally.
- [ ] Showcase capture opens successfully.
- [ ] Flows workspace is usable.
- [ ] Selected packet `Summary` and `Bytes` work.
- [ ] Stream works on a representative supported flow.
- [ ] Analysis works on a representative selected flow.
- [ ] Statistics works on the opened capture.
- [ ] Protocol Path tree can be opened.
- [ ] Normal export and index workflow is usable where supported.

## 7. Ubuntu Qt smoke checks

- [ ] Application launches normally.
- [ ] Showcase capture opens successfully.
- [ ] Flows workspace is usable.
- [ ] Selected packet `Summary` and `Bytes` work.
- [ ] Stream works on a representative supported flow.
- [ ] Analysis works on a representative selected flow.
- [ ] Statistics works on the opened capture.
- [ ] Protocol Path tree can be opened.
- [ ] Normal export and index workflow is usable where supported.

## 8. Ubuntu Tauri smoke checks

- [ ] Application launches normally.
- [ ] Showcase capture opens successfully.
- [ ] Flows workspace is usable.
- [ ] Selected packet `Summary` and `Bytes` work.
- [ ] Stream works on a representative supported flow.
- [ ] Analysis works on a representative selected flow.
- [ ] Statistics works on the opened capture.
- [ ] Protocol Path tree can be opened.
- [ ] Normal export and index workflow is usable where supported.

## 9. CLI checks

- [ ] CLI build status is known for the exact release commit.
- [ ] `summary` works on a representative PCAP input.
- [ ] `flows` works on a representative PCAP or index input.
- [ ] `flow-info` works on a representative selected flow.
- [ ] `packet-info` works on a representative packet.
- [ ] `export-flows` works on a representative export scenario.
- [ ] CLI behavior is checked from at least the release source/build
      environment.

## 10. Index compatibility checks

- [ ] Current index save and reopen workflow works on the release commit.
- [ ] Index-only reopen plus later source attach is checked where appropriate.
- [ ] An unsupported older index fails clearly.
- [ ] Rebuild-required behavior is explicit when an older index version is
      rejected.
- [ ] Older incompatible indexes are not silently accepted.

## 11. Platform wording and release-facing docs

- [ ] Release-facing docs describe Pcap Flow Lab as flow-based, not
      packet-based-first or large-capture-only.
- [ ] Release-facing docs describe Wireshark constructively as a complementary
      packet-based analyzer rather than a replacement target.
- [ ] Packet Details wording is current: `Summary` / `Bytes`.
- [ ] Stream Item Details wording is current: `Summary` / `Item Data`.
- [ ] Release-facing docs describe all four planned application archives.
- [ ] No changed release-facing doc still describes 0.3.0 as one Windows
      archive or conditional Ubuntu binaries.
- [ ] Index compatibility wording is present and user-facing.
- [ ] Showcase links and source-build links resolve.

## 12. Archive and package review

- [ ] Each archive opens into one clean top-level directory.
- [ ] Each archive contains the intended frontend executable/application, the
      same-platform `pcap-flow-lab` CLI, and the runtime files it needs.
- [ ] No archive contains tests, debug outputs, build logs, temporary files, or
      unrelated development artifacts.
- [ ] `README.md` copied from `docs/release-package-readme.md` is included in
      each manually prepared release bundle.
- [ ] `LICENSE` is included in each manually prepared release bundle unless a
      different established packaging rule is documented.
- [ ] The root GitHub `README.md` is not copied unchanged into release
      archives.
- [ ] The correct frontend is present in each archive.
- [ ] No wrong-platform CLI or frontend was copied into any archive.

## 13. Release metadata and checksums

- [ ] `SHA256SUMS.txt` is generated only after the final four archives and the
      standalone showcase asset are frozen.
- [ ] `SHA256SUMS.txt` matches all four application archives and
      `pcap_flow_lab_showcase.pcap`.

## 14. Release notes and metadata

- [ ] Release notes describe the actual 0.3.0 scope rather than an older
      pre-0.3 draft.
- [ ] Repository description matches the approved flow-based positioning.
- [ ] Topic recommendations avoid misleading replacement framing such as
      `wireshark-alternative`.

## 15. Final go/no-go

- [ ] The core promise is true: useful flow-based exploration with practical
      packet, Stream, Analysis, Statistics, index, CLI, and export workflows.
- [ ] The release is honest about current limits around TCP recovery, bounded
      Stream reconstruction, QUIC scope, and experimental Tauri status.
- [ ] The release repo and assets are fit for public publication.

# Release Checklist v0.1.0

## 1. Release goal

v0.1.0 should be a usable first public release of Pcap Flow Lab as a flow-oriented PCAP analysis tool.

It should prove that the project already delivers practical value for real captures through:

- fast capture open and index-based reopen workflows
- bounded, selected-flow on-demand analysis
- useful TCP, TLS, HTTP, and meaningful bounded QUIC selected-flow inspection
- conservative behavior when captures are incomplete, malformed, or imperfect

v0.1.0 is not trying to be:

- a Wireshark replacement
- a full protocol forensics suite
- a full TCP recovery and reassembly engine under adverse capture conditions
- a "supports everything" release with broad semantic guarantees for every malformed trace

If the core workflows are solid, understandable, and honest about limits, release it.

## 2. Must-be-working before release

- [ ] Open representative PCAP and PCAPNG captures from the UI without obvious instability.
- [ ] Save an analysis index and reopen it successfully.
- [ ] Open an index in index-only mode and attach the source capture when needed.
- [ ] Opening an index without source capture remains understandable, and source-attach or restricted-state messaging is honest and clear.
- [ ] Selected-flow analysis works on representative TCP and UDP cases.
- [ ] Stream view is useful on supported TCP/TLS/HTTP cases, including bounded request/response reconstruction where enough bytes are available.
- [ ] QUIC selected-flow inspection is useful on known supported cases, including bounded frame-level and handshake-aware details, and falls back conservatively otherwise.
- [ ] `Load more` works correctly for selected-flow packet lists and Stream lists on heavy flows.
- [ ] Large-file workflows are usable enough for the intended first release: open progress is visible, cancellation works, and common browsing actions remain responsive.
- [ ] Wireshark filter helper / integration helper is present and works for normal cases.
- [ ] Common actions do not cause obvious UI freezes or stale/broken state transitions.
- [ ] Partial/imperfect capture handling stays conservative and does not pretend to know more than the data supports.
- [ ] Core public docs exist and are minimally coherent: README, build/run instructions, current state, architecture notes, and this release checklist.

## 3. Acceptable known limitations for v0.1.0

These are acceptable for the first public release if they are documented and the working paths are solid.

- No deep TCP recovery after gaps, loss, or major disorder.
- Conservative fallback after directional gaps or incomplete payload history.
- Selected-flow analysis remains bounded and on-demand rather than globally precomputed.
- Not all malformed or imperfect captures will produce ideal semantic Stream splits.
- QUIC handling remains bounded and non-session-complete even though selected-flow inspection can expose meaningful frame-level and handshake-aware details.
- Retransmitted packets can be suppressed in the current selected-flow Stream model without implying full TCP-correct recovery.
- Packet Details depth is intentionally below Wireshark.
- Stream results are heuristic and practical, not full protocol-correct reconstruction under all edge cases.
- Partial-open captures may remain restricted, including limits on saving back to index where appropriate.

## 4. Manual pre-release checks

- [ ] Local build status is known and recorded for the exact commit intended for `v0.1.0`.
- [ ] Test status is known and recorded manually, including any intentionally accepted failures or gaps.
- [ ] README first screen has been reviewed for clarity and honesty.
- [ ] Screenshots are current enough to match the actual UI.
- [ ] Version string, tag name, and short release notes are prepared.
- [ ] Release notes explicitly describe the release as a manual `v0.1.0` publication rather than an automated multi-platform packaging pipeline.
- [ ] License file is present and correct.
- [ ] No private paths, local machine artifacts, credentials, or sensitive sample data are accidentally tracked in the repo or docs.
- [ ] No accidentally tracked large artifacts, temporary captures, local outputs, or unnecessary binary files remain in the repo, and `.gitignore` plus release-facing repo contents have been reviewed before publication.
- [ ] Any optional demo captures, screenshots, or release assets are safe to publish.

## 5. Public repo readiness

- [ ] Repository description clearly says what the project is.
- [ ] README quickly explains who the tool is for, what it does well, and what it does not try to do.
- [ ] Build/install instructions are sufficient for an engineer to get started without guessing.
- [ ] Basic usage examples exist for opening captures, opening indexes, and selected-flow inspection.
- [ ] Screenshot set is good enough to show the main workflows.
- [ ] README or release notes make clear which platforms and workflows were actually checked for `v0.1.0`.
- [ ] README or release notes make clear that Windows is the primary prebuilt artifact target, Ubuntu binaries are conditional on manual verification, and macOS is source-build-only for `v0.1.0`.
- [ ] Current-state and architecture docs make the project's maturity and direction obvious.

## 6. Nice-to-have but not blocking

- [ ] Small README wording cleanup.
- [ ] One or two better screenshots.
- [ ] Minor UI text polish where current labels are obviously rough.
- [ ] Small doc fixes for consistency across README and current-state notes.
- [ ] A short known-limitations section in release notes.

Do not delay release for broad cleanup work.

## 7. Release artifacts

- [ ] Annotated git tag for `v0.1.0`.
- [ ] Public release notes.
- [ ] Release notes include a short known-limitations section.
- [ ] Screenshot set used in the README and/or release page.
- [ ] Windows prebuilt UI zip archive is prepared and named clearly.
- [ ] Windows archive contents were reviewed manually to avoid shipping tests, debug-only outputs, or unrelated build artifacts.
- [ ] Ubuntu prebuilt archive is published only if it was manually built and manually verified for this release; otherwise Ubuntu is described as source-build-only for `v0.1.0`.
- [ ] macOS is described as source-build-only for `v0.1.0`.
- [ ] Optional demo capture or index assets if they are safe, small, and genuinely useful.

## 8. Manual publish pass

- [ ] Release title and tag text match `v0.1.0` exactly.
- [ ] Release description uses the same platform wording as the README.
- [ ] Attached artifact names are short and predictable.
- [ ] The Windows archive opens into one clean top-level folder.
- [ ] The Windows archive includes the main UI executable and the runtime files it needs, but not tests or local build clutter.
- [ ] If Ubuntu is not attached as a verified binary, the release page says source-build-only instead of implying a missing artifact.
- [ ] The release page says clearly that Pcap Flow Lab is flow-first, bounded, and not a Wireshark replacement.

## 9. Final go/no-go list

- [ ] The core promise is true: fast open/index workflows plus useful selected-flow analysis.
- [ ] The supported TCP/TLS/HTTP workflows are practically useful.
- [ ] QUIC support is honest about being meaningful but bounded and conservative.
- [ ] Large captures are usable enough for normal exploratory work.
- [ ] The UI feels stable on common workflows.
- [ ] The docs tell the truth about scope, strengths, and limitations.
- [ ] Nothing obviously embarrassing remains in the public repo.

If every item above is not perfect but the core workflow is solid, limitations are explicit, and the repo is fit for public viewing, ship v0.1.0.
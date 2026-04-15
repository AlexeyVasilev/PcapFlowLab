# Manual Release Publish Checklist v0.1.0

Use this as the final compact pass before publishing the GitHub release.

## Product and version checks

- [ ] The intended release commit is final.
- [ ] The git tag is exactly `v0.1.0`.
- [ ] The visible application version string is `0.1.0`.
- [ ] The About dialog shows `0.1.0`.

## Basic Windows release verification

- [ ] The Windows UI executable launches normally.
- [ ] The Windows UI does not open an attached console window.
- [ ] A representative sample capture can be opened successfully.
- [ ] Flow browsing, selected-flow Analysis, and selected-flow Stream all work on a normal sample case.

## Release-facing docs and screenshots

- [ ] README platform wording matches the actual artifacts being published.
- [ ] Release notes platform wording matches the actual artifacts being published.
- [ ] Screenshots are current enough to match the visible UI.
- [ ] The release notes still describe the tool as flow-first, bounded, and not a Wireshark replacement.

## Archive review

- [ ] The Windows release archive name is clear and versioned.
- [ ] The archive opens into one clean top-level folder.
- [ ] The archive contains the main UI executable and required runtime files only.
- [ ] The archive does not contain tests, debug-only outputs, local logs, or unrelated build artifacts.
- [ ] LICENSE is present in the release bundle or clearly reachable from the release page.

## Platform wording check

- [ ] Windows is described as having a prebuilt archive.
- [ ] Ubuntu is described as having a prebuilt archive only if one was manually built and manually verified; otherwise it is described as source-build-only.
- [ ] macOS is described as source-build-only for `v0.1.0`.

## GitHub release page check

- [ ] The release title and tag match `v0.1.0`.
- [ ] The release body uses the prepared draft notes.
- [ ] Attached files match the wording in the release body.
- [ ] The release page does not imply automated packaging or broader platform guarantees than were actually verified.
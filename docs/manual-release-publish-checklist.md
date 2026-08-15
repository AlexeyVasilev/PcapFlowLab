# Manual Release Publish Checklist

Use this as the compact publication-day pass for the actual GitHub release.

## Version and tag

- [ ] Release version is exactly `0.3.0`.
- [ ] Git tag is exactly `0.3.0`.
- [ ] Visible application version string matches `0.3.0`.

## Planned archives

- [ ] `PcapFlowLab-0.3.0-windows-x64-qt.zip` exists.
- [ ] `PcapFlowLab-0.3.0-windows-x64-tauri.zip` exists.
- [ ] `PcapFlowLab-0.3.0-ubuntu-x64-qt.tar.gz` exists.
- [ ] `PcapFlowLab-0.3.0-ubuntu-x64-tauri.tar.gz` exists.
- [ ] All four archive names match the agreed names exactly.

## Smoke verification status

- [ ] Windows Qt smoke check complete.
- [ ] Windows Tauri smoke check complete.
- [ ] Ubuntu Qt smoke check complete.
- [ ] Ubuntu Tauri smoke check complete.

## Release-facing wording

- [ ] README platform wording matches the attached assets.
- [ ] Release notes platform wording matches the attached assets.
- [ ] Older-index compatibility wording is present and clear.
- [ ] Packet Details wording is current: `Summary` / `Bytes`.
- [ ] Stream Item Details wording is current: `Summary` / `Item Data`.

## Package-content checks

- [ ] LICENSE and package-content checks passed.
- [ ] Each archive has one clean top-level directory.
- [ ] No unpublished, extra, debug, test, log, or temporary artifacts are
      attached.
- [ ] Pre-packaging decision about CLI inclusion in desktop archives is
      completed and documented.
- [ ] Pre-packaging decision about whether archive users get the root README or
      a short release-specific README copy is completed and documented.

## Links and guides

- [ ] Showcase guide link works:
      [`examples/showcase/README.md`](../examples/showcase/README.md)
- [ ] Source-build guide link works:
      [`user_docs/build-from-source.md`](../user_docs/build-from-source.md)

## GitHub release page

- [ ] GitHub Release title is correct.
- [ ] GitHub Release body is correct.
- [ ] Attached files match the release body exactly.
- [ ] No unpublished or unintended artifact is attached.

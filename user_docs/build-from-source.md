# Build Pcap Flow Lab from source

Prebuilt application archives are normally the easiest way to start with Pcap
Flow Lab 0.3.0 on Windows and Ubuntu. This guide is for source builds.

Pcap Flow Lab currently has two desktop frontends over the same backend:

- the primary Qt desktop application;
- the experimental Tauri desktop application.

The CLI and shared core library use the CMake build.

## Choose what to build

You can build Pcap Flow Lab in three main ways:

- `Qt desktop application`
  The primary desktop UI, built through CMake with Qt 6.8 or newer.
- `Tauri desktop application`
  The experimental alternative desktop frontend under
  `experimental/tauri-ui-spike/src-tauri`.
- `CLI/core only`
  The shared backend and `pcap-flow-lab` executable without the Qt UI.

## Common requirements

All source-build paths start with:

- Git
- CMake 3.24 or newer
- a C++20-capable compiler

Exact native dependencies differ by platform and by frontend.

## Qt installation

For the Qt desktop application, install Qt 6.8 or newer with the modules
currently used by Pcap Flow Lab:

- `Quick`
- `Qml`
- `QuickControls2`
- `Widgets`

An official Qt 6.8.x installation is the simplest path. You can either:

- invoke Qt's `qt-cmake`; or
- use normal CMake with Qt discoverable through `CMAKE_PREFIX_PATH`.

The detailed Qt examples below prefer `qt-cmake` so users do not need to guess
the Qt CMake prefix.

## Windows

### Windows - Qt

Recommended path:

- Windows 10 or Windows 11
- Microsoft C++ Build Tools or Visual Studio 2022 C++ tools
- Qt 6.8+ MSVC 2022 x64 kit
- CMake 3.24+

Other Qt-supported compiler kits may work, but this guide uses MSVC 2022 for a
simple consistent Windows path.

Use your real Qt installation path in place of `6.8.x`:

```powershell
& "C:\Qt\6.8.x\msvc2022_64\bin\qt-cmake.bat" -S . -B build-qt
cmake --build build-qt --config Release
```

Expected user-facing outputs include:

- `pcap-flow-lab-ui`
- `pcap-flow-lab`

The exact output directory depends on the CMake generator.

### Windows - Tauri

The intended Windows Tauri path uses the default MSVC Rust toolchain.

Prerequisites:

- Microsoft C++ Build Tools
- `Desktop development with C++`
- Microsoft Edge WebView2 Runtime
- Rust via `rustup`
- stable MSVC Rust toolchain
- Tauri CLI 2.x

Rust installation example:

```powershell
winget install --id Rustlang.Rustup
```

After Rust is installed:

```powershell
rustup default stable-msvc
cargo install tauri-cli --version "^2.0.0" --locked
```

Then build:

```powershell
cd experimental/tauri-ui-spike/src-tauri
cargo tauri build
```

If newly installed commands are not visible yet, restart the terminal and try
again.

On modern Windows systems WebView2 is usually already present. If it is
missing, install the Microsoft Edge WebView2 Runtime.

## Ubuntu

### Ubuntu common native prerequisites

Current non-Windows CMake builds require OpenSSL.

For the usual C++ and Qt build environment:

```sh
sudo apt update
sudo apt install build-essential libgl1-mesa-dev libssl-dev
```

Also verify your CMake version:

```sh
cmake --version
```

Pcap Flow Lab requires CMake 3.24 or newer.

Ubuntu distribution Qt packages may be older than the required Qt 6.8+ level.
If that happens, install Qt 6.8+ separately.

### Ubuntu - Qt

Example using a typical Qt Online Installer layout:

```sh
~/Qt/6.8.x/gcc_64/bin/qt-cmake -S . -B build-qt -DCMAKE_BUILD_TYPE=Release
cmake --build build-qt
```

Replace `~/Qt/6.8.x/gcc_64/bin/qt-cmake` with the real path to your installed
Qt 6.8+ toolchain.

### Ubuntu - Tauri

Install the current Tauri 2 Debian or Ubuntu system prerequisites:

```sh
sudo apt update
sudo apt install \
  libwebkit2gtk-4.1-dev \
  build-essential \
  curl \
  wget \
  file \
  libxdo-dev \
  libssl-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev
```

Then install Rust:

```sh
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```

Install the Tauri CLI:

```sh
cargo install tauri-cli --version "^2.0.0" --locked
```

Then build:

```sh
cd experimental/tauri-ui-spike/src-tauri
cargo tauri build
```

`cargo tauri build` is the current release-build command used for the Pcap Flow
Lab Tauri frontend.

## CLI/core-only build

If you only want the CLI and shared core:

```sh
cmake -S . -B build-cli \
  -DCMAKE_BUILD_TYPE=Release \
  -DPFL_BUILD_UI=OFF
cmake --build build-cli
```

On Windows with a multi-config generator you may instead use:

```powershell
cmake --build build-cli --config Release
```

Qt is not required for CLI/core-only builds. Non-Windows still requires
OpenSSL because that dependency belongs to the shared core build.

## macOS

Pcap Flow Lab 0.3.0 does not publish a verified prebuilt macOS archive. macOS
users build from source.

For the Qt desktop application, plan for:

- Xcode Command Line Tools or an equivalent Apple C++ toolchain
- CMake 3.24 or newer
- Qt 6.8 or newer
- OpenSSL available to CMake

For the Tauri frontend, plan for:

- Xcode Command Line Tools or Xcode
- Rust
- Tauri CLI
- the normal `cargo tauri build` path from
  `experimental/tauri-ui-spike/src-tauri`

Use this guide together with the normal upstream Qt and Tauri prerequisite
documentation as needed, but do not assume a published macOS binary for 0.3.0.

## Other Linux distributions

Ubuntu is the 0.3.0 prebuilt Linux release target. Other Linux distributions
are source-build-only.

Plan for:

- CMake 3.24 or newer
- a C++20 compiler
- OpenSSL development files
- Qt 6.8 or newer for the Qt UI
- distro-specific Tauri 2 WebKit and native system dependencies for the Tauri
  frontend

Package names differ by distribution, so verify the equivalent prerequisites
for your system before building.

## Build vs packaging

This guide explains how to build Pcap Flow Lab from source. It does not define
the official 0.3.0 release archive packaging procedure.

A successful local source build does not automatically mean you produced the
same archive layout that is published on GitHub Releases.

## Running after build

Expected application names:

- Qt UI: `pcap-flow-lab-ui`
- CLI: `pcap-flow-lab`
- Tauri: platform-specific output produced by `cargo tauri build`

As a first verification capture after building, open:

- [`examples/showcase/pcap_flow_lab_showcase.pcap`](../examples/showcase/pcap_flow_lab_showcase.pcap)

You can use that sample in either desktop frontend or with the CLI.

## Troubleshooting

- `CMake cannot find Qt`
  Use `qt-cmake` or make Qt discoverable through `CMAKE_PREFIX_PATH`.
- `Qt UI target was skipped`
  Verify that Qt 6.8+ and the required Qt modules are installed and
  discoverable.
- `OpenSSL not found on Linux or macOS`
  Install or configure OpenSSL development files for your platform.
- `cargo tauri command missing`
  Install the Tauri CLI.
- `Windows Tauri compiler or toolchain error`
  Verify Microsoft C++ Build Tools and the stable MSVC Rust toolchain.
- `Ubuntu Tauri WebKit error`
  Verify the documented WebKit2GTK and native system prerequisite packages.

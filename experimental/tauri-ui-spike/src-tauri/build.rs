use std::env;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn source(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn add_cpp_sources(build: &mut cc::Build, sources: &[&str]) {
    for source_path in sources {
        let path = source(source_path);
        println!("cargo:rerun-if-changed={}", path.display());
        build.file(path);
    }
}

fn copy_windows_gnu_runtime_dlls() {
    let out_dir = match env::var("OUT_DIR") {
        Ok(value) => PathBuf::from(value),
        Err(_) => return,
    };

    let exe_dir = match out_dir.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
        Some(path) => path.to_path_buf(),
        None => return,
    };

    let runtime_dir = PathBuf::from(r"C:\msys64\mingw64\bin");
    let dlls = [
        "libstdc++-6.dll",
        "libgcc_s_seh-1.dll",
        "libwinpthread-1.dll",
    ];

    for dll in dlls {
        let source = runtime_dir.join(dll);
        let target = exe_dir.join(dll);
        let _ = fs::copy(source, target);
    }
}

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    if target.ends_with("windows-gnu") {
        env::set_var("RC", r"C:\msys64\mingw64\bin\windres.exe");
        println!("cargo:rustc-check-cfg=cfg(desktop)");
        println!("cargo:rustc-cfg=desktop");
        println!("cargo:rustc-check-cfg=cfg(mobile)");
        println!("cargo:rustc-check-cfg=cfg(dev)");
        println!("cargo:rustc-cfg=dev");
        println!("cargo:rerun-if-changed=tauri.conf.json");
        println!("cargo:rerun-if-changed=capabilities");
        println!("cargo:rustc-env=TAURI_ENV_TARGET_TRIPLE={target}");
    } else {
        tauri_build::build();
    }

    let repo = repo_root();
    let src_include = repo.join("src");

    let mut build = cc::Build::new();
    build.cpp(true);
    build.include(&repo);
    build.include(&src_include);
    build.warnings(false);
    let compiler = build.get_compiler();
    if compiler.is_like_msvc() {
        build.flag_if_supported("/std:c++20");
        build.flag_if_supported("/EHsc");
    } else {
        build.std("c++20");
        build.flag_if_supported("-Wall");
        build.flag_if_supported("-Wextra");
        build.flag_if_supported("-Wpedantic");
        build.flag_if_supported("-Wconversion");
        build.flag_if_supported("-Wsign-conversion");
    }

    let sources = [
        "src/core/domain/FlowKey.cpp",
        "src/core/domain/ConnectionKey.cpp",
        "src/core/domain/Flow.cpp",
        "src/core/domain/Connection.cpp",
        "src/core/domain/ConnectionTable.cpp",
        "src/core/domain/PacketRef.cpp",
        "src/core/domain/CaptureSummary.cpp",
        "src/core/domain/PacketDetails.cpp",
        "src/core/io/PcapReader.cpp",
        "src/core/io/PcapNgReader.cpp",
        "src/core/io/PcapWriter.cpp",
        "src/core/io/FileByteSource.cpp",
        "src/core/io/PacketDataReader.cpp",
        "src/core/io/CaptureFilePacketReader.cpp",
        "src/core/index/CaptureIndex.cpp",
        "src/core/index/Serialization.cpp",
        "src/core/index/CaptureIndexWriter.cpp",
        "src/core/index/CaptureIndexReader.cpp",
        "src/core/index/ImportCheckpoint.cpp",
        "src/core/index/ImportCheckpointWriter.cpp",
        "src/core/index/ImportCheckpointReader.cpp",
        "src/core/decode/PacketDecoder.cpp",
        "src/core/reassembly/ReassemblyService.cpp",
        "src/core/services/PacketIngestor.cpp",
        "src/core/services/CaptureImportProcessor.cpp",
        "src/core/services/FastCaptureImporter.cpp",
        "src/core/services/DeepCaptureImporter.cpp",
        "src/core/services/CaptureImporter.cpp",
        "src/core/services/ChunkedCaptureImporter.cpp",
        "src/core/services/FlowExportService.cpp",
        "src/core/services/FlowAnalysisService.cpp",
        "src/core/services/PacketDetailsService.cpp",
        "src/core/services/PacketPayloadService.cpp",
        "src/core/services/PerfOpenLogger.cpp",
        "src/core/services/TlsHandshakeDetails.cpp",
        "src/core/services/TlsPacketProtocolAnalyzer.cpp",
        "src/core/services/QuicPacketProtocolAnalyzer.cpp",
        "src/core/services/DnsPacketProtocolAnalyzer.cpp",
        "src/core/services/HttpPacketProtocolAnalyzer.cpp",
        "src/core/services/FlowHintService.cpp",
        "src/core/services/QuicInitialParser.cpp",
        "src/core/services/HexDumpService.cpp",
        "src/app/frontend/FrontendSessionAdapter.cpp",
        "src/app/frontend/FrontendSessionAdapterBridge.cpp",
        "src/app/session/CaptureSession.cpp",
        "src/app/session/SelectedFlowPacketSemantics.cpp",
        "src/app/session/SessionFlowHelpers.cpp",
        "src/app/session/SessionFormatting.cpp",
        "src/app/session/SessionOpenHelpers.cpp",
        "src/app/session/SessionQuicPresentation.cpp",
        "src/app/session/SessionTlsPresentation.cpp",
        "src/app/session/SessionTcpStreamSupport.cpp",
        "src/app/session/SessionHttpReconstruction.cpp",
    ];

    add_cpp_sources(&mut build, &sources);

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=bcrypt");
    } else {
        println!("cargo:rustc-link-lib=crypto");
    }

    build.compile("pfl_tauri_bridge");

    if target.ends_with("windows-gnu") {
        copy_windows_gnu_runtime_dlls();
    }
}

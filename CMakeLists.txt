cmake_minimum_required(VERSION 3.24)

project(
    pcap_flow_lab
    VERSION 0.1.0
    DESCRIPTION "Flow-centric PCAP analyzer for large network captures"
    LANGUAGES CXX
)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PFL_BUILD_UI "Build the Qt Quick desktop UI when Qt 6 is available." ON)

add_library(pcap_flow_lab_warnings INTERFACE)

target_compile_features(pcap_flow_lab_warnings INTERFACE cxx_std_20)

if(MSVC)
    target_compile_options(pcap_flow_lab_warnings INTERFACE /W4 /permissive-)
else()
    target_compile_options(
        pcap_flow_lab_warnings
        INTERFACE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wsign-conversion
    )
endif()

add_library(
    pcap_flow_lab_core
    src/core/domain/FlowKey.cpp
    src/core/domain/ConnectionKey.cpp
    src/core/domain/Flow.cpp
    src/core/domain/Connection.cpp
    src/core/domain/ConnectionTable.cpp
    src/core/domain/PacketRef.cpp
    src/core/domain/CaptureSummary.cpp
    src/core/domain/PacketDetails.cpp
    src/core/io/PcapReader.cpp
    src/core/io/PcapNgReader.cpp
    src/core/io/PcapWriter.cpp
    src/core/io/FileByteSource.cpp
    src/core/io/PacketDataReader.cpp
    src/core/io/CaptureFilePacketReader.cpp
    src/core/index/CaptureIndex.cpp
    src/core/index/Serialization.cpp
    src/core/index/CaptureIndexWriter.cpp
    src/core/index/CaptureIndexReader.cpp
    src/core/index/ImportCheckpoint.cpp
    src/core/index/ImportCheckpointWriter.cpp
    src/core/index/ImportCheckpointReader.cpp
    src/core/decode/PacketDecoder.cpp
    src/core/reassembly/ReassemblyService.cpp
    src/core/services/PacketIngestor.cpp
    src/core/services/CaptureImportProcessor.cpp
    src/core/services/FastCaptureImporter.cpp
    src/core/services/DeepCaptureImporter.cpp
    src/core/services/CaptureImporter.cpp
    src/core/services/ChunkedCaptureImporter.cpp
    src/core/services/FlowExportService.cpp
    src/core/services/PacketDetailsService.cpp
    src/core/services/PacketPayloadService.cpp
    src/core/services/TlsPacketProtocolAnalyzer.cpp
    src/core/services/DnsPacketProtocolAnalyzer.cpp
    src/core/services/HttpPacketProtocolAnalyzer.cpp
    src/core/services/FlowHintService.cpp
    src/core/services/HexDumpService.cpp
    src/app/session/CaptureSession.cpp
)

target_link_libraries(pcap_flow_lab_core PUBLIC pcap_flow_lab_warnings)

target_include_directories(
    pcap_flow_lab_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(
    pcap_flow_lab_cli
    src/cli/main.cpp
    src/cli/CliFormatting.cpp
)

set_target_properties(pcap_flow_lab_cli PROPERTIES OUTPUT_NAME "pcap-flow-lab")

target_link_libraries(
    pcap_flow_lab_cli
    PRIVATE
        pcap_flow_lab_core
)

if(PFL_BUILD_UI)
    find_package(Qt6 QUIET COMPONENTS Quick Qml QuickControls2 Widgets)

    if(Qt6_FOUND)
        qt_standard_project_setup()

        qt_add_executable(
            pcap_flow_lab_ui
            src/ui/app/main.cpp
            src/ui/app/MainController.cpp
            src/ui/app/MainController.h
            src/ui/app/FlowListModel.cpp
            src/ui/app/FlowListModel.h
            src/ui/app/TopSummaryListModel.cpp
            src/ui/app/TopSummaryListModel.h
            src/ui/app/PacketListModel.cpp
            src/ui/app/PacketListModel.h
            src/ui/app/PacketDetailsViewModel.cpp
            src/ui/app/PacketDetailsViewModel.h
        )

        qt_add_qml_module(
            pcap_flow_lab_ui
            URI PcapFlowLab
            VERSION 1.0
            QML_FILES
                src/ui/qml/Main.qml
                src/ui/qml/components/SummaryBar.qml
                src/ui/qml/components/FlowWorkspacePane.qml
                src/ui/qml/components/StatisticsPane.qml
                src/ui/qml/components/ProtocolStatsPane.qml
                src/ui/qml/components/TopTalkersPane.qml
                src/ui/qml/components/FlowTable.qml
                src/ui/qml/components/PacketList.qml
                src/ui/qml/components/PacketDetailsPane.qml
                src/ui/qml/components/SettingsPane.qml
        )

        set_target_properties(pcap_flow_lab_ui PROPERTIES OUTPUT_NAME "pcap-flow-lab-ui")

        target_link_libraries(
            pcap_flow_lab_ui
            PRIVATE
                pcap_flow_lab_core
                Qt6::Quick
                Qt6::Qml
                Qt6::QuickControls2
                Qt6::Widgets
        )

        if(BUILD_TESTING)
            add_executable(
                pcap_flow_lab_ui_tests
                tests/ui/MainControllerUiTests.cpp
                src/ui/app/MainController.cpp
                src/ui/app/FlowListModel.cpp
                src/ui/app/TopSummaryListModel.cpp
                src/ui/app/PacketListModel.cpp
                src/ui/app/PacketDetailsViewModel.cpp
            )

            target_link_libraries(
                pcap_flow_lab_ui_tests
                PRIVATE
                    pcap_flow_lab_core
                    Qt6::Widgets
            )

            target_include_directories(
                pcap_flow_lab_ui_tests
                PRIVATE
                    ${CMAKE_CURRENT_SOURCE_DIR}/src
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests/unit
            )

            add_test(NAME pcap_flow_lab_ui_tests COMMAND pcap_flow_lab_ui_tests)
        endif()
    else()
        message(STATUS "Qt 6 Quick/QML not found, skipping pcap_flow_lab_ui target.")
    endif()
endif()

if(BUILD_TESTING)
    add_executable(
        pcap_flow_lab_core_tests
        tests/unit/test_main.cpp
        tests/unit/FlowKeyTests.cpp
        tests/unit/ConnectionTests.cpp
        tests/unit/IngestorTests.cpp
        tests/unit/ImportTests.cpp
        tests/unit/ImportModeTests.cpp
        tests/unit/AnalysisSettingsTests.cpp
        tests/unit/CliImportModeTests.cpp
        tests/unit/PacketAccessTests.cpp
        tests/unit/PacketDetailsTests.cpp
        tests/unit/PacketPayloadTests.cpp
        tests/unit/PacketProtocolDetailsTests.cpp
        tests/unit/PacketMetadataTests.cpp
        tests/unit/QueryTests.cpp
        tests/unit/ProtocolSummaryTests.cpp
        tests/unit/TopSummaryTests.cpp
        tests/unit/VlanTests.cpp
        tests/unit/ExportTests.cpp
        tests/unit/PcapNgTests.cpp
        tests/unit/IndexTests.cpp
        tests/unit/IndexFormatTests.cpp
        tests/unit/ChunkedImportTests.cpp
        tests/unit/ProtocolCoverageTests.cpp
        tests/unit/MalformedPacketHandlingTests.cpp
        tests/unit/LinuxCookedTests.cpp
        tests/unit/FragmentationTests.cpp
        tests/unit/ReassemblyArchitectureTests.cpp
        tests/unit/FlowHintsTests.cpp
        tests/unit/FlowHintsRawFixturesTests.cpp
        tests/unit/FlowHintsRealFixturesTests.cpp
    )

    target_link_libraries(
        pcap_flow_lab_core_tests
        PRIVATE
            pcap_flow_lab_core
    )

    add_test(NAME pcap_flow_lab_core_tests COMMAND pcap_flow_lab_core_tests)
endif()

























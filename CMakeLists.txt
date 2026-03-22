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
set(CMAKE_SUPPRESS_REGENERATION ON)

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
    src/core/services/PacketIngestor.cpp
    src/app/session/CaptureSession.cpp
)

target_link_libraries(pcap_flow_lab_core PUBLIC pcap_flow_lab_warnings)

target_include_directories(
    pcap_flow_lab_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(BUILD_TESTING)
    add_executable(
        pcap_flow_lab_core_tests
        tests/unit/test_main.cpp
        tests/unit/FlowKeyTests.cpp
        tests/unit/ConnectionTests.cpp
        tests/unit/IngestorTests.cpp
    )

    target_link_libraries(
        pcap_flow_lab_core_tests
        PRIVATE
            pcap_flow_lab_core
    )

    add_test(NAME pcap_flow_lab_core_tests COMMAND pcap_flow_lab_core_tests)
endif()

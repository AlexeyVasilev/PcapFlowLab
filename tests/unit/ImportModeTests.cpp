#include <filesystem>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/services/CaptureImporter.h"
#include "core/services/ChunkedCaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: import-mode.example\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

void expect_equivalent_session_results(const CaptureSession& left, const CaptureSession& right) {
    PFL_EXPECT(left.summary().packet_count == right.summary().packet_count);
    PFL_EXPECT(left.summary().flow_count == right.summary().flow_count);
    PFL_EXPECT(left.summary().total_bytes == right.summary().total_bytes);

    const auto left_rows = left.list_flows();
    const auto right_rows = right.list_flows();
    PFL_EXPECT(left_rows.size() == right_rows.size());

    for (std::size_t index = 0; index < left_rows.size(); ++index) {
        PFL_EXPECT(left_rows[index].protocol_text == right_rows[index].protocol_text);
        PFL_EXPECT(left_rows[index].protocol_hint == right_rows[index].protocol_hint);
        PFL_EXPECT(left_rows[index].service_hint == right_rows[index].service_hint);
        PFL_EXPECT(left_rows[index].packet_count == right_rows[index].packet_count);
        PFL_EXPECT(left_rows[index].total_bytes == right_rows[index].total_bytes);
    }
}

}  // namespace

void run_import_mode_tests() {
    const auto http_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(192, 168, 10, 1), ipv4(93, 184, 216, 34), 51515, 80, make_http_request_payload(), 0x18);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);
    const auto capture_path = write_temp_pcap(
        "pfl_import_modes.pcap",
        make_classic_pcap({{100, http_packet}, {200, udp_packet}})
    );

    {
        CaptureSession default_session {};
        CaptureSession fast_session {};
        CaptureSession deep_session {};

        PFL_EXPECT(default_session.open_capture(capture_path));
        PFL_EXPECT(fast_session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::fast}));
        PFL_EXPECT(deep_session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));

        expect_equivalent_session_results(default_session, fast_session);
        expect_equivalent_session_results(default_session, deep_session);
    }

    {
        CaptureImporter importer {};
        CaptureState fast_state {};
        CaptureState deep_state {};

        PFL_EXPECT(importer.import_capture(capture_path, fast_state, CaptureImportOptions {.mode = ImportMode::fast}));
        PFL_EXPECT(importer.import_capture(capture_path, deep_state, CaptureImportOptions {.mode = ImportMode::deep}));
        PFL_EXPECT(fast_state.summary.packet_count == deep_state.summary.packet_count);
        PFL_EXPECT(fast_state.summary.flow_count == deep_state.summary.flow_count);
        PFL_EXPECT(fast_state.summary.total_bytes == deep_state.summary.total_bytes);
        PFL_EXPECT(fast_state.ipv4_connections.size() == deep_state.ipv4_connections.size());
    }

    {
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_import_modes.idx";
        std::filesystem::remove(index_path);

        CaptureSession deep_session {};
        PFL_EXPECT(deep_session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        PFL_EXPECT(deep_session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));
        expect_equivalent_session_results(deep_session, loaded_session);
    }

    {
        const auto checkpoint_path = std::filesystem::temp_directory_path() / "pfl_import_modes.ckp";
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_import_modes_chunked.idx";
        std::filesystem::remove(checkpoint_path);
        std::filesystem::remove(index_path);

        ChunkedCaptureImporter importer {};
        PFL_EXPECT(importer.import_chunk(capture_path, checkpoint_path, 1) == ChunkedImportStatus::checkpoint_saved);
        PFL_EXPECT(importer.resume_chunk(checkpoint_path, 2) == ChunkedImportStatus::completed);
        PFL_EXPECT(importer.finalize_to_index(checkpoint_path, index_path));

        CaptureSession chunked_session {};
        CaptureSession fast_session {};
        PFL_EXPECT(chunked_session.load_index(index_path));
        PFL_EXPECT(fast_session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::fast}));
        expect_equivalent_session_results(chunked_session, fast_session);
    }
}

}  // namespace pfl::tests

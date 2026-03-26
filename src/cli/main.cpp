#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "app/session/CaptureSession.h"
#include "cli/CliFormatting.h"
#include "cli/CliImportMode.h"
#include "core/index/CaptureIndex.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/services/ChunkedCaptureImporter.h"

namespace {

struct ExportArgs {
    std::size_t flow_index {0};
    std::string output_path {};
};

struct OutputPathArgs {
    std::string output_path {};
};

struct CheckpointArgs {
    std::string checkpoint_path {};
    std::size_t max_packets {0};
};

struct FinalizeImportArgs {
    std::string checkpoint_path {};
    std::string output_path {};
};

struct ParsedModeArgs {
    pfl::CaptureImportOptions options {};
    bool mode_specified {false};
    bool valid {true};
    std::vector<std::string_view> remaining_args {};
};

struct PrintableFlowRow {
    std::size_t index {0};
    std::string family {};
    std::string protocol {};
    std::string endpoint_a {};
    std::string endpoint_b {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

void print_usage() {
    std::cout
        << "Usage:\n"
        << "  pcap-flow-lab summary <input> [--mode fast|deep]\n"
        << "  pcap-flow-lab flows <input> [--mode fast|deep]\n"
        << "  pcap-flow-lab inspect-packet <input> --packet-index <N> [--mode fast|deep]\n"
        << "  pcap-flow-lab hex <input> --packet-index <N> [--mode fast|deep]\n"
        << "  pcap-flow-lab export-flow <input> --flow-index <N> --out <output.pcap> [--mode fast|deep]\n"
        << "  pcap-flow-lab save-index <capture-file> --out <index-file> [--mode fast|deep]\n"
        << "  pcap-flow-lab load-index-summary <index-file>\n"
        << "  pcap-flow-lab chunked-import <capture-file> --checkpoint <checkpoint-file> --max-packets <N>\n"
        << "  pcap-flow-lab resume-import --checkpoint <checkpoint-file> --max-packets <N>\n"
        << "  pcap-flow-lab finalize-import --checkpoint <checkpoint-file> --out <index-file>\n";
}

ParsedModeArgs parse_mode_args(int argc, char* argv[], int start_index) {
    ParsedModeArgs result {};

    for (int index = start_index; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--mode") {
            if (result.mode_specified || index + 1 >= argc) {
                result.valid = false;
                return result;
            }

            const auto parsed_mode = pfl::parse_import_mode_value(argv[index + 1]);
            if (!parsed_mode.has_value()) {
                result.valid = false;
                return result;
            }

            result.options.mode = *parsed_mode;
            result.mode_specified = true;
            ++index;
            continue;
        }

        result.remaining_args.push_back(argument);
    }

    return result;
}

std::optional<std::uint64_t> parse_packet_index(const std::vector<std::string_view>& args) {
    if (args.size() != 2 || args[0] != "--packet-index") {
        return std::nullopt;
    }

    try {
        return static_cast<std::uint64_t>(std::stoull(std::string {args[1]}));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<ExportArgs> parse_export_args(const std::vector<std::string_view>& args) {
    if (args.size() != 4) {
        return std::nullopt;
    }

    std::optional<std::size_t> flow_index {};
    std::string output_path {};

    for (std::size_t index = 0; index < args.size(); index += 2) {
        const auto option = args[index];

        if (option == "--flow-index") {
            try {
                flow_index = static_cast<std::size_t>(std::stoull(std::string {args[index + 1]}));
            } catch (const std::exception&) {
                return std::nullopt;
            }
            continue;
        }

        if (option == "--out") {
            output_path = std::string {args[index + 1]};
            continue;
        }

        return std::nullopt;
    }

    if (!flow_index.has_value() || output_path.empty()) {
        return std::nullopt;
    }

    return ExportArgs {
        .flow_index = *flow_index,
        .output_path = std::move(output_path),
    };
}

std::optional<OutputPathArgs> parse_output_path_args(const std::vector<std::string_view>& args) {
    if (args.size() != 2 || args[0] != "--out") {
        return std::nullopt;
    }

    return OutputPathArgs {
        .output_path = std::string {args[1]},
    };
}

std::optional<CheckpointArgs> parse_checkpoint_args(int argc, char* argv[], int start_index) {
    if (argc != start_index + 4) {
        return std::nullopt;
    }

    std::string checkpoint_path {};
    std::optional<std::size_t> max_packets {};

    for (int index = start_index; index < argc; index += 2) {
        const std::string_view option = argv[index];
        if (index + 1 >= argc) {
            return std::nullopt;
        }

        if (option == "--checkpoint") {
            checkpoint_path = argv[index + 1];
            continue;
        }

        if (option == "--max-packets") {
            try {
                max_packets = static_cast<std::size_t>(std::stoull(argv[index + 1]));
            } catch (const std::exception&) {
                return std::nullopt;
            }
            continue;
        }

        return std::nullopt;
    }

    if (checkpoint_path.empty() || !max_packets.has_value()) {
        return std::nullopt;
    }

    return CheckpointArgs {
        .checkpoint_path = std::move(checkpoint_path),
        .max_packets = *max_packets,
    };
}

std::optional<FinalizeImportArgs> parse_finalize_import_args(int argc, char* argv[]) {
    if (argc != 6) {
        return std::nullopt;
    }

    std::string checkpoint_path {};
    std::string output_path {};

    for (int index = 2; index < argc; index += 2) {
        const std::string_view option = argv[index];
        if (index + 1 >= argc) {
            return std::nullopt;
        }

        if (option == "--checkpoint") {
            checkpoint_path = argv[index + 1];
            continue;
        }

        if (option == "--out") {
            output_path = argv[index + 1];
            continue;
        }

        return std::nullopt;
    }

    if (checkpoint_path.empty() || output_path.empty()) {
        return std::nullopt;
    }

    return FinalizeImportArgs {
        .checkpoint_path = std::move(checkpoint_path),
        .output_path = std::move(output_path),
    };
}

bool open_analysis_input(const char* input, const ParsedModeArgs& mode_args, pfl::CaptureSession& session) {
    if (pfl::looks_like_index_file(input)) {
        if (mode_args.mode_specified) {
            std::cerr << "Import mode is only supported for capture inputs.\n";
            return false;
        }

        if (session.open_input(input)) {
            return true;
        }

        std::cerr << "Failed to open input: " << input << '\n';
        return false;
    }

    if (session.open_capture(input, mode_args.options)) {
        return true;
    }

    std::cerr << "Failed to open capture: " << input << '\n';
    return false;
}

bool open_capture_only(const char* capture_file, const ParsedModeArgs& mode_args, pfl::CaptureSession& session) {
    if (session.open_capture(capture_file, mode_args.options)) {
        return true;
    }

    std::cerr << "Failed to open capture: " << capture_file << '\n';
    return false;
}

bool load_index_only(const char* index_file, pfl::CaptureSession& session) {
    if (session.load_index(index_file)) {
        return true;
    }

    std::cerr << "Failed to load index: " << index_file << '\n';
    return false;
}

PrintableFlowRow make_printable_flow_row(const pfl::FlowRow& row) {
    PrintableFlowRow printable {
        .index = row.index,
        .family = (row.family == pfl::FlowAddressFamily::ipv4) ? "v4" : "v6",
        .packet_count = row.packet_count,
        .total_bytes = row.total_bytes,
    };

    std::visit([&](const auto& key) {
        printable.protocol = pfl::format_protocol(key.protocol);
        printable.endpoint_a = pfl::format_endpoint(key.first);
        printable.endpoint_b = pfl::format_endpoint(key.second);
    }, row.key);

    return printable;
}

void print_packet_details(const pfl::PacketDetails& details) {
    const auto format_ipv4_bytes = [](const std::array<std::uint8_t, 4>& address) {
        return pfl::format_ipv4_address(
            (static_cast<std::uint32_t>(address[0]) << 24U) |
            (static_cast<std::uint32_t>(address[1]) << 16U) |
            (static_cast<std::uint32_t>(address[2]) << 8U) |
            static_cast<std::uint32_t>(address[3])
        );
    };

    std::cout << "Packet Index: " << details.packet_index << '\n';
    std::cout << "Captured Length: " << details.captured_length << '\n';
    std::cout << "Original Length: " << details.original_length << '\n';

    if (details.has_ethernet) {
        std::cout << "Ether Type: 0x" << std::hex << std::setw(4) << std::setfill('0')
                  << details.ethernet.ether_type << std::dec << '\n';
    }

    if (details.has_vlan) {
        std::cout << "VLAN tags: " << details.vlan_tags.size() << '\n';
        for (std::size_t index = 0; index < details.vlan_tags.size(); ++index) {
            std::cout << "VLAN[" << index << "] TCI: " << details.vlan_tags[index].tci
                      << " Encapsulated EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                      << details.vlan_tags[index].encapsulated_ether_type << std::dec << '\n';
        }
    }

    if (details.has_arp) {
        std::cout << "ARP Opcode: " << details.arp.opcode << '\n';
        std::cout << "ARP Sender IPv4: " << format_ipv4_bytes(details.arp.sender_ipv4) << '\n';
        std::cout << "ARP Target IPv4: " << format_ipv4_bytes(details.arp.target_ipv4) << '\n';
    }

    if (details.has_ipv4) {
        std::cout << "IPv4 Source: " << pfl::format_ipv4_address(details.ipv4.src_addr) << '\n';
        std::cout << "IPv4 Destination: " << pfl::format_ipv4_address(details.ipv4.dst_addr) << '\n';
        std::cout << "IP Protocol: " << pfl::format_protocol(static_cast<pfl::ProtocolId>(details.ipv4.protocol)) << '\n';
    }

    if (details.has_ipv6) {
        std::cout << "IPv6 Source: " << pfl::format_ipv6_address(details.ipv6.src_addr) << '\n';
        std::cout << "IPv6 Destination: " << pfl::format_ipv6_address(details.ipv6.dst_addr) << '\n';
        std::cout << "Next Header: " << pfl::format_protocol(static_cast<pfl::ProtocolId>(details.ipv6.next_header)) << '\n';
    }

    if (details.has_tcp) {
        std::cout << "TCP Source Port: " << details.tcp.src_port << '\n';
        std::cout << "TCP Destination Port: " << details.tcp.dst_port << '\n';
        std::cout << "TCP Flags: " << pfl::format_tcp_flags(details.tcp.flags) << '\n';
    }

    if (details.has_udp) {
        std::cout << "UDP Source Port: " << details.udp.src_port << '\n';
        std::cout << "UDP Destination Port: " << details.udp.dst_port << '\n';
    }

    if (details.has_icmp) {
        std::cout << "ICMP Type: " << static_cast<unsigned>(details.icmp.type) << '\n';
        std::cout << "ICMP Code: " << static_cast<unsigned>(details.icmp.code) << '\n';
    }

    if (details.has_icmpv6) {
        std::cout << "ICMPv6 Type: " << static_cast<unsigned>(details.icmpv6.type) << '\n';
        std::cout << "ICMPv6 Code: " << static_cast<unsigned>(details.icmpv6.code) << '\n';
    }
}

void print_summary(const pfl::CaptureSession& session, const std::string_view label, const std::string_view value) {
    std::cout << label << ": " << value << '\n';

    if (session.has_capture()) {
        const auto source_capture = session.capture_path().string();
        if (source_capture != value) {
            std::cout << "Source Capture: " << source_capture << '\n';
        }
    }

    std::cout << "Packets: " << session.summary().packet_count << '\n';
    std::cout << "Flows: " << session.summary().flow_count << '\n';
    std::cout << "Bytes: " << session.summary().total_bytes << '\n';
}

bool read_checkpoint(const std::filesystem::path& checkpoint_path, pfl::ImportCheckpoint& checkpoint) {
    pfl::ImportCheckpointReader reader {};
    return reader.read(checkpoint_path, checkpoint);
}

int print_chunked_result(pfl::ChunkedImportStatus status, const std::filesystem::path& checkpoint_path) {
    if (status == pfl::ChunkedImportStatus::failed) {
        return 1;
    }

    pfl::ImportCheckpoint checkpoint {};
    if (!read_checkpoint(checkpoint_path, checkpoint)) {
        std::cerr << "Failed to read checkpoint: " << checkpoint_path.string() << '\n';
        return 1;
    }

    if (status == pfl::ChunkedImportStatus::completed) {
        std::cout << "Import completed.\n";
    } else {
        std::cout << "Checkpoint saved.\n";
    }

    std::cout << "Packets processed: " << checkpoint.packets_processed << '\n';
    std::cout << "Flows: " << checkpoint.state.summary.flow_count << '\n';
    std::cout << "Bytes: " << checkpoint.state.summary.total_bytes << '\n';
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const std::string_view command = argv[1];

    if (command == "finalize-import") {
        const auto finalize_args = parse_finalize_import_args(argc, argv);
        if (!finalize_args.has_value()) {
            print_usage();
            return 1;
        }

        pfl::ChunkedCaptureImporter importer {};
        if (!importer.finalize_to_index(finalize_args->checkpoint_path, finalize_args->output_path)) {
            std::cerr << "Failed to finalize import to " << finalize_args->output_path << '\n';
            return 1;
        }

        std::cout << "Finalized import to " << finalize_args->output_path << '\n';
        return 0;
    }

    if (command == "resume-import") {
        const auto checkpoint_args = parse_checkpoint_args(argc, argv, 2);
        if (!checkpoint_args.has_value()) {
            print_usage();
            return 1;
        }

        pfl::ChunkedCaptureImporter importer {};
        const auto status = importer.resume_chunk(checkpoint_args->checkpoint_path, checkpoint_args->max_packets);
        if (status == pfl::ChunkedImportStatus::failed) {
            std::cerr << "Failed to resume import from checkpoint: " << checkpoint_args->checkpoint_path << '\n';
        }
        return print_chunked_result(status, checkpoint_args->checkpoint_path);
    }

    if (argc < 3) {
        print_usage();
        return 1;
    }

    const char* input = argv[2];

    if (command == "chunked-import") {
        const auto checkpoint_args = parse_checkpoint_args(argc, argv, 3);
        if (!checkpoint_args.has_value()) {
            print_usage();
            return 1;
        }

        pfl::ChunkedCaptureImporter importer {};
        const auto status = importer.import_chunk(input, checkpoint_args->checkpoint_path, checkpoint_args->max_packets);
        if (status == pfl::ChunkedImportStatus::failed) {
            std::cerr << "Failed to import chunk from capture: " << input << '\n';
        }
        return print_chunked_result(status, checkpoint_args->checkpoint_path);
    }

    const auto mode_args = parse_mode_args(argc, argv, 3);
    if (!mode_args.valid) {
        print_usage();
        return 1;
    }

    if (command == "summary") {
        if (!mode_args.remaining_args.empty()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_analysis_input(input, mode_args, session)) {
            return 1;
        }

        print_summary(session, "Input", input);
        return 0;
    }

    if (command == "load-index-summary") {
        if (argc != 3) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!load_index_only(input, session)) {
            return 1;
        }

        print_summary(session, "Index", input);
        return 0;
    }

    if (command == "flows") {
        if (!mode_args.remaining_args.empty()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_analysis_input(input, mode_args, session)) {
            return 1;
        }

        const auto rows = session.list_flows();
        std::cout << "Index  Family  Proto  Endpoint A                      Endpoint B                      Packets  Bytes\n";
        for (const auto& row : rows) {
            const auto printable = make_printable_flow_row(row);
            std::cout << std::left
                      << std::setw(7) << printable.index
                      << std::setw(8) << printable.family
                      << std::setw(7) << printable.protocol
                      << std::setw(32) << printable.endpoint_a
                      << std::setw(32) << printable.endpoint_b
                      << std::right
                      << std::setw(8) << printable.packet_count
                      << std::setw(7) << printable.total_bytes
                      << '\n';
        }

        return 0;
    }

    if (command == "inspect-packet") {
        const auto packet_index = parse_packet_index(mode_args.remaining_args);
        if (!packet_index.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_analysis_input(input, mode_args, session)) {
            return 1;
        }

        const auto packet = session.find_packet(*packet_index);
        if (!packet.has_value()) {
            std::cerr << "Packet not found: " << *packet_index << '\n';
            return 1;
        }

        const auto details = session.read_packet_details(*packet);
        if (!details.has_value()) {
            std::cerr << "Packet details unavailable: " << *packet_index << '\n';
            return 1;
        }

        print_packet_details(*details);
        return 0;
    }

    if (command == "hex") {
        const auto packet_index = parse_packet_index(mode_args.remaining_args);
        if (!packet_index.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_analysis_input(input, mode_args, session)) {
            return 1;
        }

        const auto packet = session.find_packet(*packet_index);
        if (!packet.has_value()) {
            std::cerr << "Packet not found: " << *packet_index << '\n';
            return 1;
        }

        const auto dump = session.read_packet_hex_dump(*packet);
        if (dump.empty()) {
            std::cerr << "Packet hex dump unavailable: " << *packet_index << '\n';
            return 1;
        }

        std::cout << dump << '\n';
        return 0;
    }

    if (command == "export-flow") {
        const auto export_args = parse_export_args(mode_args.remaining_args);
        if (!export_args.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_analysis_input(input, mode_args, session)) {
            return 1;
        }

        if (!session.export_flow_to_pcap(export_args->flow_index, export_args->output_path)) {
            std::cerr << "Failed to export flow " << export_args->flow_index << " to " << export_args->output_path << '\n';
            return 1;
        }

        std::cout << "Exported flow " << export_args->flow_index << " to " << export_args->output_path << '\n';
        return 0;
    }

    if (command == "save-index") {
        const auto output_args = parse_output_path_args(mode_args.remaining_args);
        if (!output_args.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_capture_only(input, mode_args, session)) {
            return 1;
        }

        if (!session.save_index(output_args->output_path)) {
            std::cerr << "Failed to save index to " << output_args->output_path << '\n';
            return 1;
        }

        std::cout << "Saved index to " << output_args->output_path << '\n';
        return 0;
    }

    print_usage();
    return 1;
}

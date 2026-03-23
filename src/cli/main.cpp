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

namespace {

struct ExportArgs {
    std::size_t flow_index {0};
    std::string output_path {};
};

struct OutputPathArgs {
    std::string output_path {};
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
        << "  pcap-flow-lab summary <file>\n"
        << "  pcap-flow-lab flows <file>\n"
        << "  pcap-flow-lab inspect-packet <file> --packet-index <N>\n"
        << "  pcap-flow-lab hex <file> --packet-index <N>\n"
        << "  pcap-flow-lab export-flow <file> --flow-index <N> --out <output.pcap>\n"
        << "  pcap-flow-lab save-index <capture-file> --out <index-file>\n"
        << "  pcap-flow-lab load-index-summary <index-file>\n";
}

std::optional<std::uint64_t> parse_packet_index(int argc, char* argv[]) {
    if (argc != 5) {
        return std::nullopt;
    }

    if (std::string_view(argv[3]) != "--packet-index") {
        return std::nullopt;
    }

    try {
        return static_cast<std::uint64_t>(std::stoull(argv[4]));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<ExportArgs> parse_export_args(int argc, char* argv[]) {
    if (argc != 7) {
        return std::nullopt;
    }

    std::optional<std::size_t> flow_index {};
    std::string output_path {};

    for (int index = 3; index < argc; index += 2) {
        const std::string_view option = argv[index];
        if (index + 1 >= argc) {
            return std::nullopt;
        }

        if (option == "--flow-index") {
            try {
                flow_index = static_cast<std::size_t>(std::stoull(argv[index + 1]));
            } catch (const std::exception&) {
                return std::nullopt;
            }
            continue;
        }

        if (option == "--out") {
            output_path = argv[index + 1];
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

std::optional<OutputPathArgs> parse_output_path_args(int argc, char* argv[]) {
    if (argc != 5 || std::string_view(argv[3]) != "--out") {
        return std::nullopt;
    }

    return OutputPathArgs {
        .output_path = argv[4],
    };
}

bool open_session(const char* file, pfl::CaptureSession& session) {
    if (session.open_capture(file)) {
        return true;
    }

    std::cerr << "Failed to open capture: " << file << '\n';
    return false;
}

bool load_index_session(const char* index_file, pfl::CaptureSession& session) {
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

    if (details.has_ipv4) {
        std::cout << "IPv4 Source: " << pfl::format_ipv4_address(details.ipv4.src_addr) << '\n';
        std::cout << "IPv4 Destination: " << pfl::format_ipv4_address(details.ipv4.dst_addr) << '\n';
        std::cout << "IP Protocol: " << ((details.ipv4.protocol == 6) ? "TCP" :
                                          (details.ipv4.protocol == 17) ? "UDP" : "unknown") << '\n';
    }

    if (details.has_ipv6) {
        std::cout << "IPv6 Source: " << pfl::format_ipv6_address(details.ipv6.src_addr) << '\n';
        std::cout << "IPv6 Destination: " << pfl::format_ipv6_address(details.ipv6.dst_addr) << '\n';
        std::cout << "Next Header: " << static_cast<unsigned>(details.ipv6.next_header) << '\n';
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
}

void print_summary(const pfl::CaptureSession& session, const std::string_view label, const std::string_view value) {
    std::cout << label << ": " << value << '\n';
    if (session.has_capture()) {
        std::cout << "Source Capture: " << session.capture_path().string() << '\n';
    }
    std::cout << "Packets: " << session.summary().packet_count << '\n';
    std::cout << "Flows: " << session.summary().flow_count << '\n';
    std::cout << "Bytes: " << session.summary().total_bytes << '\n';
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    const std::string_view command = argv[1];
    const char* file = argv[2];

    if (command == "summary") {
        if (argc != 3) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_session(file, session)) {
            return 1;
        }

        print_summary(session, "File", file);
        return 0;
    }

    if (command == "load-index-summary") {
        if (argc != 3) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!load_index_session(file, session)) {
            return 1;
        }

        print_summary(session, "Index", file);
        return 0;
    }

    if (command == "flows") {
        if (argc != 3) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_session(file, session)) {
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
        const auto packet_index = parse_packet_index(argc, argv);
        if (!packet_index.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_session(file, session)) {
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
        const auto packet_index = parse_packet_index(argc, argv);
        if (!packet_index.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_session(file, session)) {
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
        const auto export_args = parse_export_args(argc, argv);
        if (!export_args.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_session(file, session)) {
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
        const auto output_args = parse_output_path_args(argc, argv);
        if (!output_args.has_value()) {
            print_usage();
            return 1;
        }

        pfl::CaptureSession session {};
        if (!open_session(file, session)) {
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

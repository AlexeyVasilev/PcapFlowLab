#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "app/session/CaptureSession.h"
#include "cli/CliFormatting.h"

namespace {

void print_usage() {
    std::cout
        << "Usage:\n"
        << "  pcap-flow-lab summary <file>\n"
        << "  pcap-flow-lab flows <file>\n"
        << "  pcap-flow-lab inspect-packet <file> --packet-index <N>\n"
        << "  pcap-flow-lab hex <file> --packet-index <N>\n";
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

bool open_session(const char* file, pfl::CaptureSession& session) {
    if (session.open_capture(file)) {
        return true;
    }

    std::cerr << "Failed to open capture: " << file << '\n';
    return false;
}

struct PrintableFlowRow {
    std::string family {};
    std::string protocol {};
    std::string endpoint_a {};
    std::string endpoint_b {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

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

        std::cout << "File: " << file << '\n';
        std::cout << "Packets: " << session.summary().packet_count << '\n';
        std::cout << "Flows: " << session.summary().flow_count << '\n';
        std::cout << "Bytes: " << session.summary().total_bytes << '\n';
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

        std::vector<PrintableFlowRow> rows {};
        for (const auto& row : session.list_ipv4_flows()) {
            rows.push_back(PrintableFlowRow {
                .family = "v4",
                .protocol = pfl::format_protocol(row.key.protocol),
                .endpoint_a = pfl::format_endpoint(row.key.first),
                .endpoint_b = pfl::format_endpoint(row.key.second),
                .packet_count = row.packet_count,
                .total_bytes = row.total_bytes,
            });
        }

        for (const auto& row : session.list_ipv6_flows()) {
            rows.push_back(PrintableFlowRow {
                .family = "v6",
                .protocol = pfl::format_protocol(row.key.protocol),
                .endpoint_a = pfl::format_endpoint(row.key.first),
                .endpoint_b = pfl::format_endpoint(row.key.second),
                .packet_count = row.packet_count,
                .total_bytes = row.total_bytes,
            });
        }

        std::sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) {
            if (left.total_bytes != right.total_bytes) {
                return left.total_bytes > right.total_bytes;
            }

            if (left.packet_count != right.packet_count) {
                return left.packet_count > right.packet_count;
            }

            if (left.family != right.family) {
                return left.family < right.family;
            }

            return left.endpoint_a < right.endpoint_a;
        });

        std::cout << "Family  Proto  Endpoint A                      Endpoint B                      Packets  Bytes\n";
        for (const auto& row : rows) {
            std::cout << std::left
                      << std::setw(8) << row.family
                      << std::setw(7) << row.protocol
                      << std::setw(32) << row.endpoint_a
                      << std::setw(32) << row.endpoint_b
                      << std::right
                      << std::setw(8) << row.packet_count
                      << std::setw(7) << row.total_bytes
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

    print_usage();
    return 1;
}

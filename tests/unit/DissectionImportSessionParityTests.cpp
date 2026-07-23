#include "CommonDirectDissectionTestSupport.h"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "core/index/CaptureIndex.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/services/CaptureImportApplication.h"
#include "core/services/CaptureImporter.h"
#include "core/services/DissectionImportAdapter.h"

namespace pfl::tests {

using namespace common_direct_test;
using namespace dissection;

namespace {

const DissectionRegistry& require_common_direct_registry() {
    static const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    return *built.registry;
}

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

struct CaptureSummarySnapshot {
    std::uint64_t packet_count {0U};
    std::uint64_t flow_count {0U};
    std::uint64_t total_bytes {0U};

    [[nodiscard]] friend constexpr bool operator==(const CaptureSummarySnapshot&, const CaptureSummarySnapshot&) = default;
};

struct HintSearchSnapshot {
    std::uint8_t unresolved_payload_attempt_count {0U};
    bool unresolved_payload_attempt_budget_exhausted {false};

    [[nodiscard]] friend constexpr bool operator==(const HintSearchSnapshot&, const HintSearchSnapshot&) = default;
};

struct FlowSnapshotV4 {
    FlowKeyV4 key {};
    std::string protocol_path {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};

    [[nodiscard]] friend bool operator==(const FlowSnapshotV4&, const FlowSnapshotV4&) = default;
};

struct FlowSnapshotV6 {
    FlowKeyV6 key {};
    std::string protocol_path {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};

    [[nodiscard]] friend bool operator==(const FlowSnapshotV6&, const FlowSnapshotV6&) = default;
};

struct ConnectionSnapshotV4 {
    ConnectionKeyV4 key {};
    std::string protocol_path {};
    std::optional<FlowSnapshotV4> flow_a {};
    std::optional<FlowSnapshotV4> flow_b {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0U};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    HintSearchSnapshot hint_search_state {};

    [[nodiscard]] friend bool operator==(const ConnectionSnapshotV4&, const ConnectionSnapshotV4&) = default;
};

struct ConnectionSnapshotV6 {
    ConnectionKeyV6 key {};
    std::string protocol_path {};
    std::optional<FlowSnapshotV6> flow_a {};
    std::optional<FlowSnapshotV6> flow_b {};
    std::uint64_t packet_count {0U};
    std::uint64_t total_bytes {0U};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0U};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    HintSearchSnapshot hint_search_state {};

    [[nodiscard]] friend bool operator==(const ConnectionSnapshotV6&, const ConnectionSnapshotV6&) = default;
};

struct UnrecognizedSnapshot {
    PacketRef packet {};
    std::string reason_text {};

    [[nodiscard]] friend bool operator==(const UnrecognizedSnapshot&, const UnrecognizedSnapshot&) = default;
};

struct CaptureStateSnapshot {
    CaptureSummarySnapshot summary {};
    std::vector<std::string> protocol_registry_paths {};
    std::vector<ConnectionSnapshotV4> ipv4_connections {};
    std::vector<ConnectionSnapshotV6> ipv6_connections {};
    std::vector<UnrecognizedSnapshot> unrecognized_packets {};
};

std::string format_packet_ref(const PacketRef& packet) {
    std::ostringstream builder {};
    builder
        << "{index=" << packet.packet_index
        << ", offset=" << packet.byte_offset
        << ", dlt=" << packet.data_link_type
        << ", caplen=" << packet.captured_length
        << ", origlen=" << packet.original_length
        << ", ts=" << packet.ts_sec << '.' << packet.ts_usec
        << ", payload=" << packet.payload_length
        << ", tcp_flags=" << static_cast<unsigned int>(packet.tcp_flags)
        << ", fragmented=" << (packet.is_ip_fragmented ? "true" : "false")
        << '}';
    return builder.str();
}

std::string format_flow_key(const FlowKeyV4& key, std::string_view protocol_path) {
    std::ostringstream builder {};
    builder
        << "{src=" << key.src_addr << ':' << key.src_port
        << ", dst=" << key.dst_addr << ':' << key.dst_port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path_id=" << key.protocol_path_id
        << ", path=\"" << protocol_path << "\"}";
    return builder.str();
}

std::string format_flow_key(const FlowKeyV6& key, std::string_view protocol_path) {
    std::ostringstream builder {};
    builder
        << "{src_port=" << key.src_port
        << ", dst_port=" << key.dst_port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path_id=" << key.protocol_path_id
        << ", path=\"" << protocol_path << "\"}";
    return builder.str();
}

std::string format_connection_key(const ConnectionKeyV4& key, std::string_view protocol_path) {
    std::ostringstream builder {};
    builder
        << "{first=" << key.first.addr << ':' << key.first.port
        << ", second=" << key.second.addr << ':' << key.second.port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path_id=" << key.protocol_path_id
        << ", path=\"" << protocol_path << "\"}";
    return builder.str();
}

std::string format_connection_key(const ConnectionKeyV6& key, std::string_view protocol_path) {
    std::ostringstream builder {};
    builder
        << "{first_port=" << key.first.port
        << ", second_port=" << key.second.port
        << ", protocol=" << static_cast<int>(key.protocol)
        << ", path_id=" << key.protocol_path_id
        << ", path=\"" << protocol_path << "\"}";
    return builder.str();
}

std::string format_summary(const CaptureSummarySnapshot& summary) {
    std::ostringstream builder {};
    builder
        << "{packet_count=" << summary.packet_count
        << ", flow_count=" << summary.flow_count
        << ", total_bytes=" << summary.total_bytes
        << '}';
    return builder.str();
}

std::string require_protocol_path_text(const ProtocolPathRegistry& registry, const ProtocolPathId id) {
    if (id == kInvalidProtocolPathId) {
        return {};
    }

    const auto* path = registry.find(id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

FlowSnapshotV4 snapshot_flow(const FlowV4& flow, const ProtocolPathRegistry& registry) {
    return FlowSnapshotV4 {
        .key = flow.key,
        .protocol_path = require_protocol_path_text(registry, flow.key.protocol_path_id),
        .packets = flow.packets,
        .packet_count = flow.packet_count,
        .total_bytes = flow.total_bytes,
    };
}

FlowSnapshotV6 snapshot_flow(const FlowV6& flow, const ProtocolPathRegistry& registry) {
    return FlowSnapshotV6 {
        .key = flow.key,
        .protocol_path = require_protocol_path_text(registry, flow.key.protocol_path_id),
        .packets = flow.packets,
        .packet_count = flow.packet_count,
        .total_bytes = flow.total_bytes,
    };
}

ConnectionSnapshotV4 snapshot_connection(const ConnectionV4& connection, const ProtocolPathRegistry& registry) {
    return ConnectionSnapshotV4 {
        .key = connection.key,
        .protocol_path = require_protocol_path_text(registry, connection.key.protocol_path_id),
        .flow_a = connection.has_flow_a ? std::optional<FlowSnapshotV4> {snapshot_flow(connection.flow_a, registry)} : std::nullopt,
        .flow_b = connection.has_flow_b ? std::optional<FlowSnapshotV4> {snapshot_flow(connection.flow_b, registry)} : std::nullopt,
        .packet_count = connection.packet_count,
        .total_bytes = connection.total_bytes,
        .has_fragmented_packets = connection.has_fragmented_packets,
        .fragmented_packet_count = connection.fragmented_packet_count,
        .protocol_hint = connection.protocol_hint,
        .service_hint = connection.service_hint,
        .quic_version = connection.quic_version,
        .tls_version = connection.tls_version,
        .hint_search_state = HintSearchSnapshot {
            .unresolved_payload_attempt_count = connection.hint_search_state.unresolved_payload_attempt_count,
            .unresolved_payload_attempt_budget_exhausted =
                connection.hint_search_state.unresolved_payload_attempt_budget_exhausted,
        },
    };
}

ConnectionSnapshotV6 snapshot_connection(const ConnectionV6& connection, const ProtocolPathRegistry& registry) {
    return ConnectionSnapshotV6 {
        .key = connection.key,
        .protocol_path = require_protocol_path_text(registry, connection.key.protocol_path_id),
        .flow_a = connection.has_flow_a ? std::optional<FlowSnapshotV6> {snapshot_flow(connection.flow_a, registry)} : std::nullopt,
        .flow_b = connection.has_flow_b ? std::optional<FlowSnapshotV6> {snapshot_flow(connection.flow_b, registry)} : std::nullopt,
        .packet_count = connection.packet_count,
        .total_bytes = connection.total_bytes,
        .has_fragmented_packets = connection.has_fragmented_packets,
        .fragmented_packet_count = connection.fragmented_packet_count,
        .protocol_hint = connection.protocol_hint,
        .service_hint = connection.service_hint,
        .quic_version = connection.quic_version,
        .tls_version = connection.tls_version,
        .hint_search_state = HintSearchSnapshot {
            .unresolved_payload_attempt_count = connection.hint_search_state.unresolved_payload_attempt_count,
            .unresolved_payload_attempt_budget_exhausted =
                connection.hint_search_state.unresolved_payload_attempt_budget_exhausted,
        },
    };
}

CaptureStateSnapshot snapshot_state(const CaptureState& state) {
    CaptureStateSnapshot snapshot {
        .summary = CaptureSummarySnapshot {
            .packet_count = state.summary.packet_count,
            .flow_count = state.summary.flow_count,
            .total_bytes = state.summary.total_bytes,
        },
    };

    snapshot.protocol_registry_paths.reserve(state.protocol_path_registry.paths().size());
    for (const auto& path : state.protocol_path_registry.paths()) {
        snapshot.protocol_registry_paths.push_back(format_protocol_path(path));
    }

    auto ipv4_connections = state.ipv4_connections.list();
    std::sort(
        ipv4_connections.begin(),
        ipv4_connections.end(),
        [](const ConnectionV4* lhs, const ConnectionV4* rhs) {
            return lhs->key < rhs->key;
        }
    );
    for (const auto* connection : ipv4_connections) {
        snapshot.ipv4_connections.push_back(snapshot_connection(*connection, state.protocol_path_registry));
    }

    auto ipv6_connections = state.ipv6_connections.list();
    std::sort(
        ipv6_connections.begin(),
        ipv6_connections.end(),
        [](const ConnectionV6* lhs, const ConnectionV6* rhs) {
            return lhs->key < rhs->key;
        }
    );
    for (const auto* connection : ipv6_connections) {
        snapshot.ipv6_connections.push_back(snapshot_connection(*connection, state.protocol_path_registry));
    }

    snapshot.unrecognized_packets.reserve(state.unrecognized_packets.size());
    for (const auto& record : state.unrecognized_packets) {
        snapshot.unrecognized_packets.push_back(UnrecognizedSnapshot {
            .packet = record.packet,
            .reason_text = record.reason_text,
        });
    }

    return snapshot;
}

void record_mismatch(std::string_view field, std::string legacy, std::string unified) {
    std::ostringstream builder {};
    const auto context = current_test_context();
    if (!context.empty()) {
        builder << '[' << context << "] ";
    }
    builder << field << " mismatch: legacy=" << legacy << " unified=" << unified;
    record_failure_message(builder.str());
}

void expect_equal(std::string_view field, const std::string& legacy, const std::string& unified) {
    if (legacy != unified) {
        record_mismatch(field, legacy, unified);
    }
}

template <typename T>
void expect_equal(std::string_view field, const T& legacy, const T& unified) {
    if (!(legacy == unified)) {
        record_mismatch(field, std::to_string(legacy), std::to_string(unified));
    }
}

template <typename Reader>
void import_reader_with_unified_dissection(
    Reader& reader,
    CaptureState& state,
    const DissectionRegistry& registry,
    const FlowHintService& hint_service
) {
    while (const auto packet = reader.read_next()) {
        const auto facts = run_shadow(*packet, registry);
        auto decision = adapt_dissection_import_facts(facts);
        if (decision.has_decoded_packet()) {
            apply_decoded_packet_import(*packet, *decision.decoded_packet, state, hint_service);
            continue;
        }

        const auto packet_bytes = std::span<const std::uint8_t>(packet->bytes.data(), packet->bytes.size());
        apply_unrecognized_packet_import(*packet, packet_bytes, state, hint_service);
    }
}

CaptureState import_capture_with_legacy_decoder_for_test(
    const std::filesystem::path& capture_path,
    const CaptureImportOptions& options = {}
) {
    CaptureImporter importer {};
    CaptureState state {};
    const auto result = importer.import_capture_result(capture_path, state, options, nullptr);
    PFL_EXPECT(result != CaptureImportResult::failure);
    return state;
}

CaptureState import_capture_with_unified_dissection_for_test(
    const std::filesystem::path& capture_path,
    const CaptureImportOptions& options = {}
) {
    CaptureState state {};
    const auto& registry = require_common_direct_registry();
    const FlowHintService hint_service {options.settings, true};

    switch (detect_capture_source_format(capture_path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        PFL_REQUIRE(reader.open(capture_path));
        import_reader_with_unified_dissection(reader, state, registry, hint_service);
        PFL_EXPECT(!reader.has_error());
        break;
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        PFL_REQUIRE(reader.open(capture_path));
        import_reader_with_unified_dissection(reader, state, registry, hint_service);
        PFL_EXPECT(!reader.has_error());
        break;
    }
    default:
        PFL_REQUIRE(false);
    }

    return state;
}

void expect_packet_refs_equal(
    const std::string& label,
    const std::vector<PacketRef>& legacy,
    const std::vector<PacketRef>& unified
) {
    expect_equal(label + ".packet_count", legacy.size(), unified.size());
    const auto shared_size = std::min(legacy.size(), unified.size());
    for (std::size_t index = 0U; index < shared_size; ++index) {
        if (legacy[index] != unified[index]) {
            record_mismatch(
                label + ".packet[" + std::to_string(index) + ']',
                format_packet_ref(legacy[index]),
                format_packet_ref(unified[index])
            );
        }
    }
}

void expect_flow_equal(const std::string& label, const FlowSnapshotV4& legacy, const FlowSnapshotV4& unified) {
    if (legacy.key != unified.key) {
        record_mismatch(label + ".key", format_flow_key(legacy.key, legacy.protocol_path), format_flow_key(unified.key, unified.protocol_path));
    }
    expect_equal(label + ".protocol_path", legacy.protocol_path, unified.protocol_path);
    expect_equal(label + ".packet_count", legacy.packet_count, unified.packet_count);
    expect_equal(label + ".total_bytes", legacy.total_bytes, unified.total_bytes);
    expect_packet_refs_equal(label + ".packets", legacy.packets, unified.packets);
}

void expect_flow_equal(const std::string& label, const FlowSnapshotV6& legacy, const FlowSnapshotV6& unified) {
    if (legacy.key != unified.key) {
        record_mismatch(label + ".key", format_flow_key(legacy.key, legacy.protocol_path), format_flow_key(unified.key, unified.protocol_path));
    }
    expect_equal(label + ".protocol_path", legacy.protocol_path, unified.protocol_path);
    expect_equal(label + ".packet_count", legacy.packet_count, unified.packet_count);
    expect_equal(label + ".total_bytes", legacy.total_bytes, unified.total_bytes);
    expect_packet_refs_equal(label + ".packets", legacy.packets, unified.packets);
}

void expect_connection_equal(
    const std::string& label,
    const ConnectionSnapshotV4& legacy,
    const ConnectionSnapshotV4& unified
) {
    if (legacy.key != unified.key) {
        record_mismatch(
            label + ".key",
            format_connection_key(legacy.key, legacy.protocol_path),
            format_connection_key(unified.key, unified.protocol_path)
        );
    }
    expect_equal(label + ".protocol_path", legacy.protocol_path, unified.protocol_path);
    expect_equal(label + ".packet_count", legacy.packet_count, unified.packet_count);
    expect_equal(label + ".total_bytes", legacy.total_bytes, unified.total_bytes);
    expect_equal(label + ".has_fragmented_packets", legacy.has_fragmented_packets ? 1 : 0, unified.has_fragmented_packets ? 1 : 0);
    expect_equal(label + ".fragmented_packet_count", legacy.fragmented_packet_count, unified.fragmented_packet_count);
    expect_equal(label + ".protocol_hint", static_cast<int>(legacy.protocol_hint), static_cast<int>(unified.protocol_hint));
    expect_equal(label + ".service_hint", legacy.service_hint, unified.service_hint);
    expect_equal(label + ".quic_version", static_cast<int>(legacy.quic_version), static_cast<int>(unified.quic_version));
    expect_equal(label + ".tls_version", static_cast<int>(legacy.tls_version), static_cast<int>(unified.tls_version));
    expect_equal(
        label + ".hint_search_count",
        static_cast<unsigned int>(legacy.hint_search_state.unresolved_payload_attempt_count),
        static_cast<unsigned int>(unified.hint_search_state.unresolved_payload_attempt_count)
    );
    expect_equal(
        label + ".hint_search_exhausted",
        legacy.hint_search_state.unresolved_payload_attempt_budget_exhausted ? 1 : 0,
        unified.hint_search_state.unresolved_payload_attempt_budget_exhausted ? 1 : 0
    );

    expect_equal(label + ".has_flow_a", legacy.flow_a.has_value() ? 1 : 0, unified.flow_a.has_value() ? 1 : 0);
    expect_equal(label + ".has_flow_b", legacy.flow_b.has_value() ? 1 : 0, unified.flow_b.has_value() ? 1 : 0);
    if (legacy.flow_a.has_value() && unified.flow_a.has_value()) {
        expect_flow_equal(label + ".flow_a", *legacy.flow_a, *unified.flow_a);
    }
    if (legacy.flow_b.has_value() && unified.flow_b.has_value()) {
        expect_flow_equal(label + ".flow_b", *legacy.flow_b, *unified.flow_b);
    }
}

void expect_connection_equal(
    const std::string& label,
    const ConnectionSnapshotV6& legacy,
    const ConnectionSnapshotV6& unified
) {
    if (legacy.key != unified.key) {
        record_mismatch(
            label + ".key",
            format_connection_key(legacy.key, legacy.protocol_path),
            format_connection_key(unified.key, unified.protocol_path)
        );
    }
    expect_equal(label + ".protocol_path", legacy.protocol_path, unified.protocol_path);
    expect_equal(label + ".packet_count", legacy.packet_count, unified.packet_count);
    expect_equal(label + ".total_bytes", legacy.total_bytes, unified.total_bytes);
    expect_equal(label + ".has_fragmented_packets", legacy.has_fragmented_packets ? 1 : 0, unified.has_fragmented_packets ? 1 : 0);
    expect_equal(label + ".fragmented_packet_count", legacy.fragmented_packet_count, unified.fragmented_packet_count);
    expect_equal(label + ".protocol_hint", static_cast<int>(legacy.protocol_hint), static_cast<int>(unified.protocol_hint));
    expect_equal(label + ".service_hint", legacy.service_hint, unified.service_hint);
    expect_equal(label + ".quic_version", static_cast<int>(legacy.quic_version), static_cast<int>(unified.quic_version));
    expect_equal(label + ".tls_version", static_cast<int>(legacy.tls_version), static_cast<int>(unified.tls_version));
    expect_equal(
        label + ".hint_search_count",
        static_cast<unsigned int>(legacy.hint_search_state.unresolved_payload_attempt_count),
        static_cast<unsigned int>(unified.hint_search_state.unresolved_payload_attempt_count)
    );
    expect_equal(
        label + ".hint_search_exhausted",
        legacy.hint_search_state.unresolved_payload_attempt_budget_exhausted ? 1 : 0,
        unified.hint_search_state.unresolved_payload_attempt_budget_exhausted ? 1 : 0
    );

    expect_equal(label + ".has_flow_a", legacy.flow_a.has_value() ? 1 : 0, unified.flow_a.has_value() ? 1 : 0);
    expect_equal(label + ".has_flow_b", legacy.flow_b.has_value() ? 1 : 0, unified.flow_b.has_value() ? 1 : 0);
    if (legacy.flow_a.has_value() && unified.flow_a.has_value()) {
        expect_flow_equal(label + ".flow_a", *legacy.flow_a, *unified.flow_a);
    }
    if (legacy.flow_b.has_value() && unified.flow_b.has_value()) {
        expect_flow_equal(label + ".flow_b", *legacy.flow_b, *unified.flow_b);
    }
}

void expect_fixture_import_parity(
    const std::filesystem::path& capture_path,
    const std::string& context_label,
    const CaptureImportOptions& options = {}
) {
    const ScopedTestContext fixture_context {context_label};

    const auto legacy_state = import_capture_with_legacy_decoder_for_test(capture_path, options);
    const auto unified_state = import_capture_with_unified_dissection_for_test(capture_path, options);

    const auto legacy = snapshot_state(legacy_state);
    const auto unified = snapshot_state(unified_state);

    if (!(legacy.summary == unified.summary)) {
        record_mismatch("summary", format_summary(legacy.summary), format_summary(unified.summary));
    }

    expect_equal("protocol_registry.size", legacy.protocol_registry_paths.size(), unified.protocol_registry_paths.size());
    const auto shared_path_count = std::min(legacy.protocol_registry_paths.size(), unified.protocol_registry_paths.size());
    for (std::size_t index = 0U; index < shared_path_count; ++index) {
        expect_equal(
            "protocol_registry.path[" + std::to_string(index + 1U) + ']',
            legacy.protocol_registry_paths[index],
            unified.protocol_registry_paths[index]
        );
    }

    expect_equal("ipv4_connection_count", legacy.ipv4_connections.size(), unified.ipv4_connections.size());
    const auto shared_ipv4 = std::min(legacy.ipv4_connections.size(), unified.ipv4_connections.size());
    for (std::size_t index = 0U; index < shared_ipv4; ++index) {
        expect_connection_equal("ipv4_connection[" + std::to_string(index) + ']', legacy.ipv4_connections[index], unified.ipv4_connections[index]);
    }

    expect_equal("ipv6_connection_count", legacy.ipv6_connections.size(), unified.ipv6_connections.size());
    const auto shared_ipv6 = std::min(legacy.ipv6_connections.size(), unified.ipv6_connections.size());
    for (std::size_t index = 0U; index < shared_ipv6; ++index) {
        expect_connection_equal("ipv6_connection[" + std::to_string(index) + ']', legacy.ipv6_connections[index], unified.ipv6_connections[index]);
    }

    expect_equal("unrecognized_count", legacy.unrecognized_packets.size(), unified.unrecognized_packets.size());
    const auto shared_unrecognized = std::min(legacy.unrecognized_packets.size(), unified.unrecognized_packets.size());
    for (std::size_t index = 0U; index < shared_unrecognized; ++index) {
        const auto& legacy_record = legacy.unrecognized_packets[index];
        const auto& unified_record = unified.unrecognized_packets[index];
        if (legacy_record.packet != unified_record.packet) {
            record_mismatch(
                "unrecognized[" + std::to_string(index) + "].packet",
                format_packet_ref(legacy_record.packet),
                format_packet_ref(unified_record.packet)
            );
        }
        expect_equal(
            "unrecognized[" + std::to_string(index) + "].reason",
            legacy_record.reason_text,
            unified_record.reason_text
        );
    }
}

void expect_fixture_import_parity(
    const std::filesystem::path& relative_path,
    const CaptureImportOptions& options = {}
) {
    expect_fixture_import_parity(
        fixture_path(relative_path),
        "fixture=" + relative_path.generic_string(),
        options
    );
}

void expect_direct_and_hint_fixture_parity() {
    expect_fixture_import_parity("parsing/http/http_multi_message_3.pcap");
    expect_fixture_import_parity("parsing/tls/ipv4_tls_constricted_1.pcap");
    expect_fixture_import_parity("parsing/sctp/15_sctp_ipv4_bidirectional_flow.pcap");
}

void expect_portless_and_link_fixture_parity() {
    expect_fixture_import_parity("parsing/arp/03_arp_request_reply_ipv4.pcap");
    expect_fixture_import_parity("parsing/igmp/01_igmpv1_membership_report_mdns_group.pcap");
    expect_fixture_import_parity("parsing/linux_cooked/17_sll2_addrlen_8_ipv4_udp.pcap");
    expect_fixture_import_parity("parsing/llc_snap/07_qinq_llc_snap_ipv4_udp.pcap");
    expect_fixture_import_parity("parsing/vlan/06_qinq_arp.pcap");
}

void expect_encapsulation_fixture_parity() {
    expect_fixture_import_parity("parsing/ip_encapsulation/14_same_inner_tuple_same_outer_ipv4_two_packets.pcap");
    expect_fixture_import_parity("parsing/gre/22_gre_same_inner_tuple_same_key_two_packets.pcap");
    expect_fixture_import_parity("parsing/eoip/10_same_tunnel_id_two_packets.pcap");
    expect_fixture_import_parity("parsing/mpls_pw/16_mpls_pw_outer_vlan_inner_qinq_ipv4_udp_cw.pcap");
    expect_fixture_import_parity("parsing/ah/06_ipv4_ah_same_spi_two_packets.pcap");
    expect_fixture_import_parity("parsing/esp/04_ipv4_esp_same_spi_two_packets.pcap");
    expect_fixture_import_parity("parsing/pbb/21_pbb_outer_legacy_vlan_ipv4_udp.pcap");
}

void expect_overlay_and_fragmentation_fixture_parity() {
    expect_fixture_import_parity("parsing/vxlan/11_vxlan_inner_ipv4_tcp_bidirectional.pcap");
    expect_fixture_import_parity("parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap");
    expect_fixture_import_parity("parsing/geneve/22_geneve_identity_outer_and_inner_vlan_splits.pcap");
    expect_fixture_import_parity("parsing/gtpu/25_gtpu_outer_tagged_contexts.pcap");
    expect_fixture_import_parity("parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap");
    expect_fixture_import_parity("parsing/geneve/23_geneve_outer_ipv4_fragmentation.pcap");
    expect_fixture_import_parity("parsing/gtpu/30_gtpu_outer_ipv4_fragmentation.pcap");
}

void expect_negative_fixture_parity() {
    expect_fixture_import_parity("parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap");
    expect_fixture_import_parity("parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap");
    expect_fixture_import_parity("parsing/vxlan/29_vxlan_capture_truncation_matrix.pcap");
    expect_fixture_import_parity("parsing/linux_cooked/11_sll_unknown_protocol.pcap");
}

void expect_classic_pcap_staged_prefix_session_parity() {
    constexpr std::size_t kMinCapturedLengthForStagedImportBytes = 16U * 1024U;

    std::vector<std::uint8_t> long_hop_by_hop_header {
        17U,
        19U,
    };
    long_hop_by_hop_header.resize(160U, 0x00U);

    auto ipv6_payload = long_hop_by_hop_header;
    const auto udp_payload_length =
        static_cast<std::uint16_t>(kMinCapturedLengthForStagedImportBytes + 256U);
    const auto udp_segment = make_ipv6_udp_segment(53000U, 443U, udp_payload_length);
    ipv6_payload.insert(ipv6_payload.end(), udp_segment.begin(), udp_segment.end());

    const auto large_ipv6_packet = make_ethernet_ipv6_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
        0U,
        ipv6_payload
    );

    const auto capture_path = write_temp_pcap(
        "pfl_dissection_import_session_staged_prefix_ipv6_udp.pcap",
        make_classic_pcap_with_captured_lengths({
            ClassicPcapCapturedRecord {
                .ts_usec = 100U,
                .captured_bytes = large_ipv6_packet,
                .original_length = static_cast<std::uint32_t>(large_ipv6_packet.size() + 512U),
            },
        })
    );

    expect_fixture_import_parity(
        capture_path,
        "fixture=synthetic/classic_pcap_staged_prefix_ipv6_udp",
        {}
    );
}

void expect_geneve_packet2_keeps_only_diagnostic_path() {
    const ScopedTestContext fixture_context {
        "fixture=parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap | packet=2"
    };
    const auto packets = require_raw_fixture_packets("parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap");
    PFL_REQUIRE(packets.size() > 2U);

    const auto facts = run_shadow(packets[2], require_common_direct_registry());
    auto decision = adapt_dissection_import_facts(facts);
    PFL_EXPECT(decision.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(!decision.has_decoded_packet());
    PFL_EXPECT(decision.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_protocol_path(decision.physical_path.to_path()) == "EthernetII -> IPv4");

    CaptureState state {};
    const FlowHintService hint_service {AnalysisSettings {}, true};
    const auto packet_bytes = std::span<const std::uint8_t>(packets[2].bytes.data(), packets[2].bytes.size());
    apply_unrecognized_packet_import(packets[2], packet_bytes, state, hint_service);

    PFL_EXPECT(state.summary.packet_count == 0U);
    PFL_EXPECT(state.summary.flow_count == 0U);
    PFL_EXPECT(state.protocol_path_registry.size() == 0U);
    PFL_EXPECT(state.unrecognized_packets.size() == 1U);
}

}  // namespace

void run_dissection_import_session_parity_tests() {
    expect_direct_and_hint_fixture_parity();
    expect_portless_and_link_fixture_parity();
    expect_encapsulation_fixture_parity();
    expect_overlay_and_fragmentation_fixture_parity();
    expect_negative_fixture_parity();
    expect_classic_pcap_staged_prefix_session_parity();
    expect_geneve_packet2_keeps_only_diagnostic_path();
}

}  // namespace pfl::tests

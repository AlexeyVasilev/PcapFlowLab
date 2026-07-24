#include "tools/import_validation/ImportValidation.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <unordered_map>

namespace pfl {

namespace {

[[nodiscard]] std::string format_protocol_path_or_empty(const ProtocolPath& path) {
    return path.empty() ? std::string {} : format_protocol_path(path);
}

[[nodiscard]] std::string escape_json(std::string_view text) {
    std::ostringstream builder {};
    for (const char raw_ch : text) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        switch (ch) {
        case '\\':
            builder << "\\\\";
            break;
        case '"':
            builder << "\\\"";
            break;
        case '\b':
            builder << "\\b";
            break;
        case '\f':
            builder << "\\f";
            break;
        case '\n':
            builder << "\\n";
            break;
        case '\r':
            builder << "\\r";
            break;
        case '\t':
            builder << "\\t";
            break;
        default:
            if (ch < 0x20U) {
                builder << "\\u"
                        << std::hex
                        << std::setw(4)
                        << std::setfill('0')
                        << static_cast<unsigned int>(ch)
                        << std::dec
                        << std::setfill(' ');
            } else {
                builder << static_cast<char>(ch);
            }
            break;
        }
    }
    return builder.str();
}

[[nodiscard]] std::string quote_json_string(std::string_view text) {
    return '"' + escape_json(text) + '"';
}

[[nodiscard]] std::string format_family(const dissection::DissectionAddressFamily family) {
    switch (family) {
    case dissection::DissectionAddressFamily::ipv4:
        return "ipv4";
    case dissection::DissectionAddressFamily::ipv6:
        return "ipv6";
    default:
        return "unknown";
    }
}

[[nodiscard]] std::string format_protocol(const ProtocolId protocol) {
    return std::to_string(static_cast<int>(protocol));
}

[[nodiscard]] std::string format_ipv4_pair(const ImportValidationPacketObservation& observation) {
    std::ostringstream builder {};
    builder << observation.src_addr_v4 << "->" << observation.dst_addr_v4;
    return builder.str();
}

[[nodiscard]] std::string format_ipv6_pair(const ImportValidationPacketObservation& observation) {
    auto encode = [](const std::array<std::uint8_t, 16>& bytes) {
        std::ostringstream builder {};
        for (std::size_t index = 0U; index < bytes.size(); ++index) {
            if (index != 0U) {
                builder << ':';
            }
            builder << static_cast<unsigned int>(bytes[index]);
        }
        return builder.str();
    };

    return encode(observation.src_addr_v6) + "->" + encode(observation.dst_addr_v6);
}

[[nodiscard]] std::string format_addresses(const ImportValidationPacketObservation& observation) {
    if (!observation.has_addresses) {
        return "none";
    }
    if (observation.family == dissection::DissectionAddressFamily::ipv4) {
        return format_ipv4_pair(observation);
    }
    if (observation.family == dissection::DissectionAddressFamily::ipv6) {
        return format_ipv6_pair(observation);
    }
    return "unknown";
}

[[nodiscard]] std::string format_ports(const ImportValidationPacketObservation& observation) {
    if (!observation.has_ports) {
        return "none";
    }

    std::ostringstream builder {};
    builder << observation.src_port << "->" << observation.dst_port;
    return builder.str();
}

[[nodiscard]] std::string format_payload_length(const ImportValidationPacketObservation& observation) {
    if (!observation.has_transport_payload_length) {
        return "none";
    }
    return std::to_string(observation.captured_transport_payload_length);
}

[[nodiscard]] std::string format_tcp_flags(const ImportValidationPacketObservation& observation) {
    if (!observation.has_tcp_flags) {
        return "none";
    }
    return std::to_string(static_cast<unsigned int>(observation.tcp_flags));
}

[[nodiscard]] std::string format_parse_status(const dissection::ParseStatus status) {
    switch (status) {
    case dissection::ParseStatus::complete:
        return "complete";
    case dissection::ParseStatus::truncated:
        return "truncated";
    case dissection::ParseStatus::malformed:
        return "malformed";
    case dissection::ParseStatus::unsupported_variant:
        return "unsupported_variant";
    case dissection::ParseStatus::opaque:
        return "opaque";
    }
    return "opaque";
}

[[nodiscard]] std::string format_stop_reason(const dissection::StopReason reason) {
    switch (reason) {
    case dissection::StopReason::none:
        return "none";
    case dissection::StopReason::terminal_protocol:
        return "terminal_protocol";
    case dissection::StopReason::no_payload:
        return "no_payload";
    case dissection::StopReason::unknown_next_protocol:
        return "unknown_next_protocol";
    case dissection::StopReason::unrecognized_payload:
        return "unrecognized_payload";
    case dissection::StopReason::encrypted_payload:
        return "encrypted_payload";
    case dissection::StopReason::needs_reassembly:
        return "needs_reassembly";
    case dissection::StopReason::unsupported_variant:
        return "unsupported_variant";
    case dissection::StopReason::malformed:
        return "malformed";
    case dissection::StopReason::truncated:
        return "truncated";
    case dissection::StopReason::depth_limit:
        return "depth_limit";
    }
    return "none";
}

[[nodiscard]] std::optional<std::int64_t> packet_mismatch_numeric_delta(
    const ImportValidationPacketMismatchCategory category,
    const ImportValidationPacketObservation* legacy,
    const ImportValidationPacketObservation* unified
) {
    if (category != ImportValidationPacketMismatchCategory::payload_length ||
        legacy == nullptr ||
        unified == nullptr ||
        !legacy->has_transport_payload_length ||
        !unified->has_transport_payload_length) {
        return std::nullopt;
    }

    return static_cast<std::int64_t>(legacy->captured_transport_payload_length) -
        static_cast<std::int64_t>(unified->captured_transport_payload_length);
}

[[nodiscard]] const ImportValidationPacketObservation* select_present_observation(
    const ImportValidationPacketObservation* legacy,
    const ImportValidationPacketObservation* unified
) {
    return legacy != nullptr ? legacy : unified;
}

[[nodiscard]] std::string format_observation_presence_value(
    const ImportValidationPacketObservation* observation
) {
    return observation != nullptr ? "present" : "missing";
}

[[nodiscard]] std::string packet_field_value(
    const ImportValidationPacketObservation& observation,
    const ImportValidationPacketMismatchCategory category
) {
    switch (category) {
    case ImportValidationPacketMismatchCategory::observation_presence:
        return "present";
    case ImportValidationPacketMismatchCategory::classification:
        return format_import_validation_packet_classification(observation.classification);
    case ImportValidationPacketMismatchCategory::address_family:
        return format_family(observation.family);
    case ImportValidationPacketMismatchCategory::addresses:
        return format_addresses(observation);
    case ImportValidationPacketMismatchCategory::ports:
        return format_ports(observation);
    case ImportValidationPacketMismatchCategory::protocol:
        return format_protocol(observation.protocol);
    case ImportValidationPacketMismatchCategory::payload_length:
        return format_payload_length(observation);
    case ImportValidationPacketMismatchCategory::tcp_flags:
        return format_tcp_flags(observation);
    case ImportValidationPacketMismatchCategory::fragmentation:
        return observation.fragmented ? "true" : "false";
    case ImportValidationPacketMismatchCategory::physical_path:
        return format_protocol_path_or_empty(observation.physical_path);
    case ImportValidationPacketMismatchCategory::parse_status:
        return format_parse_status(observation.final_status);
    case ImportValidationPacketMismatchCategory::stop_reason:
        return format_stop_reason(observation.stop_reason);
    case ImportValidationPacketMismatchCategory::unrecognized_reason:
        return observation.unrecognized_reason.value_or("");
    }

    return {};
}

struct PacketMismatchGroupSignature {
    ImportValidationPacketMismatchCategory category {ImportValidationPacketMismatchCategory::classification};
    bool has_legacy_observation {true};
    bool has_unified_observation {true};
    ProtocolId legacy_protocol {ProtocolId::unknown};
    ProtocolId unified_protocol {ProtocolId::unknown};
    ProtocolPath legacy_path {};
    ProtocolPath unified_path {};
    std::optional<std::int64_t> numeric_delta {};

    [[nodiscard]] friend bool operator==(const PacketMismatchGroupSignature&, const PacketMismatchGroupSignature&) = default;
};

struct PacketMismatchGroupSignatureHash {
    [[nodiscard]] std::size_t operator()(const PacketMismatchGroupSignature& signature) const noexcept {
        std::size_t seed = static_cast<std::size_t>(signature.category);
        seed = detail::hash_combine(seed, static_cast<std::size_t>(signature.has_legacy_observation));
        seed = detail::hash_combine(seed, static_cast<std::size_t>(signature.has_unified_observation));
        seed = detail::hash_combine(seed, static_cast<std::size_t>(signature.legacy_protocol));
        seed = detail::hash_combine(seed, static_cast<std::size_t>(signature.unified_protocol));
        seed = detail::hash_combine(seed, ProtocolPathHash {}(signature.legacy_path));
        seed = detail::hash_combine(seed, ProtocolPathHash {}(signature.unified_path));
        if (signature.numeric_delta.has_value()) {
            seed = detail::hash_combine(seed, static_cast<std::size_t>(*signature.numeric_delta));
        }
        return seed;
    }
};

void note_first_divergence(
    ImportValidationFirstDivergence& first_divergence,
    const ImportValidationPacketMismatchCategory category,
    const std::uint64_t packet_index
) {
    if (!first_divergence.any_packet_index.has_value()) {
        first_divergence.any_packet_index = packet_index;
    }

    if (category == ImportValidationPacketMismatchCategory::classification &&
        !first_divergence.classification_packet_index.has_value()) {
        first_divergence.classification_packet_index = packet_index;
    }
    if (category == ImportValidationPacketMismatchCategory::physical_path &&
        !first_divergence.physical_path_packet_index.has_value()) {
        first_divergence.physical_path_packet_index = packet_index;
    }
    if (category == ImportValidationPacketMismatchCategory::payload_length &&
        !first_divergence.payload_length_packet_index.has_value()) {
        first_divergence.payload_length_packet_index = packet_index;
    }
}

void append_packet_mismatch(
    ImportValidationPacketCompareResult& result,
    std::unordered_map<PacketMismatchGroupSignature, std::size_t, PacketMismatchGroupSignatureHash>& groups_by_signature,
    const ImportValidationOptions& options,
    const ImportValidationPacketMismatchCategory category,
    const ImportValidationPacketObservation* legacy,
    const ImportValidationPacketObservation* unified
) {
    const auto* reference_observation = select_present_observation(legacy, unified);
    if (reference_observation == nullptr) {
        return;
    }

    ++result.mismatch_count;
    note_first_divergence(result.first_divergence, category, reference_observation->packet_index);

    ImportValidationPacketMismatch mismatch {
        .packet_index = reference_observation->packet_index,
        .file_offset = reference_observation->file_offset,
        .captured_length = reference_observation->captured_length,
        .original_length = reference_observation->original_length,
        .category = category,
        .legacy_value = category == ImportValidationPacketMismatchCategory::observation_presence
            ? format_observation_presence_value(legacy)
            : (legacy != nullptr ? packet_field_value(*legacy, category) : "missing"),
        .unified_value = category == ImportValidationPacketMismatchCategory::observation_presence
            ? format_observation_presence_value(unified)
            : (unified != nullptr ? packet_field_value(*unified, category) : "missing"),
        .legacy_path = legacy != nullptr ? legacy->physical_path : ProtocolPath {},
        .unified_path = unified != nullptr ? unified->physical_path : ProtocolPath {},
        .legacy_observation = legacy != nullptr ? std::optional<ImportValidationPacketObservation> {*legacy} : std::nullopt,
        .unified_observation = unified != nullptr ? std::optional<ImportValidationPacketObservation> {*unified} : std::nullopt,
    };

    if (result.mismatches.size() < options.max_reported_mismatches) {
        result.mismatches.push_back(mismatch);
    }

    const PacketMismatchGroupSignature signature {
        .category = category,
        .has_legacy_observation = legacy != nullptr,
        .has_unified_observation = unified != nullptr,
        .legacy_protocol = legacy != nullptr ? legacy->protocol : ProtocolId::unknown,
        .unified_protocol = unified != nullptr ? unified->protocol : ProtocolId::unknown,
        .legacy_path = legacy != nullptr ? legacy->physical_path : ProtocolPath {},
        .unified_path = unified != nullptr ? unified->physical_path : ProtocolPath {},
        .numeric_delta = packet_mismatch_numeric_delta(category, legacy, unified),
    };

    const auto found = groups_by_signature.find(signature);
    if (found != groups_by_signature.end()) {
        auto& group = result.groups[found->second];
        ++group.occurrence_count;
        if (group.packet_indices.size() < 8U) {
            group.packet_indices.push_back(reference_observation->packet_index);
        }
        return;
    }

    if (result.groups.size() >= options.max_reported_mismatches) {
        return;
    }

    groups_by_signature.emplace(signature, result.groups.size());
    result.groups.push_back(ImportValidationPacketMismatchGroup {
        .category = category,
        .legacy_protocol = legacy != nullptr ? legacy->protocol : ProtocolId::unknown,
        .unified_protocol = unified != nullptr ? unified->protocol : ProtocolId::unknown,
        .legacy_path = legacy != nullptr ? legacy->physical_path : ProtocolPath {},
        .unified_path = unified != nullptr ? unified->physical_path : ProtocolPath {},
        .numeric_delta = signature.numeric_delta,
        .occurrence_count = 1U,
        .packet_indices = {reference_observation->packet_index},
        .representative = std::move(mismatch),
    });
}

template <typename Predicate>
void compare_packet_field(
    ImportValidationPacketCompareResult& result,
    std::unordered_map<PacketMismatchGroupSignature, std::size_t, PacketMismatchGroupSignatureHash>& groups_by_signature,
    const ImportValidationOptions& options,
    const ImportValidationPacketMismatchCategory category,
    const ImportValidationPacketObservation& legacy,
    const ImportValidationPacketObservation& unified,
    Predicate&& differs
) {
    if (differs()) {
        append_packet_mismatch(result, groups_by_signature, options, category, &legacy, &unified);
    }
}

}  // namespace

std::string format_import_validation_packet_classification(
    const ImportValidationPacketClassification classification
) {
    switch (classification) {
    case ImportValidationPacketClassification::recognized_flow:
        return "recognized_flow";
    case ImportValidationPacketClassification::recognized_non_flow:
        return "recognized_non_flow";
    case ImportValidationPacketClassification::unrecognized:
        return "unrecognized";
    }
    return "unrecognized";
}

std::string format_import_validation_packet_mismatch_category(
    const ImportValidationPacketMismatchCategory category
) {
    switch (category) {
    case ImportValidationPacketMismatchCategory::observation_presence:
        return "observation_presence";
    case ImportValidationPacketMismatchCategory::classification:
        return "classification";
    case ImportValidationPacketMismatchCategory::address_family:
        return "address_family";
    case ImportValidationPacketMismatchCategory::addresses:
        return "addresses";
    case ImportValidationPacketMismatchCategory::ports:
        return "ports";
    case ImportValidationPacketMismatchCategory::protocol:
        return "protocol";
    case ImportValidationPacketMismatchCategory::payload_length:
        return "payload_length";
    case ImportValidationPacketMismatchCategory::tcp_flags:
        return "tcp_flags";
    case ImportValidationPacketMismatchCategory::fragmentation:
        return "fragmentation";
    case ImportValidationPacketMismatchCategory::physical_path:
        return "physical_path";
    case ImportValidationPacketMismatchCategory::parse_status:
        return "parse_status";
    case ImportValidationPacketMismatchCategory::stop_reason:
        return "stop_reason";
    case ImportValidationPacketMismatchCategory::unrecognized_reason:
        return "unrecognized_reason";
    }
    return "classification";
}

std::string format_import_validation_packet_observation_json(
    const ImportValidationPacketObservation& observation
) {
    std::ostringstream builder {};
    builder
        << "{"
        << "\"packet_index\":" << observation.packet_index << ','
        << "\"file_offset\":" << observation.file_offset << ','
        << "\"captured_length\":" << observation.captured_length << ','
        << "\"original_length\":" << observation.original_length << ','
        << "\"link_type\":" << observation.link_type << ','
        << "\"classification\":" << quote_json_string(format_import_validation_packet_classification(observation.classification)) << ','
        << "\"family\":" << static_cast<int>(observation.family) << ','
        << "\"protocol\":" << static_cast<int>(observation.protocol) << ','
        << "\"has_addresses\":" << (observation.has_addresses ? "true" : "false") << ','
        << "\"src_addr_v4\":" << observation.src_addr_v4 << ','
        << "\"dst_addr_v4\":" << observation.dst_addr_v4 << ','
        << "\"has_ports\":" << (observation.has_ports ? "true" : "false") << ','
        << "\"src_port\":" << observation.src_port << ','
        << "\"dst_port\":" << observation.dst_port << ','
        << "\"has_transport_payload_length\":" << (observation.has_transport_payload_length ? "true" : "false") << ','
        << "\"captured_transport_payload_length\":" << observation.captured_transport_payload_length << ','
        << "\"has_tcp_flags\":" << (observation.has_tcp_flags ? "true" : "false") << ','
        << "\"tcp_flags\":" << static_cast<unsigned int>(observation.tcp_flags) << ','
        << "\"fragmented\":" << (observation.fragmented ? "true" : "false") << ','
        << "\"physical_path\":" << quote_json_string(format_protocol_path_or_empty(observation.physical_path)) << ','
        << "\"parse_status\":" << static_cast<int>(observation.final_status) << ','
        << "\"stop_reason\":" << static_cast<int>(observation.stop_reason) << ','
        << "\"unrecognized_reason\":";
    if (observation.unrecognized_reason.has_value()) {
        builder << quote_json_string(*observation.unrecognized_reason);
    } else {
        builder << "null";
    }
    builder << "}";
    return builder.str();
}

std::string format_import_validation_packet_mismatch_json(
    const ImportValidationPacketMismatch& mismatch
) {
    std::ostringstream builder {};
    builder
        << "{"
        << "\"packet_index\":" << mismatch.packet_index << ','
        << "\"file_offset\":" << mismatch.file_offset << ','
        << "\"captured_length\":" << mismatch.captured_length << ','
        << "\"original_length\":" << mismatch.original_length << ','
        << "\"category\":" << quote_json_string(format_import_validation_packet_mismatch_category(mismatch.category)) << ','
        << "\"legacy_value\":" << quote_json_string(mismatch.legacy_value) << ','
        << "\"unified_value\":" << quote_json_string(mismatch.unified_value) << ','
        << "\"legacy_path\":" << quote_json_string(format_protocol_path_or_empty(mismatch.legacy_path)) << ','
        << "\"unified_path\":" << quote_json_string(format_protocol_path_or_empty(mismatch.unified_path)) << ','
        << "\"legacy_observation\":";
    if (mismatch.legacy_observation.has_value()) {
        builder << format_import_validation_packet_observation_json(*mismatch.legacy_observation);
    } else {
        builder << "null";
    }
    builder << ",\"unified_observation\":";
    if (mismatch.unified_observation.has_value()) {
        builder << format_import_validation_packet_observation_json(*mismatch.unified_observation);
    } else {
        builder << "null";
    }
    builder << "}";
    return builder.str();
}

ImportValidationPacketCompareResult compare_packet_observations(
    const std::vector<ImportValidationPacketObservation>& legacy,
    const std::vector<ImportValidationPacketObservation>& unified,
    const ImportValidationOptions& options
) {
    ImportValidationPacketCompareResult result {};
    std::unordered_map<PacketMismatchGroupSignature, std::size_t, PacketMismatchGroupSignatureHash> groups_by_signature {};

    std::size_t start_index = 0U;
    const auto shared_size = std::min(legacy.size(), unified.size());
    const auto max_size = std::max(legacy.size(), unified.size());
    std::size_t end_index = shared_size;
    if (options.packet_index.has_value()) {
        start_index = static_cast<std::size_t>(*options.packet_index);
        end_index = std::min(start_index + 1U, end_index);
    }

    for (std::size_t index = start_index; index < end_index; ++index) {
        const auto& legacy_packet = legacy[index];
        const auto& unified_packet = unified[index];

        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::classification,
            legacy_packet,
            unified_packet,
            [&]() { return legacy_packet.classification != unified_packet.classification; });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::address_family,
            legacy_packet,
            unified_packet,
            [&]() { return legacy_packet.family != unified_packet.family; });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::addresses,
            legacy_packet,
            unified_packet,
            [&]() {
                return legacy_packet.has_addresses != unified_packet.has_addresses ||
                    legacy_packet.src_addr_v4 != unified_packet.src_addr_v4 ||
                    legacy_packet.dst_addr_v4 != unified_packet.dst_addr_v4 ||
                    legacy_packet.src_addr_v6 != unified_packet.src_addr_v6 ||
                    legacy_packet.dst_addr_v6 != unified_packet.dst_addr_v6;
            });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::ports,
            legacy_packet,
            unified_packet,
            [&]() {
                return legacy_packet.has_ports != unified_packet.has_ports ||
                    legacy_packet.src_port != unified_packet.src_port ||
                    legacy_packet.dst_port != unified_packet.dst_port;
            });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::protocol,
            legacy_packet,
            unified_packet,
            [&]() { return legacy_packet.protocol != unified_packet.protocol; });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::payload_length,
            legacy_packet,
            unified_packet,
            [&]() {
                return legacy_packet.has_transport_payload_length != unified_packet.has_transport_payload_length ||
                    legacy_packet.captured_transport_payload_length != unified_packet.captured_transport_payload_length;
            });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::tcp_flags,
            legacy_packet,
            unified_packet,
            [&]() {
                return legacy_packet.has_tcp_flags != unified_packet.has_tcp_flags ||
                    legacy_packet.tcp_flags != unified_packet.tcp_flags;
            });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::fragmentation,
            legacy_packet,
            unified_packet,
            [&]() { return legacy_packet.fragmented != unified_packet.fragmented; });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::physical_path,
            legacy_packet,
            unified_packet,
            [&]() { return !(legacy_packet.physical_path == unified_packet.physical_path); });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::parse_status,
            legacy_packet,
            unified_packet,
            [&]() { return legacy_packet.final_status != unified_packet.final_status; });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::stop_reason,
            legacy_packet,
            unified_packet,
            [&]() { return legacy_packet.stop_reason != unified_packet.stop_reason; });
        compare_packet_field(
            result,
            groups_by_signature,
            options,
            ImportValidationPacketMismatchCategory::unrecognized_reason,
            legacy_packet,
            unified_packet,
            [&]() { return legacy_packet.unrecognized_reason != unified_packet.unrecognized_reason; });
    }

    if (legacy.size() != unified.size()) {
        const auto tail_start = std::max(start_index, shared_size);
        const auto tail_end = options.packet_index.has_value()
            ? std::min(start_index + 1U, max_size)
            : max_size;

        for (std::size_t index = tail_start; index < tail_end; ++index) {
            if (index < legacy.size()) {
                append_packet_mismatch(
                    result,
                    groups_by_signature,
                    options,
                    ImportValidationPacketMismatchCategory::observation_presence,
                    &legacy[index],
                    nullptr);
            } else if (index < unified.size()) {
                append_packet_mismatch(
                    result,
                    groups_by_signature,
                    options,
                    ImportValidationPacketMismatchCategory::observation_presence,
                    nullptr,
                    &unified[index]);
            }
        }
    }

    return result;
}

ImportValidationDiagnoseResult diagnose_import_validation(
    const std::filesystem::path& capture_path,
    const ImportValidationOptions& options
) {
    ImportValidationDiagnoseResult result {};
    auto effective_options = options;
    if (effective_options.packet_index.has_value()) {
        const auto required_packets = *effective_options.packet_index + 1U;
        if (!effective_options.max_packets.has_value() || *effective_options.max_packets < required_packets) {
            effective_options.max_packets = required_packets;
        }
    }

    const auto legacy = run_legacy_import_validation(capture_path, effective_options);
    if (!legacy.success) {
        result.error_text = legacy.error_text;
        return result;
    }

    const auto unified = run_unified_import_validation(capture_path, effective_options);
    if (!unified.success) {
        result.error_text = unified.error_text;
        return result;
    }

    result.success = true;
    result.legacy_metrics = legacy.metrics;
    result.unified_metrics = unified.metrics;
    result.session_compare = compare_canonical_states(
        legacy.canonical_state,
        unified.canonical_state,
        effective_options);
    result.session_compare.success = true;
    result.session_compare.legacy_metrics = legacy.metrics;
    result.session_compare.unified_metrics = unified.metrics;
    result.packet_compare = compare_packet_observations(
        legacy.packet_observations,
        unified.packet_observations,
        effective_options);

    if (effective_options.packet_index.has_value()) {
        const auto index = static_cast<std::size_t>(*effective_options.packet_index);
        if (index >= legacy.packet_observations.size() && index >= unified.packet_observations.size()) {
            result.success = false;
            result.error_text = "requested packet index is outside the imported packet range";
            return result;
        }

        if (index < legacy.packet_observations.size()) {
            result.legacy_packet = legacy.packet_observations[index];
        }
        if (index < unified.packet_observations.size()) {
            result.unified_packet = unified.packet_observations[index];
        }
    }

    return result;
}

}  // namespace pfl

#pragma once

#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <span>
#include <string>
#include <vector>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"

namespace pfl::detail {

enum class CaptureIndexSectionId : std::uint32_t {
    source_info = 1,
    summary = 2,
    ipv4_connections = 3,
    ipv6_connections = 4,
};

enum class ImportCheckpointSectionId : std::uint32_t {
    source_info = 1,
    progress = 2,
    summary = 3,
    ipv4_connections = 4,
    ipv6_connections = 5,
};

bool write_bytes(std::ostream& stream, std::span<const std::uint8_t> bytes);
bool write_u8(std::ostream& stream, std::uint8_t value);
bool write_u16(std::ostream& stream, std::uint16_t value);
bool write_u32(std::ostream& stream, std::uint32_t value);
bool write_u64(std::ostream& stream, std::uint64_t value);
bool write_i64(std::ostream& stream, std::int64_t value);
bool write_string(std::ostream& stream, const std::string& value);

bool read_bytes(std::istream& stream, std::span<std::uint8_t> bytes);
bool read_u8(std::istream& stream, std::uint8_t& value);
bool read_u16(std::istream& stream, std::uint16_t& value);
bool read_u32(std::istream& stream, std::uint32_t& value);
bool read_u64(std::istream& stream, std::uint64_t& value);
bool read_i64(std::istream& stream, std::int64_t& value);
bool read_string(std::istream& stream, std::string& value);

bool write_section(std::ostream& stream, std::uint32_t section_id, std::span<const std::uint8_t> payload);
bool read_section_header(std::istream& stream, std::uint32_t& section_id, std::uint64_t& payload_size);
bool read_section_payload(std::istream& stream, std::uint64_t payload_size, std::vector<std::uint8_t>& payload);

bool write_capture_source_info(std::ostream& stream, const CaptureSourceInfo& source_info);
bool read_capture_source_info(std::istream& stream, CaptureSourceInfo& source_info);

bool write_capture_summary(std::ostream& stream, const CaptureSummary& summary);
bool read_capture_summary(std::istream& stream, CaptureSummary& summary);

bool write_packet_ref(std::ostream& stream, const PacketRef& packet);
bool read_packet_ref(std::istream& stream, PacketRef& packet);

bool write_flow(std::ostream& stream, const FlowV4& flow);
bool write_flow(std::ostream& stream, const FlowV6& flow);
bool read_flow(std::istream& stream, FlowV4& flow);
bool read_flow(std::istream& stream, FlowV6& flow);

bool write_connection(std::ostream& stream, const ConnectionV4& connection);
bool write_connection(std::ostream& stream, const ConnectionV6& connection);
bool read_connection(std::istream& stream, ConnectionV4& connection);
bool read_connection(std::istream& stream, ConnectionV6& connection);

bool write_connection_table(std::ostream& stream, const ConnectionTableV4& table);
bool write_connection_table(std::ostream& stream, const ConnectionTableV6& table);
bool read_connection_table(std::istream& stream, ConnectionTableV4& table);
bool read_connection_table(std::istream& stream, ConnectionTableV6& table);

bool write_capture_state(std::ostream& stream, const CaptureState& state);
bool read_capture_state(std::istream& stream, CaptureState& state);

std::vector<const ConnectionV4*> sorted_connections(const ConnectionTableV4& table);
std::vector<const ConnectionV6*> sorted_connections(const ConnectionTableV6& table);

}  // namespace pfl::detail

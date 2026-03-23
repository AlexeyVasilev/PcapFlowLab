#pragma once

#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"

namespace pfl::detail {

bool write_bytes(std::ofstream& stream, std::span<const std::uint8_t> bytes);
bool write_u8(std::ofstream& stream, std::uint8_t value);
bool write_u16(std::ofstream& stream, std::uint16_t value);
bool write_u32(std::ofstream& stream, std::uint32_t value);
bool write_u64(std::ofstream& stream, std::uint64_t value);
bool write_i64(std::ofstream& stream, std::int64_t value);
bool write_string(std::ofstream& stream, const std::string& value);

bool read_bytes(std::ifstream& stream, std::span<std::uint8_t> bytes);
bool read_u8(std::ifstream& stream, std::uint8_t& value);
bool read_u16(std::ifstream& stream, std::uint16_t& value);
bool read_u32(std::ifstream& stream, std::uint32_t& value);
bool read_u64(std::ifstream& stream, std::uint64_t& value);
bool read_i64(std::ifstream& stream, std::int64_t& value);
bool read_string(std::ifstream& stream, std::string& value);

bool write_capture_source_info(std::ofstream& stream, const CaptureSourceInfo& source_info);
bool read_capture_source_info(std::ifstream& stream, CaptureSourceInfo& source_info);

bool write_capture_summary(std::ofstream& stream, const CaptureSummary& summary);
bool read_capture_summary(std::ifstream& stream, CaptureSummary& summary);

bool write_packet_ref(std::ofstream& stream, const PacketRef& packet);
bool read_packet_ref(std::ifstream& stream, PacketRef& packet);

bool write_flow(std::ofstream& stream, const FlowV4& flow);
bool write_flow(std::ofstream& stream, const FlowV6& flow);
bool read_flow(std::ifstream& stream, FlowV4& flow);
bool read_flow(std::ifstream& stream, FlowV6& flow);

bool write_connection(std::ofstream& stream, const ConnectionV4& connection);
bool write_connection(std::ofstream& stream, const ConnectionV6& connection);
bool read_connection(std::ifstream& stream, ConnectionV4& connection);
bool read_connection(std::ifstream& stream, ConnectionV6& connection);

bool write_capture_state(std::ofstream& stream, const CaptureState& state);
bool read_capture_state(std::ifstream& stream, CaptureState& state);

std::vector<const ConnectionV4*> sorted_connections(const ConnectionTableV4& table);
std::vector<const ConnectionV6*> sorted_connections(const ConnectionTableV6& table);

}  // namespace pfl::detail

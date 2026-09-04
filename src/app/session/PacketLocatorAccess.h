#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndexV16.h"

namespace pfl::session_detail {

enum class PacketLocatorAccessStatus : std::uint8_t {
    ok = 0,
    not_found,
    malformed_locator,
    source_read_failed,
};

struct PacketLocatorAccessLookupResult {
    PacketLocatorAccessStatus status {PacketLocatorAccessStatus::ok};
    std::optional<CapturePacketLocatorEntry> entry {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == PacketLocatorAccessStatus::ok;
    }
};

class PacketLocatorAccessSource {
public:
    virtual ~PacketLocatorAccessSource() = default;

    [[nodiscard]] virtual PacketLocatorAccessLookupResult lookup(std::uint64_t packet_index) const = 0;
};

class ResidentPacketLocatorAccessSource final : public PacketLocatorAccessSource {
public:
    explicit ResidentPacketLocatorAccessSource(std::span<const CapturePacketLocatorEntry> entries);

    [[nodiscard]] PacketLocatorAccessLookupResult lookup(std::uint64_t packet_index) const override;

private:
    std::span<const CapturePacketLocatorEntry> entries_ {};
};

class CaptureIndexV16PacketLocatorAccessSource final : public PacketLocatorAccessSource {
public:
    CaptureIndexV16PacketLocatorAccessSource(
        std::filesystem::path index_path,
        const CaptureIndexV16MetadataTier& metadata
    );

    [[nodiscard]] PacketLocatorAccessLookupResult lookup(std::uint64_t packet_index) const override;

private:
    std::filesystem::path index_path_ {};
    std::vector<CaptureIndexV16PacketLocatorSectionInfo> locator_sections_ {};
    PacketLocatorAccessStatus initialization_status_ {PacketLocatorAccessStatus::ok};
    std::string initialization_error_detail_ {};
};

}  // namespace pfl::session_detail

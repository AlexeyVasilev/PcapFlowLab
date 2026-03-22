#pragma once

#include <filesystem>
#include <fstream>
#include <span>

#include "core/io/IByteSource.h"

namespace pfl {

class FileByteSource final : public IByteSource {
public:
    explicit FileByteSource(const std::filesystem::path& path);
    [[nodiscard]] bool is_open() const noexcept;
    bool read_at(std::uint64_t offset, std::span<std::uint8_t> buffer) override;

private:
    std::ifstream stream_ {};
};

}  // namespace pfl

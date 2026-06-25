#include "core/io/FileByteSource.h"

#include "app/session/SelectedFlowDiagnostics.h"

namespace pfl {

FileByteSource::FileByteSource(const std::filesystem::path& path)
    : stream_(path, std::ios::binary) {
    selected_flow_diagnostics::record_file_byte_source_open(stream_.is_open());
}

bool FileByteSource::is_open() const noexcept {
    return stream_.is_open();
}

bool FileByteSource::read_at(std::uint64_t offset, std::span<std::uint8_t> buffer) {
    if (!stream_.is_open()) {
        return false;
    }

    if (buffer.empty()) {
        return true;
    }

    selected_flow_diagnostics::record_file_byte_source_read(buffer.size());

    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_) {
        return false;
    }

    stream_.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    return stream_.gcount() == static_cast<std::streamsize>(buffer.size());
}

}  // namespace pfl

#include "core/services/HexDumpService.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace pfl {

std::string HexDumpService::format(std::span<const std::uint8_t> bytes) const {
    if (bytes.empty()) {
        return {};
    }

    std::ostringstream output {};
    output << std::hex << std::setfill('0');

    for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
        const auto line_size = std::min<std::size_t>(16, bytes.size() - offset);
        output << std::setw(8) << offset << "  ";

        for (std::size_t index = 0; index < 16; ++index) {
            if (index < line_size) {
                output << std::setw(2) << static_cast<unsigned>(bytes[offset + index]) << ' ';
            } else {
                output << "   ";
            }
        }

        output << " |";
        for (std::size_t index = 0; index < line_size; ++index) {
            const auto value = bytes[offset + index];
            const auto printable = std::isprint(static_cast<unsigned char>(value)) != 0;
            output << (printable ? static_cast<char>(value) : '.');
        }
        output << '|';

        if (offset + line_size < bytes.size()) {
            output << '\n';
        }
    }

    return output.str();
}

}  // namespace pfl

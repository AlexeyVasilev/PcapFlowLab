#include "core/domain/FlowKey.h"

namespace pfl {

std::size_t FlowKeyV4Hash::operator()(const FlowKeyV4& key) const noexcept {
    auto seed = detail::hash_combine(0U, std::hash<std::uint32_t> {}(key.src_addr));
    seed = detail::hash_combine(seed, std::hash<std::uint32_t> {}(key.dst_addr));
    seed = detail::hash_combine(seed, std::hash<std::uint16_t> {}(key.src_port));
    seed = detail::hash_combine(seed, std::hash<std::uint16_t> {}(key.dst_port));
    seed = detail::hash_combine(seed, std::hash<std::uint8_t> {}(static_cast<std::uint8_t>(key.protocol)));
    return seed;
}

std::size_t FlowKeyV6Hash::operator()(const FlowKeyV6& key) const noexcept {
    auto seed = detail::hash_combine(0U, detail::hash_array16(key.src_addr));
    seed = detail::hash_combine(seed, detail::hash_array16(key.dst_addr));
    seed = detail::hash_combine(seed, std::hash<std::uint16_t> {}(key.src_port));
    seed = detail::hash_combine(seed, std::hash<std::uint16_t> {}(key.dst_port));
    seed = detail::hash_combine(seed, std::hash<std::uint8_t> {}(static_cast<std::uint8_t>(key.protocol)));
    return seed;
}

}  // namespace pfl

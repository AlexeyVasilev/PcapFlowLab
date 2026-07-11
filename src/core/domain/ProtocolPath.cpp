#include "core/domain/ProtocolPath.h"

#include <iomanip>
#include <sstream>
#include <utility>

namespace pfl {

namespace detail {

[[nodiscard]] inline std::size_t hash_combine(std::size_t seed, std::size_t value) noexcept {
    return seed ^ (value + static_cast<std::size_t>(0x9e3779b97f4a7c15ULL) + (seed << 6U) + (seed >> 2U));
}

}  // namespace detail

namespace {

[[nodiscard]] std::size_t hash_protocol_layer_identifier(const ProtocolLayerIdentifier& identifier) noexcept {
    auto seed = std::hash<std::uint8_t> {}(static_cast<std::uint8_t>(identifier.kind));
    seed = detail::hash_combine(seed, std::hash<std::uint64_t> {}(identifier.value));
    return seed;
}

[[nodiscard]] std::string format_hex_value(const std::uint64_t value, const int width) {
    std::ostringstream builder {};
    builder << "0x" << std::hex << std::setw(width) << std::setfill('0') << value;
    return builder.str();
}

[[nodiscard]] std::string protocol_layer_kind_label(const ProtocolLayerKind kind) {
    switch (kind) {
    case ProtocolLayerKind::ethernet_ii:
        return "EthernetII";
    case ProtocolLayerKind::ieee8023:
        return "IEEE 802.3";
    case ProtocolLayerKind::llc_snap:
        return "LLC/SNAP";
    case ProtocolLayerKind::linux_sll:
        return "LinuxSll";
    case ProtocolLayerKind::linux_sll2:
        return "LinuxSll2";
    case ProtocolLayerKind::vlan:
        return "VLAN";
    case ProtocolLayerKind::mpls:
        return "MPLS";
    case ProtocolLayerKind::mpls_pw:
        return "MPLS PW";
    case ProtocolLayerKind::pbb:
        return "PBB";
    case ProtocolLayerKind::pppoe:
        return "PPPoE";
    case ProtocolLayerKind::ppp:
        return "PPP";
    case ProtocolLayerKind::macsec:
        return "MACsec";
    case ProtocolLayerKind::ipv4:
        return "IPv4";
    case ProtocolLayerKind::ipv6:
        return "IPv6";
    case ProtocolLayerKind::tcp:
        return "TCP";
    case ProtocolLayerKind::udp:
        return "UDP";
    case ProtocolLayerKind::sctp:
        return "SCTP";
    case ProtocolLayerKind::icmp:
        return "ICMP";
    case ProtocolLayerKind::icmpv6:
        return "ICMPv6";
    case ProtocolLayerKind::arp:
        return "ARP";
    case ProtocolLayerKind::vxlan:
        return "VXLAN";
    case ProtocolLayerKind::geneve:
        return "Geneve";
    case ProtocolLayerKind::gtpu:
        return "GTP-U";
    case ProtocolLayerKind::gre:
        return "GRE";
    case ProtocolLayerKind::unknown:
    default:
        return "Unknown";
    }
}

[[nodiscard]] bool protocol_path_equals_view(const ProtocolPathView view, const ProtocolPath& path) noexcept {
    if (view.size() != path.size()) {
        return false;
    }

    for (std::size_t index = 0; index < view.size(); ++index) {
        if (view[index] != path[index]) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] std::size_t hash_protocol_path_view(const ProtocolPathView view) noexcept {
    auto seed = std::hash<std::size_t> {}(view.size());
    for (const auto& layer : view) {
        seed = detail::hash_combine(seed, LayerKeyHash {}(layer));
    }
    return seed;
}

}  // namespace

std::size_t LayerKeyHash::operator()(const LayerKey& key) const noexcept {
    auto seed = std::hash<std::uint16_t> {}(static_cast<std::uint16_t>(key.kind));
    seed = detail::hash_combine(seed, hash_protocol_layer_identifier(key.identifier));
    return seed;
}

ProtocolPath::ProtocolPath(std::initializer_list<LayerKey> layers)
    : layers_(layers) {}

ProtocolPath::ProtocolPath(std::vector<LayerKey> layers)
    : layers_(std::move(layers)) {}

bool ProtocolPath::operator==(const ProtocolPath& other) const noexcept {
    return layers_ == other.layers_;
}

std::size_t ProtocolPath::size() const noexcept {
    return layers_.size();
}

bool ProtocolPath::empty() const noexcept {
    return layers_.empty();
}

const LayerKey& ProtocolPath::operator[](const std::size_t index) const noexcept {
    return layers_[index];
}

const std::vector<LayerKey>& ProtocolPath::layers() const noexcept {
    return layers_;
}

ProtocolPathView ProtocolPath::view() const noexcept {
    return ProtocolPathView {layers_.data(), layers_.size()};
}

std::vector<LayerKey>::const_iterator ProtocolPath::begin() const noexcept {
    return layers_.begin();
}

std::vector<LayerKey>::const_iterator ProtocolPath::end() const noexcept {
    return layers_.end();
}

std::size_t ProtocolPathHash::operator()(const ProtocolPath& path) const noexcept {
    auto seed = std::hash<std::size_t> {}(path.size());
    for (const auto& layer : path) {
        seed = detail::hash_combine(seed, LayerKeyHash {}(layer));
    }
    return seed;
}

bool ProtocolPathBuilder::push(const LayerKey layer) noexcept {
    if (overflowed_ || size_ >= kMaxProtocolPathLayers) {
        overflowed_ = true;
        return false;
    }

    layers_[size_] = layer;
    ++size_;
    return true;
}

bool ProtocolPathBuilder::full() const noexcept {
    return size_ == kMaxProtocolPathLayers;
}

bool ProtocolPathBuilder::overflowed() const noexcept {
    return overflowed_;
}

std::size_t ProtocolPathBuilder::size() const noexcept {
    return size_;
}

bool ProtocolPathBuilder::empty() const noexcept {
    return size_ == 0U;
}

const LayerKey& ProtocolPathBuilder::operator[](const std::size_t index) const noexcept {
    return layers_[index];
}

ProtocolPathView ProtocolPathBuilder::view() const noexcept {
    return ProtocolPathView {layers_.data(), size_};
}

ProtocolPath ProtocolPathBuilder::to_path() const {
    std::vector<LayerKey> layers {};
    layers.reserve(size_);
    for (std::size_t index = 0; index < size_; ++index) {
        layers.push_back(layers_[index]);
    }
    return ProtocolPath {std::move(layers)};
}

void ProtocolPathBuilder::clear() noexcept {
    size_ = 0U;
    overflowed_ = false;
}

ProtocolPathId ProtocolPathRegistry::intern(const ProtocolPathView path) {
    if (path.empty()) {
        return kInvalidProtocolPathId;
    }

    const auto hash = hash_protocol_path_view(path);
    if (const auto found = ids_by_hash_.find(hash); found != ids_by_hash_.end()) {
        for (const auto id : found->second) {
            const auto* stored_path = find(id);
            if (stored_path != nullptr && protocol_path_equals_view(path, *stored_path)) {
                return id;
            }
        }
    }

    std::vector<LayerKey> layers {};
    layers.reserve(path.size());
    for (const auto& layer : path) {
        layers.push_back(layer);
    }
    return insert_unique_path(ProtocolPath {std::move(layers)}, hash);
}

ProtocolPathId ProtocolPathRegistry::intern(const ProtocolPath& path) {
    return intern(path.view());
}

ProtocolPathId ProtocolPathRegistry::intern(ProtocolPath&& path) {
    if (const auto found = ids_.find(path); found != ids_.end()) {
        return found->second;
    }

    const auto hash = hash_protocol_path_view(path.view());
    return insert_unique_path(std::move(path), hash);
}

const ProtocolPath* ProtocolPathRegistry::find(const ProtocolPathId id) const noexcept {
    if (id == kInvalidProtocolPathId) {
        return nullptr;
    }

    const auto index = static_cast<std::size_t>(id - 1U);
    if (index >= paths_.size()) {
        return nullptr;
    }

    return &paths_[index];
}

std::size_t ProtocolPathRegistry::size() const noexcept {
    return paths_.size();
}

const std::vector<ProtocolPath>& ProtocolPathRegistry::paths() const noexcept {
    return paths_;
}

ProtocolPathId ProtocolPathRegistry::insert_unique_path(ProtocolPath path, const std::size_t hash) {
    paths_.push_back(std::move(path));
    const auto id = static_cast<ProtocolPathId>(paths_.size());
    ids_.emplace(paths_.back(), id);
    ids_by_hash_[hash].push_back(id);
    return id;
}

ProtocolPathId ProtocolPathRegistry::insert_unique_path(ProtocolPath path) {
    const auto hash = hash_protocol_path_view(path.view());
    return insert_unique_path(std::move(path), hash);
}

std::string format_protocol_layer_key(const LayerKey& key) {
    switch (key.identifier.kind) {
    case ProtocolLayerIdentifierKind::none:
        return protocol_layer_kind_label(key.kind);
    case ProtocolLayerIdentifierKind::vlan_vid:
        return protocol_layer_kind_label(key.kind) + "(vid=" + std::to_string(key.identifier.value) + ")";
    case ProtocolLayerIdentifierKind::mpls_label:
        return protocol_layer_kind_label(key.kind) + "(label=" + std::to_string(key.identifier.value) + ")";
    case ProtocolLayerIdentifierKind::pbb_isid:
        return protocol_layer_kind_label(key.kind) + "(isid=" + format_hex_value(key.identifier.value, 6) + ")";
    case ProtocolLayerIdentifierKind::vxlan_vni:
        return protocol_layer_kind_label(key.kind) + "(vni=" + std::to_string(key.identifier.value) + ")";
    case ProtocolLayerIdentifierKind::geneve_vni:
        return protocol_layer_kind_label(key.kind) + "(vni=" + std::to_string(key.identifier.value) + ")";
    case ProtocolLayerIdentifierKind::gtpu_teid:
        return protocol_layer_kind_label(key.kind) + "(teid=" + format_hex_value(key.identifier.value, 8) + ")";
    }

    return protocol_layer_kind_label(key.kind);
}

std::string format_protocol_path(const ProtocolPath& path) {
    if (path.empty()) {
        return {};
    }

    std::ostringstream builder {};
    for (std::size_t index = 0; index < path.size(); ++index) {
        if (index != 0U) {
            builder << " -> ";
        }
        builder << format_protocol_layer_key(path[index]);
    }
    return builder.str();
}

}  // namespace pfl

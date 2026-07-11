#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <compare>
#include <functional>
#include <initializer_list>
#include <string>
#include <unordered_map>
#include <vector>

namespace pfl {

enum class ProtocolLayerKind : std::uint16_t {
    unknown = 0,
    ethernet_ii,
    ieee8023,
    llc_snap,
    linux_sll,
    linux_sll2,
    vlan,
    mpls,
    mpls_pw,
    pbb,
    pppoe,
    ppp,
    macsec,
    ipv4,
    ipv6,
    tcp,
    udp,
    sctp,
    icmp,
    icmpv6,
    arp,
    vxlan,
    geneve,
    gtpu,
    gre,
};

enum class ProtocolLayerIdentifierKind : std::uint8_t {
    none = 0,
    vlan_vid,
    mpls_label,
    pbb_isid,
    vxlan_vni,
    geneve_vni,
    gtpu_teid,
};

struct ProtocolLayerIdentifier {
    ProtocolLayerIdentifierKind kind {ProtocolLayerIdentifierKind::none};
    std::uint64_t value {0};

    [[nodiscard]] friend constexpr bool operator==(const ProtocolLayerIdentifier&, const ProtocolLayerIdentifier&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const ProtocolLayerIdentifier&, const ProtocolLayerIdentifier&) = default;
};

struct LayerKey {
    ProtocolLayerKind kind {ProtocolLayerKind::unknown};
    ProtocolLayerIdentifier identifier {};

    [[nodiscard]] friend constexpr bool operator==(const LayerKey&, const LayerKey&) = default;
    [[nodiscard]] friend constexpr auto operator<=>(const LayerKey&, const LayerKey&) = default;

    [[nodiscard]] static constexpr LayerKey unknown() noexcept;
    [[nodiscard]] static constexpr LayerKey ethernet_ii() noexcept;
    [[nodiscard]] static constexpr LayerKey ieee8023() noexcept;
    [[nodiscard]] static constexpr LayerKey llc_snap() noexcept;
    [[nodiscard]] static constexpr LayerKey linux_sll() noexcept;
    [[nodiscard]] static constexpr LayerKey linux_sll2() noexcept;
    [[nodiscard]] static constexpr LayerKey mpls_pw() noexcept;
    [[nodiscard]] static constexpr LayerKey pbb(std::uint32_t isid) noexcept;
    [[nodiscard]] static constexpr LayerKey pppoe() noexcept;
    [[nodiscard]] static constexpr LayerKey ppp() noexcept;
    [[nodiscard]] static constexpr LayerKey macsec() noexcept;
    [[nodiscard]] static constexpr LayerKey ipv4() noexcept;
    [[nodiscard]] static constexpr LayerKey ipv6() noexcept;
    [[nodiscard]] static constexpr LayerKey tcp() noexcept;
    [[nodiscard]] static constexpr LayerKey udp() noexcept;
    [[nodiscard]] static constexpr LayerKey sctp() noexcept;
    [[nodiscard]] static constexpr LayerKey icmp() noexcept;
    [[nodiscard]] static constexpr LayerKey icmpv6() noexcept;
    [[nodiscard]] static constexpr LayerKey arp() noexcept;
    [[nodiscard]] static constexpr LayerKey gre() noexcept;
    [[nodiscard]] static constexpr LayerKey vlan(std::uint16_t vid) noexcept;
    [[nodiscard]] static constexpr LayerKey mpls(std::uint32_t label) noexcept;
    [[nodiscard]] static constexpr LayerKey vxlan(std::uint32_t vni) noexcept;
    [[nodiscard]] static constexpr LayerKey geneve(std::uint32_t vni) noexcept;
    [[nodiscard]] static constexpr LayerKey gtpu(std::uint32_t teid) noexcept;
};

struct LayerKeyHash {
    [[nodiscard]] std::size_t operator()(const LayerKey& key) const noexcept;
};

class ProtocolPathView {
public:
    constexpr ProtocolPathView() noexcept = default;
    constexpr ProtocolPathView(const LayerKey* layers, const std::size_t size) noexcept
        : layers_(layers),
          size_(size) {}

    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return size_;
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return size_ == 0U;
    }

    [[nodiscard]] constexpr const LayerKey& operator[](const std::size_t index) const noexcept {
        return layers_[index];
    }

    [[nodiscard]] constexpr const LayerKey* data() const noexcept {
        return layers_;
    }

    [[nodiscard]] constexpr const LayerKey* begin() const noexcept {
        return layers_;
    }

    [[nodiscard]] constexpr const LayerKey* end() const noexcept {
        return layers_ + size_;
    }

private:
    const LayerKey* layers_ {nullptr};
    std::size_t size_ {0U};
};

class ProtocolPath {
public:
    ProtocolPath() = default;
    ProtocolPath(std::initializer_list<LayerKey> layers);
    explicit ProtocolPath(std::vector<LayerKey> layers);

    [[nodiscard]] bool operator==(const ProtocolPath& other) const noexcept;

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] const LayerKey& operator[](std::size_t index) const noexcept;
    [[nodiscard]] const std::vector<LayerKey>& layers() const noexcept;
    [[nodiscard]] ProtocolPathView view() const noexcept;

    [[nodiscard]] std::vector<LayerKey>::const_iterator begin() const noexcept;
    [[nodiscard]] std::vector<LayerKey>::const_iterator end() const noexcept;

private:
    std::vector<LayerKey> layers_ {};
};

struct ProtocolPathHash {
    [[nodiscard]] std::size_t operator()(const ProtocolPath& path) const noexcept;
};

using ProtocolPathId = std::uint32_t;
inline constexpr ProtocolPathId kInvalidProtocolPathId = 0U;
inline constexpr std::size_t kMaxProtocolPathLayers = 32U;

class ProtocolPathBuilder {
public:
    [[nodiscard]] bool push(LayerKey layer) noexcept;
    [[nodiscard]] bool full() const noexcept;
    [[nodiscard]] bool overflowed() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] const LayerKey& operator[](std::size_t index) const noexcept;
    [[nodiscard]] ProtocolPathView view() const noexcept;

    [[nodiscard]] ProtocolPath to_path() const;
    void clear() noexcept;

private:
    std::array<LayerKey, kMaxProtocolPathLayers> layers_ {};
    std::size_t size_ {0};
    bool overflowed_ {false};
};

class ProtocolPathRegistry {
public:
    [[nodiscard]] ProtocolPathId intern(ProtocolPathView path);
    [[nodiscard]] ProtocolPathId intern(const ProtocolPath& path);
    [[nodiscard]] ProtocolPathId intern(ProtocolPath&& path);
    [[nodiscard]] const ProtocolPath* find(ProtocolPathId id) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    [[nodiscard]] ProtocolPathId insert_unique_path(ProtocolPath path, std::size_t hash);
    [[nodiscard]] ProtocolPathId insert_unique_path(ProtocolPath path);

    std::vector<ProtocolPath> paths_ {};
    std::unordered_map<ProtocolPath, ProtocolPathId, ProtocolPathHash> ids_ {};
    std::unordered_map<std::size_t, std::vector<ProtocolPathId>> ids_by_hash_ {};
};

[[nodiscard]] std::string format_protocol_layer_key(const LayerKey& key);
[[nodiscard]] std::string format_protocol_path(const ProtocolPath& path);

constexpr LayerKey LayerKey::unknown() noexcept {
    return LayerKey {};
}

constexpr LayerKey LayerKey::ethernet_ii() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::ethernet_ii};
}

constexpr LayerKey LayerKey::ieee8023() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::ieee8023};
}

constexpr LayerKey LayerKey::llc_snap() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::llc_snap};
}

constexpr LayerKey LayerKey::linux_sll() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::linux_sll};
}

constexpr LayerKey LayerKey::linux_sll2() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::linux_sll2};
}

constexpr LayerKey LayerKey::mpls_pw() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::mpls_pw};
}

constexpr LayerKey LayerKey::pbb(const std::uint32_t isid) noexcept {
    return LayerKey {
        .kind = ProtocolLayerKind::pbb,
        .identifier = ProtocolLayerIdentifier {
            .kind = ProtocolLayerIdentifierKind::pbb_isid,
            .value = isid,
        },
    };
}

constexpr LayerKey LayerKey::pppoe() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::pppoe};
}

constexpr LayerKey LayerKey::ppp() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::ppp};
}

constexpr LayerKey LayerKey::macsec() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::macsec};
}

constexpr LayerKey LayerKey::ipv4() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::ipv4};
}

constexpr LayerKey LayerKey::ipv6() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::ipv6};
}

constexpr LayerKey LayerKey::tcp() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::tcp};
}

constexpr LayerKey LayerKey::udp() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::udp};
}

constexpr LayerKey LayerKey::sctp() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::sctp};
}

constexpr LayerKey LayerKey::icmp() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::icmp};
}

constexpr LayerKey LayerKey::icmpv6() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::icmpv6};
}

constexpr LayerKey LayerKey::arp() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::arp};
}

constexpr LayerKey LayerKey::gre() noexcept {
    return LayerKey {.kind = ProtocolLayerKind::gre};
}

constexpr LayerKey LayerKey::vlan(const std::uint16_t vid) noexcept {
    return LayerKey {
        .kind = ProtocolLayerKind::vlan,
        .identifier = ProtocolLayerIdentifier {
            .kind = ProtocolLayerIdentifierKind::vlan_vid,
            .value = vid,
        },
    };
}

constexpr LayerKey LayerKey::mpls(const std::uint32_t label) noexcept {
    return LayerKey {
        .kind = ProtocolLayerKind::mpls,
        .identifier = ProtocolLayerIdentifier {
            .kind = ProtocolLayerIdentifierKind::mpls_label,
            .value = label,
        },
    };
}

constexpr LayerKey LayerKey::vxlan(const std::uint32_t vni) noexcept {
    return LayerKey {
        .kind = ProtocolLayerKind::vxlan,
        .identifier = ProtocolLayerIdentifier {
            .kind = ProtocolLayerIdentifierKind::vxlan_vni,
            .value = vni,
        },
    };
}

constexpr LayerKey LayerKey::geneve(const std::uint32_t vni) noexcept {
    return LayerKey {
        .kind = ProtocolLayerKind::geneve,
        .identifier = ProtocolLayerIdentifier {
            .kind = ProtocolLayerIdentifierKind::geneve_vni,
            .value = vni,
        },
    };
}

constexpr LayerKey LayerKey::gtpu(const std::uint32_t teid) noexcept {
    return LayerKey {
        .kind = ProtocolLayerKind::gtpu,
        .identifier = ProtocolLayerIdentifier {
            .kind = ProtocolLayerIdentifierKind::gtpu_teid,
            .value = teid,
        },
    };
}

}  // namespace pfl

namespace std {

template <>
struct hash<pfl::LayerKey> {
    [[nodiscard]] size_t operator()(const pfl::LayerKey& key) const noexcept {
        return pfl::LayerKeyHash {}(key);
    }
};

template <>
struct hash<pfl::ProtocolPath> {
    [[nodiscard]] size_t operator()(const pfl::ProtocolPath& path) const noexcept {
        return pfl::ProtocolPathHash {}(path);
    }
};

}  // namespace std

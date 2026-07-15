#include "app/session/ProtocolPathPresentation.h"

#include <array>
#include <iomanip>
#include <optional>
#include <sstream>

namespace pfl::session_detail {

namespace {

struct ProtocolPathLayerPresentationDescriptor {
    ProtocolLayerKind kind {ProtocolLayerKind::unknown};
    const char* short_label {""};
    const char* full_name {""};
    const char* color_key {""};
    const char* background_color {""};
    const char* border_color {""};
    const char* text_color {""};
};

constexpr std::array<ProtocolPathLayerPresentationDescriptor, 26> kProtocolPathDescriptors {{
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ethernet_ii, "EII", "Ethernet II", "link", "#FFF1EC", "#1E3A8A", "#1E3A8A"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ieee8023, "802.3", "IEEE 802.3", "link", "#FFF1EC", "#047857", "#047857"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::linux_sll, "SLL", "Linux SLL", "link", "#FFF1EC", "#B45309", "#B45309"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::linux_sll2, "SLL2", "Linux SLL2", "link", "#FFF1EC", "#7C2D12", "#7C2D12"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::llc_snap, "LLC", "LLC/SNAP", "shim", "#FFF8D6", "#7E22CE", "#7E22CE"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::vlan, "Vl", "VLAN", "shim", "#FCE7F3", "#BE185D", "#BE185D"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::mpls, "M", "MPLS", "shim", "#FFF8D6", "#1D4ED8", "#1D4ED8"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::mpls_pw, "PW", "MPLS PW", "shim", "#FFF8D6", "#2563EB", "#2563EB"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::pbb, "PBB", "PBB", "shim", "#FFF8D6", "#C2410C", "#C2410C"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::pppoe, "PPPoE", "PPPoE", "shim", "#FFF8D6", "#A21CAF", "#A21CAF"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ppp, "PPP", "PPP", "shim", "#FFF8D6", "#047857", "#047857"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::macsec, "MS", "MACsec", "security", "#EEF3F5", "#546E7A", "#546E7A"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ipv4, "Ip4", "IPv4", "network", "#EAF7EA", "#2E7D32", "#2E7D32"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ipv6, "Ip6", "IPv6", "network", "#F7F1EA", "#8B5E34", "#8B5E34"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::tcp, "TCP", "TCP", "transport", "#EEF4FF", "#2563EB", "#111827"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::udp, "UDP", "UDP", "transport", "#FFF7E0", "#D18A00", "#111827"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::sctp, "SCTP", "SCTP", "transport", "#F4EEFF", "#7E57C2", "#111827"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::icmp, "ICMP", "ICMP", "control", "#fefce8", "#fde68a", "#854d0e"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::icmpv6, "ICMP6", "ICMPv6", "control", "#fefce8", "#fde68a", "#854d0e"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::arp, "ARP", "ARP", "control", "#fefce8", "#fde68a", "#854d0e"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::vxlan, "Vx", "VXLAN", "overlay", "#FBEAF3", "#9D2F6F", "#9D2F6F"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::geneve, "Gnv", "Geneve", "overlay", "#E7F7F5", "#0F766E", "#0F766E"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::gtpu, "GTP-U", "GTP-U", "overlay", "#E6F7FB", "#0891B2", "#0891B2"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::gre, "GRE", "GRE", "shim", "#FFF8D6", "#7C2D12", "#7C2D12"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::esp, "ESP", "ESP", "security", "#EEF3F5", "#546E7A", "#546E7A"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::unknown, "?", "Unknown", "unknown", "#F3F4F6", "#6B7280", "#6B7280"},
}};

const ProtocolPathLayerPresentationDescriptor& descriptor_for_kind(const ProtocolLayerKind kind) {
    for (const auto& descriptor : kProtocolPathDescriptors) {
        if (descriptor.kind == kind) {
            return descriptor;
        }
    }

    return kProtocolPathDescriptors.back();
}

std::optional<std::string> identifier_tooltip_text(const LayerKey& layer) {
    switch (layer.identifier.kind) {
    case ProtocolLayerIdentifierKind::none:
        return std::nullopt;
    case ProtocolLayerIdentifierKind::vlan_vid:
        return "VID: " + std::to_string(layer.identifier.value);
    case ProtocolLayerIdentifierKind::mpls_label:
        return "Label: " + std::to_string(layer.identifier.value);
    case ProtocolLayerIdentifierKind::pbb_isid: {
        std::ostringstream text {};
        text << "I-SID: 0x"
             << std::uppercase
             << std::hex
             << std::setw(6)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    case ProtocolLayerIdentifierKind::vxlan_vni:
    case ProtocolLayerIdentifierKind::geneve_vni:
        return "VNI: " + std::to_string(layer.identifier.value);
    case ProtocolLayerIdentifierKind::gtpu_teid: {
        std::ostringstream text {};
        text << "TEID: 0x"
             << std::uppercase
             << std::hex
             << std::setw(8)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    case ProtocolLayerIdentifierKind::gre_key: {
        std::ostringstream text {};
        text << "Key: 0x"
             << std::uppercase
             << std::hex
             << std::setw(8)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    case ProtocolLayerIdentifierKind::esp_spi: {
        std::ostringstream text {};
        text << "SPI: 0x"
             << std::uppercase
             << std::hex
             << std::setw(8)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    }

    return std::nullopt;
}

std::optional<std::string> identifier_display_suffix_text(const LayerKey& layer) {
    switch (layer.identifier.kind) {
    case ProtocolLayerIdentifierKind::none:
        return std::nullopt;
    case ProtocolLayerIdentifierKind::vlan_vid:
        return "VID " + std::to_string(layer.identifier.value);
    case ProtocolLayerIdentifierKind::mpls_label:
        return "label " + std::to_string(layer.identifier.value);
    case ProtocolLayerIdentifierKind::pbb_isid: {
        std::ostringstream text {};
        text << "I-SID 0x"
             << std::uppercase
             << std::hex
             << std::setw(6)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    case ProtocolLayerIdentifierKind::vxlan_vni:
    case ProtocolLayerIdentifierKind::geneve_vni:
        return "VNI " + std::to_string(layer.identifier.value);
    case ProtocolLayerIdentifierKind::gtpu_teid: {
        std::ostringstream text {};
        text << "TEID 0x"
             << std::uppercase
             << std::hex
             << std::setw(8)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    case ProtocolLayerIdentifierKind::gre_key: {
        std::ostringstream text {};
        text << "key 0x"
             << std::uppercase
             << std::hex
             << std::setw(8)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    case ProtocolLayerIdentifierKind::esp_spi: {
        std::ostringstream text {};
        text << "SPI 0x"
             << std::uppercase
             << std::hex
             << std::setw(8)
             << std::setfill('0')
             << layer.identifier.value;
        return text.str();
    }
    }

    return std::nullopt;
}

ProtocolPathBadgeRow badge_for_layer(const LayerKey& layer) {
    const auto& descriptor = descriptor_for_kind(layer.kind);
    auto tooltip = std::string {descriptor.full_name};
    if (const auto identifier_text = identifier_tooltip_text(layer); identifier_text.has_value()) {
        tooltip += '\n';
        tooltip += *identifier_text;
    }

    return ProtocolPathBadgeRow {
        .short_label = descriptor.short_label,
        .full_name = descriptor.full_name,
        .tooltip = std::move(tooltip),
        .color_key = descriptor.color_key,
        .background_color = descriptor.background_color,
        .border_color = descriptor.border_color,
        .text_color = descriptor.text_color,
    };
}

ProtocolPathPresentation unknown_protocol_path_presentation() {
    return ProtocolPathPresentation {
        .full_text = "Unknown protocol path",
        .compact_text = "?",
        .badges = {badge_for_layer(LayerKey::unknown())},
    };
}

}  // namespace

std::string format_protocol_path_layer_display_text(const LayerKey& layer) {
    const auto& descriptor = descriptor_for_kind(layer.kind);
    std::string text {descriptor.full_name};
    if (const auto suffix = identifier_display_suffix_text(layer); suffix.has_value()) {
        text += " (";
        text += *suffix;
        text += ')';
    }
    return text;
}

ProtocolPathPresentation build_protocol_path_presentation(const ProtocolPath* path) {
    if (path == nullptr || path->empty()) {
        return unknown_protocol_path_presentation();
    }

    ProtocolPathPresentation presentation {};
    presentation.full_text = format_protocol_path(*path);
    presentation.badges.reserve(path->size());

    std::ostringstream compact_text {};
    bool first_badge = true;
    for (const auto& layer : path->layers()) {
        auto badge = badge_for_layer(layer);
        if (!first_badge) {
            compact_text << '|';
        }
        first_badge = false;
        compact_text << badge.short_label;
        presentation.badges.push_back(std::move(badge));
    }

    presentation.compact_text = compact_text.str();
    return presentation;
}

ProtocolPathPresentation build_protocol_path_presentation(
    const ProtocolPathRegistry& registry,
    const ProtocolPathId protocol_path_id
) {
    if (protocol_path_id == kInvalidProtocolPathId) {
        return build_protocol_path_presentation(static_cast<const ProtocolPath*>(nullptr));
    }

    return build_protocol_path_presentation(registry.find(protocol_path_id));
}

std::vector<ProtocolPathLegendEntry> protocol_path_legend_entries() {
    std::vector<ProtocolPathLegendEntry> legend {};
    legend.reserve(kProtocolPathDescriptors.size());

    for (const auto& descriptor : kProtocolPathDescriptors) {
        if (descriptor.kind == ProtocolLayerKind::arp ||
            descriptor.kind == ProtocolLayerKind::icmp ||
            descriptor.kind == ProtocolLayerKind::icmpv6) {
            continue;
        }
        legend.push_back(ProtocolPathLegendEntry {
            .short_label = descriptor.short_label,
            .full_name = descriptor.full_name,
            .tooltip = descriptor.full_name,
            .color_key = descriptor.color_key,
            .background_color = descriptor.background_color,
            .border_color = descriptor.border_color,
            .text_color = descriptor.text_color,
        });
    }

    return legend;
}

}  // namespace pfl::session_detail

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

constexpr std::array<ProtocolPathLayerPresentationDescriptor, 19> kProtocolPathDescriptors {{
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ethernet_ii, "EII", "Ethernet II", "link", "#eef2ff", "#c7d2fe", "#3730a3"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ieee8023, "802.3", "IEEE 802.3", "link", "#eef2ff", "#c7d2fe", "#3730a3"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::linux_sll, "SLL", "Linux SLL", "link", "#eef2ff", "#c7d2fe", "#3730a3"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::linux_sll2, "SLL2", "Linux SLL2", "link", "#eef2ff", "#c7d2fe", "#3730a3"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::vlan, "Vl", "VLAN", "shim", "#fff7ed", "#fdba74", "#9a3412"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::mpls, "M", "MPLS", "shim", "#fff7ed", "#fdba74", "#9a3412"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ipv4, "Ip4", "IPv4", "network", "#ecfeff", "#a5f3fc", "#155e75"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::ipv6, "Ip6", "IPv6", "network", "#ecfeff", "#a5f3fc", "#155e75"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::tcp, "TCP", "TCP", "transport", "#eff6ff", "#93c5fd", "#1d4ed8"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::udp, "UDP", "UDP", "transport", "#eff6ff", "#93c5fd", "#1d4ed8"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::sctp, "SCTP", "SCTP", "transport", "#eff6ff", "#93c5fd", "#1d4ed8"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::icmp, "ICMP", "ICMP", "control", "#fefce8", "#fde68a", "#854d0e"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::icmpv6, "ICMP6", "ICMPv6", "control", "#fefce8", "#fde68a", "#854d0e"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::arp, "ARP", "ARP", "control", "#fefce8", "#fde68a", "#854d0e"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::vxlan, "Vx", "VXLAN", "overlay", "#ecfdf5", "#86efac", "#166534"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::geneve, "Gnv", "Geneve", "overlay", "#ecfdf5", "#86efac", "#166534"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::gtpu, "GTP-U", "GTP-U", "overlay", "#ecfdf5", "#86efac", "#166534"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::gre, "GRE", "GRE", "shim", "#fff7ed", "#fdba74", "#9a3412"},
    ProtocolPathLayerPresentationDescriptor {ProtocolLayerKind::unknown, "?", "Unknown", "unknown", "#e2e8f0", "#cbd5e1", "#334155"},
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

std::vector<ProtocolPathLegendEntry> protocol_path_legend_entries() {
    std::vector<ProtocolPathLegendEntry> legend {};
    legend.reserve(kProtocolPathDescriptors.size());

    for (const auto& descriptor : kProtocolPathDescriptors) {
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

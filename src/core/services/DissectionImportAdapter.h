#pragma once

#include <optional>

#include "core/decode/PacketDecoder.h"
#include "core/dissection/CommonDirectDissection.h"

namespace pfl {

struct DissectionImportDecision {
    dissection::ImportDissectionOutcome outcome {dissection::ImportDissectionOutcome::unrecognized};
    std::optional<DecodedPacket> decoded_packet {};
    dissection::ParseStatus final_status {dissection::ParseStatus::opaque};
    dissection::StopReason stop_reason {dissection::StopReason::none};
    ProtocolPathBuilder physical_path {};
    dissection::DissectionAddressFamily family {dissection::DissectionAddressFamily::unknown};
    ProtocolId terminal_protocol {ProtocolId::unknown};
    bool path_overflowed {false};

    [[nodiscard]] bool has_decoded_packet() const noexcept {
        return decoded_packet.has_value();
    }
};

[[nodiscard]] DissectionImportDecision adapt_dissection_import_facts(
    const dissection::ImportDissectionFacts& facts
) noexcept;

}  // namespace pfl

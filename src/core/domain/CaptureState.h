#pragma once

#include "core/domain/CaptureSummary.h"
#include "core/domain/ConnectionTable.h"

namespace pfl {

struct CaptureState {
    ConnectionTableV4 ipv4_connections {};
    ConnectionTableV6 ipv6_connections {};
    CaptureSummary summary {};
};

}  // namespace pfl

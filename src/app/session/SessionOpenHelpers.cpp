#include "app/session/SessionOpenHelpers.h"

#include <sstream>

#include "../../../core/open_context.h"

namespace pfl::session_detail {

namespace {

std::uintmax_t file_size_or_zero(const std::filesystem::path& path) {
    std::error_code error {};
    const auto size = std::filesystem::file_size(path, error);
    return error ? 0U : size;
}

std::string format_open_failure_message(const OpenFailureInfo& failure) {
    std::ostringstream builder {};
    builder << "Open failed";

    if (failure.has_file_offset) {
        builder << " at offset " << failure.file_offset;
    }

    if (failure.has_packet_index) {
        if (failure.has_file_offset) {
            builder << " (packet " << failure.packet_index << ')';
        } else {
            builder << " at packet " << failure.packet_index;
        }
    }

    if (failure.bytes_processed != 0U || failure.packets_processed != 0U) {
        builder << " after ";
        bool wrote_part = false;
        if (failure.bytes_processed != 0U) {
            builder << failure.bytes_processed << " bytes";
            wrote_part = true;
        }
        if (failure.packets_processed != 0U) {
            if (wrote_part) {
                builder << " and ";
            }
            builder << failure.packets_processed << " packets";
        }
    }

    if (!failure.reason.empty()) {
        builder << ": " << failure.reason;
    }

    return builder.str();
}

}  // namespace

OpenFailureInfo fallback_open_failure(const char* reason) {
    OpenFailureInfo failure {};
    failure.reason = reason;
    return failure;
}

std::string build_open_failure_message(const OpenContext* ctx, const OpenFailureInfo& fallback_failure) {
    if (ctx != nullptr && ctx->failure.has_details()) {
        return format_open_failure_message(ctx->failure);
    }

    return format_open_failure_message(fallback_failure);
}

void log_open_result(
    const PerfOpenLogger& logger,
    const PerfOpenOperationType operation_type,
    const std::filesystem::path& input_path,
    const bool success,
    const std::chrono::steady_clock::time_point started_at,
    const CaptureSummary& summary,
    const bool opened_from_index,
    const bool has_source_capture
) {
    if (!logger.enabled()) {
        return;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at
    );
    logger.append(PerfOpenRecord {
        .operation_type = operation_type,
        .input_path = input_path,
        .input_kind = PerfOpenLogger::detect_input_kind(input_path),
        .file_size_bytes = file_size_or_zero(input_path),
        .success = success,
        .elapsed_ms = static_cast<std::uint64_t>(elapsed.count()),
        .packet_count = summary.packet_count,
        .flow_count = summary.flow_count,
        .total_bytes = summary.total_bytes,
        .opened_from_index = opened_from_index,
        .has_source_capture = has_source_capture,
    });
}

}  // namespace pfl::session_detail

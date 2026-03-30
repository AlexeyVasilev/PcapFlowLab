#pragma once

#include <atomic>
#include <functional>
#include <utility>

#include "open_failure_info.h"
#include "open_progress.h"

using OpenProgressCallback = std::function<void(const OpenProgress&)>;

struct OpenContext {
    OpenProgress progress {};
    OpenProgressCallback on_progress {};
    std::atomic_bool cancel_requested {false};
    OpenFailureInfo failure {};

    void request_cancel() noexcept {
        cancel_requested.store(true, std::memory_order_relaxed);
    }

    [[nodiscard]] bool is_cancel_requested() const noexcept {
        return cancel_requested.load(std::memory_order_relaxed);
    }

    void clear_failure() {
        failure = {};
    }

    void set_failure(OpenFailureInfo failure_info) {
        failure = std::move(failure_info);
        failure.bytes_processed = progress.bytes_processed;
        failure.packets_processed = progress.packets_processed;
    }
};

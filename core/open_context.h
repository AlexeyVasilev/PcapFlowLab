#pragma once

#include <atomic>
#include <functional>

#include "open_progress.h"

using OpenProgressCallback = std::function<void(const OpenProgress&)>;

struct OpenContext {
    OpenProgress progress {};
    OpenProgressCallback on_progress {};
    std::atomic_bool cancel_requested {false};

    void request_cancel() noexcept {
        cancel_requested.store(true, std::memory_order_relaxed);
    }

    [[nodiscard]] bool is_cancel_requested() const noexcept {
        return cancel_requested.load(std::memory_order_relaxed);
    }
};

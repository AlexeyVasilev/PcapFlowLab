#pragma once

#include <functional>

#include "open_progress.h"

using OpenProgressCallback = std::function<void(const OpenProgress&)>;

struct OpenContext {
    OpenProgress progress;
    OpenProgressCallback on_progress {};
};

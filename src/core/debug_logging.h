#pragma once

namespace pfl::debug {

inline constexpr bool kDebugOpen = false;
inline constexpr bool kDebugImport = false;
inline constexpr bool kDebugIndexLoad = false;

template <bool Enabled, typename Fn>
inline void log_if(Fn&& fn) {
    if constexpr (Enabled) {
        fn();
    }
}

}  // namespace pfl::debug

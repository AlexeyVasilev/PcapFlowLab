#include <string_view>

#include "TestSupport.h"
#include "cli/CliImportMode.h"

namespace pfl::tests {

void run_cli_import_mode_tests() {
    const auto default_options = capture_import_options_for_ui_index(kCliFastImportModeIndex);
    PFL_EXPECT(default_options.mode == ImportMode::fast);

    const auto deep_options = capture_import_options_for_ui_index(kCliDeepImportModeIndex);
    PFL_EXPECT(deep_options.mode == ImportMode::deep);

    const auto fast = parse_import_mode_value("fast");
    const auto deep = parse_import_mode_value("deep");
    const auto invalid = parse_import_mode_value("weird");

    PFL_EXPECT(fast.has_value());
    PFL_EXPECT(*fast == ImportMode::fast);
    PFL_EXPECT(deep.has_value());
    PFL_EXPECT(*deep == ImportMode::deep);
    PFL_EXPECT(!invalid.has_value());
}

}  // namespace pfl::tests

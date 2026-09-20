#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pfl {

struct AnalysisSettings;

inline constexpr std::string_view kCaptureImportSettingHttpUsePathAsServiceHint =
    "http_use_path_as_service_hint";
inline constexpr std::string_view kCaptureImportSettingIgnoreVlanAndMplsLayersWhenGroupingFlows =
    "ignore_vlan_and_mpls_layers_when_grouping_flows";
inline constexpr std::string_view kCaptureImportSettingIgnoreGtpuTeidsWhenGroupingInnerFlows =
    "ignore_gtpu_teids_when_grouping_inner_flows";

inline constexpr std::uint32_t kCaptureImportSettingsMaxEntryCount = 64U;
inline constexpr std::uint32_t kCaptureImportSettingsMaxStableKeyBytes = 256U;
inline constexpr std::uint32_t kCaptureImportSettingsMaxDisplayNameBytes = 1024U;
inline constexpr std::uint32_t kCaptureImportSettingsMaxValueTextBytes = 4096U;

struct CaptureImportSettingRecord {
    std::string stable_key {};
    std::string display_name {};
    std::string value_text {};

    [[nodiscard]] friend bool operator==(
        const CaptureImportSettingRecord&,
        const CaptureImportSettingRecord&
    ) = default;
};

struct CaptureImportSettingsSnapshot {
    std::vector<CaptureImportSettingRecord> records {};

    [[nodiscard]] friend bool operator==(
        const CaptureImportSettingsSnapshot&,
        const CaptureImportSettingsSnapshot&
    ) = default;
};

enum class CaptureImportSettingsValidationErrorCode : std::uint8_t {
    too_many_entries = 0,
    empty_stable_key,
    stable_key_too_large,
    empty_display_name,
    display_name_too_large,
    value_text_too_large,
    duplicate_stable_key,
    missing_required_known_key,
    invalid_known_bool_value,
};

struct CaptureImportSettingsValidationError {
    CaptureImportSettingsValidationErrorCode code {
        CaptureImportSettingsValidationErrorCode::too_many_entries
    };
    std::string_view field {};
    std::optional<std::size_t> row_index {};

    [[nodiscard]] friend bool operator==(
        const CaptureImportSettingsValidationError&,
        const CaptureImportSettingsValidationError&
    ) = default;
};

struct CaptureImportSettingsValidationResult {
    bool ok {true};
    std::optional<CaptureImportSettingsValidationError> error {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return ok;
    }

    [[nodiscard]] friend bool operator==(
        const CaptureImportSettingsValidationResult&,
        const CaptureImportSettingsValidationResult&
    ) = default;
};

[[nodiscard]] CaptureImportSettingsSnapshot make_capture_import_settings_snapshot(
    const AnalysisSettings& settings
);
[[nodiscard]] CaptureImportSettingsValidationResult validate_capture_import_settings_snapshot(
    const CaptureImportSettingsSnapshot& snapshot
) noexcept;
[[nodiscard]] std::optional<bool> capture_import_settings_bool_value(
    const CaptureImportSettingsSnapshot& snapshot,
    std::string_view stable_key
) noexcept;

}  // namespace pfl

#include "core/domain/CaptureImportSettings.h"

#include "core/services/AnalysisSettings.h"

#include <array>

namespace pfl {

namespace {

struct KnownCaptureImportSettingDefinition {
    std::string_view stable_key;
    std::string_view display_name;
};

constexpr std::array<KnownCaptureImportSettingDefinition, 3> kKnownCaptureImportSettings {{
    {
        kCaptureImportSettingHttpUsePathAsServiceHint,
        "HTTP: use request path as service hint when Host is missing",
    },
    {
        kCaptureImportSettingIgnoreVlanAndMplsLayersWhenGroupingFlows,
        "Ignore VLAN and MPLS layers when grouping flows",
    },
    {
        kCaptureImportSettingIgnoreGtpuTeidsWhenGroupingInnerFlows,
        "Ignore GTP-U TEIDs when grouping inner flows",
    },
}};

[[nodiscard]] std::string bool_text(const bool value) {
    return value ? "true" : "false";
}

[[nodiscard]] CaptureImportSettingsValidationResult make_validation_error(
    const CaptureImportSettingsValidationErrorCode code,
    const std::string_view field,
    const std::optional<std::size_t> row_index = std::nullopt
) noexcept {
    return CaptureImportSettingsValidationResult {
        .ok = false,
        .error = CaptureImportSettingsValidationError {
            .code = code,
            .field = field,
            .row_index = row_index,
        },
    };
}

[[nodiscard]] bool is_known_capture_import_setting(const std::string_view stable_key) noexcept {
    for (const auto& definition : kKnownCaptureImportSettings) {
        if (definition.stable_key == stable_key) {
            return true;
        }
    }
    return false;
}

}  // namespace

CaptureImportSettingsSnapshot make_capture_import_settings_snapshot(const AnalysisSettings& settings) {
    return CaptureImportSettingsSnapshot {
        .records = {
            CaptureImportSettingRecord {
                .stable_key = std::string(kCaptureImportSettingHttpUsePathAsServiceHint),
                .display_name = "HTTP: use request path as service hint when Host is missing",
                .value_text = bool_text(settings.http_use_path_as_service_hint),
            },
            CaptureImportSettingRecord {
                .stable_key = std::string(kCaptureImportSettingIgnoreVlanAndMplsLayersWhenGroupingFlows),
                .display_name = "Ignore VLAN and MPLS layers when grouping flows",
                .value_text = bool_text(settings.ignore_vlan_and_mpls_layers_when_grouping_flows),
            },
            CaptureImportSettingRecord {
                .stable_key = std::string(kCaptureImportSettingIgnoreGtpuTeidsWhenGroupingInnerFlows),
                .display_name = "Ignore GTP-U TEIDs when grouping inner flows",
                .value_text = bool_text(settings.ignore_gtpu_teids_when_grouping_inner_flows),
            },
        },
    };
}

CaptureImportSettingsValidationResult validate_capture_import_settings_snapshot(
    const CaptureImportSettingsSnapshot& snapshot
) noexcept {
    if (snapshot.records.size() > kCaptureImportSettingsMaxEntryCount) {
        return make_validation_error(
            CaptureImportSettingsValidationErrorCode::too_many_entries,
            "records"
        );
    }

    for (std::size_t index = 0U; index < snapshot.records.size(); ++index) {
        const auto& record = snapshot.records[index];
        if (record.stable_key.empty()) {
            return make_validation_error(
                CaptureImportSettingsValidationErrorCode::empty_stable_key,
                "records.stable_key",
                index
            );
        }
        if (record.stable_key.size() > kCaptureImportSettingsMaxStableKeyBytes) {
            return make_validation_error(
                CaptureImportSettingsValidationErrorCode::stable_key_too_large,
                "records.stable_key",
                index
            );
        }
        if (record.display_name.empty()) {
            return make_validation_error(
                CaptureImportSettingsValidationErrorCode::empty_display_name,
                "records.display_name",
                index
            );
        }
        if (record.display_name.size() > kCaptureImportSettingsMaxDisplayNameBytes) {
            return make_validation_error(
                CaptureImportSettingsValidationErrorCode::display_name_too_large,
                "records.display_name",
                index
            );
        }
        if (record.value_text.size() > kCaptureImportSettingsMaxValueTextBytes) {
            return make_validation_error(
                CaptureImportSettingsValidationErrorCode::value_text_too_large,
                "records.value_text",
                index
            );
        }

        for (std::size_t prior_index = 0U; prior_index < index; ++prior_index) {
            if (snapshot.records[prior_index].stable_key == record.stable_key) {
                return make_validation_error(
                    CaptureImportSettingsValidationErrorCode::duplicate_stable_key,
                    "records.stable_key",
                    index
                );
            }
        }

        if (is_known_capture_import_setting(record.stable_key) &&
            record.value_text != "true" &&
            record.value_text != "false") {
            return make_validation_error(
                CaptureImportSettingsValidationErrorCode::invalid_known_bool_value,
                "records.value_text",
                index
            );
        }
    }

    for (const auto& definition : kKnownCaptureImportSettings) {
        bool found = false;
        for (const auto& record : snapshot.records) {
            if (record.stable_key == definition.stable_key) {
                found = true;
                break;
            }
        }
        if (!found) {
            return make_validation_error(
                CaptureImportSettingsValidationErrorCode::missing_required_known_key,
                definition.stable_key
            );
        }
    }

    return {};
}

std::optional<bool> capture_import_settings_bool_value(
    const CaptureImportSettingsSnapshot& snapshot,
    const std::string_view stable_key
) noexcept {
    for (const auto& record : snapshot.records) {
        if (record.stable_key != stable_key) {
            continue;
        }
        if (record.value_text == "true") {
            return true;
        }
        if (record.value_text == "false") {
            return false;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

}  // namespace pfl

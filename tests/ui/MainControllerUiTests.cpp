#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#ifdef WIN32
#include <windows.h>
#endif

#include <QApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QGuiApplication>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeyEvent>
#include <QMetaEnum>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQmlContext>
#include <QQuickItem>
#include <QQuickWindow>
#include <QQuickStyle>
#include <QStringList>
#include <QVariantMap>

#include "app/session/AdvancedFlowFilterFormat.h"
#include "app/session/CaptureSession.h"
#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "ui/app/AdvancedFlowFilterEditorModel.h"
#include "ui/app/AdvancedFlowFilterProtocolPathSelectorModel.h"
#include "ui/app/FlowListModel.h"
#include "ui/app/MainController.h"
#include "ui/app/PacketDetailsViewModel.h"
#include "ui/app/PacketListModel.h"
#include "ui/app/ProtocolPathStatsModel.h"
#include "ui/app/StreamListModel.h"
#include "ui/app/TopSummaryListModel.h"

namespace {

namespace test_support {

std::vector<pfl::tests::RecordedTestFailure>& failure_storage() {
    static std::vector<pfl::tests::RecordedTestFailure> failures {};
    return failures;
}

const char*& last_checkpoint_file() {
    static const char* value = "<none>";
    return value;
}

int& last_checkpoint_line() {
    static int value = 0;
    return value;
}

const char*& last_checkpoint_label() {
    static const char* value = "<none>";
    return value;
}

}  // namespace test_support

}  // namespace

namespace pfl::tests {

void expect(const bool condition, const char* expression, const char* file, const int line) {
    if (!condition) {
        std::ostringstream builder {};
        builder << file << ':' << line << " expectation failed: " << expression;
        record_failure_message(builder.str());
    }
}

void require(const bool condition, const char* expression, const char* file, const int line) {
    if (condition) {
        return;
    }

    std::ostringstream builder {};
    builder << file << ':' << line << " requirement failed: " << expression;
    throw TestFailure(builder.str());
}

void record_failure_message(std::string message) {
    test_support::failure_storage().push_back(RecordedTestFailure {
        .message = std::move(message),
    });
}

const std::vector<RecordedTestFailure>& recorded_failures() {
    return test_support::failure_storage();
}

bool has_recorded_failures() {
    return !test_support::failure_storage().empty();
}

void clear_recorded_failures() {
    test_support::failure_storage().clear();
}

}  // namespace pfl::tests

namespace {

void note_test_checkpoint(const char* file, const int line, const char* label) {
    test_support::last_checkpoint_file() = file;
    test_support::last_checkpoint_line() = line;
    test_support::last_checkpoint_label() = label;
}

std::string format_last_checkpoint() {
    std::ostringstream builder {};
    builder << test_support::last_checkpoint_file() << ':' << test_support::last_checkpoint_line()
            << " checkpoint: " << test_support::last_checkpoint_label();
    return builder.str();
}

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: ui.example\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::vector<std::uint8_t> make_http_request_without_host_payload() {
    constexpr char request[] =
        "GET /fallback/ui HTTP/1.1\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::vector<std::uint8_t> make_dns_query_payload() {
    std::vector<std::uint8_t> payload {};
    pfl::tests::append_be16(payload, 0x1234);
    pfl::tests::append_be16(payload, 0x0100);
    pfl::tests::append_be16(payload, 1);
    pfl::tests::append_be16(payload, 0);
    pfl::tests::append_be16(payload, 0);
    pfl::tests::append_be16(payload, 0);
    payload.push_back(3);
    payload.insert(payload.end(), {'a', 'p', 'i'});
    payload.push_back(7);
    payload.insert(payload.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    payload.push_back(0);
    pfl::tests::append_be16(payload, 1);
    pfl::tests::append_be16(payload, 1);
    return payload;
}

std::vector<std::uint8_t> bytes_payload(std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

QStringList packet_byte_view_labels(pfl::PacketDetailsViewModel* model) {
    QStringList labels {};
    if (model == nullptr) {
        return labels;
    }

    const auto descriptors = model->packetByteViewDescriptors();
    labels.reserve(static_cast<qsizetype>(descriptors.size()));
    for (const auto& descriptor_variant : descriptors) {
        const auto descriptor = descriptor_variant.toMap();
        labels.push_back(descriptor.value(QStringLiteral("label")).toString());
    }
    return labels;
}

bool packet_byte_view_label_starts_with(
    pfl::PacketDetailsViewModel* model,
    const QString& prefix
) {
    if (model == nullptr) {
        return false;
    }

    const auto descriptors = model->packetByteViewDescriptors();
    return std::any_of(descriptors.begin(), descriptors.end(), [&](const QVariant& descriptor_variant) {
        const auto descriptor = descriptor_variant.toMap();
        return descriptor.value(QStringLiteral("label")).toString().startsWith(prefix);
    });
}

QString find_packet_byte_view_stable_id_by_label_prefix(
    pfl::PacketDetailsViewModel* model,
    const QString& prefix
) {
    if (model == nullptr) {
        return {};
    }

    const auto descriptors = model->packetByteViewDescriptors();
    for (const auto& descriptor_variant : descriptors) {
        const auto descriptor = descriptor_variant.toMap();
        if (descriptor.value(QStringLiteral("label")).toString().startsWith(prefix)) {
            return descriptor.value(QStringLiteral("stableId")).toString();
        }
    }

    return {};
}

QVariantMap find_packet_byte_view_descriptor(
    pfl::PacketDetailsViewModel* model,
    const QString& stable_id
) {
    if (model == nullptr) {
        return {};
    }

    const auto descriptors = model->packetByteViewDescriptors();
    for (const auto& descriptor_variant : descriptors) {
        const auto descriptor = descriptor_variant.toMap();
        if (descriptor.value(QStringLiteral("stableId")).toString() == stable_id) {
            return descriptor;
        }
    }

    return {};
}

bool advanced_filter_option_checked(const QVariantList& options, const QString& label) {
    for (const auto& option_variant : options) {
        const auto option = option_variant.toMap();
        if (option.value(QStringLiteral("label")).toString() == label) {
            return option.value(QStringLiteral("checked")).toBool();
        }
    }

    return false;
}

bool advanced_filter_option_present(const QVariantList& options, const QString& label) {
    for (const auto& option_variant : options) {
        const auto option = option_variant.toMap();
        if (option.value(QStringLiteral("label")).toString() == label) {
            return true;
        }
    }

    return false;
}

QVariantMap advanced_filter_row_at(const QVariantList& rows, const int row) {
    for (const auto& row_variant : rows) {
        const auto candidate = row_variant.toMap();
        if (candidate.value(QStringLiteral("row")).toInt() == row) {
            return candidate;
        }
    }

    return {};
}

QVariantMap advanced_filter_metric_row_at(const QVariantList& rows, const int metric_id) {
    for (const auto& row_variant : rows) {
        const auto candidate = row_variant.toMap();
        if (candidate.value(QStringLiteral("metricId")).toInt() == metric_id) {
            return candidate;
        }
    }

    return {};
}

pfl::AdvancedFlowFilterEditorModel* advanced_filter_editor(pfl::MainController& controller) {
    return qobject_cast<pfl::AdvancedFlowFilterEditorModel*>(controller.advancedFlowFilterEditor());
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> make_tls_handshake_record(
    const std::uint8_t handshake_type,
    const std::vector<std::uint8_t>& body,
    const std::uint16_t version = 0x0303U
) {
    std::vector<std::uint8_t> handshake {};
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<std::uint8_t> record {};
    record.push_back(0x16U);
    pfl::tests::append_be16(record, version);
    pfl::tests::append_be16(record, static_cast<std::uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

std::vector<std::uint8_t> make_classic_pcap_with_lengths(
    const std::uint32_t ts_usec,
    const std::vector<std::uint8_t>& captured_packet,
    const std::uint32_t original_length
) {
    std::vector<std::uint8_t> bytes {};
    pfl::tests::append_le32(bytes, 0xa1b2c3d4U);
    pfl::tests::append_le16(bytes, 2U);
    pfl::tests::append_le16(bytes, 4U);
    pfl::tests::append_le32(bytes, 0U);
    pfl::tests::append_le32(bytes, 0U);
    pfl::tests::append_le32(bytes, 65535U);
    pfl::tests::append_le32(bytes, 1U);
    pfl::tests::append_le32(bytes, 1U);
    pfl::tests::append_le32(bytes, ts_usec);
    pfl::tests::append_le32(bytes, static_cast<std::uint32_t>(captured_packet.size()));
    pfl::tests::append_le32(bytes, original_length);
    bytes.insert(bytes.end(), captured_packet.begin(), captured_packet.end());
    return bytes;
}

#define UI_EXPECT(expr) (note_test_checkpoint(__FILE__, __LINE__, #expr), ::pfl::tests::expect((expr), #expr, __FILE__, __LINE__))
#define UI_REQUIRE(expr) (note_test_checkpoint(__FILE__, __LINE__, #expr), ::pfl::tests::require((expr), #expr, __FILE__, __LINE__))

bool wait_until(QApplication& app, const std::function<bool()>& predicate, const int timeoutMs = 10000) {
    QElapsedTimer timer {};
    timer.start();

    while (!predicate()) {
        if (timer.elapsed() >= timeoutMs) {
            return false;
        }

        app.processEvents(QEventLoop::AllEvents, 25);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    app.processEvents(QEventLoop::AllEvents, 25);
    return true;
}

bool wait_for_open_to_finish(QApplication& app, pfl::MainController& controller, const int timeoutMs = 10000) {
    return wait_until(app, [&controller]() {
        return !controller.isOpening();
    }, timeoutMs);
}

bool wait_for_smart_export_to_finish(QApplication& app, pfl::MainController& controller, const int timeoutMs = 15000) {
    return wait_until(app, [&controller]() {
        return !controller.smartExportInProgress();
    }, timeoutMs);
}

bool open_capture_and_wait(QApplication& app, pfl::MainController& controller, const std::filesystem::path& path) {
    if (!controller.openCaptureFile(QString::fromStdWString(path.wstring()))) {
        return false;
    }

    return wait_for_open_to_finish(app, controller) && controller.openErrorText().isEmpty();
}

bool open_index_and_wait(QApplication& app, pfl::MainController& controller, const std::filesystem::path& path) {
    if (!controller.openIndexFile(QString::fromStdWString(path.wstring()))) {
        return false;
    }

    return wait_for_open_to_finish(app, controller) && controller.openErrorText().isEmpty();
}

QString expected_endpoint_summary_for_flow(const pfl::FlowListModel& flow_model, const int flow_index) {
    const int row = flow_model.rowForFlowIndex(flow_index);
    if (row < 0) {
        return {};
    }

    const QModelIndex index = flow_model.index(row, 0);
    return QStringLiteral("%1:%2 \u2192 %3:%4 %5")
        .arg(flow_model.data(index, pfl::FlowListModel::AddressARole).toString())
        .arg(flow_model.data(index, pfl::FlowListModel::PortARole).toInt())
        .arg(flow_model.data(index, pfl::FlowListModel::AddressBRole).toString())
        .arg(flow_model.data(index, pfl::FlowListModel::PortBRole).toInt())
        .arg(flow_model.data(index, pfl::FlowListModel::ProtocolRole).toString());
}

struct LoadedQmlObject {
    std::unique_ptr<QQmlEngine> engine {};
    std::unique_ptr<QObject> object {};

    ~LoadedQmlObject() {
        if (auto* window = qobject_cast<QQuickWindow*>(object.get()); window != nullptr) {
            window->close();
        }
    }
};

LoadedQmlObject load_qml_component(const std::filesystem::path& relative_path, const char* component_name) {
    auto engine = std::make_unique<QQmlEngine>();
    const auto project_root = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
    const auto component_path = project_root / relative_path;
    QQmlComponent component(engine.get(), QUrl::fromLocalFile(QString::fromStdWString(component_path.wstring())));
    if (component.status() != QQmlComponent::Ready) {
        throw pfl::tests::TestFailure(component.errorString().toStdString());
    }

    QObject* object = component.create();
    if (object == nullptr) {
        throw pfl::tests::TestFailure(std::string("Failed to create ") + component_name + " component");
    }

    return LoadedQmlObject {
        .engine = std::move(engine),
        .object = std::unique_ptr<QObject>(object),
    };
}

LoadedQmlObject load_main_qml_component(pfl::MainController& controller) {
    auto engine = std::make_unique<QQmlEngine>();
    engine->rootContext()->setContextProperty(QStringLiteral("mainController"), &controller);
    const auto project_root = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
    const auto component_path = project_root / "src/ui/qml/Main.qml";
    QQmlComponent component(engine.get(), QUrl::fromLocalFile(QString::fromStdWString(component_path.wstring())));
    if (component.status() != QQmlComponent::Ready) {
        throw pfl::tests::TestFailure(component.errorString().toStdString());
    }

    QObject* object = component.create();
    if (object == nullptr) {
        throw pfl::tests::TestFailure("Failed to create Main.qml component");
    }

    if (auto* window = qobject_cast<QQuickWindow*>(object); window != nullptr) {
        window->setOpacity(0.0);
        window->setX(-20000);
        window->setY(-20000);
    }

    return LoadedQmlObject {
        .engine = std::move(engine),
        .object = std::unique_ptr<QObject>(object),
    };
}

LoadedQmlObject load_flow_analysis_pane_component() {
    return load_qml_component("src/ui/qml/components/FlowAnalysisPane.qml", "FlowAnalysisPane");
}

void emit_test_output(const std::string& text);

template <typename Function>
void run_ui_section(const std::string_view name, Function&& function) {
    note_test_checkpoint(__FILE__, __LINE__, name.data());
    emit_test_output(std::string {"Entering UI section: "} + std::string {name} + "\n");
    try {
        function();
    } catch (const pfl::tests::TestFailure& failure) {
        pfl::tests::record_failure_message(std::string {"section "} + std::string {name} + ": " + failure.what());
    } catch (const std::exception& exception) {
        pfl::tests::record_failure_message(
            std::string {"section "} + std::string {name} + " threw unexpected exception: " + exception.what()
        );
    } catch (...) {
        pfl::tests::record_failure_message(std::string {"section "} + std::string {name} + " threw unknown exception");
    }
}

void emit_test_output(const std::string& text) {
#ifdef WIN32
    static bool console_ready = false;
    if (!console_ready) {
        console_ready = true;
        AttachConsole(ATTACH_PARENT_PROCESS);
        ::freopen("CONOUT$", "w", stdout);
        ::freopen("CONOUT$", "w", stderr);
    }
#endif

#ifdef WIN32
    if (HANDLE handle = GetStdHandle(STD_ERROR_HANDLE); handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        const auto* bytes = text.data();
        const auto size = static_cast<DWORD>(text.size());
        if (WriteFile(handle, bytes, size, &written, nullptr) != 0) {
            return;
        }
    }
#endif

    std::fputs(text.c_str(), stderr);
    std::fflush(stderr);
}

[[noreturn]] void emit_termination_diagnostics_and_abort(const char* reason) {
    std::ostringstream builder {};
    builder << "UI test runner terminated unexpectedly: " << reason << '\n'
            << "Last checkpoint: " << format_last_checkpoint() << '\n';
    emit_test_output(builder.str());
    std::signal(SIGABRT, SIG_DFL);
    std::signal(SIGSEGV, SIG_DFL);
    std::signal(SIGILL, SIG_DFL);
    std::signal(SIGFPE, SIG_DFL);
    std::abort();
}

void ui_test_signal_handler(int signal_number) {
    switch (signal_number) {
    case SIGABRT:
        emit_termination_diagnostics_and_abort("SIGABRT");
    case SIGSEGV:
        emit_termination_diagnostics_and_abort("SIGSEGV");
    case SIGILL:
        emit_termination_diagnostics_and_abort("SIGILL");
    case SIGFPE:
        emit_termination_diagnostics_and_abort("SIGFPE");
    default:
        emit_termination_diagnostics_and_abort("unknown signal");
    }
}

void ui_test_terminate_handler() {
    try {
        if (const auto current = std::current_exception(); current != nullptr) {
            std::rethrow_exception(current);
        }
    } catch (const std::exception& exception) {
        std::ostringstream builder {};
        builder << "UI test runner hit std::terminate after exception: " << exception.what() << '\n'
                << "Last checkpoint: " << format_last_checkpoint() << '\n';
        emit_test_output(builder.str());
    } catch (...) {
        std::ostringstream builder {};
        builder << "UI test runner hit std::terminate with unknown exception\n"
                << "Last checkpoint: " << format_last_checkpoint() << '\n';
        emit_test_output(builder.str());
    }

    std::signal(SIGABRT, SIG_DFL);
    std::abort();
}

bool item_visible(QObject* root, const char* objectName) {
    auto* item = root->findChild<QQuickItem*>(QString::fromLatin1(objectName));
    if (item == nullptr) {
        return false;
    }

    return item->property("visible").toBool();
}

QObject* named_object(QObject* root, const char* objectName) {
    return root->findChild<QObject*>(QString::fromLatin1(objectName));
}

QQuickItem* find_quick_item_by_object_name(QQuickItem* root, const QString& object_name) {
    if (root == nullptr) {
        return nullptr;
    }

    if (root->objectName() == object_name) {
        return root;
    }

    const auto child_items = root->childItems();
    for (auto* child : child_items) {
        if (auto* match = find_quick_item_by_object_name(child, object_name); match != nullptr) {
            return match;
        }
    }

    return nullptr;
}

QQuickItem* popup_content_item(QObject* popup) {
    if (popup == nullptr) {
        return nullptr;
    }

    const auto content_item_value = popup->property("contentItem");
    if (content_item_value.isValid()) {
        if (auto* content_object = qvariant_cast<QObject*>(content_item_value);
            auto* content_item = qobject_cast<QQuickItem*>(content_object)) {
            return content_item;
        }
    }

    const auto window_value = popup->property("window");
    if (window_value.isValid()) {
        if (auto* window = qvariant_cast<QQuickWindow*>(window_value); window != nullptr) {
            return window->contentItem();
        }
    }

    return nullptr;
}

QQuickItem* popup_visual_item(QObject* popup, const char* objectName) {
    return find_quick_item_by_object_name(popup_content_item(popup), QString::fromLatin1(objectName));
}

QObject* find_object_with_text(QObject* root, const QString& text);

int qt_key_for_text_character(const QChar character) {
    if (character.isDigit()) {
        return Qt::Key_0 + character.digitValue();
    }

    if (character.isLetter()) {
        const auto upper = character.toUpper().unicode();
        if (upper >= 'A' && upper <= 'Z') {
            return Qt::Key_A + static_cast<int>(upper - 'A');
        }
    }

    switch (character.unicode()) {
    case '.':
        return Qt::Key_Period;
    case ':':
        return Qt::Key_Colon;
    case '-':
        return Qt::Key_Minus;
    case '_':
        return Qt::Key_Underscore;
    default:
        return 0;
    }
}

bool type_text_into_field(QApplication& app, QQuickWindow* window, QObject* field, const QString& text) {
    auto* item = qobject_cast<QQuickItem*>(field);
    if (window == nullptr || item == nullptr) {
        return false;
    }

    window->requestActivate();
    item->forceActiveFocus(Qt::OtherFocusReason);
    app.processEvents(QEventLoop::AllEvents, 25);

    for (const auto character : text) {
        const auto key = qt_key_for_text_character(character);
        if (key == 0) {
            return false;
        }

        auto* focus_object = QGuiApplication::focusObject();
        if (focus_object == nullptr) {
            return false;
        }

        const QString key_text(character);
        QKeyEvent press_event(QEvent::KeyPress, key, Qt::NoModifier, key_text);
        QCoreApplication::sendEvent(focus_object, &press_event);
        QKeyEvent release_event(QEvent::KeyRelease, key, Qt::NoModifier, key_text);
        QCoreApplication::sendEvent(focus_object, &release_event);
        app.processEvents(QEventLoop::AllEvents, 25);
    }

    return true;
}

QObject* find_object_with_text(QObject* root, const QString& text) {
    if (root == nullptr) {
        return nullptr;
    }

    if (root->property("text").toString() == text) {
        return root;
    }

    const auto children = root->findChildren<QObject*>();
    for (auto* child : children) {
        if (child != nullptr && child->property("text").toString() == text) {
            return child;
        }
    }

    return nullptr;
}

QStringList direct_child_tab_button_texts(QObject* root, const char* objectName) {
    QStringList labels {};
    auto* container = named_object(root, objectName);
    if (container == nullptr) {
        return labels;
    }

    const auto children = container->findChildren<QObject*>(QString {}, Qt::FindDirectChildrenOnly);
    for (auto* child : children) {
        if (child == nullptr) {
            continue;
        }

        const auto text = child->property("text");
        if (text.isValid()) {
            const auto label = text.toString();
            if (!label.isEmpty()) {
                labels.push_back(label);
            }
        }
    }

    return labels;
}

int direct_child_item_index_by_object_name(QQuickItem* root, const QString& object_name) {
    if (root == nullptr) {
        return -1;
    }

    const auto children = root->childItems();
    for (int index = 0; index < static_cast<int>(children.size()); ++index) {
        if (children[index] != nullptr && children[index]->objectName() == object_name) {
            return index;
        }
    }

    return -1;
}

QString packet_size_bucket_label(const std::uint32_t captured_length) {
    if (captured_length <= 63U) {
        return QStringLiteral("0-63");
    }
    if (captured_length <= 127U) {
        return QStringLiteral("64-127");
    }
    if (captured_length <= 255U) {
        return QStringLiteral("128-255");
    }
    if (captured_length <= 511U) {
        return QStringLiteral("256-511");
    }
    if (captured_length <= 1023U) {
        return QStringLiteral("512-1023");
    }
    if (captured_length <= 1399U) {
        return QStringLiteral("1024-1399");
    }
    if (captured_length <= 1499U) {
        return QStringLiteral("1400-1550");
    }
    if (captured_length <= 2499U) {
        return QStringLiteral("1551-2499");
    }
    if (captured_length <= 5000U) {
        return QStringLiteral("2500-5000");
    }

    return QStringLiteral("5001+");
}

qulonglong histogram_packet_count(const QVariantList& histogram, const QString& bucketLabel) {
    for (const auto& value : histogram) {
        const auto row = value.toMap();
        if (row.value(QStringLiteral("bucketLabel")).toString() == bucketLabel) {
            return row.value(QStringLiteral("packetCount")).toULongLong();
        }
    }

    return 0U;
}

qulonglong histogram_total_count(const QVariantList& histogram) {
    qulonglong total = 0U;
    for (const auto& value : histogram) {
        total += value.toMap().value(QStringLiteral("packetCount")).toULongLong();
    }

    return total;
}

QString histogram_packet_count_text(const QVariantList& histogram, const QString& bucketLabel) {
    for (const auto& value : histogram) {
        const auto row = value.toMap();
        if (row.value(QStringLiteral("bucketLabel")).toString() == bucketLabel) {
            return row.value(QStringLiteral("packetCountText")).toString();
        }
    }

    return {};
}

std::vector<std::string> read_text_file_lines(const std::filesystem::path& path) {
    std::ifstream stream {path};
    std::vector<std::string> lines {};
    std::string line {};
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::string read_text_file_text(const std::filesystem::path& path) {
    std::ifstream stream {path, std::ios::binary};
    UI_REQUIRE(stream.is_open());
    return std::string(std::istreambuf_iterator<char> {stream}, std::istreambuf_iterator<char> {});
}

std::filesystem::path write_temp_advanced_filter_file(const std::string& filename, const std::string& text) {
    const auto path = std::filesystem::temp_directory_path() / filename;
    std::ofstream stream {path, std::ios::binary | std::ios::trunc};
    UI_REQUIRE(stream.is_open());
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    UI_REQUIRE(stream.good());
    return path;
}

std::filesystem::path write_temp_advanced_filter_document(
    const std::string& filename,
    const pfl::session_detail::AdvancedFlowFilterDocument& document
) {
    const auto formatted = pfl::session_detail::format_advanced_flow_filter_text(document);
    UI_REQUIRE(formatted.status == pfl::session_detail::AdvancedFlowFilterTextFormatStatus::ok);
    return write_temp_advanced_filter_file(filename, formatted.text);
}

std::filesystem::path write_temp_sized_advanced_filter_service_document(
    const std::string& filename,
    const std::size_t total_size
) {
    constexpr std::string_view prefix = "format_version = 3\nservice.contains.ci.include = \"";
    constexpr std::string_view suffix = "\"\n";
    UI_REQUIRE(total_size >= prefix.size() + suffix.size());

    std::string text {};
    text.reserve(total_size);
    text += prefix;
    text.append(total_size - prefix.size() - suffix.size(), 'a');
    text += suffix;
    UI_REQUIRE(text.size() == total_size);
    return write_temp_advanced_filter_file(filename, text);
}

std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields {};
    std::string current {};
    bool in_quotes = false;

    for (std::size_t index = 0; index < line.size(); ++index) {
        const auto ch = line[index];
        if (ch == '"') {
            if (in_quotes && index + 1U < line.size() && line[index + 1U] == '"') {
                current.push_back('"');
                ++index;
            } else {
                in_quotes = !in_quotes;
            }
            continue;
        }

        if (ch == ',' && !in_quotes) {
            fields.push_back(current);
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    fields.push_back(current);
    return fields;
}

pfl::session_detail::AdvancedFlowFilterDocument make_flow_protocol_advanced_document(const pfl::ProtocolId protocol) {
    pfl::session_detail::AdvancedFlowFilterDocument document {};
    document.configured_spec.flow_protocol.include.push_back(protocol);
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_address_family_advanced_document(const pfl::FlowAddressFamily family) {
    pfl::session_detail::AdvancedFlowFilterDocument document {};
    document.configured_spec.address_family.include.push_back(family);
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_disabled_flow_protocol_advanced_document(const pfl::ProtocolId protocol) {
    auto document = make_flow_protocol_advanced_document(protocol);
    document.section_states.flow_protocol = false;
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_flow_protocol_include_exclude_advanced_document() {
    pfl::session_detail::AdvancedFlowFilterDocument document {};
    document.configured_spec.flow_protocol.include.push_back(pfl::ProtocolId::tcp);
    document.configured_spec.flow_protocol.include.push_back(pfl::ProtocolId::udp);
    document.configured_spec.flow_protocol.exclude.push_back(pfl::ProtocolId::udp);
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_ports_include_exclude_advanced_document() {
    using namespace pfl::session_detail;

    AdvancedFlowFilterDocument document {};
    document.configured_spec.ports.include.push_back(AdvancedFlowFilterPortPredicate {
        .scope = AdvancedFlowFilterPortScope::either_endpoint,
        .range = AdvancedFlowFilterPortRange {.first = 80U, .last = 80U},
    });
    document.configured_spec.ports.exclude.push_back(AdvancedFlowFilterPortPredicate {
        .scope = AdvancedFlowFilterPortScope::either_endpoint,
        .range = AdvancedFlowFilterPortRange {.first = 53U, .last = 53U},
    });
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_port_text_entry_document() {
    using namespace pfl::session_detail;

    AdvancedFlowFilterDocument document {};
    document.configured_spec.ports.include.push_back(AdvancedFlowFilterPortPredicate {
        .scope = AdvancedFlowFilterPortScope::either_endpoint,
        .range = AdvancedFlowFilterPortRange {.first = 8U, .last = 8U},
    });
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_address_prefix_text_entry_document() {
    using namespace pfl::session_detail;

    AdvancedFlowFilterDocument document {};
    document.configured_spec.addresses.ipv4_include.push_back(AdvancedFlowFilterIpv4AddressPredicate {
        .match_kind = AdvancedFlowFilterAddressMatchKind::cidr,
        .scope = AdvancedFlowFilterEndpointScope::either_endpoint,
        .value = pfl::tests::ipv4(10, 71, 0, 0),
        .prefix_length = 1U,
    });
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_traffic_text_entry_document() {
    using namespace pfl::session_detail;

    AdvancedFlowFilterDocument document {};
    document.configured_spec.aggregate.packet_count =
        AdvancedFlowFilterInclusiveRange<std::uint64_t> {.min = 1ULL, .max = std::nullopt};
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_service_text_entry_document() {
    using namespace pfl::session_detail;

    AdvancedFlowFilterDocument document {};
    document.configured_spec.service.include.push_back(AdvancedFlowFilterServicePredicate {
        .kind = AdvancedFlowFilterServicePredicateKind::contains,
        .value = "u",
        .case_sensitivity = AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive,
    });
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_contains_layer_text_entry_document() {
    using namespace pfl::session_detail;

    AdvancedFlowFilterDocument document {};
    document.configured_spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
        .match_kind = AdvancedFlowFilterProtocolPathMatchKind::contains_layer,
        .layers = {{
            .kind = pfl::ProtocolLayerKind::vxlan,
            .identifier = pfl::ProtocolLayerIdentifier {
                .kind = pfl::ProtocolLayerIdentifierKind::vxlan_vni,
                .value = 100U,
            },
        }},
    });
    return document;
}

pfl::session_detail::AdvancedFlowFilterDocument make_protocol_path_identifier_file_workflow_document() {
    using namespace pfl::session_detail;

    AdvancedFlowFilterDocument document {};
    document.configured_spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
        .match_kind = AdvancedFlowFilterProtocolPathMatchKind::path_prefix,
        .layers = {
            {.kind = pfl::ProtocolLayerKind::ethernet_ii},
            {.kind = pfl::ProtocolLayerKind::ipv4},
            {.kind = pfl::ProtocolLayerKind::udp},
            {.kind = pfl::ProtocolLayerKind::geneve, .identifier = pfl::ProtocolLayerIdentifier {
                .kind = pfl::ProtocolLayerIdentifierKind::geneve_vni,
                .value = 100U,
            }},
        },
    });
    document.configured_spec.protocol_path.include.push_back(AdvancedFlowFilterProtocolPathPredicate {
        .match_kind = AdvancedFlowFilterProtocolPathMatchKind::exact_path,
        .layers = {
            {.kind = pfl::ProtocolLayerKind::ethernet_ii},
            {.kind = pfl::ProtocolLayerKind::ipv4},
            {.kind = pfl::ProtocolLayerKind::udp},
            {.kind = pfl::ProtocolLayerKind::gtpu, .identifier = pfl::ProtocolLayerIdentifier {
                .kind = pfl::ProtocolLayerIdentifierKind::gtpu_teid,
                .value = 0x01020304U,
            }},
            {.kind = pfl::ProtocolLayerKind::ipv4},
            {.kind = pfl::ProtocolLayerKind::tcp},
        },
    });
    return document;
}

bool protocol_path_layers_have_identifiers(
    const std::vector<pfl::session_detail::AdvancedFlowFilterProtocolLayerPredicate>& layers
) {
    return std::any_of(layers.begin(), layers.end(), [](const auto& layer) {
        return layer.identifier.has_value() &&
            layer.identifier->kind != pfl::ProtocolLayerIdentifierKind::none;
    });
}

const pfl::session_detail::AdvancedFlowFilterProtocolLayerPredicate* find_protocol_path_predicate_layer(
    const pfl::session_detail::AdvancedFlowFilterProtocolPathPredicate& predicate,
    const pfl::ProtocolLayerKind kind
) {
    const auto it = std::find_if(predicate.layers.begin(), predicate.layers.end(), [&](const auto& layer) {
        return layer.kind == kind;
    });
    return it == predicate.layers.end() ? nullptr : &*it;
}

int find_flow_index_by_protocol_hint(pfl::FlowListModel* model, const QString& hint) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::FlowListModel::ProtocolHintRole).toString() == hint) {
            return model->data(index, pfl::FlowListModel::FlowIndexRole).toInt();
        }
    }

    return -1;
}

int find_flow_index_by_protocol(pfl::FlowListModel* model, const QString& protocol) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::FlowListModel::ProtocolRole).toString() == protocol) {
            return model->data(index, pfl::FlowListModel::FlowIndexRole).toInt();
        }
    }

    return -1;
}

int find_flow_index_by_service_hint(pfl::FlowListModel* model, const QString& service_hint) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::FlowListModel::ServiceHintRole).toString() == service_hint) {
            return model->data(index, pfl::FlowListModel::FlowIndexRole).toInt();
        }
    }

    return -1;
}

QStringList visible_flow_protocol_paths(pfl::FlowListModel* model) {
    QStringList texts {};
    for (int row = 0; row < model->rowCount(); ++row) {
        texts.push_back(model->data(model->index(row, 0), pfl::FlowListModel::ProtocolPathTextRole).toString());
    }
    return texts;
}

int find_flow_index_by_family(pfl::FlowListModel* model, const QString& family) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::FlowListModel::FamilyRole).toString() == family) {
            return model->data(index, pfl::FlowListModel::FlowIndexRole).toInt();
        }
    }

    return -1;
}

int find_flow_index_by_packet_count(pfl::FlowListModel* model, const qulonglong packetCount) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::FlowListModel::PacketsRole).toULongLong() == packetCount) {
            return model->data(index, pfl::FlowListModel::FlowIndexRole).toInt();
        }
    }

    if (model->rowCount() == 1) {
        return model->data(model->index(0, 0), pfl::FlowListModel::FlowIndexRole).toInt();
    }

    return -1;
}

int find_packet_row_by_flow_row_number(pfl::PacketListModel* model, const qulonglong row_number) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::PacketListModel::RowNumberRole).toULongLong() == row_number) {
            return row;
        }
    }

    return -1;
}

int find_stream_row_by_source_packets_text(pfl::StreamListModel* model, const QString& source_packets_text) {
    for (int row = 0; row < model->rowCount(); ++row) {
        if (model->data(model->index(row, 0), pfl::StreamListModel::SourcePacketsTextRole).toString() == source_packets_text) {
            return row;
        }
    }

    return -1;
}

int find_protocol_path_stats_row_by_path_text(pfl::ProtocolPathStatsModel* model, const QString& path_text) {
    for (int row = 0; row < model->rowCount(); ++row) {
        if (model->data(model->index(row, 0), pfl::ProtocolPathStatsModel::PathTextRole).toString() == path_text) {
            return row;
        }
    }

    return -1;
}

int count_protocol_path_root_rows(const QVariantList& rows) {
    int count = 0;
    for (const auto& value : rows) {
        const auto row = value.toMap();
        if (row.value(QStringLiteral("parentNodeId")).toULongLong() == pfl::kInvalidProtocolPathStatisticsNodeId) {
            ++count;
        }
    }
    return count;
}

QVariantMap find_protocol_distribution_row(const QVariantList& rows, const QString& title) {
    for (const auto& value : rows) {
        const auto row = value.toMap();
        if (row.value(QStringLiteral("title")).toString() == title) {
            return row;
        }
    }

    return {};
}

QVariantMap find_flow_packet_histogram_row(const QVariantList& rows, const QString& label) {
    for (const auto& value : rows) {
        const auto row = value.toMap();
        if (row.value(QStringLiteral("label")).toString() == label) {
            return row;
        }
    }

    return {};
}

QVariantMap find_top_level_summary_layer(const QVariantList& layers, const QString& id, int occurrence = 0) {
    int current = 0;
    for (const auto& value : layers) {
        const auto layer = value.toMap();
        if (layer.value(QStringLiteral("id")).toString() != id) {
            continue;
        }
        if (current == occurrence) {
            return layer;
        }
        ++current;
    }
    return {};
}

QString find_summary_field_value(const QVariantMap& layer, const QString& label) {
    const auto fields = layer.value(QStringLiteral("fields")).toList();
    for (const auto& value : fields) {
        const auto field = value.toMap();
        if (field.value(QStringLiteral("label")).toString() == label) {
            return field.value(QStringLiteral("value")).toString();
        }
    }
    return {};
}

void append_summary_layer_search_text(QStringList& lines, const QVariantMap& layer) {
    const auto layer_id = layer.value(QStringLiteral("id")).toString();
    const auto title = layer.value(QStringLiteral("title")).toString();
    if (!title.isEmpty()) {
        lines.push_back(title);
    }

    const auto fields = layer.value(QStringLiteral("fields")).toList();
    for (const auto& value : fields) {
        const auto field = value.toMap();
        const auto label = field.value(QStringLiteral("label")).toString();
        const auto field_value = field.value(QStringLiteral("value")).toString();
        if (!label.isEmpty() && !field_value.isEmpty()) {
            lines.push_back(QStringLiteral("%1: %2").arg(label, field_value));
            if (layer_id == QStringLiteral("tls")) {
                lines.push_back(QStringLiteral("TLS %1: %2").arg(label, field_value));
            }
        } else if (!label.isEmpty()) {
            lines.push_back(label);
        } else if (!field_value.isEmpty()) {
            lines.push_back(field_value);
        }
    }

    const auto children = layer.value(QStringLiteral("children")).toList();
    for (const auto& child_value : children) {
        append_summary_layer_search_text(lines, child_value.toMap());
    }
}

QString summary_layers_search_text(const QVariantList& layers) {
    QStringList lines {};
    for (const auto& value : layers) {
        append_summary_layer_search_text(lines, value.toMap());
    }
    return lines.join(QLatin1Char('\n'));
}

QString combined_details_search_text(pfl::PacketDetailsViewModel* model) {
    QStringList lines {};
    lines.push_back(model->summaryText());
    const auto layer_text = summary_layers_search_text(model->summaryLayers());
    if (!layer_text.isEmpty()) {
        lines.push_back(layer_text);
    }
    return lines.join(QLatin1Char('\n'));
}

std::filesystem::path ui_test_root() {
    return std::filesystem::path(__FILE__).parent_path().parent_path();
}

QJsonObject load_json_object(const std::filesystem::path& path) {
    QFile file(QString::fromStdWString(path.wstring()));
    UI_REQUIRE(file.open(QIODevice::ReadOnly));
    const auto document = QJsonDocument::fromJson(file.readAll());
    UI_REQUIRE(!document.isNull());
    UI_REQUIRE(document.isObject());
    return document.object();
}

std::vector<std::uint64_t> expected_packet_indices(const QJsonArray& packet_numbers) {
    std::vector<std::uint64_t> indices {};
    indices.reserve(static_cast<std::size_t>(packet_numbers.size()));
    for (const auto& value : packet_numbers) {
        const auto packet_number = value.toInteger();
        UI_REQUIRE(packet_number > 0);
        indices.push_back(static_cast<std::uint64_t>(packet_number - 1));
    }
    return indices;
}

bool text_contains_required_fragments(const QString& text, const QJsonArray& fragments) {
    for (const auto& value : fragments) {
        if (!text.contains(value.toString())) {
            return false;
        }
    }
    return true;
}

bool text_omits_forbidden_fragments(const QString& text, const QJsonArray& fragments) {
    for (const auto& value : fragments) {
        if (text.contains(value.toString())) {
            return false;
        }
    }
    return true;
}

[[maybe_unused]] QString normalize_direction_text(const QString& direction) {
    if (direction == QStringLiteral("A→B") || direction == QString::fromUtf8("Aв†’B")) {
        return QStringLiteral("A->B");
    }
    if (direction == QStringLiteral("B→A") || direction == QString::fromUtf8("Bв†’A")) {
        return QStringLiteral("B->A");
    }
    return direction;
}

QString canonical_direction_text(const QString& direction) {
    const auto canonical_ab = QStringLiteral("A") + QChar(0x2192) + QStringLiteral("B");
    const auto canonical_ba = QStringLiteral("B") + QChar(0x2192) + QStringLiteral("A");
    if (direction == canonical_ab || direction == QString::fromUtf8("Aв†’B") || direction == QString::fromUtf8("AРІвЂ вЂ™B")) {
        return QStringLiteral("A->B");
    }
    if (direction == canonical_ba || direction == QString::fromUtf8("Bв†’A") || direction == QString::fromUtf8("BРІвЂ вЂ™A")) {
        return QStringLiteral("B->A");
    }
    return direction;
}

QString packet_direction_for_number(const std::vector<pfl::PacketRow>& packet_rows, const std::uint64_t packet_number) {
    const auto packet_index = packet_number - 1U;
    const auto it = std::find_if(packet_rows.begin(), packet_rows.end(), [packet_index](const pfl::PacketRow& row) {
        return row.packet_index == packet_index;
    });
    if (it == packet_rows.end()) {
        UI_EXPECT(false);
        return {};
    }
    const auto direction = QString::fromStdString(it->direction_text);
    if (direction == QString::fromUtf8("A→B")) {
        return QStringLiteral("A->B");
    }
    if (direction == QString::fromUtf8("B→A")) {
        return QStringLiteral("B->A");
    }
    return direction;
}

std::vector<const pfl::StreamItemRow*> find_matching_stream_rows(
    const std::vector<pfl::StreamItemRow>& rows,
    const QString& direction,
    const QString& label,
    const std::vector<std::uint64_t>& packet_indices
) {
    std::vector<const pfl::StreamItemRow*> matches {};
    for (const auto& row : rows) {
        const auto row_direction = QString::fromStdString(row.direction_text) == QString::fromUtf8("A→B")
            ? QStringLiteral("A->B")
            : (QString::fromStdString(row.direction_text) == QString::fromUtf8("B→A")
                ? QStringLiteral("B->A")
                : QString::fromStdString(row.direction_text));
        if (row_direction != direction) {
            continue;
        }
        if (QString::fromStdString(row.label) != label) {
            continue;
        }
        if (row.packet_indices != packet_indices) {
            continue;
        }
        matches.push_back(&row);
    }
    return matches;
}

void run_quic_fixture_reference_tests(QApplication& app, const std::filesystem::path& spec_path) {
    try {
    const auto spec = load_json_object(spec_path);
    const auto fixture_relative_path = spec.value(QStringLiteral("fixture_relative_path")).toString();
    UI_REQUIRE(!fixture_relative_path.isEmpty());

    const auto fixture_path = ui_test_root() / fixture_relative_path.toStdString();

    pfl::MainController controller {};
    UI_REQUIRE(open_capture_and_wait(app, controller, fixture_path));

    auto* details_model = qobject_cast<pfl::PacketDetailsViewModel*>(controller.packetDetailsModel());
    auto* stream_model = qobject_cast<pfl::StreamListModel*>(controller.streamModel());
    UI_REQUIRE(details_model != nullptr);
    UI_REQUIRE(stream_model != nullptr);
    controller.setFlowDetailsTabIndex(1);
    controller.setSelectedFlowIndex(0);

    pfl::CaptureSession session {};
    UI_REQUIRE(session.open_capture(fixture_path));

    const auto packet_rows = session.list_flow_packets(0);
    UI_EXPECT(packet_rows.size() == static_cast<std::size_t>(spec.value(QStringLiteral("packet_count")).toInteger()));

    for (const auto& packet_value : spec.value(QStringLiteral("packet_expectations")).toArray()) {
        const auto packet_expectation = packet_value.toObject();
        const auto packet_number = static_cast<std::uint64_t>(packet_expectation.value(QStringLiteral("packet_number")).toInteger());
        UI_EXPECT(packet_number > 0U);
        UI_EXPECT(canonical_direction_text(packet_direction_for_number(packet_rows, packet_number)) ==
                  packet_expectation.value(QStringLiteral("direction")).toString());

        controller.setSelectedPacketIndex(packet_number - 1U);
        UI_EXPECT(details_model->detailsTitle() == QStringLiteral("Packet Details"));

        const auto summary_text = combined_details_search_text(details_model);
        UI_EXPECT(text_contains_required_fragments(summary_text, packet_expectation.value(QStringLiteral("detail_required_substrings")).toArray()));
        UI_EXPECT(text_omits_forbidden_fragments(summary_text, packet_expectation.value(QStringLiteral("detail_forbidden_substrings")).toArray()));
    }

    const auto stream_rows = session.list_flow_stream_items(0);

    const auto stream_sequence = spec.value(QStringLiteral("stream_sequence")).toArray();
    UI_EXPECT(controller.loadedStreamItemCount() == static_cast<qulonglong>(stream_sequence.size()));
    UI_EXPECT(controller.totalStreamItemCount() == static_cast<qulonglong>(stream_sequence.size()));
    UI_EXPECT(!controller.streamPartiallyLoaded());
    UI_EXPECT(!controller.canLoadMoreStreamItems());
    UI_EXPECT(stream_model->rowCount() == stream_sequence.size());
    UI_EXPECT(stream_rows.size() == static_cast<std::size_t>(stream_sequence.size()));
    for (qsizetype sequence_index = 0; sequence_index < stream_sequence.size(); ++sequence_index) {
        const auto sequence_value = stream_sequence[sequence_index];
        const auto sequence_entry = sequence_value.toObject();
        const auto& row = stream_rows[static_cast<std::size_t>(sequence_index)];
        const auto row_direction = QString::fromStdString(row.direction_text) == QString::fromUtf8("A→B")
            ? QStringLiteral("A->B")
            : (QString::fromStdString(row.direction_text) == QString::fromUtf8("B→A")
                ? QStringLiteral("B->A")
                : QString::fromStdString(row.direction_text));
        UI_EXPECT(row_direction == sequence_entry.value(QStringLiteral("direction")).toString());
        UI_EXPECT(QString::fromStdString(row.label) == sequence_entry.value(QStringLiteral("ui_label")).toString());
        UI_EXPECT(row.packet_indices == expected_packet_indices(sequence_entry.value(QStringLiteral("source_packets")).toArray()));
    }

    for (const auto& stream_value : spec.value(QStringLiteral("stream_expectations")).toArray()) {
        const auto stream_expectation = stream_value.toObject();
        const auto matches = find_matching_stream_rows(
            stream_rows,
            stream_expectation.value(QStringLiteral("direction")).toString(),
            stream_expectation.value(QStringLiteral("ui_label")).toString(),
            expected_packet_indices(stream_expectation.value(QStringLiteral("source_packets")).toArray())
        );
        UI_EXPECT(matches.size() == static_cast<std::size_t>(stream_expectation.value(QStringLiteral("count")).toInteger()));

        for (const auto* row : matches) {
            UI_REQUIRE(row != nullptr);
        }
    }

    for (const auto& absence_value : spec.value(QStringLiteral("stream_absence_expectations")).toArray()) {
        const auto absence = absence_value.toObject();
        const auto kind = absence.value(QStringLiteral("kind")).toString();
        const auto needle = absence.value(QStringLiteral("value")).toString();
        UI_EXPECT(!needle.isEmpty());

        for (const auto& row : stream_rows) {
            const auto label = QString::fromStdString(row.label);
            if (kind == QStringLiteral("label_substring")) {
                UI_EXPECT(!label.contains(needle));
            } else if (kind == QStringLiteral("exact_label")) {
                UI_EXPECT(label != needle);
            } else {
                UI_EXPECT(false);
            }
        }
    }
    } catch (const pfl::tests::TestFailure& failure) {
        pfl::tests::record_failure_message(failure.what());
    } catch (const std::exception& exception) {
        pfl::tests::record_failure_message(
            std::string {"run_quic_fixture_reference_tests threw unexpected exception: "} + exception.what()
        );
    } catch (...) {
        pfl::tests::record_failure_message("run_quic_fixture_reference_tests threw unknown exception");
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    std::set_terminate(ui_test_terminate_handler);
    std::signal(SIGABRT, ui_test_signal_handler);
    std::signal(SIGSEGV, ui_test_signal_handler);
    std::signal(SIGILL, ui_test_signal_handler);
    std::signal(SIGFPE, ui_test_signal_handler);
    note_test_checkpoint(__FILE__, __LINE__, "main:start");
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    QApplication app(argc, argv);

    using namespace pfl;
    using namespace pfl::tests;

    clear_recorded_failures();
    emit_test_output("Running UI tests...\n");

    try {

    const auto http_flow = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80, make_http_request_payload(), 0x12);
    const auto dns_flow = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53, make_dns_query_payload());
    const auto generic_tcp = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 2222, 443, 5, 0x18);

    const auto capture_path = write_temp_pcap(
        "pfl_ui_drilldown.pcap",
        make_classic_pcap({
            {100, http_flow},
            {200, dns_flow},
            {300, generic_tcp},
        })
    );

    MainController controller {};
    UI_EXPECT(!controller.canSaveIndex());
    UI_EXPECT(!controller.canExportSelectedFlow());
    UI_EXPECT(!controller.hasSourceCapture());
    UI_EXPECT(!controller.openedFromIndex());
    UI_EXPECT(!controller.canAttachSourceCapture());
    UI_EXPECT(controller.statisticsMode() == 0);
    controller.setStatisticsMode(1);
    UI_EXPECT(controller.statisticsMode() == 1);
    controller.setStatisticsMode(2);
    UI_EXPECT(controller.statisticsMode() == 2);
    controller.setStatisticsMode(99);
    UI_EXPECT(controller.statisticsMode() == 0);

    UI_EXPECT(controller.tcpFlowCount() + controller.udpFlowCount() + controller.sctpFlowCount() + controller.otherFlowCount() == controller.flowCount());
    UI_EXPECT(controller.tcpPacketCount() + controller.udpPacketCount() + controller.sctpPacketCount() + controller.otherPacketCount() == controller.packetCount());
    UI_EXPECT(controller.tcpTotalBytes() + controller.udpTotalBytes() + controller.sctpTotalBytes() + controller.otherTotalBytes() == controller.totalBytes());
    UI_EXPECT(controller.ipv4FlowCount() + controller.ipv6FlowCount() == controller.flowCount());
    UI_EXPECT(controller.ipv4PacketCount() + controller.ipv6PacketCount() == controller.packetCount());
    UI_EXPECT(controller.ipv4TotalBytes() + controller.ipv6TotalBytes() == controller.totalBytes());

    UI_EXPECT(controller.statusText().isEmpty());

    run_ui_section("analysis_pane_smoke", [&]() {
        auto pane = load_flow_analysis_pane_component();
        pane.object->setProperty("hasActiveFlow", false);
        pane.object->setProperty("analysisLoading", false);
        pane.object->setProperty("analysisAvailable", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(pane.object.get(), "analysisEmptyState"));
        UI_EXPECT(!item_visible(pane.object.get(), "analysisLoadingState"));
        UI_EXPECT(!item_visible(pane.object.get(), "analysisResultContent"));

        pane.object->setProperty("hasActiveFlow", true);
        pane.object->setProperty("analysisLoading", true);
        pane.object->setProperty("analysisAvailable", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!item_visible(pane.object.get(), "analysisEmptyState"));
        UI_EXPECT(item_visible(pane.object.get(), "analysisLoadingState"));
        UI_EXPECT(!item_visible(pane.object.get(), "analysisResultContent"));

        pane.object->setProperty("analysisLoading", false);
        pane.object->setProperty("analysisAvailable", true);
        pane.object->setProperty("packetSizeHistogramAllModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("all")}, {QStringLiteral("packetCount"), 3U}, {QStringLiteral("packetCountText"), QStringLiteral("3")}},
        });
        pane.object->setProperty("packetSizeHistogramAToBModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("a")}, {QStringLiteral("packetCount"), 2U}, {QStringLiteral("packetCountText"), QStringLiteral("2")}},
        });
        pane.object->setProperty("packetSizeHistogramBToAModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("b")}, {QStringLiteral("packetCount"), 1U}, {QStringLiteral("packetCountText"), QStringLiteral("1")}},
        });
        pane.object->setProperty("capturedPacketSizeHistogramAllModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("all-captured")}, {QStringLiteral("packetCount"), 5U}, {QStringLiteral("packetCountText"), QStringLiteral("5")}},
        });
        pane.object->setProperty("capturedPacketSizeHistogramAToBModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("a-captured")}, {QStringLiteral("packetCount"), 4U}, {QStringLiteral("packetCountText"), QStringLiteral("4")}},
        });
        pane.object->setProperty("capturedPacketSizeHistogramBToAModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("b-captured")}, {QStringLiteral("packetCount"), 1U}, {QStringLiteral("packetCountText"), QStringLiteral("1")}},
        });
        pane.object->setProperty("interArrivalHistogramAllModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("all")}, {QStringLiteral("packetCount"), 4U}, {QStringLiteral("packetCountText"), QStringLiteral("4")}},
        });
        pane.object->setProperty("interArrivalHistogramAToBModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("a")}, {QStringLiteral("packetCount"), 3U}, {QStringLiteral("packetCountText"), QStringLiteral("3")}},
        });
        pane.object->setProperty("interArrivalHistogramBToAModel", QVariantList {
            QVariantMap {{QStringLiteral("bucketLabel"), QStringLiteral("b")}, {QStringLiteral("packetCount"), 1U}, {QStringLiteral("packetCountText"), QStringLiteral("1")}},
        });
        pane.object->setProperty("endpointSummaryText", QString::fromUtf8("10.0.0.1:40000 \xE2\x86\x92 10.0.0.2:80 TCP"));
        pane.object->setProperty("protocolHint", QStringLiteral("HTTP"));
        pane.object->setProperty("maxCapturedPacketSizeText", QStringLiteral("200 B"));
        pane.object->setProperty("packetSizeHistogramMaximumOriginalText", QStringLiteral("1.5 KB (1 536 B)"));
        pane.object->setProperty("packetSizeHistogramMaximumOriginalAToBText", QStringLiteral("1 KB (1 024 B)"));
        pane.object->setProperty("packetSizeHistogramMaximumOriginalBToAText", QStringLiteral("512 B"));
        pane.object->setProperty("packetSizeHistogramMaximumCapturedText", QStringLiteral("200 B"));
        pane.object->setProperty("packetSizeHistogramMaximumCapturedAToBText", QStringLiteral("160 B"));
        pane.object->setProperty("packetSizeHistogramMaximumCapturedBToAText", QStringLiteral("96 B"));
        pane.object->setProperty("rateGraphAvailable", true);
        pane.object->setProperty("rateGraphStatusText", QStringLiteral(""));
        pane.object->setProperty("rateGraphWindowText", QStringLiteral("Window: 10 ms (auto)"));
        pane.object->setProperty("durationText", QStringLiteral("00:00:00.010"));
        pane.object->setProperty("rateSeriesAToBModel", QVariantList {
            QVariantMap {{QStringLiteral("xUs"), 0ULL}, {QStringLiteral("xSeconds"), 0.0}, {QStringLiteral("originalDataPerSecond"), 30000.0}, {QStringLiteral("packetsPerSecond"), 200.0}},
            QVariantMap {{QStringLiteral("xUs"), 10000ULL}, {QStringLiteral("xSeconds"), 0.01}, {QStringLiteral("originalDataPerSecond"), 10000.0}, {QStringLiteral("packetsPerSecond"), 100.0}},
        });
        pane.object->setProperty("rateSeriesBToAModel", QVariantList {
            QVariantMap {{QStringLiteral("xUs"), 0ULL}, {QStringLiteral("xSeconds"), 0.0}, {QStringLiteral("originalDataPerSecond"), 5000.0}, {QStringLiteral("packetsPerSecond"), 50.0}},
            QVariantMap {{QStringLiteral("xUs"), 10000ULL}, {QStringLiteral("xSeconds"), 0.01}, {QStringLiteral("originalDataPerSecond"), 7500.0}, {QStringLiteral("packetsPerSecond"), 75.0}},
        });
        pane.object->setProperty("sequencePreviewModel", QVariantList {
            QVariantMap {
                {QStringLiteral("packetNumber"), 1U},
                {QStringLiteral("direction"), QStringLiteral("A->B")},
                {QStringLiteral("deltaTimeText"), QStringLiteral("0.000 ms")},
                {QStringLiteral("capturedLength"), 100U},
                {QStringLiteral("originalLength"), 128U},
                {QStringLiteral("transportPayloadText"), QStringLiteral("46")},
                {QStringLiteral("timestampText"), QStringLiteral("00:00:01.000000")},
            },
            QVariantMap {
                {QStringLiteral("packetNumber"), 2U},
                {QStringLiteral("direction"), QStringLiteral("B->A")},
                {QStringLiteral("deltaTimeText"), QStringLiteral("250.000 ms")},
                {QStringLiteral("capturedLength"), 200U},
                {QStringLiteral("originalLength"), 200U},
                {QStringLiteral("transportPayloadText"), QStringLiteral("146")},
                {QStringLiteral("timestampText"), QStringLiteral("00:00:01.250000")},
            },
        });
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!item_visible(pane.object.get(), "analysisEmptyState"));
        UI_EXPECT(!item_visible(pane.object.get(), "analysisLoadingState"));
        UI_EXPECT(item_visible(pane.object.get(), "analysisResultContent"));
        UI_EXPECT(named_object(pane.object.get(), "analysisEndpointSummaryLabel") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisEndpointSummaryLabel")->property("text").toString() == QString::fromUtf8("10.0.0.1:40000 \xE2\x86\x92 10.0.0.2:80"));
        UI_EXPECT(named_object(pane.object.get(), "analysisProtocolSummaryLabel") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisProtocolSummaryLabel")->property("text").toString() == QStringLiteral("Protocol: TCP (HTTP)"));
        UI_EXPECT(named_object(pane.object.get(), "packetSizeHistogramMaxLabel") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "packetSizeHistogramMaxLabel")->property("text").toString() == QStringLiteral("max: 3"));
        UI_EXPECT(named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumCaption") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumValue") != nullptr);
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumCaption")->property("text").toString() ==
            QStringLiteral("Maximum original packet size:")
        );
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumValue")->property("text").toString() ==
            QStringLiteral("1.5 KB (1 536 B)")
        );
        UI_EXPECT(named_object(pane.object.get(), "interArrivalHistogramMaxLabel") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "interArrivalHistogramMaxLabel")->property("text").toString() == QStringLiteral("max: 4"));
        UI_EXPECT(pane.object->property("packetSizeHistogramMetricMode").toInt() == 0);
        UI_EXPECT(pane.object->property("packetSizeHistogramDirectionMode").toInt() == 0);
        UI_EXPECT(pane.object->property("interArrivalHistogramDirectionMode").toInt() == 0);
        UI_EXPECT(named_object(pane.object.get(), "packetSizeHistogramMetricOriginalButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "packetSizeHistogramMetricCapturedButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "packetSizeHistogramModeAllButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "interArrivalHistogramModeAllButton") != nullptr);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 3);
        UI_EXPECT(pane.object->property("displayedInterArrivalHistogramTotal").toInt() == 4);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateWindowLabel") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateWindowLabel")->property("text").toString() == QStringLiteral("Window: 10 ms (auto)"));
        UI_EXPECT(named_object(pane.object.get(), "analysisRateMetricOriginalDataButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateMetricPacketsButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateMetricCapturedDataButton") == nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateDirectionAToBButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateDirectionBToAButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateDirectionBothButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateGraphCanvas") != nullptr);
        pane.object->setProperty("packetSizeHistogramMetricMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumCaption")->property("text").toString() ==
            QStringLiteral("Maximum captured packet size:")
        );
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumValue")->property("text").toString() ==
            QStringLiteral("200 B")
        );
        pane.object->setProperty("packetSizeHistogramDirectionMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumValue")->property("text").toString() ==
            QStringLiteral("160 B")
        );
        pane.object->setProperty("packetSizeHistogramMetricMode", 0);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumCaption")->property("text").toString() ==
            QStringLiteral("Maximum original packet size:")
        );
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumValue")->property("text").toString() ==
            QStringLiteral("1 KB (1 024 B)")
        );
        pane.object->setProperty("packetSizeHistogramDirectionMode", 2);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(
            named_object(pane.object.get(), "analysisPacketSizeHistogramMaximumValue")->property("text").toString() ==
            QStringLiteral("512 B")
        );
        auto* analysisPaneItem = qobject_cast<QQuickItem*>(pane.object.get());
        auto* rateGraphSurface = qobject_cast<QQuickItem*>(named_object(pane.object.get(), "analysisRateGraphSurface"));
        auto* rateGraphCanvas = qobject_cast<QQuickItem*>(named_object(pane.object.get(), "analysisRateGraphCanvas"));
        UI_EXPECT(analysisPaneItem != nullptr);
        UI_EXPECT(rateGraphSurface != nullptr);
        UI_EXPECT(rateGraphCanvas != nullptr);
        analysisPaneItem->setWidth(900);
        analysisPaneItem->setHeight(700);
        app.processEvents(QEventLoop::AllEvents, 25);
        const auto initialSurfaceWidth = rateGraphSurface->width();
        analysisPaneItem->setWidth(1200);
        app.processEvents(QEventLoop::AllEvents, 25);
        const auto widenedSurfaceWidth = rateGraphSurface->width();
        UI_EXPECT(widenedSurfaceWidth >= initialSurfaceWidth - 0.5);
        UI_EXPECT(pane.object->property("rateMetricMode").toInt() == 0);
        UI_EXPECT(pane.object->property("rateDirectionMode").toInt() == 2);
        UI_EXPECT(pane.object->property("renderedRateSeriesAToB").toList().size() == 2);
        UI_EXPECT(pane.object->property("renderedRateSeriesBToA").toList().size() == 2);
        UI_EXPECT(rateGraphSurface->width() >= widenedSurfaceWidth - 0.5);
        const auto canvasSizeAfterSwitches = rateGraphCanvas->property("canvasSize").toSizeF();
        UI_EXPECT(std::fabs(canvasSizeAfterSwitches.width() - rateGraphCanvas->width()) <= 1.0);
        UI_EXPECT(std::fabs(canvasSizeAfterSwitches.height() - rateGraphCanvas->height()) <= 1.0);
        pane.object->setProperty("packetSizeHistogramMetricMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 1);
        pane.object->setProperty("packetSizeHistogramDirectionMode", 1);
        pane.object->setProperty("interArrivalHistogramDirectionMode", 2);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 4);
        UI_EXPECT(pane.object->property("displayedInterArrivalHistogramTotal").toInt() == 1);
        pane.object->setProperty("rateDirectionMode", 0);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("renderedRateSeriesAToB").toList().size() == 2);
        UI_EXPECT(pane.object->property("renderedRateSeriesBToA").toList().isEmpty());
        pane.object->setProperty("rateDirectionMode", 1);
        pane.object->setProperty("rateMetricMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("renderedRateSeriesAToB").toList().isEmpty());
        UI_EXPECT(pane.object->property("renderedRateSeriesBToA").toList().size() == 2);
        UI_EXPECT(rateGraphSurface->width() >= widenedSurfaceWidth - 0.5);
        const auto canvasSizeAfterModeToggle = rateGraphCanvas->property("canvasSize").toSizeF();
        UI_EXPECT(std::fabs(canvasSizeAfterModeToggle.width() - rateGraphCanvas->width()) <= 1.0);
        UI_EXPECT(std::fabs(canvasSizeAfterModeToggle.height() - rateGraphCanvas->height()) <= 1.0);
        pane.object->setProperty("analysisContextResetToken", 7);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("packetSizeHistogramMetricMode").toInt() == 0);
        UI_EXPECT(pane.object->property("packetSizeHistogramDirectionMode").toInt() == 0);
        UI_EXPECT(pane.object->property("interArrivalHistogramDirectionMode").toInt() == 0);
        UI_EXPECT(pane.object->property("rateMetricMode").toInt() == 0);
        UI_EXPECT(pane.object->property("rateDirectionMode").toInt() == 2);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 3);
        pane.object->setProperty("rateGraphAvailable", false);
        pane.object->setProperty("rateGraphStatusText", QStringLiteral("Flow too short for rate graph"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(pane.object.get(), "analysisRateGraphFallbackLabel"));
    });

    MainController idle_cancel_controller {};
    idle_cancel_controller.cancelOpen();
    UI_EXPECT(!idle_cancel_controller.isOpening());
    UI_EXPECT(idle_cancel_controller.statusText().isEmpty());
    UI_EXPECT(open_capture_and_wait(app, controller, capture_path));
    UI_EXPECT(controller.canSaveIndex());
    UI_EXPECT(controller.hasSourceCapture());
    UI_EXPECT(!controller.openedFromIndex());
    UI_EXPECT(!controller.canAttachSourceCapture());
    UI_EXPECT(!controller.canExportSelectedFlow());
    UI_EXPECT(controller.flowFilterText().isEmpty());
    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.statisticsMode() == 0);
    controller.setStatisticsMode(1);
    UI_EXPECT(controller.statisticsMode() == 1);
    controller.setStatisticsMode(2);
    UI_EXPECT(controller.statisticsMode() == 2);
    controller.setStatisticsMode(99);
    UI_EXPECT(controller.statisticsMode() == 0);

    UI_EXPECT(controller.tcpFlowCount() + controller.udpFlowCount() + controller.sctpFlowCount() + controller.otherFlowCount() == controller.flowCount());
    UI_EXPECT(controller.tcpPacketCount() + controller.udpPacketCount() + controller.sctpPacketCount() + controller.otherPacketCount() == controller.packetCount());
    UI_EXPECT(controller.tcpTotalBytes() + controller.udpTotalBytes() + controller.sctpTotalBytes() + controller.otherTotalBytes() == controller.totalBytes());
    UI_EXPECT(controller.ipv4FlowCount() + controller.ipv6FlowCount() == controller.flowCount());
    UI_EXPECT(controller.ipv4PacketCount() + controller.ipv6PacketCount() == controller.packetCount());
    UI_EXPECT(controller.ipv4TotalBytes() + controller.ipv6TotalBytes() == controller.totalBytes());

    UI_EXPECT(controller.statusText().isEmpty());

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> progress_packets {};
    progress_packets.reserve(1001);
    for (std::uint32_t index = 0; index < 1001U; ++index) {
        progress_packets.push_back({100U + index, http_flow});
    }
    const auto progress_capture_path = write_temp_pcap(
        "pfl_ui_open_progress.pcap",
        make_classic_pcap(progress_packets)
    );

    MainController progress_controller {};
    bool saw_opening_true = false;
    qulonglong max_progress_packets = 0U;
    qulonglong max_progress_bytes = 0U;
    qulonglong max_progress_total_bytes = 0U;
    QObject::connect(&progress_controller, &MainController::openProgressChanged, [&]() {
        if (progress_controller.isOpening()) {
            saw_opening_true = true;
        }
        max_progress_packets = std::max(max_progress_packets, progress_controller.openProgressPackets());
        max_progress_bytes = std::max(max_progress_bytes, progress_controller.openProgressBytes());
        max_progress_total_bytes = std::max(max_progress_total_bytes, progress_controller.openProgressTotalBytes());
    });
    UI_EXPECT(progress_controller.openCaptureFile(QString::fromStdWString(progress_capture_path.wstring())));
    UI_EXPECT(progress_controller.isOpening());
    UI_EXPECT(!progress_controller.openCaptureFile(QString::fromStdWString(progress_capture_path.wstring())));
    UI_EXPECT(wait_for_open_to_finish(app, progress_controller));
    UI_EXPECT(saw_opening_true);
    UI_EXPECT(max_progress_packets >= 1000U);
    UI_EXPECT(max_progress_bytes > 0U);
    UI_EXPECT(max_progress_total_bytes == static_cast<qulonglong>(std::filesystem::file_size(progress_capture_path)));
    UI_EXPECT(!progress_controller.isOpening());
    UI_EXPECT(progress_controller.openProgressPackets() == 0U);
    UI_EXPECT(progress_controller.openProgressBytes() == 0U);
    UI_EXPECT(progress_controller.openProgressTotalBytes() == 0U);
    UI_EXPECT(progress_controller.openProgressPercent() == 0.0);

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> cancel_packets {};
    cancel_packets.reserve(50000);
    for (std::uint32_t index = 0; index < 50000U; ++index) {
        cancel_packets.push_back({100U + index, http_flow});
    }
    const auto cancel_capture_path = write_temp_pcap(
        "pfl_ui_open_cancel.pcap",
        make_classic_pcap(cancel_packets)
    );

    MainController cancel_controller {};
    UI_EXPECT(open_capture_and_wait(app, cancel_controller, capture_path));
    const auto preserved_cancel_input_path = cancel_controller.currentInputPath();
    const auto preserved_cancel_flow_count = cancel_controller.flowCount();
    UI_EXPECT(cancel_controller.openCaptureFile(QString::fromStdWString(cancel_capture_path.wstring())));
    UI_EXPECT(cancel_controller.isOpening());
    cancel_controller.cancelOpen();
    UI_EXPECT(!cancel_controller.openCaptureFile(QString::fromStdWString(cancel_capture_path.wstring())));
    UI_EXPECT(wait_for_open_to_finish(app, cancel_controller, 20000));
    UI_EXPECT(cancel_controller.hasCapture());
    UI_EXPECT(cancel_controller.currentInputPath() == preserved_cancel_input_path);
    UI_EXPECT(cancel_controller.flowCount() == preserved_cancel_flow_count);
    UI_EXPECT(cancel_controller.statusText() == QStringLiteral("Open cancelled."));
    UI_EXPECT(!cancel_controller.statusIsError());
    UI_EXPECT(cancel_controller.openErrorText().isEmpty());
    UI_EXPECT(!cancel_controller.isOpening());
    UI_EXPECT(cancel_controller.openProgressPackets() == 0U);
    UI_EXPECT(cancel_controller.openProgressBytes() == 0U);
    UI_EXPECT(cancel_controller.openProgressTotalBytes() == 0U);
    UI_EXPECT(cancel_controller.openProgressPercent() == 0.0);
    const auto saved_index_path = std::filesystem::temp_directory_path() / "pfl_ui_saved_analysis.idx";
    std::error_code remove_error {};
    std::filesystem::remove(saved_index_path, remove_error);
    UI_EXPECT(controller.saveAnalysisIndex(QString::fromStdWString(saved_index_path.wstring())));
    UI_EXPECT(wait_until(app, [&controller, &saved_index_path]() {
        return !controller.indexSaveInProgress() && std::filesystem::exists(saved_index_path);
    }));
    UI_EXPECT(controller.statusText() == QStringLiteral("Analysis index saved successfully: %1").arg(QString::fromStdWString(saved_index_path.wstring())));
    UI_EXPECT(!controller.statusIsError());

    const auto no_selection_export_path = std::filesystem::temp_directory_path() / "pfl_ui_no_selection_export.pcap";
    std::filesystem::remove(no_selection_export_path, remove_error);
    UI_EXPECT(!controller.exportSelectedFlow(QString::fromStdWString(no_selection_export_path.wstring())));
    UI_EXPECT(controller.statusText() == QStringLiteral("No flow selected for export."));
    UI_EXPECT(controller.statusIsError());
    UI_EXPECT(!std::filesystem::exists(no_selection_export_path));

    auto* wireshark_flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
    UI_EXPECT(wireshark_flow_model != nullptr);
    const int wireshark_http_flow_index = find_flow_index_by_protocol_hint(wireshark_flow_model, QStringLiteral("HTTP"));
    const int wireshark_dns_flow_index = find_flow_index_by_protocol_hint(wireshark_flow_model, QStringLiteral("DNS"));
    UI_EXPECT(wireshark_http_flow_index >= 0);
    UI_EXPECT(wireshark_dns_flow_index >= 0);

    controller.setSelectedFlowIndex(wireshark_dns_flow_index);
    UI_EXPECT(controller.selectedFlowHasWiresharkFilter());
    UI_EXPECT(
        controller.selectedFlowWiresharkFilter() ==
        QStringLiteral("ip.addr == 10.0.0.3 && ip.addr == 10.0.0.4 && udp.port == 5353")
    );

    controller.setSelectedFlowIndex(wireshark_http_flow_index);
    UI_EXPECT(controller.selectedFlowHasWiresharkFilter());
    UI_EXPECT(
        controller.selectedFlowWiresharkFilter() ==
        QStringLiteral("ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 1111")
    );
    controller.setShowWiresharkFilterForSelectedFlow(false);
    UI_EXPECT(!controller.selectedFlowHasWiresharkFilter());
    UI_EXPECT(controller.selectedFlowWiresharkFilter().isEmpty());
    controller.setShowWiresharkFilterForSelectedFlow(true);
    UI_EXPECT(controller.selectedFlowHasWiresharkFilter());
    UI_EXPECT(
        controller.selectedFlowWiresharkFilter() ==
        QStringLiteral("ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 1111")
    );

    const auto equal_port_capture_path = write_temp_pcap(
        "pfl_ui_wireshark_equal_ports.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_udp_packet_with_payload(
                ipv4(10, 30, 0, 1), ipv4(10, 30, 0, 2), 7777, 7777, 12)},
        })
    );
    MainController equal_port_controller {};
    UI_EXPECT(open_capture_and_wait(app, equal_port_controller, equal_port_capture_path));
    auto* equal_port_flow_model = qobject_cast<FlowListModel*>(equal_port_controller.flowModel());
    UI_EXPECT(equal_port_flow_model != nullptr);
    UI_EXPECT(equal_port_flow_model->rowCount() == 1);
    equal_port_controller.setSelectedFlowIndex(0);
    UI_EXPECT(equal_port_controller.selectedFlowHasWiresharkFilter());
    UI_EXPECT(
        equal_port_controller.selectedFlowWiresharkFilter() ==
        QStringLiteral("ip.addr == 10.30.0.1 && ip.addr == 10.30.0.2 && udp.port == 7777")
    );

    const auto first_observed_orientation_capture_path = write_temp_pcap(
        "pfl_ui_first_observed_orientation.pcap",
        make_classic_pcap({
            {200, make_ethernet_ipv4_tcp_packet(ipv4(203, 0, 113, 20), ipv4(203, 0, 113, 10), 443, 50000)},
            {100, make_ethernet_ipv4_tcp_packet(ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 20), 50000, 443)},
        })
    );
    MainController first_observed_orientation_controller {};
    UI_EXPECT(open_capture_and_wait(app, first_observed_orientation_controller, first_observed_orientation_capture_path));
    auto* first_observed_orientation_flow_model =
        qobject_cast<FlowListModel*>(first_observed_orientation_controller.flowModel());
    UI_EXPECT(first_observed_orientation_flow_model != nullptr);
    UI_REQUIRE(first_observed_orientation_flow_model->rowCount() == 1);
    const auto first_observed_orientation_index = first_observed_orientation_flow_model->index(0, 0);
    UI_EXPECT(
        first_observed_orientation_flow_model->data(first_observed_orientation_index, FlowListModel::AddressARole).toString() ==
        QStringLiteral("203.0.113.20")
    );
    UI_EXPECT(
        first_observed_orientation_flow_model->data(first_observed_orientation_index, FlowListModel::PortARole).toUInt() == 443U
    );
    UI_EXPECT(
        first_observed_orientation_flow_model->data(first_observed_orientation_index, FlowListModel::AddressBRole).toString() ==
        QStringLiteral("203.0.113.10")
    );
    UI_EXPECT(
        first_observed_orientation_flow_model->data(first_observed_orientation_index, FlowListModel::PortBRole).toUInt() == 50000U
    );
    first_observed_orientation_controller.setSelectedFlowIndex(0);
    UI_EXPECT(first_observed_orientation_controller.selectedFlowHasWiresharkFilter());
    UI_EXPECT(
        first_observed_orientation_controller.selectedFlowWiresharkFilter() ==
        QStringLiteral("ip.addr == 203.0.113.20 && ip.addr == 203.0.113.10 && tcp.port == 50000")
    );


    auto* analysis_flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
    UI_EXPECT(analysis_flow_model != nullptr);
    const int analysis_http_flow_index = find_flow_index_by_protocol_hint(analysis_flow_model, QStringLiteral("HTTP"));
    UI_EXPECT(analysis_http_flow_index >= 0);
    bool saw_analysis_loading = false;
    QObject::connect(&controller, &MainController::analysisStateChanged, [&]() {
        if (controller.analysisLoading()) {
            saw_analysis_loading = true;
        }
    });
    controller.setSelectedFlowIndex(analysis_http_flow_index);
    controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(controller.currentTabIndex() == 1);
    UI_EXPECT(controller.analysisLoading());
    UI_EXPECT(wait_until(app, [&controller]() {
        return !controller.analysisLoading() && controller.analysisAvailable();
    }));
    UI_EXPECT(saw_analysis_loading);
    UI_EXPECT(controller.analysisTimelineFirstPacketTime() == QStringLiteral("1970-01-01 00:00:01.000 UTC"));
    UI_EXPECT(controller.analysisTimelineLastPacketTime() == QStringLiteral("1970-01-01 00:00:01.000 UTC"));
    UI_EXPECT(controller.analysisTimelineLargestGapText() == QStringLiteral("0 us"));
    UI_EXPECT(controller.analysisTimelinePacketCountConsidered() == 1U);
    UI_EXPECT(controller.analysisTimelinePacketCountConsideredText() == QStringLiteral("1"));
    UI_EXPECT(controller.analysisTotalPackets() == 1U);
    UI_EXPECT(controller.analysisTotalPacketsText() == QStringLiteral("1"));
    UI_EXPECT(controller.analysisTotalBytes() == static_cast<qulonglong>(http_flow.size()));
    UI_EXPECT(controller.analysisTotalBytesText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisEndpointSummaryText() == expected_endpoint_summary_for_flow(*analysis_flow_model, analysis_http_flow_index));
    UI_EXPECT(controller.analysisDurationText() == QStringLiteral("00:00:00.000"));
    UI_EXPECT(controller.analysisPacketsPerSecondText() == QStringLiteral("0.000 pkt/s"));
    UI_EXPECT(controller.analysisPacketsPerSecondAToBText() == QStringLiteral("0.000 pkt/s"));
    UI_EXPECT(controller.analysisPacketsPerSecondBToAText() == QStringLiteral("0.000 pkt/s"));
    UI_EXPECT(controller.analysisBytesPerSecondText() == QStringLiteral("0 B/s"));
    UI_EXPECT(controller.analysisBytesPerSecondAToBText() == QStringLiteral("0 B/s"));
    UI_EXPECT(controller.analysisBytesPerSecondBToAText() == QStringLiteral("0 B/s"));
    UI_EXPECT(controller.analysisAveragePacketSizeText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisAveragePacketSizeAToBText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisAveragePacketSizeBToAText() == QStringLiteral("0 B"));
    UI_EXPECT(controller.analysisAverageInterArrivalText() == QStringLiteral("0 us"));
    UI_EXPECT(controller.analysisMinPacketSizeText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisMinPacketSizeAToBText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisMinPacketSizeBToAText().isEmpty());
    UI_EXPECT(controller.analysisMaxPacketSizeText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisMaxCapturedPacketSizeText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisMaxPacketSizeAToBText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisMaxPacketSizeBToAText().isEmpty());
    UI_EXPECT(controller.analysisPacketSizeHistogramMaximumOriginalText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisPacketSizeHistogramMaximumOriginalAToBText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisPacketSizeHistogramMaximumOriginalBToAText().isEmpty());
    UI_EXPECT(controller.analysisPacketSizeHistogramMaximumCapturedText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisPacketSizeHistogramMaximumCapturedAToBText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisPacketSizeHistogramMaximumCapturedBToAText().isEmpty());
    UI_EXPECT(controller.analysisPacketRatioText() == QStringLiteral("1 : 0"));
    UI_EXPECT(controller.analysisByteRatioText() == QStringLiteral("1 : 0"));
    UI_EXPECT(controller.analysisPacketDirectionText() == QStringLiteral("Mostly A->B"));
    UI_EXPECT(controller.analysisDataDirectionText() == QStringLiteral("Mostly A->B"));
    UI_EXPECT(controller.analysisProtocolHint() == QStringLiteral("HTTP"));
    UI_EXPECT(controller.analysisServiceHint() == QStringLiteral("ui.example"));
    UI_EXPECT(controller.analysisHasTcpControlCounts());
    UI_EXPECT(controller.analysisTcpSynPackets() == 1U);
    UI_EXPECT(controller.analysisTcpSynPacketsText() == QStringLiteral("1"));
    UI_EXPECT(controller.analysisTcpFinPackets() == 0U);
    UI_EXPECT(controller.analysisTcpFinPacketsText() == QStringLiteral("0"));
    UI_EXPECT(controller.analysisTcpRstPackets() == 0U);
    UI_EXPECT(controller.analysisTcpRstPacketsText() == QStringLiteral("0"));
    UI_EXPECT(controller.analysisProtocolVersionText().isEmpty());
    UI_EXPECT(controller.analysisProtocolServiceText().isEmpty());
    UI_EXPECT(controller.analysisProtocolFallbackText().isEmpty());
    UI_EXPECT(controller.analysisBurstCount() == 0U);
    UI_EXPECT(controller.analysisBurstCountText() == QStringLiteral("0"));
    UI_EXPECT(controller.analysisLongestBurstPacketCount() == 0U);
    UI_EXPECT(controller.analysisLongestBurstPacketCountText() == QStringLiteral("0"));
    UI_EXPECT(controller.analysisLargestBurstBytesText() == QStringLiteral("0 B"));
    UI_EXPECT(controller.analysisIdleGapCount() == 0U);
    UI_EXPECT(controller.analysisIdleGapCountText() == QStringLiteral("0"));
    UI_EXPECT(controller.analysisLargestIdleGapText() == QStringLiteral("0 us"));
    UI_EXPECT(controller.analysisPacketsAToB() == 1U);
    UI_EXPECT(controller.analysisPacketsAToBText() == QStringLiteral("1"));
    UI_EXPECT(controller.analysisPacketsBToA() == 0U);
    UI_EXPECT(controller.analysisPacketsBToAText() == QStringLiteral("0"));
    UI_EXPECT(controller.analysisBytesAToB() == static_cast<qulonglong>(http_flow.size()));
    UI_EXPECT(controller.analysisBytesAToBText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisBytesBToA() == 0U);
    UI_EXPECT(controller.analysisBytesBToAText() == QStringLiteral("0 B"));
    UI_EXPECT(!controller.analysisRateGraphAvailable());
    UI_EXPECT(controller.analysisRateGraphStatusText() == QStringLiteral("Flow too short for rate graph"));
    UI_EXPECT(controller.analysisRateGraphWindowText() == QStringLiteral("Window: 10 ms (auto)"));
    UI_EXPECT(controller.analysisRateSeriesAToB().isEmpty());
    UI_EXPECT(controller.analysisRateSeriesBToA().isEmpty());
    UI_EXPECT(controller.analysisInterArrivalHistogram().size() == 9);
    UI_EXPECT(histogram_total_count(controller.analysisInterArrivalHistogram()) == 0U);
    UI_EXPECT(controller.analysisInterArrivalHistogramAll().size() == 9);
    UI_EXPECT(controller.analysisInterArrivalHistogramAToB().size() == 9);
    UI_EXPECT(controller.analysisInterArrivalHistogramBToA().size() == 9);
    UI_EXPECT(histogram_total_count(controller.analysisInterArrivalHistogramAll()) == 0U);
    UI_EXPECT(histogram_total_count(controller.analysisInterArrivalHistogramAToB()) == 0U);
    UI_EXPECT(histogram_total_count(controller.analysisInterArrivalHistogramBToA()) == 0U);
    UI_EXPECT(controller.analysisPacketSizeHistogram().size() == 10);
    UI_EXPECT(controller.analysisPacketSizeHistogramAll().size() == 10);
    UI_EXPECT(controller.analysisPacketSizeHistogramAToB().size() == 10);
    UI_EXPECT(controller.analysisPacketSizeHistogramBToA().size() == 10);
    UI_EXPECT(
        histogram_packet_count(
            controller.analysisPacketSizeHistogram(),
            packet_size_bucket_label(static_cast<std::uint32_t>(http_flow.size()))
        ) == 1U
    );
    UI_EXPECT(histogram_total_count(controller.analysisPacketSizeHistogramAll()) == 1U);
    UI_EXPECT(histogram_total_count(controller.analysisPacketSizeHistogramAToB()) == 1U);
    UI_EXPECT(histogram_total_count(controller.analysisPacketSizeHistogramBToA()) == 0U);
    const auto controller_sequence_preview = controller.analysisSequencePreview();
    UI_EXPECT(controller_sequence_preview.size() == 1);
    UI_REQUIRE(controller_sequence_preview.size() >= 1);
    const auto first_sequence_row = controller_sequence_preview.front().toMap();
    UI_EXPECT(first_sequence_row.value(QStringLiteral("packetNumber")).toULongLong() == 1U);
    UI_EXPECT(first_sequence_row.value(QStringLiteral("direction")).toString() == QStringLiteral("A->B"));
    UI_EXPECT(first_sequence_row.value(QStringLiteral("deltaTimeText")).toString() == QStringLiteral("0.000 ms"));
    UI_EXPECT(first_sequence_row.value(QStringLiteral("capturedLength")).toUInt() == static_cast<uint>(http_flow.size()));
    UI_EXPECT(first_sequence_row.value(QStringLiteral("originalLength")).toUInt() == static_cast<uint>(http_flow.size()));
    UI_EXPECT(first_sequence_row.value(QStringLiteral("transportPayloadText")).toString() == QString::number(make_http_request_payload().size()));
    auto* controller_packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
    UI_EXPECT(controller_packet_model != nullptr);
    UI_EXPECT(controller_packet_model->rowCount() == 1);
    controller.setCurrentTabIndex(0);
    UI_EXPECT(controller.currentTabIndex() == 0);
    controller.setSelectedFlowIndex(-1);
    UI_EXPECT(!controller.analysisLoading());
    UI_EXPECT(!controller.analysisAvailable());
    UI_EXPECT(controller.analysisTimelineFirstPacketTime().isEmpty());
    UI_EXPECT(controller.analysisTimelineLastPacketTime().isEmpty());
    UI_EXPECT(controller.analysisTimelineLargestGapText().isEmpty());
    UI_EXPECT(controller.analysisTimelinePacketCountConsidered() == 0U);
    UI_EXPECT(controller.analysisTimelinePacketCountConsideredText().isEmpty());
    UI_EXPECT(controller.analysisTotalPacketsText().isEmpty());
    UI_EXPECT(controller.analysisTotalBytesText().isEmpty());
    UI_EXPECT(controller.analysisEndpointSummaryText().isEmpty());
    UI_EXPECT(controller.analysisPacketsPerSecondText().isEmpty());
    UI_EXPECT(controller.analysisPacketsPerSecondAToBText().isEmpty());
    UI_EXPECT(controller.analysisPacketsPerSecondBToAText().isEmpty());
    UI_EXPECT(controller.analysisBytesPerSecondText().isEmpty());
    UI_EXPECT(controller.analysisBytesPerSecondAToBText().isEmpty());
    UI_EXPECT(controller.analysisBytesPerSecondBToAText().isEmpty());
    UI_EXPECT(controller.analysisAveragePacketSizeText().isEmpty());
    UI_EXPECT(controller.analysisAveragePacketSizeAToBText().isEmpty());
    UI_EXPECT(controller.analysisAveragePacketSizeBToAText().isEmpty());
    UI_EXPECT(controller.analysisAverageInterArrivalText().isEmpty());
    UI_EXPECT(controller.analysisMinPacketSizeText().isEmpty());
    UI_EXPECT(controller.analysisMinPacketSizeAToBText().isEmpty());
    UI_EXPECT(controller.analysisMinPacketSizeBToAText().isEmpty());
    UI_EXPECT(controller.analysisMaxPacketSizeText().isEmpty());
    UI_EXPECT(controller.analysisMaxCapturedPacketSizeText().isEmpty());
    UI_EXPECT(controller.analysisMaxPacketSizeAToBText().isEmpty());
    UI_EXPECT(controller.analysisMaxPacketSizeBToAText().isEmpty());
    UI_EXPECT(controller.analysisPacketRatioText().isEmpty());
    UI_EXPECT(controller.analysisByteRatioText().isEmpty());
    UI_EXPECT(controller.analysisPacketDirectionText().isEmpty());
    UI_EXPECT(controller.analysisDataDirectionText().isEmpty());
    UI_EXPECT(controller.analysisProtocolVersionText().isEmpty());
    UI_EXPECT(controller.analysisProtocolServiceText().isEmpty());
    UI_EXPECT(controller.analysisProtocolFallbackText().isEmpty());
    UI_EXPECT(!controller.analysisHasTcpControlCounts());
    UI_EXPECT(controller.analysisTcpSynPackets() == 0U);
    UI_EXPECT(controller.analysisTcpSynPacketsText().isEmpty());
    UI_EXPECT(controller.analysisTcpFinPackets() == 0U);
    UI_EXPECT(controller.analysisTcpFinPacketsText().isEmpty());
    UI_EXPECT(controller.analysisTcpRstPackets() == 0U);
    UI_EXPECT(controller.analysisTcpRstPacketsText().isEmpty());
    UI_EXPECT(controller.analysisBurstCount() == 0U);
    UI_EXPECT(controller.analysisBurstCountText().isEmpty());
    UI_EXPECT(controller.analysisLongestBurstPacketCount() == 0U);
    UI_EXPECT(controller.analysisLongestBurstPacketCountText().isEmpty());
    UI_EXPECT(controller.analysisLargestBurstBytesText().isEmpty());
    UI_EXPECT(controller.analysisIdleGapCount() == 0U);
    UI_EXPECT(controller.analysisIdleGapCountText().isEmpty());
    UI_EXPECT(controller.analysisLargestIdleGapText().isEmpty());
    UI_EXPECT(controller.analysisPacketsAToBText().isEmpty());
    UI_EXPECT(controller.analysisPacketsBToAText().isEmpty());
    UI_EXPECT(controller.analysisBytesAToBText().isEmpty());
    UI_EXPECT(controller.analysisBytesBToAText().isEmpty());
    UI_EXPECT(controller.analysisInterArrivalHistogram().isEmpty());
    UI_EXPECT(controller.analysisInterArrivalHistogramAll().isEmpty());
    UI_EXPECT(controller.analysisInterArrivalHistogramAToB().isEmpty());
    UI_EXPECT(controller.analysisInterArrivalHistogramBToA().isEmpty());
    UI_EXPECT(controller.analysisPacketSizeHistogram().isEmpty());
    UI_EXPECT(controller.analysisPacketSizeHistogramAll().isEmpty());
    UI_EXPECT(controller.analysisPacketSizeHistogramAToB().isEmpty());
    UI_EXPECT(controller.analysisPacketSizeHistogramBToA().isEmpty());
    UI_EXPECT(controller.analysisSequencePreview().isEmpty());
    UI_EXPECT(!controller.analysisRateGraphAvailable());
    UI_EXPECT(controller.analysisRateGraphStatusText().isEmpty());
    UI_EXPECT(controller.analysisRateGraphWindowText().isEmpty());
    UI_EXPECT(controller.analysisRateSeriesAToB().isEmpty());
    UI_EXPECT(controller.analysisRateSeriesBToA().isEmpty());

    const int analysis_dns_flow_index = find_flow_index_by_protocol_hint(analysis_flow_model, QStringLiteral("DNS"));
    UI_EXPECT(analysis_dns_flow_index >= 0);
    controller.setSelectedFlowIndex(analysis_dns_flow_index);
    controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&controller]() {
        return !controller.analysisLoading() && controller.analysisAvailable();
    }));
    UI_EXPECT(controller.analysisProtocolHint() == QStringLiteral("DNS"));
    UI_EXPECT(controller.analysisProtocolFallbackText() == QStringLiteral("No protocol-specific metadata available"));
    UI_EXPECT(!controller.analysisHasTcpControlCounts());

    const auto tls_analysis_fixture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "tls" / "tls_client_hello_1.pcap";
    MainController tls_analysis_controller {};
    UI_EXPECT(open_capture_and_wait(app, tls_analysis_controller, tls_analysis_fixture_path));
    tls_analysis_controller.setSelectedFlowIndex(0);
    tls_analysis_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&tls_analysis_controller]() {
        return !tls_analysis_controller.analysisLoading() && tls_analysis_controller.analysisAvailable();
    }));
    UI_EXPECT(tls_analysis_controller.analysisProtocolHint() == QStringLiteral("TLS"));
    UI_EXPECT(!tls_analysis_controller.analysisProtocolVersionText().isEmpty());
    UI_EXPECT(tls_analysis_controller.analysisServiceHint() == QStringLiteral("auth.split.io"));
    UI_EXPECT(tls_analysis_controller.analysisProtocolServiceText() == QStringLiteral("auth.split.io"));

    const auto quic_analysis_fixture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "quic" / "quic_initial_ch_1.pcap";
    MainController quic_analysis_controller {};
    UI_EXPECT(open_capture_and_wait(app, quic_analysis_controller, quic_analysis_fixture_path));
    quic_analysis_controller.setSelectedFlowIndex(0);
    quic_analysis_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&quic_analysis_controller]() {
        return !quic_analysis_controller.analysisLoading() && quic_analysis_controller.analysisAvailable();
    }));
    UI_EXPECT(quic_analysis_controller.analysisProtocolHint() == QStringLiteral("QUIC"));
    UI_EXPECT(!quic_analysis_controller.analysisProtocolVersionText().isEmpty());
    UI_EXPECT(quic_analysis_controller.analysisServiceHint() == QStringLiteral("bag.itunes.apple.com"));
    UI_EXPECT(quic_analysis_controller.analysisProtocolServiceText() == QStringLiteral("bag.itunes.apple.com"));

    const auto burst_packet_a = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 55000, 443, 10, 0x18
    );
    const auto burst_packet_b = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 60, 0, 2), ipv4(10, 60, 0, 1), 443, 55000, 20, 0x18
    );
    const auto burst_packet_c = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 55000, 443, 30, 0x18
    );
    const auto burst_packet_d = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 60, 0, 2), ipv4(10, 60, 0, 1), 443, 55000, 40, 0x18
    );
    const auto burst_packet_e = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 55000, 443, 50, 0x18
    );
    const auto burst_packet_f = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 60, 0, 2), ipv4(10, 60, 0, 1), 443, 55000, 5, 0x18
    );
    const auto burst_capture_path = write_temp_pcap(
        "pfl_ui_burst_idle_summary.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 0U, burst_packet_a),
            make_pcapng_enhanced_packet_block(0U, 1U, 400U, burst_packet_b),
            make_pcapng_enhanced_packet_block(0U, 1U, 800U, burst_packet_c),
            make_pcapng_enhanced_packet_block(0U, 1U, 200000U, burst_packet_d),
            make_pcapng_enhanced_packet_block(0U, 1U, 200500U, burst_packet_e),
            make_pcapng_enhanced_packet_block(0U, 1U, 400000U, burst_packet_f),
        })
    );

    MainController burst_analysis_controller {};
    UI_EXPECT(open_capture_and_wait(app, burst_analysis_controller, burst_capture_path));
    burst_analysis_controller.setSelectedFlowIndex(0);
    burst_analysis_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&burst_analysis_controller]() {
        return !burst_analysis_controller.analysisLoading() && burst_analysis_controller.analysisAvailable();
    }));
    UI_EXPECT(burst_analysis_controller.analysisBurstCount() == 2U);
    UI_EXPECT(burst_analysis_controller.analysisBurstCountText() == QStringLiteral("2"));
    UI_EXPECT(burst_analysis_controller.analysisLongestBurstPacketCount() == 3U);
    UI_EXPECT(burst_analysis_controller.analysisLongestBurstPacketCountText() == QStringLiteral("3"));
    UI_EXPECT(burst_analysis_controller.analysisLargestBurstBytesText() == QStringLiteral("222 B"));
    UI_EXPECT(burst_analysis_controller.analysisIdleGapCount() == 2U);
    UI_EXPECT(burst_analysis_controller.analysisIdleGapCountText() == QStringLiteral("2"));
    UI_EXPECT(burst_analysis_controller.analysisLargestIdleGapText() == QStringLiteral("199.500 ms"));

    const auto format_base_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 56000, 443, 0, 0x18
    );
    UI_EXPECT(format_base_packet.size() < 512U);
    const auto format_base_packet_size = static_cast<std::uint32_t>(format_base_packet.size());
    const auto payload_1kb = static_cast<std::uint16_t>(1024U - format_base_packet_size);
    const auto payload_512b = static_cast<std::uint16_t>(512U - format_base_packet_size);
    const auto packet_1kb = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 56000, 443, payload_1kb, 0x18
    );
    const auto packet_512b = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 56000, 443, payload_512b, 0x18
    );
    UI_EXPECT(packet_1kb.size() == 1024U);
    UI_EXPECT(packet_512b.size() == 512U);

    const auto formatting_capture_path = write_temp_pcap(
        "pfl_ui_analysis_formatting.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 0U, packet_1kb),
            make_pcapng_enhanced_packet_block(0U, 1U, 1000000U, packet_512b),
        })
    );

    MainController formatting_controller {};
    UI_EXPECT(open_capture_and_wait(app, formatting_controller, formatting_capture_path));
    formatting_controller.setSelectedFlowIndex(0);
    formatting_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&formatting_controller]() {
        return !formatting_controller.analysisLoading() && formatting_controller.analysisAvailable();
    }));
    UI_EXPECT(formatting_controller.analysisTotalPacketsText() == QStringLiteral("2"));
    UI_EXPECT(formatting_controller.analysisTotalBytesText() == QStringLiteral("1.5 KB"));
    UI_EXPECT(formatting_controller.analysisBytesPerSecondText() == QStringLiteral("1.5 KB/s"));
    UI_EXPECT(formatting_controller.analysisAveragePacketSizeText() == QStringLiteral("768 B"));
    UI_EXPECT(formatting_controller.analysisMinPacketSizeText() == QStringLiteral("512 B"));
    UI_EXPECT(formatting_controller.analysisMaxPacketSizeText() == QStringLiteral("1 KB"));
    UI_EXPECT(formatting_controller.analysisMaxCapturedPacketSizeText() == QStringLiteral("1 KB (1 024 B)"));
    UI_EXPECT(formatting_controller.analysisPacketSizeHistogramMaximumOriginalText() == QStringLiteral("1 KB (1 024 B)"));
    UI_EXPECT(formatting_controller.analysisPacketSizeHistogramMaximumCapturedText() == QStringLiteral("1 KB (1 024 B)"));
    UI_EXPECT(formatting_controller.analysisBytesAToBText() == QStringLiteral("1.5 KB"));
    UI_EXPECT(formatting_controller.analysisBytesBToAText() == QStringLiteral("0 B"));

    const auto metrics_packet_100 = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 80, 0, 1), ipv4(10, 80, 0, 2), 57000, 443, 46, 0x18
    );
    const auto metrics_packet_200 = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 80, 0, 2), ipv4(10, 80, 0, 1), 443, 57000, 146, 0x18
    );
    UI_EXPECT(metrics_packet_100.size() == 100U);
    UI_EXPECT(metrics_packet_200.size() == 200U);
    const auto metrics_capture_path = write_temp_pcap(
        "pfl_ui_analysis_directional_metrics_table.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 0U, metrics_packet_100),
            make_pcapng_enhanced_packet_block(0U, 1U, 250000U, metrics_packet_200),
            make_pcapng_enhanced_packet_block(0U, 1U, 500000U, metrics_packet_100),
            make_pcapng_enhanced_packet_block(0U, 2U, 0U, metrics_packet_200),
        })
    );

    MainController metrics_controller {};
    UI_EXPECT(open_capture_and_wait(app, metrics_controller, metrics_capture_path));
    auto* metrics_flow_model = qobject_cast<FlowListModel*>(metrics_controller.flowModel());
    UI_EXPECT(metrics_flow_model != nullptr);
    metrics_controller.setSelectedFlowIndex(0);
    metrics_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&metrics_controller]() {
        return !metrics_controller.analysisLoading() && metrics_controller.analysisAvailable();
    }));
    UI_EXPECT(metrics_controller.analysisEndpointSummaryText() == expected_endpoint_summary_for_flow(*metrics_flow_model, 0));
    UI_EXPECT(metrics_controller.analysisPacketsPerSecondText() == QStringLiteral("4.000 pkt/s"));
    UI_EXPECT(metrics_controller.analysisPacketsPerSecondAToBText() == QStringLiteral("2.000 pkt/s"));
    UI_EXPECT(metrics_controller.analysisPacketsPerSecondBToAText() == QStringLiteral("2.000 pkt/s"));
    UI_EXPECT(metrics_controller.analysisBytesPerSecondText() == QStringLiteral("600 B/s"));
    UI_EXPECT(metrics_controller.analysisBytesPerSecondAToBText() == QStringLiteral("200 B/s"));
    UI_EXPECT(metrics_controller.analysisBytesPerSecondBToAText() == QStringLiteral("400 B/s"));
    UI_EXPECT(metrics_controller.analysisAveragePacketSizeText() == QStringLiteral("150 B"));
    UI_EXPECT(metrics_controller.analysisAveragePacketSizeAToBText() == QStringLiteral("100 B"));
    UI_EXPECT(metrics_controller.analysisAveragePacketSizeBToAText() == QStringLiteral("200 B"));
    UI_EXPECT(metrics_controller.analysisMinPacketSizeText() == QStringLiteral("100 B"));
    UI_EXPECT(metrics_controller.analysisMinPacketSizeAToBText() == QStringLiteral("100 B"));
    UI_EXPECT(metrics_controller.analysisMinPacketSizeBToAText() == QStringLiteral("200 B"));
    UI_EXPECT(metrics_controller.analysisMaxPacketSizeText() == QStringLiteral("200 B"));
    UI_EXPECT(metrics_controller.analysisMaxCapturedPacketSizeText() == QStringLiteral("200 B"));
    UI_EXPECT(metrics_controller.analysisMaxPacketSizeAToBText() == QStringLiteral("100 B"));
    UI_EXPECT(metrics_controller.analysisMaxPacketSizeBToAText() == QStringLiteral("200 B"));

    const auto directional_a_small = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 71, 0, 1), ipv4(10, 71, 0, 2), 56100, 443, 0, 0x18
    );
    const auto directional_b_large = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 71, 0, 2), ipv4(10, 71, 0, 1), 443, 56100, 2476, 0x18
    );
    const auto directional_a_mid = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 71, 0, 1), ipv4(10, 71, 0, 2), 56100, 443, 1376, 0x18
    );
    const auto directional_b_huge = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 71, 0, 2), ipv4(10, 71, 0, 1), 443, 56100, 5000, 0x18
    );
    const auto directional_capture_path = write_temp_pcap(
        "pfl_ui_analysis_directional_histograms.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 0U, directional_a_small),
            make_pcapng_enhanced_packet_block(0U, 1U, 9U, directional_b_large),
            make_pcapng_enhanced_packet_block(0U, 1U, 99U, directional_a_mid),
            make_pcapng_enhanced_packet_block(0U, 1U, 999U, directional_b_huge),
        })
    );

    MainController directional_histogram_controller {};
    UI_EXPECT(open_capture_and_wait(app, directional_histogram_controller, directional_capture_path));
    directional_histogram_controller.setSelectedFlowIndex(0);
    directional_histogram_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&directional_histogram_controller]() {
        return !directional_histogram_controller.analysisLoading() && directional_histogram_controller.analysisAvailable();
    }));
    UI_EXPECT(histogram_total_count(directional_histogram_controller.analysisPacketSizeHistogramAll()) == 4U);
    UI_EXPECT(histogram_total_count(directional_histogram_controller.analysisPacketSizeHistogramAToB()) == 2U);
    UI_EXPECT(histogram_total_count(directional_histogram_controller.analysisPacketSizeHistogramBToA()) == 2U);
    UI_EXPECT(
        histogram_total_count(directional_histogram_controller.analysisPacketSizeHistogramAll()) ==
        histogram_total_count(directional_histogram_controller.analysisPacketSizeHistogramAToB()) +
        histogram_total_count(directional_histogram_controller.analysisPacketSizeHistogramBToA())
    );
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisPacketSizeHistogramAToB(), "0-63") == 1U);
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisPacketSizeHistogramAToB(), "1400-1550") == 1U);
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisPacketSizeHistogramBToA(), "2500-5000") == 1U);
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisPacketSizeHistogramBToA(), "5001+") == 1U);
    UI_EXPECT(histogram_total_count(directional_histogram_controller.analysisInterArrivalHistogramAll()) == 3U);
    UI_EXPECT(histogram_total_count(directional_histogram_controller.analysisInterArrivalHistogramAToB()) == 1U);
    UI_EXPECT(histogram_total_count(directional_histogram_controller.analysisInterArrivalHistogramBToA()) == 2U);
    UI_EXPECT(
        histogram_total_count(directional_histogram_controller.analysisInterArrivalHistogramAll()) ==
        histogram_total_count(directional_histogram_controller.analysisInterArrivalHistogramAToB()) +
        histogram_total_count(directional_histogram_controller.analysisInterArrivalHistogramBToA())
    );
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisInterArrivalHistogramBToA(), "0-9 us") == 1U);
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisInterArrivalHistogramAToB(), "10-99 us") == 1U);
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisInterArrivalHistogramBToA(), "100-999 us") == 1U);
    int analysis_state_change_count = 0;
    QObject::connect(&directional_histogram_controller, &MainController::analysisStateChanged, [&]() {
        ++analysis_state_change_count;
    });
    run_ui_section("analysis_histogram_pane_projection", [&]() {
        auto pane = load_flow_analysis_pane_component();
        pane.object->setProperty("analysisAvailable", true);
        pane.object->setProperty("hasActiveFlow", true);
        pane.object->setProperty("packetSizeHistogramAllModel", directional_histogram_controller.analysisPacketSizeHistogramAll());
        pane.object->setProperty("packetSizeHistogramAToBModel", directional_histogram_controller.analysisPacketSizeHistogramAToB());
        pane.object->setProperty("packetSizeHistogramBToAModel", directional_histogram_controller.analysisPacketSizeHistogramBToA());
        pane.object->setProperty("capturedPacketSizeHistogramAllModel", directional_histogram_controller.analysisCapturedPacketSizeHistogramAll());
        pane.object->setProperty("capturedPacketSizeHistogramAToBModel", directional_histogram_controller.analysisCapturedPacketSizeHistogramAToB());
        pane.object->setProperty("capturedPacketSizeHistogramBToAModel", directional_histogram_controller.analysisCapturedPacketSizeHistogramBToA());
        pane.object->setProperty("interArrivalHistogramAllModel", directional_histogram_controller.analysisInterArrivalHistogramAll());
        pane.object->setProperty("interArrivalHistogramAToBModel", directional_histogram_controller.analysisInterArrivalHistogramAToB());
        pane.object->setProperty("interArrivalHistogramBToAModel", directional_histogram_controller.analysisInterArrivalHistogramBToA());
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("packetSizeHistogramMetricMode").toInt() == 0);
        UI_EXPECT(pane.object->property("packetSizeHistogramDirectionMode").toInt() == 0);
        UI_EXPECT(pane.object->property("interArrivalHistogramDirectionMode").toInt() == 0);
        pane.object->setProperty("packetSizeHistogramMetricMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 4);
        pane.object->setProperty("packetSizeHistogramDirectionMode", 2);
        pane.object->setProperty("interArrivalHistogramDirectionMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 2);
        UI_EXPECT(pane.object->property("displayedInterArrivalHistogramTotal").toInt() == 1);
    });
    UI_EXPECT(analysis_state_change_count == 0);

    const auto packet_balanced_large_a = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 72, 0, 1), ipv4(10, 72, 0, 2), 56200, 443, 1100, 0x18
    );
    const auto packet_balanced_small_b = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 72, 0, 2), ipv4(10, 72, 0, 1), 443, 56200, 0, 0x18
    );
    const auto packet_balanced_byte_skew_capture = write_temp_pcap(
        "pfl_ui_analysis_packet_balanced_byte_skew.pcap",
        make_classic_pcap({
            {100U, packet_balanced_large_a},
            {200U, packet_balanced_small_b},
            {300U, packet_balanced_large_a},
            {400U, packet_balanced_small_b},
        })
    );

    MainController packet_balanced_byte_skew_controller {};
    UI_EXPECT(open_capture_and_wait(app, packet_balanced_byte_skew_controller, packet_balanced_byte_skew_capture));
    packet_balanced_byte_skew_controller.setSelectedFlowIndex(0);
    packet_balanced_byte_skew_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&packet_balanced_byte_skew_controller]() {
        return !packet_balanced_byte_skew_controller.analysisLoading() && packet_balanced_byte_skew_controller.analysisAvailable();
    }));
    UI_EXPECT(packet_balanced_byte_skew_controller.analysisPacketDirectionText() == QStringLiteral("Balanced"));
    UI_EXPECT(packet_balanced_byte_skew_controller.analysisDataDirectionText() == QStringLiteral("Mostly A->B"));

    const auto many_small_a = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 73, 0, 1), ipv4(10, 73, 0, 2), 56300, 443, 0, 0x18
    );
    const auto one_large_b = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 73, 0, 2), ipv4(10, 73, 0, 1), 443, 56300, 300, 0x18
    );
    const auto byte_balanced_packet_skew_capture = write_temp_pcap(
        "pfl_ui_analysis_byte_balanced_packet_skew.pcap",
        make_classic_pcap({
            {100U, many_small_a},
            {200U, many_small_a},
            {300U, many_small_a},
            {400U, many_small_a},
            {500U, one_large_b},
        })
    );

    MainController byte_balanced_packet_skew_controller {};
    UI_EXPECT(open_capture_and_wait(app, byte_balanced_packet_skew_controller, byte_balanced_packet_skew_capture));
    byte_balanced_packet_skew_controller.setSelectedFlowIndex(0);
    byte_balanced_packet_skew_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&byte_balanced_packet_skew_controller]() {
        return !byte_balanced_packet_skew_controller.analysisLoading() && byte_balanced_packet_skew_controller.analysisAvailable();
    }));
    UI_EXPECT(byte_balanced_packet_skew_controller.analysisPacketDirectionText() == QStringLiteral("Mostly A->B"));
    UI_EXPECT(byte_balanced_packet_skew_controller.analysisDataDirectionText() == QStringLiteral("Balanced"));

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> grouped_packets {};
    grouped_packets.reserve(1024);
    for (std::uint32_t index = 0; index < 1024U; ++index) {
        grouped_packets.push_back({100U + index, http_flow});
    }
    const auto grouped_capture_path = write_temp_pcap(
        "pfl_ui_analysis_grouped_counts.pcap",
        make_classic_pcap(grouped_packets)
    );

    MainController grouped_controller {};
    UI_EXPECT(open_capture_and_wait(app, grouped_controller, grouped_capture_path));
    grouped_controller.setSelectedFlowIndex(0);
    grouped_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&grouped_controller]() {
        return !grouped_controller.analysisLoading() && grouped_controller.analysisAvailable();
    }));
    UI_EXPECT(grouped_controller.analysisTotalPacketsText() == QStringLiteral("1 024"));
    UI_EXPECT(grouped_controller.analysisTimelinePacketCountConsideredText() == QStringLiteral("1 024"));
    UI_EXPECT(
        histogram_packet_count_text(
            grouped_controller.analysisPacketSizeHistogram(),
            packet_size_bucket_label(static_cast<std::uint32_t>(http_flow.size()))
        ) == QStringLiteral("1 024")
    );

    const auto sequence_packet_a = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 80, 0, 1), ipv4(10, 80, 0, 2), 57000, 443, 12, 0x02
    );
    const auto sequence_packet_b = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 80, 0, 2), ipv4(10, 80, 0, 1), 443, 57000, 8, 0x12
    );
    const auto sequence_packet_c = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 80, 0, 1), ipv4(10, 80, 0, 2), 57000, 443, 4, 0x18
    );
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> sequence_packets {};
    sequence_packets.reserve(25);
    sequence_packets.push_back({100U, sequence_packet_a});
    sequence_packets.push_back({250U, sequence_packet_b});
    sequence_packets.push_back({500U, sequence_packet_c});
    for (std::uint32_t index = 3U; index < 25U; ++index) {
        sequence_packets.push_back({500U + (index * 100U), (index % 2U == 0U) ? sequence_packet_a : sequence_packet_b});
    }
    const auto sequence_capture_path = write_temp_pcap(
        "pfl_ui_analysis_sequence_export.pcap",
        make_classic_pcap(sequence_packets)
    );

    MainController sequence_export_controller {};
    UI_EXPECT(!sequence_export_controller.canExportAnalysisSequence());
    const auto no_selection_sequence_export_path = std::filesystem::temp_directory_path() / "pfl_ui_no_selection_sequence.csv";
    std::filesystem::remove(no_selection_sequence_export_path, remove_error);
    UI_EXPECT(!sequence_export_controller.exportSelectedFlowSequenceCsv(QString::fromStdWString(no_selection_sequence_export_path.wstring())));
    UI_EXPECT(sequence_export_controller.analysisSequenceExportStatusText() == QStringLiteral("No flow selected for sequence export."));
    UI_EXPECT(sequence_export_controller.analysisSequenceExportStatusIsError());
    UI_EXPECT(open_capture_and_wait(app, sequence_export_controller, sequence_capture_path));
    sequence_export_controller.setSelectedFlowIndex(0);
    sequence_export_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&sequence_export_controller]() {
        return !sequence_export_controller.analysisLoading() && sequence_export_controller.analysisAvailable();
    }));
    UI_EXPECT(sequence_export_controller.canExportAnalysisSequence());
    UI_EXPECT(sequence_export_controller.analysisSequencePreview().size() == 20);

    bool saw_sequence_export_in_progress = false;
    QObject::connect(&sequence_export_controller, &MainController::analysisSequenceExportStateChanged, [&]() {
        if (sequence_export_controller.analysisSequenceExportInProgress()) {
            saw_sequence_export_in_progress = true;
        }
    });

    const auto sequence_export_path = std::filesystem::temp_directory_path() / "pfl_ui_selected_flow_sequence.csv";
    std::filesystem::remove(sequence_export_path, remove_error);
    UI_EXPECT(sequence_export_controller.exportSelectedFlowSequenceCsv(QString::fromStdWString(sequence_export_path.wstring())));
    UI_EXPECT(wait_until(app, [&sequence_export_controller]() {
        return !sequence_export_controller.analysisSequenceExportInProgress();
    }));
    UI_EXPECT(saw_sequence_export_in_progress);
    UI_EXPECT(sequence_export_controller.analysisSequenceExportStatusText().contains(QStringLiteral("Flow sequence CSV exported:")));
    UI_EXPECT(!sequence_export_controller.analysisSequenceExportStatusIsError());
    UI_EXPECT(std::filesystem::exists(sequence_export_path));

    const auto sequence_csv_lines = read_text_file_lines(sequence_export_path);
    UI_EXPECT(sequence_csv_lines.size() == 26U);
    UI_REQUIRE(sequence_csv_lines.size() >= 4U);
    UI_EXPECT(sequence_csv_lines.front() == "flow_packet_index,packet_index,direction,timestamp,delta_us,captured_length,original_length,transport_payload_length,tcp_flags,protocol_hint");

    const auto first_export_row = split_csv_line(sequence_csv_lines[1]);
    UI_EXPECT(first_export_row.size() == 10U);
    UI_REQUIRE(first_export_row.size() >= 10U);
    UI_EXPECT(first_export_row[0] == "1");
    UI_EXPECT(first_export_row[1] == "0");
    UI_EXPECT(first_export_row[2] == "A->B");
    UI_EXPECT(first_export_row[3] == "00:00:01.000100");
    UI_EXPECT(first_export_row[4] == "0");
    UI_EXPECT(first_export_row[5] == std::to_string(sequence_packet_a.size()));
    UI_EXPECT(first_export_row[6] == std::to_string(sequence_packet_a.size()));
    UI_EXPECT(first_export_row[7] == "12");
    UI_EXPECT(first_export_row[8] == "SYN");
    UI_EXPECT(first_export_row[9].empty());

    const auto second_export_row = split_csv_line(sequence_csv_lines[2]);
    UI_EXPECT(second_export_row.size() == 10U);
    UI_REQUIRE(second_export_row.size() >= 10U);
    UI_EXPECT(second_export_row[0] == "2");
    UI_EXPECT(second_export_row[1] == "1");
    UI_EXPECT(second_export_row[2] == "B->A");
    UI_EXPECT(second_export_row[3] == "00:00:02.000250");
    UI_EXPECT(second_export_row[4] == "1000150");
    UI_EXPECT(second_export_row[7] == "8");
    UI_EXPECT(second_export_row[8] == "ACK|SYN");
    UI_EXPECT(second_export_row[9].empty());

    const auto third_export_row = split_csv_line(sequence_csv_lines[3]);
    UI_EXPECT(third_export_row.size() == 10U);
    UI_REQUIRE(third_export_row.size() >= 10U);
    UI_EXPECT(third_export_row[0] == "3");
    UI_EXPECT(third_export_row[1] == "2");
    UI_EXPECT(third_export_row[2] == "A->B");
    UI_EXPECT(third_export_row[3] == "00:00:03.000500");
    UI_EXPECT(third_export_row[4] == "1000250");
    UI_EXPECT(third_export_row[7] == "4");
    UI_EXPECT(third_export_row[8] == "ACK|PSH");
    UI_EXPECT(third_export_row[9].empty());

    const auto invalid_sequence_export_path = std::filesystem::temp_directory_path() / "pfl_missing_sequence_export_dir" / "selected_flow_sequence.csv";
    std::filesystem::remove(invalid_sequence_export_path, remove_error);
    UI_EXPECT(sequence_export_controller.exportSelectedFlowSequenceCsv(QString::fromStdWString(invalid_sequence_export_path.wstring())));
    UI_EXPECT(wait_until(app, [&sequence_export_controller]() {
        return !sequence_export_controller.analysisSequenceExportInProgress()
            && sequence_export_controller.analysisSequenceExportStatusIsError();
    }));
    UI_EXPECT(sequence_export_controller.analysisSequenceExportStatusText() == QStringLiteral("Failed to open output CSV file."));

    MainController multi_flow_controller {};
    UI_EXPECT(open_capture_and_wait(app, multi_flow_controller, capture_path));
    auto* multi_flow_model = qobject_cast<FlowListModel*>(multi_flow_controller.flowModel());
    auto* multi_packet_model = qobject_cast<PacketListModel*>(multi_flow_controller.packetModel());
    UI_EXPECT(multi_flow_model != nullptr);
    UI_EXPECT(multi_packet_model != nullptr);
    UI_EXPECT(multi_flow_controller.selectedFlowCount() == 0U);
    UI_EXPECT(!multi_flow_controller.canExportSelectedFlows());
    UI_EXPECT(multi_flow_controller.canExportUnselectedFlows());
    UI_EXPECT(multi_flow_controller.canExportAllFlowsInfoCsv());

    const int http_selected_flow_index = find_flow_index_by_protocol_hint(multi_flow_model, QStringLiteral("HTTP"));
    const int dns_selected_flow_index = find_flow_index_by_protocol_hint(multi_flow_model, QStringLiteral("DNS"));
    UI_EXPECT(http_selected_flow_index >= 0);
    UI_EXPECT(dns_selected_flow_index >= 0);

    multi_flow_model->setFlowChecked(http_selected_flow_index, true);
    UI_EXPECT(multi_flow_controller.selectedFlowCount() == 1U);
    UI_EXPECT(multi_flow_model->isFlowChecked(http_selected_flow_index));
    UI_EXPECT(multi_flow_controller.canExportSelectedFlows());
    UI_EXPECT(multi_flow_controller.canExportUnselectedFlows());

    multi_flow_model->setFlowChecked(dns_selected_flow_index, true);
    UI_EXPECT(multi_flow_controller.selectedFlowCount() == 2U);
    UI_EXPECT(multi_flow_model->isFlowChecked(dns_selected_flow_index));

    multi_flow_controller.setSelectedFlowIndex(http_selected_flow_index);
    UI_EXPECT(multi_flow_controller.selectedFlowIndex() == http_selected_flow_index);
    UI_EXPECT(multi_flow_controller.selectedFlowCount() == 2U);
    UI_EXPECT(multi_packet_model->rowCount() == 1);

    const auto selected_export_path = std::filesystem::temp_directory_path() / "pfl_ui_export_selected_flows.pcap";
    std::filesystem::remove(selected_export_path, remove_error);
    UI_EXPECT(multi_flow_controller.exportSelectedFlows(QString::fromStdWString(selected_export_path.wstring())));
    CaptureSession selected_export_session {};
    UI_EXPECT(selected_export_session.open_capture(selected_export_path));
    UI_EXPECT(selected_export_session.summary().flow_count == 2U);
    UI_EXPECT(selected_export_session.summary().packet_count == 2U);
    const auto selected_export_stats = selected_export_session.protocol_summary();
    UI_EXPECT(selected_export_stats.hint_http.flow_count == 1U);
    UI_EXPECT(selected_export_stats.hint_dns.flow_count == 1U);
    UI_EXPECT(selected_export_stats.hint_unknown.flow_count == 0U);

    const auto unselected_export_path = std::filesystem::temp_directory_path() / "pfl_ui_export_unselected_flows.pcap";
    std::filesystem::remove(unselected_export_path, remove_error);
    UI_EXPECT(multi_flow_controller.exportUnselectedFlows(QString::fromStdWString(unselected_export_path.wstring())));
    CaptureSession unselected_export_session {};
    UI_EXPECT(unselected_export_session.open_capture(unselected_export_path));
    UI_EXPECT(unselected_export_session.summary().flow_count == 1U);
    UI_EXPECT(unselected_export_session.summary().packet_count == 1U);
    UI_EXPECT(unselected_export_session.protocol_summary().hint_unknown.flow_count == 1U);

    const auto flow_info_csv_path = std::filesystem::temp_directory_path() / "pfl_ui_all_flows_info.csv";
    std::filesystem::remove(flow_info_csv_path, remove_error);
    UI_EXPECT(multi_flow_controller.exportAllFlowsInfoCsv(QString::fromStdWString(flow_info_csv_path.wstring())));
    UI_EXPECT(wait_until(app, [&multi_flow_controller]() {
        return multi_flow_controller.statusText().contains(QStringLiteral("Flow info CSV exported:"));
    }));
    UI_EXPECT(!multi_flow_controller.statusIsError());
    UI_EXPECT(std::filesystem::exists(flow_info_csv_path));
    const auto flow_info_csv_lines = read_text_file_lines(flow_info_csv_path);
    UI_EXPECT(flow_info_csv_lines.size() == 4U);
    UI_REQUIRE(flow_info_csv_lines.size() >= 2U);
    UI_EXPECT(flow_info_csv_lines.front() ==
        "flow_id,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,protocol_path");
    UI_EXPECT(!QString::fromStdString(flow_info_csv_lines.front()).contains(QStringLiteral("file_name")));
    UI_EXPECT(!QString::fromStdString(flow_info_csv_lines.front()).contains(QStringLiteral("exported_packet_count")));
    UI_EXPECT(QString::fromStdString(flow_info_csv_lines[1]).contains(QStringLiteral("\"EthernetII->IPv4->TCP\"")));
    UI_EXPECT(!QString::fromStdString(flow_info_csv_lines[1]).contains(QStringLiteral("EthernetII -> IPv4 -> TCP")));
    const auto flow_info_first_row = split_csv_line(flow_info_csv_lines[1]);
    UI_EXPECT(flow_info_first_row.size() == 16U);
    UI_REQUIRE(flow_info_first_row.size() >= 16U);
    UI_EXPECT(flow_info_first_row[15] == "EthernetII->IPv4->TCP");

    multi_flow_controller.clearSelectedFlows();
    UI_EXPECT(multi_flow_controller.selectedFlowCount() == 0U);
    UI_EXPECT(!multi_flow_controller.canExportSelectedFlows());
    UI_EXPECT(multi_flow_controller.canExportUnselectedFlows());
    UI_EXPECT(multi_flow_controller.selectedFlowIndex() == http_selected_flow_index);
    UI_EXPECT(multi_packet_model->rowCount() == 1);

    CaptureSession index_session {};
    UI_EXPECT(index_session.open_capture(capture_path));
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_ui_mode_test.idx";
    std::filesystem::remove(index_path, remove_error);
    UI_EXPECT(index_session.save_index(index_path));

    const auto moved_capture_path = std::filesystem::temp_directory_path() / "pfl_ui_mode_test_source.gone.pcap";
    const auto mismatched_attach_path = std::filesystem::temp_directory_path() / "pfl_ui_mode_test_source_mismatch.pcap";
    std::filesystem::remove(moved_capture_path, remove_error);
    std::filesystem::remove(mismatched_attach_path, remove_error);
    std::filesystem::rename(capture_path, moved_capture_path);

    UI_EXPECT(open_index_and_wait(app, controller, index_path));
    UI_EXPECT(controller.openedFromIndex());
    UI_EXPECT(!controller.hasSourceCapture());
    UI_EXPECT(controller.canAttachSourceCapture());
    UI_EXPECT(!controller.canSaveIndex());
    UI_EXPECT(controller.flowCount() == 3U);

    auto mismatched_capture_bytes = make_classic_pcap({
        {100, http_flow},
        {200, dns_flow},
        {300, generic_tcp},
    });
    mismatched_capture_bytes.back() ^= 0xFFU;
    {
        std::ofstream mismatched_stream(mismatched_attach_path, std::ios::binary | std::ios::trunc);
        mismatched_stream.write(reinterpret_cast<const char*>(mismatched_capture_bytes.data()), static_cast<std::streamsize>(mismatched_capture_bytes.size()));
    }
    std::filesystem::last_write_time(mismatched_attach_path, std::filesystem::last_write_time(moved_capture_path));

    UI_EXPECT(!controller.attachSourceCapture(QString::fromStdWString(mismatched_attach_path.wstring())));
    UI_EXPECT(controller.openedFromIndex());
    UI_EXPECT(!controller.hasSourceCapture());
    UI_EXPECT(controller.canAttachSourceCapture());
    UI_EXPECT(controller.statusIsError());

    UI_EXPECT(controller.attachSourceCapture(QString::fromStdWString(moved_capture_path.wstring())));
    UI_EXPECT(controller.openedFromIndex());
    UI_EXPECT(controller.hasSourceCapture());
    UI_EXPECT(!controller.canAttachSourceCapture());
    UI_EXPECT(controller.canSaveIndex());
    UI_EXPECT(!controller.statusIsError());

    UI_EXPECT(open_capture_and_wait(app, controller, moved_capture_path));

    const auto preserved_input_path = controller.currentInputPath();
    const auto preserved_flow_count = controller.flowCount();
    const auto missing_capture_path = std::filesystem::temp_directory_path() / "pfl_ui_missing_open_capture.pcap";
    std::filesystem::remove(missing_capture_path, remove_error);
    UI_EXPECT(controller.openCaptureFile(QString::fromStdWString(missing_capture_path.wstring())));
    UI_EXPECT(wait_for_open_to_finish(app, controller));
    UI_EXPECT(controller.hasCapture());
    UI_EXPECT(controller.flowCount() == preserved_flow_count);
    UI_EXPECT(controller.currentInputPath() == preserved_input_path);
    UI_EXPECT(controller.openErrorText() == QStringLiteral("Failed to open capture file."));


    auto partial_capture_bytes = make_classic_pcap({
        {100, http_flow},
        {200, dns_flow},
    });
    partial_capture_bytes.resize(partial_capture_bytes.size() - 5U);
    const auto partial_capture_path = write_temp_pcap("pfl_ui_partial_open_capture.pcap", partial_capture_bytes);

    MainController partial_controller {};
    UI_EXPECT(open_capture_and_wait(app, partial_controller, partial_capture_path));
    UI_EXPECT(partial_controller.hasCapture());
    UI_EXPECT(partial_controller.packetCount() == 1U);
    UI_EXPECT(partial_controller.flowCount() == 1U);
    UI_EXPECT(partial_controller.canSaveIndex());
    UI_EXPECT(partial_controller.partialOpen());
    UI_EXPECT(partial_controller.openErrorText().isEmpty());
    UI_EXPECT(partial_controller.statusText().isEmpty());
    UI_EXPECT(partial_controller.partialOpenWarningText().contains(QStringLiteral("Capture opened partially.")));
    UI_EXPECT(partial_controller.partialOpenWarningText().contains(QStringLiteral("Results are incomplete.")));
    auto* partial_packet_model = qobject_cast<PacketListModel*>(partial_controller.packetModel());
    UI_EXPECT(partial_packet_model != nullptr);
    partial_controller.setSelectedFlowIndex(0);
    UI_EXPECT(partial_packet_model->rowCount() == 1);
    const auto partial_index_path = std::filesystem::temp_directory_path() / "pfl_ui_partial_should_save.idx";
    std::filesystem::remove(partial_index_path, remove_error);
    UI_EXPECT(partial_controller.saveAnalysisIndex(QString::fromStdWString(partial_index_path.wstring())));
    UI_EXPECT(wait_until(app, [&partial_controller, &partial_index_path]() {
        return !partial_controller.indexSaveInProgress() && std::filesystem::exists(partial_index_path);
    }));
    UI_EXPECT(partial_controller.statusText() == QStringLiteral("Analysis index saved successfully: %1").arg(QString::fromStdWString(partial_index_path.wstring())));
    UI_EXPECT(!partial_controller.statusIsError());
    auto* flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
    UI_EXPECT(flow_model != nullptr);
    UI_EXPECT(flow_model->rowCount() == 3);

    bool sawHttp = false;
    bool sawDns = false;
    for (int row = 0; row < flow_model->rowCount(); ++row) {
        const auto index = flow_model->index(row, 0);
        const auto hint = flow_model->data(index, FlowListModel::ProtocolHintRole).toString();
        const auto service = flow_model->data(index, FlowListModel::ServiceHintRole).toString();

        if (hint == QStringLiteral("HTTP")) {
            sawHttp = true;
            UI_EXPECT(service == QStringLiteral("ui.example"));
            const auto addressA = flow_model->data(index, FlowListModel::AddressARole).toString();
            const auto portA = flow_model->data(index, FlowListModel::PortARole).toUInt();
            const auto addressB = flow_model->data(index, FlowListModel::AddressBRole).toString();
            const auto portB = flow_model->data(index, FlowListModel::PortBRole).toUInt();
            UI_EXPECT(
                (addressA == QStringLiteral("10.0.0.1") && portA == 1111U) ||
                (addressB == QStringLiteral("10.0.0.1") && portB == 1111U)
            );
        }

        if (hint == QStringLiteral("DNS")) {
            sawDns = true;
            UI_EXPECT(service == QStringLiteral("api.example"));
            const auto portA = flow_model->data(index, FlowListModel::PortARole).toUInt();
            const auto portB = flow_model->data(index, FlowListModel::PortBRole).toUInt();
            UI_EXPECT(portA == 53U || portB == 53U);
        }
    }
    UI_EXPECT(sawHttp);
    UI_EXPECT(sawDns);

    const auto quic_fixture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "quic" / "quic_initial_ch_1.pcap";
    MainController quic_controller {};
    UI_EXPECT(open_capture_and_wait(app, quic_controller, quic_fixture_path));
    auto* quic_flow_model = qobject_cast<FlowListModel*>(quic_controller.flowModel());
    UI_EXPECT(quic_flow_model != nullptr);
    UI_EXPECT(quic_flow_model->rowCount() == 1);
    UI_EXPECT(quic_flow_model->data(quic_flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("QUIC"));
    UI_EXPECT(quic_flow_model->data(quic_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("bag.itunes.apple.com"));
    quic_controller.setSelectedFlowIndex(0);
    UI_EXPECT(quic_flow_model->data(quic_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("bag.itunes.apple.com"));
    auto* quic_packet_model = qobject_cast<PacketListModel*>(quic_controller.packetModel());
    auto* quic_stream_model = qobject_cast<StreamListModel*>(quic_controller.streamModel());
    auto* quic_details_model = qobject_cast<PacketDetailsViewModel*>(quic_controller.packetDetailsModel());
    UI_EXPECT(quic_packet_model != nullptr);
    UI_EXPECT(quic_stream_model != nullptr);
    UI_EXPECT(quic_details_model != nullptr);
    UI_EXPECT(quic_packet_model->rowCount() >= 1);
    quic_controller.setSelectedPacketIndex(0);
    UI_EXPECT(wait_until(app, [&]() {
        const auto labels = packet_byte_view_labels(quic_details_model);
        const auto quic_layer = find_top_level_summary_layer(quic_details_model->summaryLayers(), QStringLiteral("quic"));
        const auto tls_layer = find_top_level_summary_layer(quic_details_model->summaryLayers(), QStringLiteral("tls"));
        return quic_details_model->detailsTitle() == QStringLiteral("Packet Details") &&
            !quic_layer.isEmpty() &&
            !tls_layer.isEmpty() &&
            find_summary_field_value(quic_layer, QStringLiteral("Packet Type")) == QStringLiteral("Initial") &&
            find_summary_field_value(tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello") &&
            labels.contains(QStringLiteral("QUIC Initial Decrypted Payload")) &&
            packet_byte_view_label_starts_with(quic_details_model, QStringLiteral("CRYPTO Frame")) &&
            packet_byte_view_label_starts_with(quic_details_model, QStringLiteral("TLS Handshake Message, ClientHello"));
    }));
    UI_EXPECT(quic_details_model->detailsTitle() == QStringLiteral("Packet Details"));
    const auto quic_packet_layers = quic_details_model->summaryLayers();
    const auto quic_packet_quic_layer = find_top_level_summary_layer(quic_packet_layers, QStringLiteral("quic"));
    const auto quic_packet_tls_layer = find_top_level_summary_layer(quic_packet_layers, QStringLiteral("tls"));
    UI_EXPECT(!quic_packet_quic_layer.isEmpty());
    UI_EXPECT(!quic_packet_tls_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(quic_packet_quic_layer, QStringLiteral("Packet Type")) == QStringLiteral("Initial"));
    UI_EXPECT(find_summary_field_value(quic_packet_tls_layer, QStringLiteral("SNI")) == QStringLiteral("bag.itunes.apple.com"));
    UI_EXPECT(find_summary_field_value(quic_packet_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));
    UI_EXPECT(packet_byte_view_labels(quic_details_model).contains(QStringLiteral("QUIC Initial Packet")));
    UI_EXPECT(packet_byte_view_labels(quic_details_model).contains(QStringLiteral("QUIC Initial Protected Payload")));
    UI_EXPECT(packet_byte_view_labels(quic_details_model).contains(QStringLiteral("QUIC Initial Decrypted Payload")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_details_model, QStringLiteral("CRYPTO Frame")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_details_model, QStringLiteral("CRYPTO Frame Data")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_details_model, QStringLiteral("TLS Handshake Message, ClientHello")));
    UI_EXPECT(!packet_byte_view_labels(quic_details_model).contains(QStringLiteral("TLS Handshake Record")));
    const auto quic_crypto_data_view_id = find_packet_byte_view_stable_id_by_label_prefix(
        quic_details_model,
        QStringLiteral("CRYPTO Frame Data")
    );
    UI_EXPECT(!quic_crypto_data_view_id.isEmpty());
    quic_controller.selectPacketByteView(quic_crypto_data_view_id);
    UI_EXPECT(wait_until(app, [&]() {
        return quic_details_model->selectedPacketByteViewId() == quic_crypto_data_view_id;
    }));
    UI_EXPECT(quic_details_model->selectedPacketByteViewText().contains(QStringLiteral("03 03")));
    const auto quic_tls_handshake_view_id = find_packet_byte_view_stable_id_by_label_prefix(
        quic_details_model,
        QStringLiteral("TLS Handshake Message, ClientHello")
    );
    UI_EXPECT(!quic_tls_handshake_view_id.isEmpty());
    quic_controller.selectPacketByteView(quic_tls_handshake_view_id);
    UI_EXPECT(wait_until(app, [&]() {
        return quic_details_model->selectedPacketByteViewId() == quic_tls_handshake_view_id;
    }));
    UI_EXPECT(quic_details_model->selectedPacketByteViewText().contains(QStringLiteral("01 00")));

    quic_controller.setFlowDetailsTabIndex(1);
    UI_EXPECT(quic_stream_model->rowCount() >= 1);
    const auto find_quic_initial_like_row = [](StreamListModel* model) {
        for (int row = 0; row < model->rowCount(); ++row) {
            const auto label = model->data(model->index(row, 0), StreamListModel::LabelRole).toString();
            if (label == QStringLiteral("QUIC Initial: CRYPTO")) {
                return row;
            }
        }
        return -1;
    };
    const int quic_initial_row = find_quic_initial_like_row(quic_stream_model);
    UI_EXPECT(quic_initial_row >= 0);
    const auto quic_stream_item_index = quic_stream_model->data(
        quic_stream_model->index(quic_initial_row, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    quic_controller.setSelectedStreamItemIndex(quic_stream_item_index);
    UI_EXPECT(quic_details_model->detailsTitle() == QStringLiteral("Stream Item Details"));

    const auto quic_multi_crypto_fixture_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "quic" / "quic_example_2.pcap";
    MainController quic_multi_crypto_controller {};
    UI_EXPECT(open_capture_and_wait(app, quic_multi_crypto_controller, quic_multi_crypto_fixture_path));
    auto* quic_multi_crypto_flow_model = qobject_cast<FlowListModel*>(quic_multi_crypto_controller.flowModel());
    auto* quic_multi_crypto_details_model =
        qobject_cast<PacketDetailsViewModel*>(quic_multi_crypto_controller.packetDetailsModel());
    UI_EXPECT(quic_multi_crypto_flow_model != nullptr);
    UI_EXPECT(quic_multi_crypto_details_model != nullptr);
    UI_EXPECT(quic_multi_crypto_flow_model->rowCount() == 1);
    quic_multi_crypto_controller.setSelectedFlowIndex(0);
    quic_multi_crypto_controller.setSelectedPacketIndex(2);
    UI_EXPECT(wait_until(app, [&]() {
        const auto labels = packet_byte_view_labels(quic_multi_crypto_details_model);
        return !quic_multi_crypto_details_model->summaryLayers().isEmpty() &&
            labels.contains(QStringLiteral("QUIC Initial Decrypted Payload")) &&
            packet_byte_view_label_starts_with(quic_multi_crypto_details_model, QStringLiteral("CRYPTO Frame")) &&
            packet_byte_view_label_starts_with(quic_multi_crypto_details_model, QStringLiteral("TLS Handshake Message, ClientHello"));
    }));
    UI_EXPECT(!quic_multi_crypto_details_model->summaryLayers().isEmpty());
    const auto quic_multi_crypto_labels = packet_byte_view_labels(quic_multi_crypto_details_model);
    const auto quic_multi_crypto_quic_layer =
        find_top_level_summary_layer(quic_multi_crypto_details_model->summaryLayers(), QStringLiteral("quic"));
    const auto quic_multi_crypto_tls_layer =
        find_top_level_summary_layer(quic_multi_crypto_details_model->summaryLayers(), QStringLiteral("tls"));
    UI_EXPECT(quic_multi_crypto_labels.contains(QStringLiteral("QUIC Initial Decrypted Payload")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_multi_crypto_details_model, QStringLiteral("CRYPTO Frame")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_multi_crypto_details_model, QStringLiteral("CRYPTO Frame Data")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_multi_crypto_details_model, QStringLiteral("TLS Handshake Message, ClientHello")));
    UI_EXPECT(!quic_multi_crypto_labels.contains(QStringLiteral("TLS Handshake Record")));
    const auto quic_multi_crypto_handshake_view_id = find_packet_byte_view_stable_id_by_label_prefix(
        quic_multi_crypto_details_model,
        QStringLiteral("TLS Handshake Message, ClientHello")
    );
    UI_EXPECT(!quic_multi_crypto_handshake_view_id.isEmpty());
    quic_multi_crypto_controller.selectPacketByteView(quic_multi_crypto_handshake_view_id);
    UI_EXPECT(wait_until(app, [&]() {
        return quic_multi_crypto_details_model->selectedPacketByteViewId() == quic_multi_crypto_handshake_view_id;
    }));
    UI_EXPECT(quic_multi_crypto_details_model->selectedPacketByteViewText().contains(QStringLiteral("01 00")));
    UI_EXPECT(!quic_multi_crypto_quic_layer.isEmpty());
    UI_EXPECT(!quic_multi_crypto_tls_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(quic_multi_crypto_quic_layer, QStringLiteral("Packet Type")) == QStringLiteral("Initial"));
    UI_EXPECT(find_summary_field_value(quic_multi_crypto_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));
    UI_EXPECT(quic_multi_crypto_details_model->payloadTabTitle() == QStringLiteral("Payload"));

    MainController quic_multi_packet_controller {};
    UI_EXPECT(open_capture_and_wait(app, quic_multi_packet_controller, quic_multi_crypto_fixture_path));
    auto* quic_multi_packet_flow_model = qobject_cast<FlowListModel*>(quic_multi_packet_controller.flowModel());
    auto* quic_multi_packet_details_model =
        qobject_cast<PacketDetailsViewModel*>(quic_multi_packet_controller.packetDetailsModel());
    UI_EXPECT(quic_multi_packet_flow_model != nullptr);
    UI_EXPECT(quic_multi_packet_details_model != nullptr);
    UI_EXPECT(quic_multi_packet_flow_model->rowCount() == 1);
    quic_multi_packet_controller.setSelectedFlowIndex(0);
    quic_multi_packet_controller.setSelectedPacketIndex(0);
    UI_EXPECT(wait_until(app, [&]() {
        const auto labels = packet_byte_view_labels(quic_multi_packet_details_model);
        const auto tls_layer = find_top_level_summary_layer(
            quic_multi_packet_details_model->summaryLayers(),
            QStringLiteral("tls")
        );
        return !quic_multi_packet_details_model->summaryLayers().isEmpty() &&
            !tls_layer.isEmpty() &&
            find_summary_field_value(tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello") &&
            labels.contains(QStringLiteral("QUIC Initial Decrypted Payload")) &&
            packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("CRYPTO Frame")) &&
            packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("CRYPTO Frame Data")) &&
            packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("QUIC CRYPTO Stream")) &&
            packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("TLS Handshake Message, ClientHello"));
    }));
    const auto quic_multi_packet_labels = packet_byte_view_labels(quic_multi_packet_details_model);
    UI_EXPECT(quic_multi_packet_labels.contains(QStringLiteral("QUIC Initial Decrypted Payload")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("CRYPTO Frame")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("CRYPTO Frame Data")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("QUIC CRYPTO Stream")));
    UI_EXPECT(packet_byte_view_label_starts_with(quic_multi_packet_details_model, QStringLiteral("TLS Handshake Message, ClientHello")));
    UI_EXPECT(!quic_multi_packet_labels.contains(QStringLiteral("TLS Handshake Record")));
    quic_multi_packet_controller.selectPacketByteView(QStringLiteral("quic_crypto_stream:0:0"));
    UI_EXPECT(wait_until(app, [&]() {
        return quic_multi_packet_details_model->selectedPacketByteViewId() == QStringLiteral("quic_crypto_stream:0:0") &&
            quic_multi_packet_details_model->selectedPacketByteViewStatusText().contains(
                QStringLiteral("Reassembled from 4 CRYPTO frames"));
    }));
    quic_multi_packet_controller.selectPacketByteView(QStringLiteral("tls_handshake:0:0"));
    UI_EXPECT(wait_until(app, [&]() {
        return quic_multi_packet_details_model->selectedPacketByteViewId() == QStringLiteral("tls_handshake:0:0") &&
            quic_multi_packet_details_model->selectedPacketByteViewStatusText().contains(
                QStringLiteral("Reassembled from 4 CRYPTO frames"));
    }));
    UI_EXPECT(quic_multi_packet_details_model->selectedPacketByteViewText().contains(QStringLiteral("01 00")));
    const auto quic_multi_packet_quic_layer =
        find_top_level_summary_layer(quic_multi_packet_details_model->summaryLayers(), QStringLiteral("quic"));
    const auto quic_multi_packet_tls_layer =
        find_top_level_summary_layer(quic_multi_packet_details_model->summaryLayers(), QStringLiteral("tls"));
    UI_EXPECT(!quic_multi_packet_quic_layer.isEmpty());
    UI_EXPECT(!quic_multi_packet_tls_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(quic_multi_packet_quic_layer, QStringLiteral("Packet Type")) == QStringLiteral("Initial"));
    UI_EXPECT(find_summary_field_value(quic_multi_packet_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));
    UI_EXPECT(quic_multi_packet_details_model->payloadTabTitle() == QStringLiteral("Payload"));

    const auto quic_youtube_fixture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "quic" / "quic_test_2.pcap";
    MainController quic_youtube_controller {};
    UI_EXPECT(open_capture_and_wait(app, quic_youtube_controller, quic_youtube_fixture_path));
    auto* quic_youtube_flow_model = qobject_cast<FlowListModel*>(quic_youtube_controller.flowModel());
    auto* quic_youtube_packet_model = qobject_cast<PacketListModel*>(quic_youtube_controller.packetModel());
    auto* quic_youtube_stream_model = qobject_cast<StreamListModel*>(quic_youtube_controller.streamModel());
    auto* quic_youtube_details_model = qobject_cast<PacketDetailsViewModel*>(quic_youtube_controller.packetDetailsModel());
    UI_EXPECT(quic_youtube_flow_model != nullptr);
    UI_EXPECT(quic_youtube_packet_model != nullptr);
    UI_EXPECT(quic_youtube_stream_model != nullptr);
    UI_EXPECT(quic_youtube_details_model != nullptr);
    UI_EXPECT(quic_youtube_flow_model->rowCount() >= 1);
    quic_youtube_controller.setSelectedFlowIndex(0);
    UI_EXPECT(quic_youtube_flow_model->data(quic_youtube_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("www.youtube.com"));

    quic_youtube_controller.setSelectedPacketIndex(0);
    const auto quic_youtube_packet_quic_layer =
        find_top_level_summary_layer(quic_youtube_details_model->summaryLayers(), QStringLiteral("quic"));
    const auto quic_youtube_packet_tls_layer =
        find_top_level_summary_layer(quic_youtube_details_model->summaryLayers(), QStringLiteral("tls"));
    UI_EXPECT(!quic_youtube_packet_quic_layer.isEmpty());
    UI_EXPECT(!quic_youtube_packet_tls_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(quic_youtube_packet_quic_layer, QStringLiteral("Packet Type")) == QStringLiteral("Initial"));
    UI_EXPECT(find_summary_field_value(quic_youtube_packet_tls_layer, QStringLiteral("SNI")) == QStringLiteral("www.youtube.com"));
    UI_EXPECT(find_summary_field_value(quic_youtube_packet_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));

    quic_youtube_controller.setFlowDetailsTabIndex(1);
    const int quic_youtube_initial_row = find_quic_initial_like_row(quic_youtube_stream_model);
    UI_EXPECT(quic_youtube_initial_row >= 0);
    const auto quic_youtube_stream_item_index = quic_youtube_stream_model->data(
        quic_youtube_stream_model->index(quic_youtube_initial_row, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    quic_youtube_controller.setSelectedStreamItemIndex(quic_youtube_stream_item_index);
    const auto quic_youtube_stream_quic_layer =
        find_top_level_summary_layer(quic_youtube_details_model->summaryLayers(), QStringLiteral("quic"));
    const auto quic_youtube_stream_tls_layer =
        find_top_level_summary_layer(quic_youtube_details_model->summaryLayers(), QStringLiteral("tls"));
    UI_EXPECT(!quic_youtube_stream_quic_layer.isEmpty());
    UI_EXPECT(!quic_youtube_stream_tls_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(quic_youtube_stream_quic_layer, QStringLiteral("Packet Type")) == QStringLiteral("Initial"));
    UI_EXPECT(find_summary_field_value(quic_youtube_stream_tls_layer, QStringLiteral("SNI")) == QStringLiteral("www.youtube.com"));
    UI_EXPECT(find_summary_field_value(quic_youtube_stream_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));

    const auto quic_tiktok_fixture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "quic" / "quic_test_3.pcap";
    MainController quic_tiktok_controller {};
    UI_EXPECT(open_capture_and_wait(app, quic_tiktok_controller, quic_tiktok_fixture_path));
    auto* quic_tiktok_flow_model = qobject_cast<FlowListModel*>(quic_tiktok_controller.flowModel());
    auto* quic_tiktok_stream_model = qobject_cast<StreamListModel*>(quic_tiktok_controller.streamModel());
    auto* quic_tiktok_details_model = qobject_cast<PacketDetailsViewModel*>(quic_tiktok_controller.packetDetailsModel());
    UI_EXPECT(quic_tiktok_flow_model != nullptr);
    UI_EXPECT(quic_tiktok_stream_model != nullptr);
    UI_EXPECT(quic_tiktok_details_model != nullptr);
    UI_EXPECT(quic_tiktok_flow_model->rowCount() >= 1);
    quic_tiktok_controller.setSelectedFlowIndex(0);
    UI_EXPECT(quic_tiktok_flow_model->data(quic_tiktok_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("log22-normal-useast1a.tiktokv.com"));
    quic_tiktok_controller.setFlowDetailsTabIndex(1);
    const int quic_tiktok_initial_row = find_quic_initial_like_row(quic_tiktok_stream_model);
    UI_EXPECT(quic_tiktok_initial_row >= 0);
    const auto quic_tiktok_stream_item_index = quic_tiktok_stream_model->data(
        quic_tiktok_stream_model->index(quic_tiktok_initial_row, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    quic_tiktok_controller.setSelectedStreamItemIndex(quic_tiktok_stream_item_index);
    const auto quic_tiktok_quic_layer =
        find_top_level_summary_layer(quic_tiktok_details_model->summaryLayers(), QStringLiteral("quic"));
    const auto quic_tiktok_tls_layer =
        find_top_level_summary_layer(quic_tiktok_details_model->summaryLayers(), QStringLiteral("tls"));
    UI_EXPECT(!quic_tiktok_quic_layer.isEmpty());
    UI_EXPECT(!quic_tiktok_tls_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(quic_tiktok_quic_layer, QStringLiteral("Packet Type")) == QStringLiteral("Initial"));
    UI_EXPECT(find_summary_field_value(quic_tiktok_tls_layer, QStringLiteral("SNI")) == QStringLiteral("log22-normal-useast1a.tiktokv.com"));
    UI_EXPECT(find_summary_field_value(quic_tiktok_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));
    controller.setFlowFilterText(QStringLiteral("ui.example"));
    UI_EXPECT(flow_model->rowCount() == 1);
    UI_EXPECT(flow_model->data(flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("HTTP"));

    controller.setFlowFilterText(QStringLiteral("53"));
    UI_EXPECT(flow_model->rowCount() == 1);
    UI_EXPECT(flow_model->data(flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("DNS"));

    controller.setFlowFilterText(QStringLiteral(""));
    UI_EXPECT(flow_model->rowCount() == 3);

    controller.sortFlows(3);
    UI_EXPECT(controller.flowSortColumn() == 3);
    UI_EXPECT(controller.flowSortAscending());

    controller.sortFlows(4);
    UI_EXPECT(controller.flowSortColumn() == 4);
    UI_EXPECT(controller.flowSortAscending());

    controller.sortFlows(5);
    UI_EXPECT(controller.flowSortColumn() == 5);
    UI_EXPECT(controller.flowSortAscending());

    controller.sortFlows(5);
    UI_EXPECT(!controller.flowSortAscending());

    controller.setFlowFilterText(QStringLiteral("ui.example"));
    UI_EXPECT(flow_model->rowCount() == 1);
    controller.setSelectedFlowIndex(flow_model->data(flow_model->index(0, 0), FlowListModel::FlowIndexRole).toInt());
    UI_EXPECT(controller.canExportSelectedFlow());

    const auto exported_flow_path = std::filesystem::temp_directory_path() / "pfl_ui_selected_flow_export.pcap";
    std::filesystem::remove(exported_flow_path, remove_error);
    UI_EXPECT(controller.exportSelectedFlow(QString::fromStdWString(exported_flow_path.wstring())));
    UI_EXPECT(std::filesystem::exists(exported_flow_path));
    UI_EXPECT(controller.statusText() == QStringLiteral("Flow exported successfully."));
    UI_EXPECT(!controller.statusIsError());

    CaptureSession exported_flow_session {};
    UI_EXPECT(exported_flow_session.open_capture(exported_flow_path));
    UI_EXPECT(exported_flow_session.summary().packet_count == 1U);
    UI_EXPECT(exported_flow_session.summary().flow_count == 1U);

    auto* packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
    UI_EXPECT(packet_model != nullptr);
    UI_EXPECT(packet_model->rowCount() == 1);

    const auto packet_index_model = packet_model->index(0, 0);
    UI_EXPECT(packet_index_model.isValid());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::RowNumberRole).toUInt() == 1U);
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::DirectionTextRole).toString() == QString::fromUtf8("A\xE2\x86\x92" "B"));
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::PayloadLengthRole).toUInt() == make_http_request_payload().size());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::OriginalLengthRole).toUInt() == http_flow.size());
    UI_EXPECT(!packet_model->data(packet_index_model, PacketListModel::SuspectedTcpRetransmissionRole).toBool());
    UI_EXPECT(packet_model->data(packet_index_model, PacketListModel::TcpFlagsTextRole).toString() == QStringLiteral("ACK|SYN"));

    const auto retransmit_capture_path = write_temp_pcap(
        "pfl_ui_selected_flow_retransmit_marker.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 22, 0, 1), ipv4(10, 22, 0, 2), 44000, 80, bytes_payload("alpha"), 1000U, 2000U, 0x18)},
            {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 22, 0, 1), ipv4(10, 22, 0, 2), 44000, 80, bytes_payload("alpha"), 1000U, 2000U, 0x18)},
            {300, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 22, 1, 1), ipv4(10, 22, 1, 2), 44001, 80, bytes_payload("clean"), 3000U, 4000U, 0x18)},
            {400, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 22, 1, 1), ipv4(10, 22, 1, 2), 44001, 80, bytes_payload("other"), 3000U, 4000U, 0x18)},
        })
    );

    MainController retransmit_controller {};
    UI_EXPECT(open_capture_and_wait(app, retransmit_controller, retransmit_capture_path));
    auto* retransmit_flow_model = qobject_cast<FlowListModel*>(retransmit_controller.flowModel());
    UI_EXPECT(retransmit_flow_model != nullptr);
    UI_EXPECT(retransmit_flow_model->rowCount() == 2);
    retransmit_controller.setFlowDetailsTabIndex(1);

    retransmit_controller.setSelectedFlowIndex(retransmit_flow_model->data(retransmit_flow_model->index(0, 0), FlowListModel::FlowIndexRole).toInt());
    auto* retransmit_packet_model = qobject_cast<PacketListModel*>(retransmit_controller.packetModel());
    auto* retransmit_stream_model = qobject_cast<StreamListModel*>(retransmit_controller.streamModel());
    UI_EXPECT(retransmit_packet_model != nullptr);
    UI_EXPECT(retransmit_stream_model != nullptr);
    UI_EXPECT(retransmit_packet_model->rowCount() == 2);
    UI_EXPECT(!retransmit_packet_model->data(retransmit_packet_model->index(0, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());
    UI_EXPECT(retransmit_packet_model->data(retransmit_packet_model->index(1, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());
    UI_EXPECT(retransmit_stream_model->rowCount() == 1);
    UI_EXPECT(retransmit_stream_model->data(retransmit_stream_model->index(0, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TCP Payload"));
    UI_EXPECT(retransmit_stream_model->data(retransmit_stream_model->index(0, 0), StreamListModel::PacketCountRole).toUInt() == 1U);
    UI_EXPECT(retransmit_stream_model->data(retransmit_stream_model->index(0, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #1"));

    retransmit_controller.setSelectedFlowIndex(retransmit_flow_model->data(retransmit_flow_model->index(1, 0), FlowListModel::FlowIndexRole).toInt());
    UI_EXPECT(retransmit_packet_model->rowCount() == 2);
    UI_EXPECT(!retransmit_packet_model->data(retransmit_packet_model->index(0, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());
    UI_EXPECT(!retransmit_packet_model->data(retransmit_packet_model->index(1, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());
    UI_EXPECT(retransmit_stream_model->rowCount() == 2);

    controller.setSelectedPacketIndex(0);
    auto* details_model = qobject_cast<PacketDetailsViewModel*>(controller.packetDetailsModel());
    UI_EXPECT(details_model != nullptr);
    UI_EXPECT(details_model->hasPacket());
    UI_EXPECT(details_model->summaryText().contains(QStringLiteral("Packet number in file: 1")));
    UI_EXPECT(!details_model->summaryLayers().isEmpty());
    const auto expected_packet_byte_labels = QStringList {
        QStringLiteral("Ethernet II Frame"),
        QStringLiteral("IPv4 Packet"),
        QStringLiteral("TCP Segment"),
    };
    UI_EXPECT(packet_byte_view_labels(details_model) == expected_packet_byte_labels);
    UI_EXPECT(details_model->selectedPacketByteViewId() == QStringLiteral("ethernet:0:0"));
    UI_EXPECT(details_model->selectedPacketByteViewText().contains(QStringLiteral("00000000")));
    controller.selectPacketByteView(QStringLiteral("tcp:0:0"));
    UI_EXPECT(details_model->selectedPacketByteViewId() == QStringLiteral("tcp:0:0"));
    UI_EXPECT(details_model->selectedPacketByteViewText().contains(QStringLiteral("47 45 54 20 2f")));
    const auto byte_view_selection_capture_path = write_temp_pcap(
        "pfl_ui_packet_byte_view_selection.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 90, 0, 1), ipv4(10, 90, 0, 2), 45000, 80, bytes_payload("payload-a"), 0x18)},
            {200, make_ethernet_ipv4_tcp_packet(
                ipv4(10, 90, 0, 1), ipv4(10, 90, 0, 2), 45000, 80)},
        })
    );

    MainController byte_view_selection_controller {};
    UI_EXPECT(open_capture_and_wait(app, byte_view_selection_controller, byte_view_selection_capture_path));
    auto* byte_view_selection_flow_model = qobject_cast<FlowListModel*>(byte_view_selection_controller.flowModel());
    auto* byte_view_selection_packet_model = qobject_cast<PacketListModel*>(byte_view_selection_controller.packetModel());
    auto* byte_view_selection_details_model =
        qobject_cast<PacketDetailsViewModel*>(byte_view_selection_controller.packetDetailsModel());
    UI_EXPECT(byte_view_selection_flow_model != nullptr);
    UI_EXPECT(byte_view_selection_packet_model != nullptr);
    UI_EXPECT(byte_view_selection_details_model != nullptr);
    UI_EXPECT(byte_view_selection_flow_model->rowCount() == 1);

    byte_view_selection_controller.setSelectedFlowIndex(0);
    UI_EXPECT(byte_view_selection_packet_model->rowCount() == 2);

    const auto first_byte_view_packet_index = byte_view_selection_packet_model->data(
        byte_view_selection_packet_model->index(0, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    const auto second_byte_view_packet_index = byte_view_selection_packet_model->data(
        byte_view_selection_packet_model->index(1, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();

    byte_view_selection_controller.setSelectedPacketIndex(first_byte_view_packet_index);
    byte_view_selection_controller.selectPacketByteView(QStringLiteral("ipv4:0:0"));
    UI_EXPECT(byte_view_selection_details_model->selectedPacketByteViewId() == QStringLiteral("ipv4:0:0"));

    byte_view_selection_controller.setSelectedPacketIndex(second_byte_view_packet_index);
    UI_EXPECT(byte_view_selection_details_model->selectedPacketByteViewId() == QStringLiteral("ipv4:0:0"));
    UI_EXPECT(packet_byte_view_labels(byte_view_selection_details_model).contains(QStringLiteral("TCP Segment")));

    byte_view_selection_controller.setSelectedPacketIndex(first_byte_view_packet_index);
    byte_view_selection_controller.selectPacketByteView(QStringLiteral("tcp:0:0"));
    UI_EXPECT(byte_view_selection_details_model->selectedPacketByteViewId() == QStringLiteral("tcp:0:0"));

    byte_view_selection_controller.setSelectedPacketIndex(second_byte_view_packet_index);
    UI_EXPECT(byte_view_selection_details_model->selectedPacketByteViewId() == QStringLiteral("tcp:0:0"));
    UI_EXPECT(byte_view_selection_details_model->selectedPacketByteViewAvailable());
    UI_EXPECT(byte_view_selection_details_model->selectedPacketByteViewText().contains(QStringLiteral("00000000")));

    const auto vxlan_byte_view_capture_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "vxlan" /
        "13_vxlan_inner_vlan_ipv4_tcp.pcap";
    MainController vxlan_byte_view_controller {};
    UI_EXPECT(open_capture_and_wait(app, vxlan_byte_view_controller, vxlan_byte_view_capture_path));
    auto* vxlan_byte_view_flow_model = qobject_cast<FlowListModel*>(vxlan_byte_view_controller.flowModel());
    auto* vxlan_byte_view_details_model =
        qobject_cast<PacketDetailsViewModel*>(vxlan_byte_view_controller.packetDetailsModel());
    UI_EXPECT(vxlan_byte_view_flow_model != nullptr);
    UI_EXPECT(vxlan_byte_view_details_model != nullptr);
    UI_EXPECT(vxlan_byte_view_flow_model->rowCount() == 1);
    vxlan_byte_view_controller.setSelectedFlowIndex(0);
    vxlan_byte_view_controller.setSelectedPacketIndex(0);
    UI_EXPECT(wait_until(app, [&]() {
        return packet_byte_view_labels(vxlan_byte_view_details_model).contains(QStringLiteral("VXLAN Packet")) &&
            packet_byte_view_labels(vxlan_byte_view_details_model).contains(QStringLiteral("Inner Ethernet II Frame"));
    }));
    const auto vxlan_descriptor =
        find_packet_byte_view_descriptor(vxlan_byte_view_details_model, QStringLiteral("vxlan:0:0"));
    const auto inner_ethernet_descriptor =
        find_packet_byte_view_descriptor(vxlan_byte_view_details_model, QStringLiteral("inner_ethernet:0:0"));
    UI_EXPECT(!vxlan_descriptor.isEmpty());
    UI_EXPECT(!inner_ethernet_descriptor.isEmpty());
    UI_EXPECT(vxlan_descriptor.value(QStringLiteral("label")).toString() == QStringLiteral("VXLAN Packet"));
    UI_EXPECT(vxlan_descriptor.value(QStringLiteral("parentStableId")).toString() == QStringLiteral("udp:0:0"));
    UI_EXPECT(vxlan_descriptor.value(QStringLiteral("availableLength")).toULongLong() ==
        inner_ethernet_descriptor.value(QStringLiteral("availableLength")).toULongLong() + 8ULL);
    vxlan_byte_view_controller.selectPacketByteView(QStringLiteral("vxlan:0:0"));
    UI_EXPECT(wait_until(app, [&]() {
        return vxlan_byte_view_details_model->selectedPacketByteViewId() == QStringLiteral("vxlan:0:0") &&
            vxlan_byte_view_details_model->selectedPacketByteViewAvailableLength() ==
                vxlan_descriptor.value(QStringLiteral("availableLength")).toULongLong() &&
            !vxlan_byte_view_details_model->selectedPacketByteViewText().isEmpty();
    }));

    controller.setCurrentTabIndex(2);
    controller.drillDownToEndpoint(QStringLiteral("10.0.0.1:1111"));

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("10.0.0.1:1111"));
    UI_EXPECT(controller.selectedFlowIndex() == -1);
    UI_EXPECT(!controller.canExportSelectedFlow());
    UI_EXPECT(controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(!details_model->selectedPacketByteViewAvailable());
    UI_EXPECT(details_model->selectedPacketByteViewText().isEmpty());
    UI_EXPECT(details_model->packetByteViewDescriptors().isEmpty());
    UI_EXPECT(flow_model->rowCount() == 1);

    controller.setCurrentTabIndex(2);
    controller.drillDownToPort(53U);

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("53"));
    UI_EXPECT(flow_model->rowCount() == 1);
    UI_EXPECT(flow_model->data(flow_model->index(0, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("DNS"));

    const auto hostless_http_capture_path = write_temp_pcap(
        "pfl_ui_http_settings.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 43000, 80, make_http_request_without_host_payload(), 0x18)},
        })
    );
    const auto vlan_grouping_capture_path = write_temp_pcap(
        "pfl_ui_vlan_grouping_settings.pcap",
        make_classic_pcap({
            {100, add_vlan_tags(
                make_ethernet_ipv4_tcp_packet(
                    ipv4(10, 30, 0, 1), ipv4(10, 30, 0, 2), 44000, 443),
                {{0x8100U, 100U}})},
            {200, add_vlan_tags(
                make_ethernet_ipv4_tcp_packet(
                    ipv4(10, 30, 0, 2), ipv4(10, 30, 0, 1), 443, 44000),
                {{0x8100U, 200U}})},
        })
    );
    const auto gtpu_teid_grouping_capture_path =
        ui_test_root() / "data" / "parsing" / "gtpu" / "35_gtpu_bidirectional_different_teids_same_inner_tcp.pcap";
    const auto vlan_grouping_index_path = std::filesystem::temp_directory_path() / "pfl_ui_vlan_grouping_settings.idx";
    const auto gtpu_teid_grouping_index_path = std::filesystem::temp_directory_path() / "pfl_ui_gtpu_teid_grouping_settings.idx";
    {
        CaptureSession index_seed_session {};
        UI_EXPECT(index_seed_session.open_capture(vlan_grouping_capture_path));
        UI_EXPECT(index_seed_session.save_index(vlan_grouping_index_path));
    }
    {
        CaptureSession index_seed_session {};
        UI_EXPECT(index_seed_session.open_capture(
            gtpu_teid_grouping_capture_path,
            CaptureImportOptions {
                .settings = AnalysisSettings {
                    .ignore_gtpu_teids_when_grouping_inner_flows = true,
                },
            }));
        UI_EXPECT(index_seed_session.save_index(gtpu_teid_grouping_index_path));
    }

    MainController settings_controller {};
    UI_EXPECT(!settings_controller.httpUsePathAsServiceHint());
    UI_EXPECT(open_capture_and_wait(app, settings_controller, hostless_http_capture_path));
    auto* settings_flow_model = qobject_cast<FlowListModel*>(settings_controller.flowModel());
    UI_EXPECT(settings_flow_model != nullptr);
    UI_EXPECT(settings_flow_model->rowCount() == 1);
    UI_EXPECT(settings_flow_model->data(settings_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString().isEmpty());

    settings_controller.setHttpUsePathAsServiceHint(true);
    UI_EXPECT(settings_controller.httpUsePathAsServiceHint());
    UI_EXPECT(settings_flow_model->data(settings_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString().isEmpty());

    UI_EXPECT(open_capture_and_wait(app, settings_controller, hostless_http_capture_path));
    UI_EXPECT(settings_flow_model->rowCount() == 1);
    UI_EXPECT(settings_flow_model->data(settings_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("/fallback/ui"));

    run_ui_section("settings_pane_wireshark_checkbox", [&]() {
        auto settings_pane = load_qml_component("src/ui/qml/components/SettingsPane.qml", "SettingsPane");
        auto* wireshark_setting_checkbox = named_object(settings_pane.object.get(), "showWiresharkFilterForSelectedFlowCheckBox");
        UI_EXPECT(wireshark_setting_checkbox != nullptr);
        UI_EXPECT(wireshark_setting_checkbox->property("visible").toBool());
        settings_pane.object->setProperty("showWiresharkFilterForSelectedFlow", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!wireshark_setting_checkbox->property("checked").toBool());
        settings_pane.object->setProperty("showWiresharkFilterForSelectedFlow", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wireshark_setting_checkbox->property("checked").toBool());
    });

    run_ui_section("settings_pane_protocol_path_checkbox", [&]() {
        auto settings_pane = load_qml_component("src/ui/qml/components/SettingsPane.qml", "SettingsPane");
        auto* protocol_path_checkbox = named_object(settings_pane.object.get(), "showProtocolPathColumnCheckBox");
        UI_EXPECT(protocol_path_checkbox != nullptr);
        UI_EXPECT(protocol_path_checkbox->property("visible").toBool());
        settings_pane.object->setProperty("showProtocolPathColumn", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!protocol_path_checkbox->property("checked").toBool());
        settings_pane.object->setProperty("showProtocolPathColumn", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(protocol_path_checkbox->property("checked").toBool());
    });

    run_ui_section("settings_pane_fragmented_packet_count_checkbox", [&]() {
        MainController fragmented_column_controller {};
        UI_EXPECT(!fragmented_column_controller.showFragmentedPacketCountColumn());

        auto settings_pane = load_qml_component("src/ui/qml/components/SettingsPane.qml", "SettingsPane");
        auto* fragmented_packet_count_checkbox =
            named_object(settings_pane.object.get(), "showFragmentedPacketCountColumnCheckBox");
        UI_EXPECT(fragmented_packet_count_checkbox != nullptr);
        UI_EXPECT(fragmented_packet_count_checkbox->property("visible").toBool());
        UI_EXPECT(!fragmented_packet_count_checkbox->property("checked").toBool());
        settings_pane.object->setProperty("showFragmentedPacketCountColumn", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(fragmented_packet_count_checkbox->property("checked").toBool());
        settings_pane.object->setProperty("showFragmentedPacketCountColumn", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!fragmented_packet_count_checkbox->property("checked").toBool());
    });

    run_ui_section("settings_dialog_cancel_discards_pending_changes", [&]() {
        MainController dialog_controller {};
        auto main_window = load_main_qml_component(dialog_controller);
        auto* settings_dialog = named_object(main_window.object.get(), "settingsDialog");
        auto* settings_pane = named_object(main_window.object.get(), "settingsDialogPane");
        UI_REQUIRE(settings_dialog != nullptr);
        UI_REQUIRE(settings_pane != nullptr);
        auto* use_possible_tls_quic_checkbox = named_object(settings_pane, "usePossibleTlsQuicCheckBox");
        UI_REQUIRE(use_possible_tls_quic_checkbox != nullptr);
        UI_EXPECT(!dialog_controller.usePossibleTlsQuic());
        UI_EXPECT(!settings_dialog->property("draftUsePossibleTlsQuic").toBool());

        UI_REQUIRE(QMetaObject::invokeMethod(settings_dialog, "open"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!use_possible_tls_quic_checkbox->property("checked").toBool());
        UI_EXPECT(!settings_dialog->property("draftUsePossibleTlsQuic").toBool());

        UI_REQUIRE(QMetaObject::invokeMethod(use_possible_tls_quic_checkbox, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(use_possible_tls_quic_checkbox->property("checked").toBool());
        UI_EXPECT(settings_dialog->property("draftUsePossibleTlsQuic").toBool());
        UI_EXPECT(!dialog_controller.usePossibleTlsQuic());

        UI_REQUIRE(QMetaObject::invokeMethod(settings_dialog, "reject"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!dialog_controller.usePossibleTlsQuic());

        UI_REQUIRE(QMetaObject::invokeMethod(settings_dialog, "open"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!use_possible_tls_quic_checkbox->property("checked").toBool());
        UI_EXPECT(!settings_dialog->property("draftUsePossibleTlsQuic").toBool());

        UI_REQUIRE(QMetaObject::invokeMethod(use_possible_tls_quic_checkbox, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(use_possible_tls_quic_checkbox->property("checked").toBool());
        UI_EXPECT(settings_dialog->property("draftUsePossibleTlsQuic").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(settings_dialog, "accept"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(dialog_controller.usePossibleTlsQuic());

        UI_REQUIRE(QMetaObject::invokeMethod(settings_dialog, "open"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(use_possible_tls_quic_checkbox->property("checked").toBool());
        UI_EXPECT(settings_dialog->property("draftUsePossibleTlsQuic").toBool());
    });

    run_ui_section("settings_pane_capture_processing_helper_text", [&]() {
        auto settings_pane = load_qml_component("src/ui/qml/components/SettingsPane.qml", "SettingsPane");
        auto* settings_tabs = named_object(settings_pane.object.get(), "settingsTabs");
        auto* http_help_text = named_object(settings_pane.object.get(), "httpUsePathAsServiceHintHelpText");
        auto* vlan_help_text = named_object(settings_pane.object.get(), "ignoreVlanAndMplsLayersWhenGroupingFlowsHelpText");
        auto* gtpu_help_text = named_object(settings_pane.object.get(), "ignoreGtpuTeidsWhenGroupingInnerFlowsHelpText");
        UI_REQUIRE(settings_tabs != nullptr);
        UI_REQUIRE(http_help_text != nullptr);
        UI_REQUIRE(vlan_help_text != nullptr);
        UI_REQUIRE(gtpu_help_text != nullptr);
        settings_tabs->setProperty("currentIndex", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(http_help_text->property("text").toString() == QStringLiteral("Applied when the next raw capture is opened."));
        UI_EXPECT(vlan_help_text->property("text").toString() == QStringLiteral("Applied when importing a raw capture. Existing indexes keep their stored flow grouping."));
        UI_EXPECT(gtpu_help_text->property("text").toString() == QStringLiteral("Applied when importing a raw capture. Existing indexes keep their stored flow grouping."));
    });

    run_ui_section("settings_pane_ignore_vlan_grouping_checkbox", [&]() {
        auto settings_pane = load_qml_component("src/ui/qml/components/SettingsPane.qml", "SettingsPane");
        auto* settings_tabs = named_object(settings_pane.object.get(), "settingsTabs");
        auto* vlan_grouping_checkbox = named_object(settings_pane.object.get(), "ignoreVlanAndMplsLayersWhenGroupingFlowsCheckBox");
        UI_EXPECT(settings_tabs != nullptr);
        UI_EXPECT(vlan_grouping_checkbox != nullptr);
        settings_tabs->setProperty("currentIndex", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(vlan_grouping_checkbox->property("visible").toBool());
        settings_pane.object->setProperty("ignoreVlanAndMplsLayersWhenGroupingFlows", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!vlan_grouping_checkbox->property("checked").toBool());
        settings_pane.object->setProperty("ignoreVlanAndMplsLayersWhenGroupingFlows", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(vlan_grouping_checkbox->property("checked").toBool());
    });

    run_ui_section("settings_pane_ignore_gtpu_teid_grouping_checkbox", [&]() {
        auto settings_pane = load_qml_component("src/ui/qml/components/SettingsPane.qml", "SettingsPane");
        auto* settings_tabs = named_object(settings_pane.object.get(), "settingsTabs");
        auto* gtpu_grouping_checkbox = named_object(settings_pane.object.get(), "ignoreGtpuTeidsWhenGroupingInnerFlowsCheckBox");
        auto* vlan_grouping_checkbox = named_object(settings_pane.object.get(), "ignoreVlanAndMplsLayersWhenGroupingFlowsCheckBox");
        UI_EXPECT(settings_tabs != nullptr);
        UI_EXPECT(gtpu_grouping_checkbox != nullptr);
        UI_EXPECT(vlan_grouping_checkbox != nullptr);
        settings_tabs->setProperty("currentIndex", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(gtpu_grouping_checkbox->property("visible").toBool());
        settings_pane.object->setProperty("ignoreGtpuTeidsWhenGroupingInnerFlows", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!gtpu_grouping_checkbox->property("checked").toBool());
        settings_pane.object->setProperty("ignoreVlanAndMplsLayersWhenGroupingFlows", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!gtpu_grouping_checkbox->property("checked").toBool());
        settings_pane.object->setProperty("ignoreGtpuTeidsWhenGroupingInnerFlows", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(gtpu_grouping_checkbox->property("checked").toBool());
        UI_EXPECT(vlan_grouping_checkbox->property("checked").toBool());
    });

    run_ui_section("flow_grouping_warning_text", [&]() {
        MainController vlan_grouping_controller {};
        UI_EXPECT(!vlan_grouping_controller.ignoreVlanAndMplsLayersWhenGroupingFlows());
        UI_EXPECT(vlan_grouping_controller.flowGroupingWarningText().isEmpty());
        UI_EXPECT(open_capture_and_wait(app, vlan_grouping_controller, vlan_grouping_capture_path));
        UI_EXPECT(vlan_grouping_controller.flowGroupingWarningText().isEmpty());

        auto* vlan_grouping_flow_model = qobject_cast<FlowListModel*>(vlan_grouping_controller.flowModel());
        UI_REQUIRE(vlan_grouping_flow_model != nullptr);
        UI_EXPECT(vlan_grouping_flow_model->rowCount() == 2);

        vlan_grouping_controller.setIgnoreVlanAndMplsLayersWhenGroupingFlows(true);
        UI_EXPECT(vlan_grouping_controller.ignoreVlanAndMplsLayersWhenGroupingFlows());
        UI_EXPECT(vlan_grouping_controller.statusText() ==
            QStringLiteral("Reopen the current raw capture to apply the VLAN and MPLS flow-grouping setting."));
        UI_EXPECT(vlan_grouping_controller.flowGroupingWarningText().isEmpty());
        UI_EXPECT(vlan_grouping_flow_model->rowCount() == 2);

        UI_EXPECT(open_capture_and_wait(app, vlan_grouping_controller, vlan_grouping_capture_path));
        UI_EXPECT(vlan_grouping_controller.flowGroupingWarningText() ==
            QStringLiteral("VLAN and MPLS layers are ignored for flow grouping. Flows from different VLANs or MPLS paths may be merged."));
        UI_EXPECT(vlan_grouping_flow_model->rowCount() == 1);
    });

    run_ui_section("flow_grouping_index_warning_text", [&]() {
        MainController vlan_grouping_index_controller {};
        UI_EXPECT(!vlan_grouping_index_controller.ignoreVlanAndMplsLayersWhenGroupingFlows());
        UI_EXPECT(open_index_and_wait(app, vlan_grouping_index_controller, vlan_grouping_index_path));
        UI_EXPECT(vlan_grouping_index_controller.openedFromIndex());
        UI_EXPECT(vlan_grouping_index_controller.flowGroupingWarningText().isEmpty());
        vlan_grouping_index_controller.setIgnoreVlanAndMplsLayersWhenGroupingFlows(true);
        UI_EXPECT(vlan_grouping_index_controller.ignoreVlanAndMplsLayersWhenGroupingFlows());
        UI_EXPECT(vlan_grouping_index_controller.statusText() ==
            QStringLiteral("Settings updated. Capture-processing changes apply when a raw capture is opened."));
        UI_EXPECT(vlan_grouping_index_controller.flowGroupingWarningText().isEmpty());
    });

    run_ui_section("gtpu_teid_grouping_info_text", [&]() {
        MainController gtpu_grouping_controller {};
        UI_EXPECT(!gtpu_grouping_controller.ignoreGtpuTeidsWhenGroupingInnerFlows());
        UI_EXPECT(gtpu_grouping_controller.gtpuTeidGroupingInfoText().isEmpty());
        UI_EXPECT(open_capture_and_wait(app, gtpu_grouping_controller, gtpu_teid_grouping_capture_path));
        UI_EXPECT(gtpu_grouping_controller.gtpuTeidGroupingInfoText().isEmpty());

        auto* gtpu_grouping_flow_model = qobject_cast<FlowListModel*>(gtpu_grouping_controller.flowModel());
        UI_REQUIRE(gtpu_grouping_flow_model != nullptr);
        UI_EXPECT(gtpu_grouping_flow_model->rowCount() == 2);

        gtpu_grouping_controller.setIgnoreGtpuTeidsWhenGroupingInnerFlows(true);
        UI_EXPECT(gtpu_grouping_controller.ignoreGtpuTeidsWhenGroupingInnerFlows());
        UI_EXPECT(gtpu_grouping_controller.statusText() ==
            QStringLiteral("Reopen the current raw capture to apply the GTP-U TEID flow-grouping setting."));
        UI_EXPECT(gtpu_grouping_controller.gtpuTeidGroupingInfoText().isEmpty());
        UI_EXPECT(gtpu_grouping_flow_model->rowCount() == 2);

        UI_EXPECT(open_capture_and_wait(app, gtpu_grouping_controller, gtpu_teid_grouping_capture_path));
        UI_EXPECT(gtpu_grouping_controller.gtpuTeidGroupingInfoText() ==
            QStringLiteral("GTP-U TEIDs are ignored for inner-flow grouping. Flows from different GTP-U tunnels may be merged."));
        UI_EXPECT(gtpu_grouping_controller.flowGroupingWarningText().isEmpty());
        UI_EXPECT(gtpu_grouping_flow_model->rowCount() == 1);
    });

    run_ui_section("gtpu_teid_grouping_index_info_text", [&]() {
        MainController gtpu_grouping_index_controller {};
        UI_EXPECT(!gtpu_grouping_index_controller.ignoreGtpuTeidsWhenGroupingInnerFlows());
        UI_EXPECT(open_index_and_wait(app, gtpu_grouping_index_controller, gtpu_teid_grouping_index_path));
        UI_EXPECT(gtpu_grouping_index_controller.openedFromIndex());
        UI_EXPECT(gtpu_grouping_index_controller.gtpuTeidGroupingInfoText().isEmpty());
        gtpu_grouping_index_controller.setIgnoreGtpuTeidsWhenGroupingInnerFlows(true);
        UI_EXPECT(gtpu_grouping_index_controller.ignoreGtpuTeidsWhenGroupingInnerFlows());
        UI_EXPECT(gtpu_grouping_index_controller.statusText() ==
            QStringLiteral("Settings updated. Capture-processing changes apply when a raw capture is opened."));
        UI_EXPECT(gtpu_grouping_index_controller.gtpuTeidGroupingInfoText().isEmpty());
    });

    run_ui_section("flow_table_wireshark_filter_row", [&]() {
        auto flow_table = load_qml_component("src/ui/qml/components/FlowTable.qml", "FlowTable");
        UI_EXPECT(named_object(flow_table.object.get(), "flowTextFilterField") != nullptr);
        UI_EXPECT(named_object(flow_table.object.get(), "flowTextFilterClearButton") != nullptr);
        UI_EXPECT(find_object_with_text(flow_table.object.get(), QStringLiteral("Send flow to Analysis")) == nullptr);
        UI_EXPECT(named_object(flow_table.object.get(), "wiresharkFilterRow") != nullptr);
        flow_table.object->setProperty("wiresharkFilterVisible", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!item_visible(flow_table.object.get(), "wiresharkFilterRow"));
        flow_table.object->setProperty("wiresharkFilterVisible", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(flow_table.object.get(), "wiresharkFilterRow"));
    });

    run_ui_section("flow_table_protocol_path_column_visibility", [&]() {
        auto flow_table = load_qml_component("src/ui/qml/components/FlowTable.qml", "FlowTable");
        UI_EXPECT(named_object(flow_table.object.get(), "pathHeaderCell") != nullptr);
        flow_table.object->setProperty("showProtocolPathColumn", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!item_visible(flow_table.object.get(), "pathHeaderCell"));
        flow_table.object->setProperty("showProtocolPathColumn", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(flow_table.object.get(), "pathHeaderCell"));
    });

    run_ui_section("flow_table_fragmented_packet_count_column_visibility", [&]() {
        auto flow_table = load_qml_component("src/ui/qml/components/FlowTable.qml", "FlowTable");
        UI_EXPECT(named_object(flow_table.object.get(), "fragHeaderCell") != nullptr);
        UI_EXPECT(!item_visible(flow_table.object.get(), "fragHeaderCell"));

        flow_table.object->setProperty("showFragmentedPacketCountColumn", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(flow_table.object.get(), "fragHeaderCell"));

        flow_table.object->setProperty("showProtocolPathColumn", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(flow_table.object.get(), "fragHeaderCell"));
        UI_EXPECT(!item_visible(flow_table.object.get(), "pathHeaderCell"));

        flow_table.object->setProperty("showFragmentedPacketCountColumn", false);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!item_visible(flow_table.object.get(), "fragHeaderCell"));

        flow_table.object->setProperty("showProtocolPathColumn", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(flow_table.object.get(), "pathHeaderCell"));
    });

    run_ui_section("packet_list_flags_column_visibility", [&]() {
        auto* flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
        auto* packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
        UI_REQUIRE(flow_model != nullptr);
        UI_REQUIRE(packet_model != nullptr);
        controller.setFlowFilterText(QStringLiteral(""));
        app.processEvents(QEventLoop::AllEvents, 25);

        auto packet_list = load_qml_component("src/ui/qml/components/PacketList.qml", "PacketList");
        packet_list.object->setProperty("packetModel", QVariant::fromValue(static_cast<QObject*>(packet_model)));

        const auto sync_packet_list = [&]() {
            packet_list.object->setProperty("showFlagsColumn", controller.selectedFlowUsesTcp());
            packet_list.object->setProperty("selectedPacketIndex", QVariant::fromValue(controller.selectedPacketIndex()));
            app.processEvents(QEventLoop::AllEvents, 25);
        };

        const int tcp_flow_index = find_flow_index_by_service_hint(flow_model, QStringLiteral("ui.example"));
        const int udp_flow_index = find_flow_index_by_protocol_hint(flow_model, QStringLiteral("DNS"));
        UI_REQUIRE(tcp_flow_index >= 0);
        UI_REQUIRE(udp_flow_index >= 0);

        controller.setSelectedFlowIndex(tcp_flow_index);
        UI_EXPECT(wait_until(app, [&]() {
            return !controller.packetsLoading() && packet_model->rowCount() >= 1;
        }));
        UI_EXPECT(controller.selectedFlowUsesTcp());
        sync_packet_list();
        UI_EXPECT(item_visible(packet_list.object.get(), "packetFlagsHeaderLabel"));
        UI_EXPECT(packet_model->data(packet_model->index(0, 0), PacketListModel::TcpFlagsTextRole).toString() == QStringLiteral("ACK|SYN"));

        controller.setSelectedFlowIndex(udp_flow_index);
        UI_EXPECT(wait_until(app, [&]() {
            return !controller.packetsLoading() && packet_model->rowCount() >= 1;
        }));
        UI_EXPECT(!controller.selectedFlowUsesTcp());
        sync_packet_list();
        UI_EXPECT(!item_visible(packet_list.object.get(), "packetFlagsHeaderLabel"));

        controller.setSelectedFlowIndex(tcp_flow_index);
        UI_EXPECT(wait_until(app, [&]() {
            return !controller.packetsLoading() && packet_model->rowCount() >= 1;
        }));
        UI_EXPECT(controller.selectedFlowUsesTcp());
        sync_packet_list();
        UI_EXPECT(item_visible(packet_list.object.get(), "packetFlagsHeaderLabel"));
    });

    run_ui_section("packet_list_flags_column_hidden_for_icmp", [&]() {
        MainController icmp_controller {};
        UI_EXPECT(open_capture_and_wait(
            app,
            icmp_controller,
            ui_test_root() / "data" / "parsing" / "icmp" / "01_icmp_echo_request.pcap"));
        auto* icmp_flow_model = qobject_cast<FlowListModel*>(icmp_controller.flowModel());
        auto* icmp_packet_model = qobject_cast<PacketListModel*>(icmp_controller.packetModel());
        UI_REQUIRE(icmp_flow_model != nullptr);
        UI_REQUIRE(icmp_packet_model != nullptr);
        UI_REQUIRE(icmp_flow_model->rowCount() >= 1);

        auto packet_list = load_qml_component("src/ui/qml/components/PacketList.qml", "PacketList");
        packet_list.object->setProperty("packetModel", QVariant::fromValue(static_cast<QObject*>(icmp_packet_model)));

        const int icmp_flow_index = find_flow_index_by_protocol(icmp_flow_model, QStringLiteral("ICMP"));
        UI_REQUIRE(icmp_flow_index >= 0);
        icmp_controller.setSelectedFlowIndex(icmp_flow_index);
        UI_EXPECT(wait_until(app, [&]() {
            return !icmp_controller.packetsLoading() && icmp_packet_model->rowCount() >= 1;
        }));
        packet_list.object->setProperty("showFlagsColumn", icmp_controller.selectedFlowUsesTcp());
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!icmp_controller.selectedFlowUsesTcp());
        UI_EXPECT(!item_visible(packet_list.object.get(), "packetFlagsHeaderLabel"));
    });

    run_ui_section("packet_details_tabs_protocol_removed", [&]() {
        auto packet_details_pane = load_qml_component("src/ui/qml/components/PacketDetailsPane.qml", "PacketDetailsPane");
        PacketDetailsViewModel packet_model {};
        packet_model.setPacketDetailsText(QStringLiteral("Packet number in file: 1"));
        packet_model.setPacketBytePresentation(
            {},
            QStringLiteral("frame:0:0"),
            QStringLiteral("Captured Packet"),
            true,
            QStringLiteral("complete"),
            0U,
            {},
            QStringLiteral("Byte view loaded."),
            QStringLiteral("00000000")
        );
        packet_details_pane.object->setProperty("packetDetailsModel", QVariant::fromValue(static_cast<QObject*>(&packet_model)));
        app.processEvents(QEventLoop::AllEvents, 25);

        const auto expected_packet_tab_labels = QStringList {
            QStringLiteral("Summary"),
            QStringLiteral("Bytes")
        };
        UI_EXPECT(direct_child_tab_button_texts(
            packet_details_pane.object.get(),
            "packetDetailsPacketTabs"
        ) == expected_packet_tab_labels);
        UI_EXPECT(!direct_child_tab_button_texts(
            packet_details_pane.object.get(),
            "packetDetailsPacketTabs"
        ).contains(QStringLiteral("Protocol")));

        auto* packet_tabs = named_object(packet_details_pane.object.get(), "packetDetailsPacketTabs");
        UI_REQUIRE(packet_tabs != nullptr);
        packet_tabs->setProperty("currentIndex", 2);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(packet_tabs->property("currentIndex").toInt() == 0);
    });

    run_ui_section("packet_details_zero_length_byte_view_availability", [&]() {
        PacketDetailsViewModel packet_model {};
        packet_model.setPacketDetailsText(QStringLiteral("Packet number in file: 1"));
        packet_model.setPacketBytePresentation(
            {
                QVariantMap {
                    {QStringLiteral("stableId"), QStringLiteral("tcp:0:0")},
                    {QStringLiteral("label"), QStringLiteral("TCP Segment")},
                    {QStringLiteral("depth"), 0},
                    {QStringLiteral("availableLength"), 0},
                    {QStringLiteral("supportsPayloadOnly"), true},
                }
            },
            QStringLiteral("tcp:0:0"),
            QStringLiteral("TCP Segment"),
            true,
            QStringLiteral("complete"),
            0U,
            QVariant::fromValue(0U),
            QStringLiteral("Available: 0 bytes"),
            {}
        );

        UI_EXPECT(packet_model.selectedPacketByteViewId() == QStringLiteral("tcp:0:0"));
        UI_EXPECT(packet_model.selectedPacketByteViewAvailable());
        UI_EXPECT(packet_model.selectedPacketByteViewAvailableLength() == 0U);
        UI_EXPECT(packet_model.selectedPacketByteViewText().isEmpty());

        packet_model.clearPacketBytePresentation();
        UI_EXPECT(packet_model.selectedPacketByteViewId().isEmpty());
        UI_EXPECT(!packet_model.selectedPacketByteViewAvailable());
        UI_EXPECT(packet_model.selectedPacketByteViewText().isEmpty());
    });

    run_ui_section("packet_details_unrecognized_captured_packet_fallback", [&]() {
        const auto truncated_fixture_path =
            ui_test_root() / "data" / "parsing" / "packet_byte_views" / "02_truncated_ethernet_header.pcap";
        const auto ethernet_fixture_path =
            ui_test_root() / "data" / "parsing" / "packet_byte_views" / "01_ethernet_ipv4_udp.pcap";

        MainController controller {};
        UI_EXPECT(open_capture_and_wait(app, controller, truncated_fixture_path));

        auto* packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
        auto* details_model = qobject_cast<PacketDetailsViewModel*>(controller.packetDetailsModel());
        UI_REQUIRE(packet_model != nullptr);
        UI_REQUIRE(details_model != nullptr);

        controller.selectUnrecognizedPackets();
        UI_EXPECT(controller.unrecognizedPacketsSelected());
        UI_EXPECT(wait_until(app, [&]() {
            return packet_model->rowCount() == 1;
        }));

        const auto packet_index = packet_model->data(
            packet_model->index(0, 0),
            PacketListModel::PacketIndexRole
        ).toULongLong();
        const auto authoritative_reason_text = packet_model->data(
            packet_model->index(0, 0),
            PacketListModel::ReasonTextRole
        ).toString();
        UI_EXPECT(!authoritative_reason_text.isEmpty());
        controller.setSelectedPacketIndex(packet_index);

        const QStringList expected_fallback_labels {
            QStringLiteral("Captured Packet"),
        };
        UI_EXPECT(wait_until(app, [&]() {
            return details_model->hasPacket()
                && !details_model->summaryLayers().isEmpty()
                && packet_byte_view_labels(details_model) == expected_fallback_labels
                && details_model->selectedPacketByteViewId() == QStringLiteral("frame:0:0")
                && details_model->selectedPacketByteViewAvailable()
                && details_model->selectedPacketByteViewAvailableLength() == 10U
                && !details_model->selectedPacketByteViewText().isEmpty();
        }));

        const auto frame_layer = find_top_level_summary_layer(details_model->summaryLayers(), QStringLiteral("frame"));
        UI_EXPECT(!frame_layer.isEmpty());
        UI_EXPECT(find_summary_field_value(frame_layer, QStringLiteral("Captured Length")) == QStringLiteral("10 bytes"));
        UI_EXPECT(find_summary_field_value(frame_layer, QStringLiteral("Original Length")) == QStringLiteral("46 bytes"));
        UI_EXPECT(combined_details_search_text(details_model).contains(authoritative_reason_text));
        UI_EXPECT(details_model->selectedPacketByteViewLabel() == QStringLiteral("Captured Packet"));
        UI_EXPECT(details_model->selectedPacketByteViewStatusText().contains(QStringLiteral("Available: 10 bytes")));
        UI_EXPECT(details_model->selectedPacketByteViewStatusText().contains(QStringLiteral("Declared: 46 bytes")));
        UI_EXPECT(details_model->selectedPacketByteViewText().contains(QStringLiteral("00 11 22 33 44 55 66 77 88 99")));
        UI_EXPECT(!packet_byte_view_labels(details_model).contains(QStringLiteral("Ethernet II Frame")));
        UI_EXPECT(details_model->selectedPacketByteViewStatusText() != QStringLiteral("No byte views are available for this packet."));

        UI_EXPECT(open_capture_and_wait(app, controller, ethernet_fixture_path));
        auto* recognized_packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
        auto* recognized_details_model = qobject_cast<PacketDetailsViewModel*>(controller.packetDetailsModel());
        UI_REQUIRE(recognized_packet_model != nullptr);
        UI_REQUIRE(recognized_details_model != nullptr);
        UI_EXPECT(!controller.unrecognizedPacketsSelected());

        auto* recognized_flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
        UI_REQUIRE(recognized_flow_model != nullptr);
        UI_EXPECT(recognized_flow_model->rowCount() == 1);
        controller.setSelectedFlowIndex(0);
        UI_EXPECT(wait_until(app, [&]() {
            return recognized_packet_model->rowCount() == 1;
        }));

        const auto recognized_packet_index = recognized_packet_model->data(
            recognized_packet_model->index(0, 0),
            PacketListModel::PacketIndexRole
        ).toULongLong();
        controller.setSelectedPacketIndex(recognized_packet_index);

        const QStringList expected_recognized_labels {
            QStringLiteral("Ethernet II Frame"),
            QStringLiteral("IPv4 Packet"),
            QStringLiteral("UDP Datagram"),
        };
        UI_EXPECT(wait_until(app, [&]() {
            const auto labels = packet_byte_view_labels(recognized_details_model);
            return labels.contains(expected_recognized_labels[0])
                && labels.contains(expected_recognized_labels[1])
                && labels.contains(expected_recognized_labels[2])
                && !recognized_details_model->selectedPacketByteViewId().isEmpty()
                && recognized_details_model->selectedPacketByteViewAvailable()
                && !recognized_details_model->selectedPacketByteViewText().isEmpty();
        }));
        const auto recognized_labels = packet_byte_view_labels(recognized_details_model);
        UI_EXPECT(recognized_labels.contains(expected_recognized_labels[0]));
        UI_EXPECT(recognized_labels.contains(expected_recognized_labels[1]));
        UI_EXPECT(recognized_labels.contains(expected_recognized_labels[2]));
        UI_EXPECT(recognized_details_model->selectedPacketByteViewId() == QStringLiteral("ethernet:0:0"));
        UI_EXPECT(recognized_details_model->selectedPacketByteViewAvailable());
        UI_EXPECT(!recognized_details_model->selectedPacketByteViewText().isEmpty());
        UI_EXPECT(!recognized_labels.contains(QStringLiteral("Captured Packet")));
        UI_EXPECT(!recognized_details_model->selectedPacketByteViewText().contains(
            QStringLiteral("00 11 22 33 44 55 66 77 88 99")));
    });

    run_ui_section("stream_item_details_tabs_protocol_removed", [&]() {
        auto packet_details_pane = load_qml_component("src/ui/qml/components/PacketDetailsPane.qml", "PacketDetailsPane");
        PacketDetailsViewModel stream_item_model {};
        stream_item_model.setPacketDetailsText(QStringLiteral("Label: HTTP GET /"));
        stream_item_model.setDetailsTitle(QStringLiteral("Stream Item Details"));
        stream_item_model.setStreamItemPresentation(
            QStringLiteral("HTTP GET /"),
            QStringLiteral("Source packet: #1"),
            {}
        );
        stream_item_model.setPayloadTabTitle(QStringLiteral("Item Data"));
        stream_item_model.setStreamItemDataPresentation(
            false,
            QStringLiteral("http_message"),
            QStringLiteral("unavailable"),
            QStringLiteral("synthetic"),
            QStringLiteral("packet_local"),
            0U,
            {},
            {},
            {},
            {},
            QStringLiteral("Item data unavailable."),
            {}
        );
        packet_details_pane.object->setProperty(
            "packetDetailsModel",
            QVariant::fromValue(static_cast<QObject*>(&stream_item_model))
        );
        app.processEvents(QEventLoop::AllEvents, 25);

        const auto expected_stream_tab_labels = QStringList {
            QStringLiteral("Summary"),
            QStringLiteral("Item Data")
        };
        UI_EXPECT(direct_child_tab_button_texts(
            packet_details_pane.object.get(),
            "packetDetailsStreamTabs"
        ) == expected_stream_tab_labels);
        UI_EXPECT(!direct_child_tab_button_texts(
            packet_details_pane.object.get(),
            "packetDetailsStreamTabs"
        ).contains(QStringLiteral("Protocol")));

        auto* stream_tabs = named_object(packet_details_pane.object.get(), "packetDetailsStreamTabs");
        UI_REQUIRE(stream_tabs != nullptr);
        stream_tabs->setProperty("currentIndex", 2);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(stream_tabs->property("currentIndex").toInt() == 0);
    });

    const auto protocol_path_capture_path = write_temp_pcap(
        "pfl_ui_protocol_path_roles.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 30, 0, 1), ipv4(10, 30, 0, 2), 43010, 443)},
        })
    );

    const int packet_size_section = static_cast<int>(MainController::StatisticsOptionalSection::packet_size_distribution);
    const int histogram_section = static_cast<int>(MainController::StatisticsOptionalSection::flow_packet_histogram);
    const int protocol_path_section = static_cast<int>(MainController::StatisticsOptionalSection::protocol_path);
    const int protocol_hints_section = static_cast<int>(MainController::StatisticsOptionalSection::protocol_hints);
    const int quic_tls_section = static_cast<int>(MainController::StatisticsOptionalSection::quic_tls);
    const int top_flows_section = static_cast<int>(MainController::StatisticsOptionalSection::top_flows);
    const int top_endpoints_ports_section = static_cast<int>(MainController::StatisticsOptionalSection::top_endpoints_ports);
    const int section_not_requested = static_cast<int>(MainController::StatisticsSectionRequestState::not_requested);
    const int section_ready = static_cast<int>(MainController::StatisticsSectionRequestState::ready);
    const auto zero_unrecognized_tcp_packet =
        make_ethernet_ipv4_tcp_packet(ipv4(10, 42, 0, 1), ipv4(10, 42, 0, 2), 46001, 443);
    const auto zero_unrecognized_capture_path = write_temp_pcap(
        "pfl_ui_statistics_unrecognized_zero.pcap",
        make_classic_pcap({
            {100, zero_unrecognized_tcp_packet},
        })
    );
    const std::vector<std::uint8_t> unrecognized_ethernet_packet {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x88, 0xb5,
        0x01, 0x02, 0x03, 0x04,
    };
    const auto nonzero_unrecognized_tcp_packet =
        make_ethernet_ipv4_tcp_packet(ipv4(10, 42, 1, 1), ipv4(10, 42, 1, 2), 46002, 443);
    const auto nonzero_unrecognized_capture_path = write_temp_pcap(
        "pfl_ui_statistics_unrecognized_nonzero.pcap",
        make_classic_pcap({
            {100, nonzero_unrecognized_tcp_packet},
            {200, unrecognized_ethernet_packet},
        })
    );

    run_ui_section("statistics_sections_lazy_loading", [&]() {
        UI_EXPECT(QMetaEnum::fromType<MainController::StatisticsSectionRequestState>().isValid());
        UI_EXPECT(QMetaEnum::fromType<MainController::StatisticsOptionalSection>().isValid());
        auto statistics_pane = load_qml_component("src/ui/qml/components/StatisticsPane.qml", "StatisticsPane");
        UI_REQUIRE(named_object(statistics_pane.object.get(), "packetSizeDistributionToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "flowPacketHistogramToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "protocolPathStatisticsToggleButton") != nullptr);
        auto* protocol_path_export_button = named_object(statistics_pane.object.get(), "protocolPathExportButton");
        UI_REQUIRE(protocol_path_export_button != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "protocolHintStatisticsToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "quicTlsStatisticsToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "topFlowStatisticsToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "topEndpointPortStatisticsToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "captureMetricsToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "flowCharacteristicsToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "directionDistributionToggleButton") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "statisticsColumn") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "captureTimeSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "captureMetricsSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "flowCharacteristicsSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "directionDistributionSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "packetDirectionDistributionSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "dataDirectionDistributionSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "captureStartValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "captureEndValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "captureDurationValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "averageCapturedPacketSizeValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "averageOriginalPacketSizeValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "averagePacketRateValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "averageCapturedDataRateValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "averageOriginalDataRateValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "truncatedPacketsValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "notCapturedBytesValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "captureCompletenessValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "onlyAToBFlowsValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "serviceRecognizedFlowsValue") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "dataDirectionDistributionHelpText") != nullptr);
        UI_EXPECT(named_object(statistics_pane.object.get(), "captureStartValue")->property("text").toString()
            == QString::fromUtf8("\xE2\x80\x94"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "averagePacketRateValue")->property("text").toString()
            == QString::fromUtf8("\xE2\x80\x94"));
        UI_EXPECT(!item_visible(statistics_pane.object.get(), "statisticsPartialOpenWarning"));
        UI_EXPECT(find_object_with_text(statistics_pane.object.get(), QStringLiteral("Capture Time")) == nullptr);

        auto stable_toggle_component = load_qml_component(
            "src/ui/qml/components/CollapsibleStatisticsSection.qml",
            "CollapsibleStatisticsSection"
        );
        stable_toggle_component.object->setProperty("title", QStringLiteral("Renamed Title"));
        stable_toggle_component.object->setProperty("toggleObjectName", QStringLiteral("stableStatisticsToggle"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_REQUIRE(named_object(stable_toggle_component.object.get(), "stableStatisticsToggle") != nullptr);

        statistics_pane.object->setProperty("captureMetricsExpanded", true);
        statistics_pane.object->setProperty("flowCharacteristicsExpanded", true);
        statistics_pane.object->setProperty("directionDistributionExpanded", true);
        statistics_pane.object->setProperty("tcpFlagsExpanded", true);
        statistics_pane.object->setProperty("packetSizeDistributionExpanded", true);
        statistics_pane.object->setProperty("packetSizeDistributionDisplayMode", 1);
        statistics_pane.object->setProperty("flowPacketHistogramExpanded", true);
        statistics_pane.object->setProperty("flowPacketHistogramDisplayMode", 2);
        statistics_pane.object->setProperty("protocolPathExpanded", true);
        statistics_pane.object->setProperty("protocolHintsExpanded", true);
        statistics_pane.object->setProperty("quicTlsExpanded", true);
        statistics_pane.object->setProperty("topFlowsExpanded", true);
        statistics_pane.object->setProperty("topEndpointsPortsExpanded", true);
        statistics_pane.object->setProperty("statisticsSectionsResetToken", 1);
        UI_EXPECT(!statistics_pane.object->property("captureMetricsExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("flowCharacteristicsExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("directionDistributionExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("tcpFlagsExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("packetSizeDistributionExpanded").toBool());
        UI_EXPECT(statistics_pane.object->property("packetSizeDistributionDisplayMode").toInt() == 0);
        UI_EXPECT(!statistics_pane.object->property("flowPacketHistogramExpanded").toBool());
        UI_EXPECT(statistics_pane.object->property("flowPacketHistogramDisplayMode").toInt() == 0);
        UI_EXPECT(!statistics_pane.object->property("protocolPathExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("protocolHintsExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("quicTlsExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("topFlowsExpanded").toBool());
        UI_EXPECT(!statistics_pane.object->property("topEndpointsPortsExpanded").toBool());
        UI_EXPECT(!protocol_path_export_button->property("enabled").toBool());

        statistics_pane.object->setProperty("hasCapture", true);
        statistics_pane.object->setProperty("flowCount", 58);
        statistics_pane.object->setProperty("statisticsPartialOpenWarningText",
            QStringLiteral("Statistics cover successfully imported packets only; the capture was opened partially."));
        statistics_pane.object->setProperty("captureTimeStatistics", QVariantMap {
            {QStringLiteral("captureStartText"), QStringLiteral("1970-01-01 00:00:00.100 UTC")},
            {QStringLiteral("captureEndText"), QStringLiteral("1970-01-01 00:00:00.400 UTC")},
            {QStringLiteral("durationText"), QStringLiteral("00:00:00.300")},
        });
        statistics_pane.object->setProperty("captureMetrics", QVariantMap {
            {QStringLiteral("averageCapturedPacketSizeText"), QStringLiteral("54 B")},
            {QStringLiteral("averageOriginalPacketSizeText"), QStringLiteral("54 B")},
            {QStringLiteral("averagePacketRateText"), QStringLiteral("13 333.33 pkt/s")},
            {QStringLiteral("averageCapturedDataRateText"), QStringLiteral("720 KB/s")},
            {QStringLiteral("averageOriginalDataRateText"), QStringLiteral("720 KB/s")},
            {QStringLiteral("truncatedPacketsText"), QStringLiteral("0 (0%)")},
            {QStringLiteral("notCapturedBytesText"), QStringLiteral("0 B")},
            {QStringLiteral("captureCompletenessText"), QStringLiteral("100%")},
        });
        statistics_pane.object->setProperty("flowCharacteristics", QVariantMap {
            {QStringLiteral("onlyAToBFlowsText"), QStringLiteral("2 (67%)")},
            {QStringLiteral("serviceRecognizedFlowsText"), QStringLiteral("0 (0%)")},
        });
        statistics_pane.object->setProperty("packetDirectionDistribution", QVariantMap {
            {QStringLiteral("rows"), QVariantList {
                QVariantMap {
                    {QStringLiteral("label"), QStringLiteral("Mostly A -> B")},
                    {QStringLiteral("flowCountText"), QStringLiteral("2")},
                    {QStringLiteral("percentText"), QStringLiteral("67%")},
                },
                QVariantMap {
                    {QStringLiteral("label"), QStringLiteral("Balanced")},
                    {QStringLiteral("flowCountText"), QStringLiteral("1")},
                    {QStringLiteral("percentText"), QStringLiteral("33%")},
                },
                QVariantMap {
                    {QStringLiteral("label"), QStringLiteral("Mostly B -> A")},
                    {QStringLiteral("flowCountText"), QStringLiteral("0")},
                    {QStringLiteral("percentText"), QStringLiteral("0%")},
                },
            }},
        });
        statistics_pane.object->setProperty("dataDirectionDistribution", QVariantMap {
            {QStringLiteral("helpText"), QStringLiteral("Flows grouped by directional original-byte balance.")},
            {QStringLiteral("rows"), QVariantList {
                QVariantMap {
                    {QStringLiteral("label"), QStringLiteral("Mostly A -> B")},
                    {QStringLiteral("flowCountText"), QStringLiteral("2")},
                    {QStringLiteral("percentText"), QStringLiteral("67%")},
                },
                QVariantMap {
                    {QStringLiteral("label"), QStringLiteral("Balanced")},
                    {QStringLiteral("flowCountText"), QStringLiteral("1")},
                    {QStringLiteral("percentText"), QStringLiteral("33%")},
                },
                QVariantMap {
                    {QStringLiteral("label"), QStringLiteral("Mostly B -> A")},
                    {QStringLiteral("flowCountText"), QStringLiteral("0")},
                    {QStringLiteral("percentText"), QStringLiteral("0%")},
                },
            }},
        });
        statistics_pane.object->setProperty("tcpFlagStatistics", QVariantMap {
            {QStringLiteral("helpText"), QStringLiteral(
                "Counts TCP packets with the corresponding flag set. A packet may contribute to more than one row. SYN includes SYN+ACK."
            )},
            {QStringLiteral("rows"), QVariantList {
                QVariantMap {
                    {QStringLiteral("stableId"), QStringLiteral("syn")},
                    {QStringLiteral("label"), QStringLiteral("SYN")},
                    {QStringLiteral("packetCountText"), QStringLiteral("2")},
                    {QStringLiteral("percentText"), QStringLiteral("50%")},
                },
                QVariantMap {
                    {QStringLiteral("stableId"), QStringLiteral("fin")},
                    {QStringLiteral("label"), QStringLiteral("FIN")},
                    {QStringLiteral("packetCountText"), QStringLiteral("1")},
                    {QStringLiteral("percentText"), QStringLiteral("25%")},
                },
                QVariantMap {
                    {QStringLiteral("stableId"), QStringLiteral("rst")},
                    {QStringLiteral("label"), QStringLiteral("RST")},
                    {QStringLiteral("packetCountText"), QStringLiteral("1")},
                    {QStringLiteral("percentText"), QStringLiteral("25%")},
                },
            }},
        });
        statistics_pane.object->setProperty("protocolPathSectionState", section_ready);
        statistics_pane.object->setProperty("topFlowSectionState", section_ready);
        statistics_pane.object->setProperty("topFlowsExpanded", true);
        statistics_pane.object->setProperty("topFlowRows", QVariantList {
            QVariantMap {
                {QStringLiteral("flowIndexText"), QStringLiteral("1")},
                {QStringLiteral("endpointA"), QStringLiteral("192.0.2.10 : 41000")},
                {QStringLiteral("endpointB"), QStringLiteral("198.51.100.10 : 443")},
                {QStringLiteral("protocolText"), QStringLiteral("TCP")},
                {QStringLiteral("detectedProtocolText"), QStringLiteral("TLS")},
                {QStringLiteral("serviceText"), QStringLiteral("bulk-download.example.test")},
                {QStringLiteral("protocolPathCompactText"), QStringLiteral("EII|Ip4|TCP")},
                {QStringLiteral("packetCountText"), QStringLiteral("2")},
                {QStringLiteral("capturedBytesText"), QStringLiteral("84 B")},
                {QStringLiteral("originalBytesText"), QStringLiteral("200 B")},
            },
            QVariantMap {
                {QStringLiteral("flowIndexText"), QStringLiteral("2")},
                {QStringLiteral("endpointA"), QStringLiteral("[2001:db8::10] : 42000")},
                {QStringLiteral("endpointB"), QStringLiteral("[2001:db8::20] : 9000")},
                {QStringLiteral("protocolText"), QStringLiteral("UDP")},
                {QStringLiteral("detectedProtocolText"), QStringLiteral("QUIC")},
                {QStringLiteral("serviceText"), QStringLiteral("quic.example")},
                {QStringLiteral("protocolPathCompactText"), QStringLiteral("EII|Ip6|UDP")},
                {QStringLiteral("packetCountText"), QStringLiteral("3")},
                {QStringLiteral("capturedBytesText"), QStringLiteral("210 B")},
                {QStringLiteral("originalBytesText"), QStringLiteral("210 B")},
            },
        });
        statistics_pane.object->setProperty("unrecognizedStatsPacketCount", 0);
        statistics_pane.object->setProperty("unrecognizedStatsCapturedBytes", 2048);
        statistics_pane.object->setProperty("unrecognizedStatsOriginalBytes", 3072);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(protocol_path_export_button->property("enabled").toBool());
        UI_EXPECT(!item_visible(statistics_pane.object.get(), "unrecognizedStatsSection"));
        UI_EXPECT(item_visible(statistics_pane.object.get(), "statisticsPartialOpenWarning"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "captureStartValue")->property("text").toString()
            == QStringLiteral("1970-01-01 00:00:00.100 UTC"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "captureEndValue")->property("text").toString()
            == QStringLiteral("1970-01-01 00:00:00.400 UTC"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "captureDurationValue")->property("text").toString()
            == QStringLiteral("00:00:00.300"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "averageCapturedPacketSizeValue")->property("text").toString()
            == QStringLiteral("54 B"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "averageOriginalPacketSizeValue")->property("text").toString()
            == QStringLiteral("54 B"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "averagePacketRateValue")->property("text").toString()
            == QStringLiteral("13 333.33 pkt/s"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "averageCapturedDataRateValue")->property("text").toString()
            == QStringLiteral("720 KB/s"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "averageOriginalDataRateValue")->property("text").toString()
            == QStringLiteral("720 KB/s"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "truncatedPacketsValue")->property("text").toString()
            == QStringLiteral("0 (0%)"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "notCapturedBytesValue")->property("text").toString()
            == QStringLiteral("0 B"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "captureCompletenessValue")->property("text").toString()
            == QStringLiteral("100%"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "onlyAToBFlowsValue")->property("text").toString()
            == QStringLiteral("2 (67%)"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "serviceRecognizedFlowsValue")->property("text").toString()
            == QStringLiteral("0 (0%)"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "dataDirectionDistributionHelpText")->property("text").toString()
            == QStringLiteral("Flows grouped by directional original-byte balance."));
        UI_REQUIRE(wait_until(app, [&]() {
            return named_object(statistics_pane.object.get(), "topFlowTableFlickable") != nullptr
                && named_object(statistics_pane.object.get(), "topFlowTableContent") != nullptr
                && named_object(statistics_pane.object.get(), "topFlowTableHeader") != nullptr
                && named_object(statistics_pane.object.get(), "topFlowRowsRepeater") != nullptr;
        }));
        UI_REQUIRE(named_object(statistics_pane.object.get(), "topFlowsSection") != nullptr);
        UI_EXPECT(item_visible(statistics_pane.object.get(), "topFlowsSection"));
        UI_EXPECT(qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "topFlowsSection"))
            ->property("expanded").toBool());
        auto* top_flow_table_flickable =
            qobject_cast<QQuickItem*>(named_object(statistics_pane.object.get(), "topFlowTableFlickable"));
        auto* top_flow_table_content =
            qobject_cast<QQuickItem*>(named_object(statistics_pane.object.get(), "topFlowTableContent"));
        auto* top_flow_rows_repeater = named_object(statistics_pane.object.get(), "topFlowRowsRepeater");
        UI_REQUIRE(top_flow_table_flickable != nullptr);
        UI_REQUIRE(top_flow_table_content != nullptr);
        UI_REQUIRE(top_flow_rows_repeater != nullptr);
        UI_EXPECT(top_flow_rows_repeater->property("count").toInt() == 2);
        UI_EXPECT(top_flow_table_flickable->height() > 0.0);
        UI_EXPECT(top_flow_table_flickable->property("contentWidth").toReal() > 0.0);
        UI_EXPECT(top_flow_table_flickable->property("contentHeight").toReal() > 0.0);
        UI_EXPECT(top_flow_table_content->property("implicitHeight").toReal() > 0.0);
        UI_EXPECT(!qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "captureMetricsSection"))
            ->property("expanded").toBool());
        UI_EXPECT(!qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "flowCharacteristicsSection"))
            ->property("expanded").toBool());
        UI_EXPECT(!qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "directionDistributionSection"))
            ->property("expanded").toBool());
        UI_REQUIRE(named_object(statistics_pane.object.get(), "tcpFlagsSection") != nullptr);
        UI_EXPECT(!qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "tcpFlagsSection"))
            ->property("expanded").toBool());

        statistics_pane.object->setProperty("unrecognizedStatsPacketCount", 250206);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(statistics_pane.object.get(), "unrecognizedStatsSection"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "unrecognizedStatsPacketValue")->property("text").toString()
            == QStringLiteral("250 206"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "unrecognizedStatsCapturedBytesValue")->property("text").toString()
            == QStringLiteral("2 KB"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "unrecognizedStatsOriginalBytesValue")->property("text").toString()
            == QStringLiteral("3 KB"));
        auto* statistics_column = qobject_cast<QQuickItem*>(named_object(statistics_pane.object.get(), "statisticsColumn"));
        UI_REQUIRE(statistics_column != nullptr);
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("captureTimeSection")) >= 0);
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("unrecognizedStatsSection")) >= 0);
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("packetSizeDistributionSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("unrecognizedStatsSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("flowPacketHistogramSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("packetSizeDistributionSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("protocolPathSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("flowPacketHistogramSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("protocolHintsSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("protocolPathSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("captureMetricsSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("protocolHintsSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("flowCharacteristicsSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("captureMetricsSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("directionDistributionSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("flowCharacteristicsSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("tcpFlagsSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("directionDistributionSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("quicTlsSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("tcpFlagsSection")));
        UI_EXPECT(direct_child_item_index_by_object_name(statistics_column, QStringLiteral("topEndpointsPortsSection"))
            > direct_child_item_index_by_object_name(statistics_column, QStringLiteral("quicTlsSection")));

        statistics_pane.object->setProperty("captureMetricsExpanded", true);
        statistics_pane.object->setProperty("flowCharacteristicsExpanded", true);
        statistics_pane.object->setProperty("directionDistributionExpanded", true);
        statistics_pane.object->setProperty("tcpFlagsExpanded", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "captureMetricsSection"))
            ->property("expanded").toBool());
        UI_EXPECT(qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "flowCharacteristicsSection"))
            ->property("expanded").toBool());
        UI_EXPECT(qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "directionDistributionSection"))
            ->property("expanded").toBool());
        UI_EXPECT(qobject_cast<QObject*>(named_object(statistics_pane.object.get(), "tcpFlagsSection"))
            ->property("expanded").toBool());
        UI_REQUIRE(named_object(statistics_pane.object.get(), "packetDirectionDistributionSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "dataDirectionDistributionSection") != nullptr);
        UI_REQUIRE(named_object(statistics_pane.object.get(), "tcpFlagsToggleButton") != nullptr);
        const auto tcp_flag_statistics = statistics_pane.object->property("tcpFlagStatistics").toMap();
        const auto tcp_flag_rows = tcp_flag_statistics.value(QStringLiteral("rows")).toList();
        UI_EXPECT(tcp_flag_rows.size() == 3);
        auto* tcp_flags_help_text = named_object(statistics_pane.object.get(), "tcpFlagsHelpText");
        auto* tcp_flags_rows_repeater = named_object(statistics_pane.object.get(), "tcpFlagsRowsRepeater");
        UI_REQUIRE(tcp_flags_help_text != nullptr);
        UI_REQUIRE(tcp_flags_rows_repeater != nullptr);
        UI_EXPECT(tcp_flags_rows_repeater->property("count").toInt() == 3);
        UI_EXPECT(tcp_flags_help_text->property("text").toString()
            == QStringLiteral("Counts TCP packets with the corresponding flag set. A packet may contribute to more than one row. SYN includes SYN+ACK."));

        statistics_pane.object->setProperty("unrecognizedStatsPacketCount", 0);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!item_visible(statistics_pane.object.get(), "unrecognizedStatsSection"));
        statistics_pane.object->setProperty("statisticsPartialOpenWarningText", QString {});
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!item_visible(statistics_pane.object.get(), "statisticsPartialOpenWarning"));

        statistics_pane.object->setProperty("packetSizeDistributionExpanded", true);
        statistics_pane.object->setProperty("packetSizeDistributionState", section_ready);
        statistics_pane.object->setProperty("packetSizeDistributionMaximumCapturedPacketLengthText", QStringLiteral("1.5 KB (1 536 B)"));
        statistics_pane.object->setProperty("packetSizeDistributionMaximumOriginalPacketLengthText", QStringLiteral("4 KB (4 096 B)"));
        statistics_pane.object->setProperty("packetSizeDistributionRows", QVariantList {
            QVariantMap {
                {QStringLiteral("label"), QStringLiteral("0-63")},
                {QStringLiteral("capturedPacketCountText"), QStringLiteral("2")},
                {QStringLiteral("capturedNormalizedFraction"), 1.0},
                {QStringLiteral("originalPacketCountText"), QStringLiteral("1")},
                {QStringLiteral("originalNormalizedFraction"), 0.5},
            },
            QVariantMap {
                {QStringLiteral("label"), QStringLiteral("64-127")},
                {QStringLiteral("capturedPacketCountText"), QStringLiteral("1")},
                {QStringLiteral("capturedNormalizedFraction"), 0.5},
                {QStringLiteral("originalPacketCountText"), QStringLiteral("2")},
                {QStringLiteral("originalNormalizedFraction"), 1.0},
            },
        });
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(named_object(statistics_pane.object.get(), "packetSizeDistributionModeCapturedButton") != nullptr);
        UI_EXPECT(named_object(statistics_pane.object.get(), "packetSizeDistributionModeOriginalButton") != nullptr);
        UI_EXPECT(named_object(statistics_pane.object.get(), "packetSizeDistributionMaximumPacketLengthValue")
            ->property("text").toString() == QStringLiteral("Maximum captured packet size: 1.5 KB (1 536 B)"));
        statistics_pane.object->setProperty("packetSizeDistributionDisplayMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(named_object(statistics_pane.object.get(), "packetSizeDistributionModeOriginalButton")->property("checked").toBool());
        UI_EXPECT(named_object(statistics_pane.object.get(), "packetSizeDistributionMaximumPacketLengthValue")
            ->property("text").toString() == QStringLiteral("Maximum original packet size: 4 KB (4 096 B)"));

        statistics_pane.object->setProperty("flowPacketHistogramExpanded", true);
        statistics_pane.object->setProperty("flowPacketHistogramState", section_ready);
        statistics_pane.object->setProperty("flowPacketHistogramExcludedZeroPacketFlowCount", 2);
        statistics_pane.object->setProperty("flowPacketHistogramRows", QVariantList {
            QVariantMap {
                {QStringLiteral("label"), QStringLiteral("1")},
                {QStringLiteral("flowCount"), QVariant::fromValue<qulonglong>(1U)},
                {QStringLiteral("capturedByteCount"), QVariant::fromValue<qulonglong>(512U)},
                {QStringLiteral("capturedByteCountText"), QStringLiteral("512 B")},
                {QStringLiteral("originalByteCount"), QVariant::fromValue<qulonglong>(0U)},
                {QStringLiteral("originalByteCountText"), QStringLiteral("0 B")},
                {QStringLiteral("normalizedFlowFraction"), 1.0},
                {QStringLiteral("normalizedCapturedByteFraction"), 0.5},
                {QStringLiteral("normalizedOriginalByteFraction"), 0.0},
            },
            QVariantMap {
                {QStringLiteral("label"), QStringLiteral("3-5")},
                {QStringLiteral("flowCount"), QVariant::fromValue<qulonglong>(1U)},
                {QStringLiteral("capturedByteCount"), QVariant::fromValue<qulonglong>(1024U)},
                {QStringLiteral("capturedByteCountText"), QStringLiteral("1 KB")},
                {QStringLiteral("originalByteCount"), QVariant::fromValue<qulonglong>(1536U)},
                {QStringLiteral("originalByteCountText"), QStringLiteral("1.5 KB")},
                {QStringLiteral("normalizedFlowFraction"), 1.0},
                {QStringLiteral("normalizedCapturedByteFraction"), 1.0},
                {QStringLiteral("normalizedOriginalByteFraction"), 1.0},
            },
        });
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(statistics_pane.object.get(), "flowPacketHistogramExcludedZeroPacketLabel"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "flowPacketHistogramExcludedZeroPacketLabel")->property("text").toString()
            == QStringLiteral("Excluded zero-packet flows: 2"));
        UI_EXPECT(named_object(statistics_pane.object.get(), "flowPacketHistogramModeFlowsButton") != nullptr);
        UI_EXPECT(named_object(statistics_pane.object.get(), "flowPacketHistogramModeCapturedBytesButton") != nullptr);
        UI_EXPECT(named_object(statistics_pane.object.get(), "flowPacketHistogramModeOriginalBytesButton") != nullptr);
        UI_EXPECT(statistics_pane.object->property("flowPacketHistogramDisplayMode").toInt() == 0);
        statistics_pane.object->setProperty("flowPacketHistogramDisplayMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(statistics_pane.object->property("flowPacketHistogramDisplayMode").toInt() == 1);
        UI_EXPECT(statistics_pane.object->property("flowPacketHistogramState").toInt() == section_ready);
        UI_EXPECT(named_object(statistics_pane.object.get(), "flowPacketHistogramModeCapturedBytesButton")->property("checked").toBool());
        statistics_pane.object->setProperty("flowPacketHistogramDisplayMode", 2);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(named_object(statistics_pane.object.get(), "flowPacketHistogramModeOriginalBytesButton")->property("checked").toBool());
        statistics_pane.object->setProperty("flowPacketHistogramExpanded", false);
        statistics_pane.object->setProperty("flowPacketHistogramExpanded", true);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(statistics_pane.object->property("flowPacketHistogramDisplayMode").toInt() == 2);

        const auto histogram_capture_path = write_temp_pcap(
            "pfl_ui_flow_packet_histogram_sections.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 40, 0, 1), ipv4(10, 40, 0, 2), 44001, 443)},
                {200, make_ethernet_ipv4_tcp_packet(ipv4(10, 40, 0, 3), ipv4(10, 40, 0, 4), 44002, 443)},
                {300, make_ethernet_ipv4_tcp_packet(ipv4(10, 40, 0, 3), ipv4(10, 40, 0, 4), 44002, 443)},
                {400, make_ethernet_ipv4_tcp_packet(ipv4(10, 40, 0, 5), ipv4(10, 40, 0, 6), 44003, 443)},
                {500, make_ethernet_ipv4_tcp_packet(ipv4(10, 40, 0, 5), ipv4(10, 40, 0, 6), 44003, 443)},
                {600, make_ethernet_ipv4_tcp_packet(ipv4(10, 40, 0, 5), ipv4(10, 40, 0, 6), 44003, 443)},
                {700, make_ethernet_ipv4_tcp_packet(ipv4(10, 40, 0, 5), ipv4(10, 40, 0, 6), 44003, 443)},
            })
        );

        MainController histogram_controller {};
        UI_EXPECT(open_capture_and_wait(app, histogram_controller, histogram_capture_path));
        UI_EXPECT(histogram_controller.currentTabIndex() == 0);
        UI_EXPECT(histogram_controller.packetSizeDistributionState() == section_not_requested);
        UI_EXPECT(histogram_controller.flowPacketHistogramState() == section_not_requested);
        UI_EXPECT(histogram_controller.protocolPathSectionState() == section_not_requested);
        UI_EXPECT(histogram_controller.protocolHintsSectionState() == section_not_requested);
        UI_EXPECT(histogram_controller.quicTlsSectionState() == section_not_requested);
        UI_EXPECT(histogram_controller.topEndpointPortSectionState() == section_not_requested);

        histogram_controller.setCurrentTabIndex(2);
        UI_EXPECT(histogram_controller.currentTabIndex() == 2);
        UI_EXPECT(histogram_controller.packetSizeDistributionState() == section_not_requested);
        UI_EXPECT(histogram_controller.flowPacketHistogramState() == section_not_requested);
        UI_EXPECT(histogram_controller.protocolPathSectionState() == section_not_requested);
        UI_EXPECT(histogram_controller.protocolHintsSectionState() == section_not_requested);
        UI_EXPECT(histogram_controller.quicTlsSectionState() == section_not_requested);
        UI_EXPECT(histogram_controller.topEndpointPortSectionState() == section_not_requested);

        histogram_controller.setStatisticsSectionExpanded(packet_size_section, true);
        UI_EXPECT(histogram_controller.packetSizeDistributionState() == section_ready);
        UI_EXPECT(histogram_controller.packetSizeDistributionTotalPacketCount() == 7U);
        UI_EXPECT(histogram_controller.packetSizeDistributionMaximumBucketPacketCount() == 7U);
        UI_EXPECT(histogram_controller.packetSizeDistributionMaximumCapturedPacketLength() > 0U);
        UI_EXPECT(histogram_controller.packetSizeDistributionMaximumCapturedPacketLengthText().endsWith(QStringLiteral("B")));
        UI_EXPECT(histogram_controller.packetSizeDistributionMaximumOriginalPacketLength() > 0U);
        UI_EXPECT(histogram_controller.packetSizeDistributionMaximumOriginalPacketLengthText().endsWith(QStringLiteral("B")));
        const auto packet_size_rows = histogram_controller.packetSizeDistributionRows();
        UI_EXPECT(packet_size_rows.size() == 13);
        UI_EXPECT(packet_size_rows[0].toMap().value(QStringLiteral("label")).toString() == QStringLiteral("0-63"));
        UI_EXPECT(packet_size_rows[12].toMap().value(QStringLiteral("label")).toString() == QStringLiteral("25001+"));
        UI_EXPECT(find_flow_packet_histogram_row(packet_size_rows, QStringLiteral("0-63")).value(QStringLiteral("capturedPacketCount")).toULongLong() == 7U);
        UI_EXPECT(find_flow_packet_histogram_row(packet_size_rows, QStringLiteral("0-63")).value(QStringLiteral("capturedNormalizedFraction")).toDouble() == 1.0);
        UI_EXPECT(find_flow_packet_histogram_row(packet_size_rows, QStringLiteral("0-63")).value(QStringLiteral("originalPacketCount")).toULongLong() == 7U);
        UI_EXPECT(find_flow_packet_histogram_row(packet_size_rows, QStringLiteral("0-63")).value(QStringLiteral("originalNormalizedFraction")).toDouble() == 1.0);

        histogram_controller.setStatisticsSectionExpanded(packet_size_section, false);
        UI_EXPECT(histogram_controller.packetSizeDistributionState() == section_ready);
        histogram_controller.setStatisticsSectionExpanded(packet_size_section, true);
        UI_EXPECT(histogram_controller.packetSizeDistributionRows() == packet_size_rows);

        histogram_controller.setStatisticsSectionExpanded(histogram_section, true);
        UI_EXPECT(histogram_controller.flowPacketHistogramState() == section_ready);
        UI_EXPECT(histogram_controller.flowPacketHistogramTotalFlowCount() == 3U);
        UI_EXPECT(histogram_controller.flowPacketHistogramMaximumBucketFlowCount() == 1U);
        UI_EXPECT(histogram_controller.flowPacketHistogramExcludedZeroPacketFlowCount() == 0U);
        const auto histogram_rows = histogram_controller.flowPacketHistogramRows();
        UI_EXPECT(histogram_rows.size() == 12);
        UI_EXPECT(histogram_rows[0].toMap().value(QStringLiteral("label")).toString() == QStringLiteral("1"));
        UI_EXPECT(histogram_rows[1].toMap().value(QStringLiteral("label")).toString() == QStringLiteral("2"));
        UI_EXPECT(histogram_rows[2].toMap().value(QStringLiteral("label")).toString() == QStringLiteral("3-5"));
        UI_EXPECT(histogram_rows[11].toMap().value(QStringLiteral("label")).toString() == QStringLiteral("5001+"));
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("flowCount")).toULongLong() == 1U);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("2")).value(QStringLiteral("flowCount")).toULongLong() == 1U);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("3-5")).value(QStringLiteral("flowCount")).toULongLong() == 1U);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("normalizedFraction")).toDouble() == 1.0);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("3-5")).value(QStringLiteral("normalizedFraction")).toDouble() == 1.0);

        histogram_controller.setStatisticsSectionExpanded(histogram_section, false);
        UI_EXPECT(histogram_controller.flowPacketHistogramState() == section_ready);
        histogram_controller.setStatisticsSectionExpanded(histogram_section, true);
        UI_EXPECT(histogram_controller.flowPacketHistogramRows() == histogram_rows);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("capturedByteCount")).toULongLong() > 0U);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("capturedByteCountText")).toString().endsWith(QStringLiteral("B")));
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("originalByteCount")).toULongLong() > 0U);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("originalByteCountText")).toString().endsWith(QStringLiteral("B")));
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("normalizedFlowFraction")).toDouble() == 1.0);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("normalizedCapturedByteFraction")).toDouble() >= 0.0);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("normalizedOriginalByteFraction")).toDouble() >= 0.0);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("3-5")).value(QStringLiteral("normalizedCapturedByteFraction")).toDouble() == 1.0);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("3-5")).value(QStringLiteral("normalizedOriginalByteFraction")).toDouble() == 1.0);
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("capturedByteCountText")).toString() != QStringLiteral("0 B"));
        UI_EXPECT(find_flow_packet_histogram_row(histogram_rows, QStringLiteral("1")).value(QStringLiteral("originalByteCountText")).toString() != QStringLiteral("0 B"));

        MainController deferred_histogram_controller {};
        UI_EXPECT(open_capture_and_wait(app, deferred_histogram_controller, histogram_capture_path));
        deferred_histogram_controller.setStatisticsSectionExpanded(packet_size_section, true);
        UI_EXPECT(deferred_histogram_controller.packetSizeDistributionState() == section_not_requested);
        deferred_histogram_controller.setCurrentTabIndex(2);
        UI_EXPECT(deferred_histogram_controller.packetSizeDistributionState() == section_ready);

        MainController deferred_flow_histogram_controller {};
        UI_EXPECT(open_capture_and_wait(app, deferred_flow_histogram_controller, histogram_capture_path));
        deferred_flow_histogram_controller.setStatisticsSectionExpanded(histogram_section, true);
        UI_EXPECT(deferred_flow_histogram_controller.flowPacketHistogramState() == section_not_requested);
        deferred_flow_histogram_controller.setCurrentTabIndex(2);
        UI_EXPECT(deferred_flow_histogram_controller.flowPacketHistogramState() == section_ready);

        MainController unrecognized_controller {};
        UI_EXPECT(open_capture_and_wait(app, unrecognized_controller, nonzero_unrecognized_capture_path));
        UI_EXPECT(unrecognized_controller.tcpFlowCount() == 1U);
        UI_EXPECT(unrecognized_controller.tcpPacketCount() == 1U);
        UI_EXPECT(unrecognized_controller.ipv4FlowCount() == 1U);
        UI_EXPECT(unrecognized_controller.ipv4PacketCount() == 1U);
        UI_EXPECT(unrecognized_controller.packetCount() == 2U);
        UI_EXPECT(unrecognized_controller.capturedBytes() ==
            static_cast<qulonglong>(nonzero_unrecognized_tcp_packet.size() + unrecognized_ethernet_packet.size()));
        UI_EXPECT(unrecognized_controller.originalBytes() ==
            static_cast<qulonglong>(nonzero_unrecognized_tcp_packet.size() + unrecognized_ethernet_packet.size()));
        UI_EXPECT(unrecognized_controller.unrecognizedStatsPacketCount() == 1U);
        UI_EXPECT(unrecognized_controller.unrecognizedStatsCapturedBytes() == 18U);
        UI_EXPECT(unrecognized_controller.unrecognizedStatsOriginalBytes() == 18U);

        UI_EXPECT(open_capture_and_wait(app, unrecognized_controller, zero_unrecognized_capture_path));
        UI_EXPECT(unrecognized_controller.tcpFlowCount() == 1U);
        UI_EXPECT(unrecognized_controller.tcpPacketCount() == 1U);
        UI_EXPECT(unrecognized_controller.ipv4FlowCount() == 1U);
        UI_EXPECT(unrecognized_controller.ipv4PacketCount() == 1U);
        UI_EXPECT(unrecognized_controller.packetCount() == 1U);
        UI_EXPECT(unrecognized_controller.capturedBytes() == static_cast<qulonglong>(zero_unrecognized_tcp_packet.size()));
        UI_EXPECT(unrecognized_controller.originalBytes() == static_cast<qulonglong>(zero_unrecognized_tcp_packet.size()));
        UI_EXPECT(unrecognized_controller.unrecognizedStatsPacketCount() == 0U);
        UI_EXPECT(unrecognized_controller.unrecognizedStatsCapturedBytes() == 0U);
        UI_EXPECT(unrecognized_controller.unrecognizedStatsOriginalBytes() == 0U);

        UI_EXPECT(open_capture_and_wait(app, unrecognized_controller, nonzero_unrecognized_capture_path));
        UI_EXPECT(unrecognized_controller.packetCount() == 2U);
        UI_EXPECT(unrecognized_controller.capturedBytes() ==
            static_cast<qulonglong>(nonzero_unrecognized_tcp_packet.size() + unrecognized_ethernet_packet.size()));
        UI_EXPECT(unrecognized_controller.originalBytes() ==
            static_cast<qulonglong>(nonzero_unrecognized_tcp_packet.size() + unrecognized_ethernet_packet.size()));
        UI_EXPECT(unrecognized_controller.unrecognizedStatsPacketCount() == 1U);
        UI_EXPECT(unrecognized_controller.unrecognizedStatsCapturedBytes() == 18U);
        UI_EXPECT(unrecognized_controller.unrecognizedStatsOriginalBytes() == 18U);

        MainController quic_tls_controller {};
        const auto tls_fixture_path = ui_test_root() / "data" / "parsing" / "tls" / "tls_1_2_badssl_baseline_14.pcap";
        UI_EXPECT(open_capture_and_wait(app, quic_tls_controller, tls_fixture_path));
        quic_tls_controller.setCurrentTabIndex(2);
        UI_EXPECT(quic_tls_controller.quicTlsSectionState() == section_not_requested);
        quic_tls_controller.setStatisticsSectionExpanded(quic_tls_section, true);
        UI_EXPECT(quic_tls_controller.quicTlsSectionState() == section_ready);
        UI_EXPECT(quic_tls_controller.quicTotalFlows() == 0U);
        UI_EXPECT(quic_tls_controller.tlsTotalFlows() > 0U);
        quic_tls_controller.setStatisticsSectionExpanded(quic_tls_section, false);
        quic_tls_controller.setStatisticsSectionExpanded(quic_tls_section, true);
        UI_EXPECT(quic_tls_controller.quicTlsSectionState() == section_ready);

        const auto top_talkers_capture_path = write_temp_pcap(
            "pfl_ui_top_talkers_sections.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 1), ipv4(10, 41, 1, 1), 45001, 80)},
                {110, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 2), ipv4(10, 41, 1, 2), 45002, 80)},
                {120, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 3), ipv4(10, 41, 1, 3), 45003, 80)},
                {130, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 4), ipv4(10, 41, 1, 4), 45004, 80)},
                {140, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 5), ipv4(10, 41, 1, 5), 45005, 80)},
                {150, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 6), ipv4(10, 41, 1, 6), 45006, 80)},
                {160, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 7), ipv4(10, 41, 1, 7), 45007, 80)},
                {170, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 8), ipv4(10, 41, 1, 8), 45008, 80)},
                {180, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 9), ipv4(10, 41, 1, 9), 45009, 80)},
                {190, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 10), ipv4(10, 41, 1, 10), 45010, 80)},
                {200, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 11), ipv4(10, 41, 1, 11), 45011, 80)},
                {210, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 12), ipv4(10, 41, 1, 12), 45012, 80)},
                {220, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 13), ipv4(10, 41, 1, 13), 45013, 80)},
                {230, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 14), ipv4(10, 41, 1, 14), 45014, 80)},
                {240, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 15), ipv4(10, 41, 1, 15), 45015, 80)},
                {250, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 16), ipv4(10, 41, 1, 16), 45016, 80)},
                {260, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 17), ipv4(10, 41, 1, 17), 45017, 80)},
                {270, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 18), ipv4(10, 41, 1, 18), 45018, 80)},
                {280, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 19), ipv4(10, 41, 1, 19), 45019, 80)},
                {290, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 20), ipv4(10, 41, 1, 20), 45020, 80)},
                {300, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 21), ipv4(10, 41, 1, 21), 45021, 80)},
                {310, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 22), ipv4(10, 41, 1, 22), 45022, 80)},
                {320, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 23), ipv4(10, 41, 1, 23), 45023, 80)},
                {330, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 24), ipv4(10, 41, 1, 24), 45024, 80)},
                {340, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 25), ipv4(10, 41, 1, 25), 45025, 80)},
                {350, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 26), ipv4(10, 41, 1, 26), 45026, 80)},
                {360, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 27), ipv4(10, 41, 1, 27), 45027, 80)},
                {370, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 28), ipv4(10, 41, 1, 28), 45028, 80)},
                {380, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 29), ipv4(10, 41, 1, 29), 45029, 80)},
                {390, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 30), ipv4(10, 41, 1, 30), 45030, 80)},
                {400, make_ethernet_ipv4_tcp_packet(ipv4(10, 41, 0, 31), ipv4(10, 41, 1, 31), 45031, 80)},
            })
        );

        MainController top_talkers_controller {};
        UI_EXPECT(open_capture_and_wait(app, top_talkers_controller, top_talkers_capture_path));
        top_talkers_controller.setCurrentTabIndex(2);
        auto* top_endpoints_model = qobject_cast<TopSummaryListModel*>(top_talkers_controller.topEndpointsModel());
        auto* top_ports_model = qobject_cast<TopSummaryListModel*>(top_talkers_controller.topPortsModel());
        UI_REQUIRE(top_endpoints_model != nullptr);
        UI_REQUIRE(top_ports_model != nullptr);
        UI_EXPECT(top_talkers_controller.topFlowSectionState() == section_not_requested);
        UI_EXPECT(top_talkers_controller.topEndpointPortSectionState() == section_not_requested);
        UI_EXPECT(top_endpoints_model->rowCount() == 0);
        UI_EXPECT(top_ports_model->rowCount() == 0);
        top_talkers_controller.setStatisticsSectionExpanded(top_flows_section, true);
        UI_EXPECT(top_talkers_controller.topFlowSectionState() == section_ready);
        UI_EXPECT(!top_talkers_controller.topFlowRows().isEmpty());
        top_talkers_controller.setStatisticsSectionExpanded(top_endpoints_ports_section, true);
        UI_EXPECT(top_talkers_controller.topEndpointPortSectionState() == section_ready);
        UI_EXPECT(top_endpoints_model->rowCount() > 0);
        UI_EXPECT(top_ports_model->rowCount() > 0);

        UI_EXPECT(open_capture_and_wait(app, top_talkers_controller, protocol_path_capture_path));
        UI_EXPECT(top_talkers_controller.topFlowSectionState() == section_not_requested);
        UI_EXPECT(top_talkers_controller.topEndpointPortSectionState() == section_not_requested);
        UI_EXPECT(top_talkers_controller.topFlowRows().isEmpty());
        UI_EXPECT(top_endpoints_model->rowCount() == 0);
        UI_EXPECT(top_ports_model->rowCount() == 0);
    });

    MainController protocol_path_controller {};
    UI_EXPECT(open_capture_and_wait(app, protocol_path_controller, protocol_path_capture_path));
    auto* protocol_path_flow_model = qobject_cast<FlowListModel*>(protocol_path_controller.flowModel());
    UI_EXPECT(protocol_path_flow_model != nullptr);
    UI_EXPECT(protocol_path_flow_model->rowCount() == 1);
    {
        const auto protocol_path_index = protocol_path_flow_model->index(0, 0);
        UI_EXPECT(protocol_path_flow_model->data(protocol_path_index, FlowListModel::ProtocolPathTextRole).toString() == QStringLiteral("EthernetII -> IPv4 -> TCP"));
        UI_EXPECT(protocol_path_flow_model->data(protocol_path_index, FlowListModel::ProtocolPathCompactTextRole).toString() == QStringLiteral("EII|Ip4|TCP"));
        const auto badge_list = protocol_path_flow_model->data(protocol_path_index, FlowListModel::ProtocolPathBadgesRole).toList();
        UI_EXPECT(badge_list.size() == 3);
        UI_EXPECT(badge_list[0].toMap().value(QStringLiteral("shortLabel")).toString() == QStringLiteral("EII"));
        UI_EXPECT(badge_list[1].toMap().value(QStringLiteral("shortLabel")).toString() == QStringLiteral("Ip4"));
        UI_EXPECT(badge_list[2].toMap().value(QStringLiteral("shortLabel")).toString() == QStringLiteral("TCP"));
    }
    {
        auto* protocol_path_stats_model = qobject_cast<ProtocolPathStatsModel*>(protocol_path_controller.protocolPathStatsModel());
        UI_EXPECT(protocol_path_stats_model != nullptr);
        protocol_path_controller.setCurrentTabIndex(2);
        UI_EXPECT(protocol_path_controller.protocolPathSectionState() == section_not_requested);
        UI_EXPECT(protocol_path_stats_model->rowCount() == 0);
        protocol_path_controller.setStatisticsSectionExpanded(protocol_path_section, true);
        UI_EXPECT(protocol_path_controller.protocolPathSectionState() == section_ready);
        const auto protocol_path_rows = protocol_path_controller.protocolPathStatistics();
        UI_EXPECT(protocol_path_stats_model->rowCount() == count_protocol_path_root_rows(protocol_path_rows));
        const auto first_row = protocol_path_stats_model->index(0, 0);
        UI_EXPECT(first_row.isValid());
        UI_EXPECT(!protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::LayerTextRole).toString().isEmpty());
        UI_EXPECT(!protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::PathTextRole).toString().isEmpty());
        UI_EXPECT(protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::FlowCountRole).toULongLong() >= 1U);
        UI_EXPECT(protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::PacketCountRole).toULongLong() >= 1U);
        UI_EXPECT(protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::FlowCountTextRole).toString().contains('%'));
        UI_EXPECT(protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::PacketCountTextRole).toString().contains('%'));
        UI_EXPECT(!protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::OriginalByteCountTextRole).toString().isEmpty());
        UI_EXPECT(protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::OriginalByteCountTextRole).toString().contains(QStringLiteral("B")));
        UI_EXPECT(protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::NodeIdRole).toULongLong() != pfl::kInvalidProtocolPathStatisticsNodeId);
        UI_EXPECT(protocol_path_stats_model->data(first_row, ProtocolPathStatsModel::HasChildrenRole).toBool());
        UI_EXPECT(!protocol_path_rows.isEmpty());
        UI_EXPECT(protocol_path_rows.front().toMap().contains(QStringLiteral("originalByteCountText")));
        protocol_path_stats_model->expandAll();
        UI_EXPECT(protocol_path_stats_model->rowCount() == protocol_path_rows.size());
    }

    const auto protocol_path_mode_capture_path = ui_test_root() / "data" / "parsing" / "vxlan" / "10_vxlan_same_inner_tuple_different_vni.pcap";
    MainController protocol_path_mode_controller {};
    UI_EXPECT(open_capture_and_wait(app, protocol_path_mode_controller, protocol_path_mode_capture_path));
    auto* protocol_path_mode_stats_model = qobject_cast<ProtocolPathStatsModel*>(protocol_path_mode_controller.protocolPathStatsModel());
    UI_EXPECT(protocol_path_mode_stats_model != nullptr);
    UI_EXPECT(protocol_path_mode_controller.statisticsMode() == 0);
    protocol_path_mode_controller.setCurrentTabIndex(2);
    UI_EXPECT(protocol_path_mode_controller.protocolPathSectionState() == section_not_requested);
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == 0);
    protocol_path_mode_controller.setStatisticsMode(1);
    UI_EXPECT(protocol_path_mode_controller.statisticsMode() == 1);
    UI_EXPECT(protocol_path_mode_controller.protocolPathSectionState() == section_not_requested);
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == 0);

    protocol_path_mode_controller.setStatisticsSectionExpanded(protocol_path_section, true);
    UI_EXPECT(protocol_path_mode_controller.protocolPathSectionState() == section_ready);
    const auto identity_rows = protocol_path_mode_controller.protocolPathStatistics();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == count_protocol_path_root_rows(identity_rows));
    protocol_path_mode_stats_model->expandAll();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == identity_rows.size());
    UI_EXPECT(find_protocol_path_stats_row_by_path_text(
        protocol_path_mode_stats_model,
        QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)")) >= 0);
    protocol_path_mode_stats_model->collapseAll();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == count_protocol_path_root_rows(identity_rows));

    const auto root_row = protocol_path_mode_stats_model->index(0, 0);
    UI_EXPECT(root_row.isValid());
    const auto root_node_id = protocol_path_mode_stats_model->data(root_row, ProtocolPathStatsModel::NodeIdRole).toULongLong();
    UI_EXPECT(root_node_id != pfl::kInvalidProtocolPathStatisticsNodeId);
    UI_EXPECT(protocol_path_mode_stats_model->data(root_row, ProtocolPathStatsModel::HasChildrenRole).toBool());
    UI_EXPECT(!protocol_path_mode_stats_model->data(root_row, ProtocolPathStatsModel::ExpandedRole).toBool());
    UI_EXPECT(!protocol_path_mode_stats_model->data(root_row, ProtocolPathStatsModel::OriginalByteCountTextRole).toString().isEmpty());

    protocol_path_mode_stats_model->toggleExpanded(root_node_id);
    UI_EXPECT(protocol_path_mode_stats_model->data(protocol_path_mode_stats_model->index(0, 0), ProtocolPathStatsModel::ExpandedRole).toBool());
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() > count_protocol_path_root_rows(identity_rows));

    protocol_path_mode_stats_model->collapseAll();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == count_protocol_path_root_rows(identity_rows));

    protocol_path_mode_controller.setStatisticsMode(2);
    UI_EXPECT(protocol_path_mode_controller.statisticsMode() == 2);
    UI_EXPECT(protocol_path_mode_controller.protocolPathSectionState() == section_ready);
    const auto terminal_rows = protocol_path_mode_controller.protocolPathStatistics();
    UI_EXPECT(!protocol_path_mode_stats_model->canExpand());
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == terminal_rows.size());
    UI_EXPECT(find_protocol_path_stats_row_by_path_text(
        protocol_path_mode_stats_model,
        QStringLiteral("EthernetII -> IPv4 -> UDP")) < 0);
    const auto terminal_row = find_protocol_path_stats_row_by_path_text(
        protocol_path_mode_stats_model,
        QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"));
    UI_EXPECT(terminal_row >= 0);
    UI_EXPECT(protocol_path_mode_stats_model->data(
        protocol_path_mode_stats_model->index(terminal_row, 0),
        ProtocolPathStatsModel::LayerTextRole).toString() ==
        QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"));
    protocol_path_mode_stats_model->collapseAll();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == terminal_rows.size());
    protocol_path_mode_stats_model->expandAll();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == terminal_rows.size());

    protocol_path_mode_controller.setStatisticsSectionExpanded(protocol_path_section, false);
    protocol_path_mode_controller.setStatisticsMode(0);
    UI_EXPECT(protocol_path_mode_controller.statisticsMode() == 0);
    UI_EXPECT(protocol_path_mode_controller.protocolPathSectionState() == section_not_requested);
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == 0);
    protocol_path_mode_controller.setStatisticsSectionExpanded(protocol_path_section, true);
    UI_EXPECT(protocol_path_mode_controller.protocolPathSectionState() == section_ready);
    const auto kind_overview_rows = protocol_path_mode_controller.protocolPathStatistics();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == count_protocol_path_root_rows(kind_overview_rows));
    protocol_path_mode_stats_model->expandAll();
    UI_EXPECT(protocol_path_mode_stats_model->rowCount() == kind_overview_rows.size());
    UI_EXPECT(find_protocol_path_stats_row_by_path_text(
        protocol_path_mode_stats_model,
        QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN")) >= 0);

    run_ui_section("protocol_path_export_button_wiring", [&]() {
        MainController protocol_path_export_controller {};
        UI_EXPECT(open_capture_and_wait(app, protocol_path_export_controller, protocol_path_mode_capture_path));
        auto* protocol_path_export_stats_model =
            qobject_cast<ProtocolPathStatsModel*>(protocol_path_export_controller.protocolPathStatsModel());
        UI_REQUIRE(protocol_path_export_stats_model != nullptr);

        protocol_path_export_controller.setCurrentTabIndex(2);
        protocol_path_export_controller.setStatisticsMode(1);
        protocol_path_export_controller.setStatisticsSectionExpanded(protocol_path_section, true);
        UI_EXPECT(protocol_path_export_controller.protocolPathSectionState() == section_ready);
        UI_EXPECT(wait_until(app, [&]() {
            return !protocol_path_export_controller.protocolPathStatistics().isEmpty();
        }));

        protocol_path_export_stats_model->collapseAll();
        const auto collapsed_visible_row_count = protocol_path_export_stats_model->rowCount();
        const auto collapsed_output_path =
            std::filesystem::temp_directory_path() / "pfl_ui_protocol_path_export_collapsed.txt";
        std::filesystem::remove(collapsed_output_path);
        UI_EXPECT(protocol_path_export_controller.exportProtocolPathTree(
            QString::fromStdWString(collapsed_output_path.wstring())));
        const auto collapsed_text = read_text_file_text(collapsed_output_path);
        UI_EXPECT(collapsed_text.find("Protocol Path Tree\n") != std::string::npos);
        UI_EXPECT(collapsed_text.find("Mode: Identity tree\n") != std::string::npos);
        UI_EXPECT(collapsed_text.find("      VXLAN (VNI 100)") != std::string::npos);
        UI_EXPECT(collapsed_text.find('\t') == std::string::npos);

        protocol_path_export_stats_model->expandAll();
        UI_EXPECT(protocol_path_export_stats_model->rowCount() > collapsed_visible_row_count);
        const auto expanded_output_path =
            std::filesystem::temp_directory_path() / "pfl_ui_protocol_path_export_expanded.txt";
        std::filesystem::remove(expanded_output_path);
        UI_EXPECT(protocol_path_export_controller.exportProtocolPathTree(
            QString::fromStdWString(expanded_output_path.wstring())));
        const auto expanded_text = read_text_file_text(expanded_output_path);

        UI_EXPECT(expanded_text == collapsed_text);
        UI_EXPECT(protocol_path_export_controller.statusText()
            == QStringLiteral("Protocol Path Tree exported successfully."));
    });

    MainController protocol_path_filter_controller {};
    UI_EXPECT(open_capture_and_wait(app, protocol_path_filter_controller, protocol_path_mode_capture_path));
    auto* protocol_path_filter_flow_model = qobject_cast<FlowListModel*>(protocol_path_filter_controller.flowModel());
    auto* protocol_path_filter_stats_model = qobject_cast<ProtocolPathStatsModel*>(protocol_path_filter_controller.protocolPathStatsModel());
    UI_REQUIRE(protocol_path_filter_flow_model != nullptr);
    UI_REQUIRE(protocol_path_filter_stats_model != nullptr);
    protocol_path_filter_controller.setCurrentTabIndex(2);
    protocol_path_filter_controller.setStatisticsSectionExpanded(protocol_path_section, true);
    UI_EXPECT(protocol_path_filter_flow_model->rowCount() == 2);
    UI_EXPECT(!protocol_path_filter_controller.hasProtocolPathFlowFilter());

    protocol_path_filter_controller.setStatisticsMode(1);
    protocol_path_filter_stats_model->expandAll();
    const auto identity_vni_100_row = find_protocol_path_stats_row_by_path_text(
        protocol_path_filter_stats_model,
        QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)")
    );
    UI_REQUIRE(identity_vni_100_row >= 0);
    const auto identity_vni_100_node_id = protocol_path_filter_stats_model->data(
        protocol_path_filter_stats_model->index(identity_vni_100_row, 0),
        ProtocolPathStatsModel::NodeIdRole
    ).toULongLong();
    protocol_path_filter_stats_model->selectNode(identity_vni_100_node_id);
    UI_EXPECT(protocol_path_filter_stats_model->hasSelectedNode());
    UI_EXPECT(protocol_path_filter_stats_model->selectedNodeId() == identity_vni_100_node_id);
    UI_EXPECT(protocol_path_filter_stats_model->selectedNodeFilterLabel()
        == QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)"));
    UI_EXPECT(protocol_path_filter_stats_model->selectedNodeFlowCount() == 1U);

    protocol_path_filter_controller.showSelectedProtocolPathFlows();
    UI_EXPECT(protocol_path_filter_controller.currentTabIndex() == 0);
    UI_EXPECT(protocol_path_filter_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_filter_controller.protocolPathFlowFilterText() ==
        QStringLiteral("Identity tree / EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)"));
    UI_EXPECT(protocol_path_filter_flow_model->rowCount() == 1);
    UI_EXPECT((protocol_path_filter_flow_model->visibleFlowIndices() == std::vector<int> {0}));

    protocol_path_filter_controller.setStatisticsMode(2);
    protocol_path_filter_controller.setCurrentTabIndex(2);
    const auto terminal_vni_100_row = find_protocol_path_stats_row_by_path_text(
        protocol_path_filter_stats_model,
        QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP")
    );
    UI_REQUIRE(terminal_vni_100_row >= 0);
    const auto terminal_vni_100_node_id = protocol_path_filter_stats_model->data(
        protocol_path_filter_stats_model->index(terminal_vni_100_row, 0),
        ProtocolPathStatsModel::NodeIdRole
    ).toULongLong();
    protocol_path_filter_stats_model->selectNode(terminal_vni_100_node_id);
    protocol_path_filter_controller.showSelectedProtocolPathFlows();
    UI_EXPECT(protocol_path_filter_controller.protocolPathFlowFilterText() ==
        QStringLiteral("Terminal paths / EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"));
    UI_EXPECT(protocol_path_filter_flow_model->rowCount() == 1);
    UI_EXPECT((protocol_path_filter_flow_model->visibleFlowIndices() == std::vector<int> {0}));

    const auto protocol_path_and_text_capture_path =
        ui_test_root() / "data" / "parsing" / "vxlan" / "12_vxlan_same_outer_tuple_different_inner_flows.pcap";
    MainController protocol_path_and_text_controller {};
    UI_EXPECT(open_capture_and_wait(app, protocol_path_and_text_controller, protocol_path_and_text_capture_path));
    auto* protocol_path_and_text_flow_model = qobject_cast<FlowListModel*>(protocol_path_and_text_controller.flowModel());
    auto* protocol_path_and_text_stats_model = qobject_cast<ProtocolPathStatsModel*>(protocol_path_and_text_controller.protocolPathStatsModel());
    UI_REQUIRE(protocol_path_and_text_flow_model != nullptr);
    UI_REQUIRE(protocol_path_and_text_stats_model != nullptr);
    auto protocol_path_and_text_flow_table = load_qml_component("src/ui/qml/components/FlowTable.qml", "FlowTable");
    protocol_path_and_text_flow_table.object->setProperty(
        "flowModel",
        QVariant::fromValue(protocol_path_and_text_controller.flowModel())
    );
    UI_EXPECT(named_object(protocol_path_and_text_flow_table.object.get(), "flowFilterStatusLabel") != nullptr);
    protocol_path_and_text_controller.setCurrentTabIndex(2);
    protocol_path_and_text_controller.setStatisticsSectionExpanded(protocol_path_section, true);
    UI_EXPECT(protocol_path_and_text_flow_model->rowCount() == 2);
    UI_EXPECT(protocol_path_and_text_flow_model->totalFlowCount() == 2);
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 2);
    UI_EXPECT(!protocol_path_and_text_flow_model->hasActiveFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText().isEmpty());
    UI_EXPECT(!item_visible(protocol_path_and_text_flow_table.object.get(), "flowFilterStatusLabel"));

    run_ui_section("advanced_flow_filter_toolbar_mode_switching", [&]() {
        MainController advanced_filter_controller {};
        UI_EXPECT(open_capture_and_wait(app, advanced_filter_controller, protocol_path_and_text_capture_path));
        auto* advanced_filter_flow_model = qobject_cast<FlowListModel*>(advanced_filter_controller.flowModel());
        UI_REQUIRE(advanced_filter_flow_model != nullptr);

        auto main_window = load_main_qml_component(advanced_filter_controller);
        auto* flow_text_filter_field = named_object(main_window.object.get(), "flowTextFilterField");
        auto* use_advanced_filter_button = named_object(main_window.object.get(), "useAdvancedFlowFilterButton");
        auto* simple_clear_button = named_object(main_window.object.get(), "flowTextFilterClearButton");
        auto* advanced_settings_button = named_object(main_window.object.get(), "advancedFlowFilterSettingsButton");
        auto* advanced_display_name_label = named_object(main_window.object.get(), "advancedFlowFilterDisplayNameLabel");
        auto* advanced_rule_count_label = named_object(main_window.object.get(), "advancedFlowFilterRuleCountLabel");
        auto* use_simple_filter_button = named_object(main_window.object.get(), "useSimpleFlowFilterButton");
        auto* advanced_clear_button = named_object(main_window.object.get(), "advancedFlowFilterClearButton");
        auto* global_settings_dialog = named_object(main_window.object.get(), "settingsDialog");
        UI_REQUIRE(flow_text_filter_field != nullptr);
        UI_REQUIRE(use_advanced_filter_button != nullptr);
        UI_REQUIRE(simple_clear_button != nullptr);
        UI_REQUIRE(advanced_settings_button != nullptr);
        UI_REQUIRE(advanced_display_name_label != nullptr);
        UI_REQUIRE(advanced_rule_count_label != nullptr);
        UI_REQUIRE(use_simple_filter_button != nullptr);
        UI_REQUIRE(advanced_clear_button != nullptr);
        UI_REQUIRE(global_settings_dialog != nullptr);

        UI_EXPECT(advanced_filter_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::simple));
        UI_EXPECT(advanced_filter_controller.flowFilterText().isEmpty());
        UI_EXPECT(advanced_filter_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(advanced_filter_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(advanced_filter_controller.advancedFlowFilterSettingsAvailable());
        UI_EXPECT(!advanced_filter_controller.advancedFlowFilterClearAvailable());
        UI_EXPECT(item_visible(main_window.object.get(), "flowTextFilterField"));
        UI_EXPECT(item_visible(main_window.object.get(), "useAdvancedFlowFilterButton"));
        UI_EXPECT(item_visible(main_window.object.get(), "flowTextFilterClearButton"));
        UI_EXPECT(!item_visible(main_window.object.get(), "advancedFlowFilterSettingsButton"));
        UI_EXPECT(advanced_settings_button != global_settings_dialog);

        advanced_filter_controller.setFlowFilterText(QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_controller.flowFilterText() == QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_flow_model->filterText() == QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(advanced_filter_flow_model->hasActiveFlowFilter());

        UI_REQUIRE(QMetaObject::invokeMethod(use_advanced_filter_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(advanced_filter_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::advanced));
        UI_EXPECT(advanced_filter_controller.flowFilterText() == QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_flow_model->filterText().isEmpty());
        UI_EXPECT(advanced_filter_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(!advanced_filter_flow_model->hasActiveFlowFilter());
        UI_EXPECT(item_visible(main_window.object.get(), "advancedFlowFilterSettingsButton"));
        UI_EXPECT(item_visible(main_window.object.get(), "advancedFlowFilterDisplayNameLabel"));
        UI_EXPECT(item_visible(main_window.object.get(), "advancedFlowFilterRuleCountLabel"));
        UI_EXPECT(item_visible(main_window.object.get(), "useSimpleFlowFilterButton"));
        UI_EXPECT(item_visible(main_window.object.get(), "advancedFlowFilterClearButton"));
        UI_EXPECT(!item_visible(main_window.object.get(), "flowTextFilterField"));
        UI_EXPECT(advanced_settings_button->property("enabled").toBool());
        UI_EXPECT(advanced_display_name_label->property("text").toString() == QStringLiteral("Filter: Custom filter"));
        UI_EXPECT(advanced_rule_count_label->property("text").toString() == QStringLiteral("0 rules"));
        UI_EXPECT(!advanced_clear_button->property("enabled").toBool());

        UI_REQUIRE(QMetaObject::invokeMethod(use_simple_filter_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(advanced_filter_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::simple));
        UI_EXPECT(advanced_filter_controller.flowFilterText() == QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_flow_model->filterText() == QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(advanced_filter_flow_model->hasActiveFlowFilter());
        UI_EXPECT(item_visible(main_window.object.get(), "flowTextFilterField"));
        UI_EXPECT(!item_visible(main_window.object.get(), "advancedFlowFilterSettingsButton"));

        advanced_filter_controller.useAdvancedFlowFilter();
        advanced_filter_controller.useSimpleFlowFilter();
        UI_EXPECT(advanced_filter_controller.flowFilterText() == QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_flow_model->filterText() == QStringLiteral("10001"));
        UI_EXPECT(advanced_filter_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(advanced_filter_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));

        UI_REQUIRE(QMetaObject::invokeMethod(simple_clear_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(advanced_filter_controller.flowFilterText().isEmpty());
        UI_EXPECT(advanced_filter_flow_model->filterText().isEmpty());
        UI_EXPECT(advanced_filter_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(advanced_filter_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(advanced_filter_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
    });

    run_ui_section("advanced_flow_filter_settings_editor_apply_cancel", [&]() {
        const auto advanced_settings_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_settings_apply_cancel.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 71, 0, 1), ipv4(10, 71, 0, 2), 51001, 80)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 71, 0, 3), ipv4(10, 71, 0, 4), 53000, 53)},
                {300U, make_ethernet_ipv6_udp_with_hop_by_hop_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
                    54000,
                    443
                )},
            })
        );

        MainController advanced_settings_controller {};
        UI_EXPECT(open_capture_and_wait(app, advanced_settings_controller, advanced_settings_capture_path));
        auto* advanced_settings_flow_model = qobject_cast<FlowListModel*>(advanced_settings_controller.flowModel());
        auto* advanced_settings_editor = advanced_filter_editor(advanced_settings_controller);
        UI_REQUIRE(advanced_settings_flow_model != nullptr);
        UI_REQUIRE(advanced_settings_editor != nullptr);
        constexpr int detected_protocol_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::detected_protocol);
        constexpr int directionality_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::directionality);
        constexpr int flow_protocol_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::flow_protocol);
        constexpr int ports_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::ports);
        constexpr int ip_addresses_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::ip_addresses);

        advanced_settings_controller.useAdvancedFlowFilter();
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterSettingsAvailable());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterSectionEnabled(flow_protocol_section_id));
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterSectionEnabled(ports_section_id));
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterSectionEnabled(ip_addresses_section_id));
        UI_EXPECT(!advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(detected_protocol_section_id),
            QStringLiteral("Possible TLS")));
        UI_EXPECT(!advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(detected_protocol_section_id),
            QStringLiteral("Possible QUIC")));
        UI_EXPECT(advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(directionality_section_id),
            QStringLiteral("Only A -> B packets")));
        UI_EXPECT(advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(directionality_section_id),
            QStringLiteral("Packets in both directions")));
        UI_EXPECT(!advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(directionality_section_id),
            QStringLiteral("One direction")));
        UI_EXPECT(!advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(directionality_section_id),
            QStringLiteral("Both directions")));
        UI_EXPECT(!advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(directionality_section_id),
            QStringLiteral("Unidirectional")));
        UI_EXPECT(!advanced_filter_option_present(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(directionality_section_id),
            QStringLiteral("Bidirectional")));
        UI_EXPECT(!advanced_filter_option_checked(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        UI_EXPECT(!advanced_settings_controller.advancedFlowFilterDraftClearAllAvailable());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterPortRows(false).isEmpty());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterAddressRows(false).isEmpty());
        UI_EXPECT(!advanced_settings_controller.advancedFlowFilterSectionHasExclusions(ports_section_id));
        UI_EXPECT(!advanced_settings_controller.advancedFlowFilterSectionHasExclusions(ip_addresses_section_id));
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterEditorValidationText().isEmpty());

        auto advanced_settings_window = load_main_qml_component(advanced_settings_controller);
        auto* advanced_settings_button =
            named_object(advanced_settings_window.object.get(), "advancedFlowFilterSettingsButton");
        auto* advanced_settings_dialog =
            named_object(advanced_settings_window.object.get(), "advancedFlowFilterSettingsDialog");
        UI_REQUIRE(advanced_settings_button != nullptr);
        UI_REQUIRE(advanced_settings_dialog != nullptr);

        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return advanced_settings_dialog->property("visible").toBool()
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterFlowProtocolSection") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterFlowProtocolCollapseButton") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterFlowProtocolContent") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterFlowProtocolIncludeUdpCheckBox") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterDetectedProtocolIncludeTlsCheckBox") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterTlsVersionIncludeTls13CheckBox") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterDirectionalityIncludeBidirectionalCheckBox") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsSection") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsCollapseButton") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsContent") != nullptr;
        }));

        auto* flow_protocol_content =
            popup_visual_item(advanced_settings_dialog, "advancedFlowFilterFlowProtocolContent");
        auto* flow_protocol_collapse_button =
            popup_visual_item(advanced_settings_dialog, "advancedFlowFilterFlowProtocolCollapseButton");
        auto* ports_content =
            popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsContent");
        UI_REQUIRE(flow_protocol_content != nullptr);
        UI_REQUIRE(flow_protocol_collapse_button != nullptr);
        UI_REQUIRE(ports_content != nullptr);
        UI_EXPECT(!flow_protocol_content->property("visible").toBool());
        UI_EXPECT(!ports_content->property("visible").toBool());
        UI_EXPECT(advanced_settings_editor->sectionSummaryText(flow_protocol_section_id).isEmpty());
        UI_EXPECT(advanced_settings_editor->sectionSummaryText(ports_section_id).isEmpty());

        UI_REQUIRE(QMetaObject::invokeMethod(flow_protocol_collapse_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(flow_protocol_content->property("visible").toBool());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 3);
        UI_REQUIRE(QMetaObject::invokeMethod(flow_protocol_collapse_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!flow_protocol_content->property("visible").toBool());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 3);
        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);

        advanced_settings_controller.beginAdvancedFlowFilterEdit();
        advanced_settings_controller.addAdvancedFlowFilterPortRow(false);
        advanced_settings_controller.setAdvancedFlowFilterPortRowRangeEnabled(false, 0, true);
        advanced_settings_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("8000"));
        UI_EXPECT(!advanced_settings_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("Range rules require both From and To values")));
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!advanced_settings_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        advanced_settings_controller.cancelAdvancedFlowFilterEdit();
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterPortRows(false).isEmpty());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!advanced_settings_flow_model->hasAdvancedFlowIndexFilter());

        advanced_settings_controller.beginAdvancedFlowFilterEdit();
        advanced_settings_controller.addAdvancedFlowFilterPortRow(false);
        advanced_settings_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("80"));
        const auto port_row_zero = advanced_filter_row_at(
            advanced_settings_controller.advancedFlowFilterPortRows(false),
            0
        );
        UI_EXPECT(port_row_zero.value(QStringLiteral("scope")).toInt()
            == static_cast<int>(pfl::session_detail::AdvancedFlowFilterPortScope::either_endpoint));
        UI_EXPECT(!port_row_zero.value(QStringLiteral("rangeEnabled")).toBool());
        UI_EXPECT(port_row_zero.value(QStringLiteral("primaryText")).toString() == QStringLiteral("80"));
        UI_EXPECT(port_row_zero.value(QStringLiteral("secondaryText")).toString().isEmpty());
        advanced_settings_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));
        UI_EXPECT(advanced_filter_option_checked(
            advanced_settings_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        advanced_settings_controller.cancelAdvancedFlowFilterEdit();
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!advanced_settings_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterPortRows(false).isEmpty());

        advanced_settings_controller.beginAdvancedFlowFilterEdit();
        advanced_settings_controller.addAdvancedFlowFilterPortRow(false);
        advanced_settings_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("80"));
        UI_EXPECT(advanced_settings_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(advanced_settings_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_protocol(advanced_settings_flow_model, QStringLiteral("TCP")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(advanced_settings_flow_model, QStringLiteral("UDP")) < 0);
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(advanced_settings_editor->sectionSummaryText(ports_section_id) == QStringLiteral("1 rule"));

        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return advanced_settings_dialog->property("visible").toBool()
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsCollapseButton") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsEnabledCheckBox") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsContent") != nullptr;
        }));

        auto* ports_collapse_button =
            popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsCollapseButton");
        auto* ports_enabled_check_box =
            popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsEnabledCheckBox");
        ports_content = popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsContent");
        UI_REQUIRE(ports_collapse_button != nullptr);
        UI_REQUIRE(ports_enabled_check_box != nullptr);
        UI_REQUIRE(ports_content != nullptr);
        UI_EXPECT(ports_content->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(ports_collapse_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!ports_content->property("visible").toBool());
        UI_EXPECT(advanced_settings_editor->sectionSummaryText(ports_section_id) == QStringLiteral("1 rule"));
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 1);
        UI_REQUIRE(QMetaObject::invokeMethod(ports_enabled_check_box, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!ports_content->property("visible").toBool());
        UI_EXPECT(!advanced_settings_editor->sectionEnabled(ports_section_id));
        UI_EXPECT(advanced_settings_editor->sectionSummaryText(ports_section_id)
            == QStringLiteral("1 rule · Disabled"));
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 1);
        UI_REQUIRE(QMetaObject::invokeMethod(ports_enabled_check_box, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(advanced_settings_editor->sectionEnabled(ports_section_id));
        UI_EXPECT(advanced_settings_editor->sectionSummaryText(ports_section_id) == QStringLiteral("1 rule"));
        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);

        advanced_settings_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterSectionEnabled(ports_section_id));
        UI_EXPECT(advanced_filter_row_at(
            advanced_settings_controller.advancedFlowFilterPortRows(false),
            0
        ).value(QStringLiteral("primaryText")).toString() == QStringLiteral("80"));
        advanced_settings_controller.setAdvancedFlowFilterSectionEnabled(ports_section_id, false);
        UI_EXPECT(!advanced_settings_controller.advancedFlowFilterSectionEnabled(ports_section_id));
        UI_EXPECT(advanced_filter_row_at(
            advanced_settings_controller.advancedFlowFilterPortRows(false),
            0
        ).value(QStringLiteral("primaryText")).toString() == QStringLiteral("80"));
        UI_EXPECT(advanced_settings_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(!advanced_settings_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!advanced_settings_flow_model->hasActiveFlowFilter());
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(advanced_settings_editor->sectionSummaryText(ports_section_id)
            == QStringLiteral("1 rule · Disabled"));

        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            auto* content = popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsContent");
            return advanced_settings_dialog->property("visible").toBool()
                && content != nullptr
                && content->property("visible").toBool();
        }));
        ports_content = popup_visual_item(advanced_settings_dialog, "advancedFlowFilterPortsContent");
        UI_REQUIRE(ports_content != nullptr);
        UI_EXPECT(ports_content->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);

        advanced_settings_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!advanced_settings_controller.advancedFlowFilterSectionEnabled(ports_section_id));
        UI_EXPECT(advanced_filter_row_at(
            advanced_settings_controller.advancedFlowFilterPortRows(false),
            0
        ).value(QStringLiteral("primaryText")).toString() == QStringLiteral("80"));
        advanced_settings_controller.setAdvancedFlowFilterSectionEnabled(ports_section_id, true);
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterSectionEnabled(ports_section_id));
        UI_EXPECT(advanced_filter_row_at(
            advanced_settings_controller.advancedFlowFilterPortRows(false),
            0
        ).value(QStringLiteral("primaryText")).toString() == QStringLiteral("80"));
        UI_EXPECT(advanced_settings_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(advanced_settings_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_settings_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_protocol(advanced_settings_flow_model, QStringLiteral("TCP")) >= 0);
        UI_EXPECT(advanced_settings_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
    });

    run_ui_section("advanced_flow_filter_settings_text_input_focus_stability", [&]() {
        using TrafficMetric = pfl::AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric;

        MainController revision_controller {};
        auto* revision_editor = advanced_filter_editor(revision_controller);
        UI_REQUIRE(revision_editor != nullptr);
        constexpr auto packet_count_metric = static_cast<int>(TrafficMetric::packet_count);

        revision_controller.applyAdvancedFlowFilterDocument(make_port_text_entry_document());
        revision_controller.beginAdvancedFlowFilterEdit();
        const auto port_revision_before = revision_editor->revision();
        const auto port_summary_revision_before = revision_editor->sectionSummaryRevision();
        revision_editor->setPortRowPrimaryText(false, 0, QStringLiteral("80"));
        UI_EXPECT(advanced_filter_row_at(
            revision_editor->portRows(false),
            0
        ).value(QStringLiteral("primaryText")).toString() == QStringLiteral("80"));
        UI_EXPECT(revision_editor->revision() == port_revision_before);
        UI_EXPECT(revision_editor->sectionSummaryRevision() > port_summary_revision_before);
        revision_controller.cancelAdvancedFlowFilterEdit();

        revision_controller.applyAdvancedFlowFilterDocument(make_address_prefix_text_entry_document());
        revision_controller.beginAdvancedFlowFilterEdit();
        const auto address_revision_before = revision_editor->revision();
        const auto address_summary_revision_before = revision_editor->sectionSummaryRevision();
        revision_editor->setAddressRowPrefixText(false, 0, QStringLiteral("16"));
        UI_EXPECT(advanced_filter_row_at(
            revision_editor->addressRows(false),
            0
        ).value(QStringLiteral("prefixText")).toString() == QStringLiteral("16"));
        UI_EXPECT(revision_editor->revision() == address_revision_before);
        UI_EXPECT(revision_editor->sectionSummaryRevision() > address_summary_revision_before);
        revision_controller.cancelAdvancedFlowFilterEdit();

        revision_controller.applyAdvancedFlowFilterDocument(make_traffic_text_entry_document());
        revision_controller.beginAdvancedFlowFilterEdit();
        const auto traffic_revision_before = revision_editor->revision();
        revision_editor->setTrafficMinText(packet_count_metric, QStringLiteral("12"));
        UI_EXPECT(advanced_filter_metric_row_at(
            revision_editor->commonTrafficRows(),
            packet_count_metric
        ).value(QStringLiteral("minText")).toString() == QStringLiteral("12"));
        UI_EXPECT(revision_editor->revision() == traffic_revision_before);
        revision_controller.cancelAdvancedFlowFilterEdit();

        revision_controller.applyAdvancedFlowFilterDocument(make_service_text_entry_document());
        revision_controller.beginAdvancedFlowFilterEdit();
        const auto service_revision_before = revision_editor->revision();
        revision_editor->setServiceTextRowText(false, 0, QStringLiteral("ui"));
        UI_EXPECT(advanced_filter_row_at(
            revision_editor->serviceTextRows(false),
            0
        ).value(QStringLiteral("text")).toString() == QStringLiteral("ui"));
        UI_EXPECT(revision_editor->revision() == service_revision_before);
        revision_controller.cancelAdvancedFlowFilterEdit();

        revision_controller.applyAdvancedFlowFilterDocument(make_contains_layer_text_entry_document());
        revision_controller.beginAdvancedFlowFilterEdit();
        const auto contains_layer_revision_before = revision_editor->revision();
        revision_editor->setContainsLayerRowExactValueText(false, 0, QStringLiteral("200"));
        UI_EXPECT(advanced_filter_row_at(
            revision_editor->containsLayerRows(false),
            0
        ).value(QStringLiteral("exactValueText")).toString() == QStringLiteral("200"));
        UI_EXPECT(revision_editor->revision() == contains_layer_revision_before);
        revision_controller.cancelAdvancedFlowFilterEdit();

        revision_controller.applyAdvancedFlowFilterDocument(pfl::session_detail::AdvancedFlowFilterDocument {});
        revision_controller.beginAdvancedFlowFilterEdit();
        const auto structural_revision_before = revision_editor->revision();
        revision_editor->addPortRow(false);
        UI_EXPECT(revision_editor->revision() > structural_revision_before);
        revision_controller.cancelAdvancedFlowFilterEdit();

        const auto focus_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_text_input_focus_stability.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 91, 0, 1), ipv4(10, 91, 0, 2), 51001, 80)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 91, 0, 3), ipv4(10, 91, 0, 4), 53000, 53)},
            })
        );

        MainController focus_controller {};
        UI_EXPECT(open_capture_and_wait(app, focus_controller, focus_capture_path));
        focus_controller.useAdvancedFlowFilter();
        focus_controller.applyAdvancedFlowFilterDocument(make_port_text_entry_document());

        auto main_window = load_main_qml_component(focus_controller);
        auto* window = qobject_cast<QQuickWindow*>(main_window.object.get());
        auto* settings_button = named_object(main_window.object.get(), "advancedFlowFilterSettingsButton");
        auto* advanced_settings_dialog = named_object(main_window.object.get(), "advancedFlowFilterSettingsDialog");
        UI_REQUIRE(window != nullptr);
        UI_REQUIRE(settings_button != nullptr);
        UI_REQUIRE(advanced_settings_dialog != nullptr);

        UI_REQUIRE(QMetaObject::invokeMethod(settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return advanced_settings_dialog->property("visible").toBool()
                && popup_content_item(advanced_settings_dialog) != nullptr;
        }));

        UI_EXPECT(wait_until(app, [&]() {
            return popup_visual_item(
                advanced_settings_dialog,
                "advancedFlowFilterPortsIncludeRow0PrimaryTextField"
            ) != nullptr;
        }));

        auto* port_text_field = popup_visual_item(
            advanced_settings_dialog,
            "advancedFlowFilterPortsIncludeRow0PrimaryTextField"
        );
        UI_REQUIRE(port_text_field != nullptr);
        UI_EXPECT(type_text_into_field(app, window, port_text_field, QStringLiteral("01234")));
        UI_EXPECT(port_text_field->property("text").toString() == QStringLiteral("801234"));
        UI_EXPECT(advanced_filter_row_at(
            focus_controller.advancedFlowFilterPortRows(false),
            0
        ).value(QStringLiteral("primaryText")).toString() == QStringLiteral("801234"));
        UI_EXPECT(port_text_field->property("activeFocus").toBool());

        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);
    });

    run_ui_section("advanced_flow_filter_file_workflow", [&]() {
        const auto file_workflow_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_file_workflow.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 92, 0, 1), ipv4(10, 92, 0, 2), 51001, 80)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 92, 0, 3), ipv4(10, 92, 0, 4), 53000, 53)},
                {300U, make_ethernet_ipv6_udp_with_hop_by_hop_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
                    54000,
                    443
                )},
            })
        );

        constexpr int flow_protocol_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::flow_protocol);

        MainController file_workflow_controller {};
        UI_EXPECT(open_capture_and_wait(app, file_workflow_controller, file_workflow_capture_path));
        auto* file_workflow_flow_model = qobject_cast<FlowListModel*>(file_workflow_controller.flowModel());
        UI_REQUIRE(file_workflow_flow_model != nullptr);
        file_workflow_controller.useAdvancedFlowFilter();
        file_workflow_controller.beginAdvancedFlowFilterEdit();

        const auto tcp_filter_path = write_temp_advanced_filter_document(
            "pfl_ui_tcp_open.filter",
            make_flow_protocol_advanced_document(ProtocolId::tcp)
        );
        file_workflow_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(tcp_filter_path.wstring());
        });
        file_workflow_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(file_workflow_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_tcp_open"));
        UI_EXPECT(file_workflow_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(file_workflow_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(file_workflow_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_protocol(file_workflow_flow_model, QStringLiteral("TCP")) >= 0);

        const auto malformed_filter_path = write_temp_advanced_filter_file(
            "pfl_ui_invalid_open.filter",
            "format_version = 3\n"
            "flow_protocol.include = tcpish\n"
        );
        file_workflow_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(malformed_filter_path.wstring());
        });
        file_workflow_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(file_workflow_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_tcp_open"));
        UI_EXPECT(file_workflow_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(file_workflow_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(file_workflow_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("Unknown flow protocol token")));

        file_workflow_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            false);
        file_workflow_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        UI_EXPECT(file_workflow_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_tcp_open *"));
        UI_EXPECT(file_workflow_controller.saveAdvancedFlowFilterFile());
        UI_EXPECT(file_workflow_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_tcp_open"));
        UI_EXPECT(file_workflow_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(read_text_file_text(tcp_filter_path).find("flow_protocol.include = udp\n") != std::string::npos);
        UI_EXPECT(file_workflow_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_protocol(file_workflow_flow_model, QStringLiteral("TCP")) < 0);
        UI_EXPECT(find_flow_index_by_protocol(file_workflow_flow_model, QStringLiteral("UDP")) >= 0);

        file_workflow_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            false);
        file_workflow_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            true);
        const auto ipv6_filter_path = write_temp_advanced_filter_document(
            "pfl_ui_ipv6_open.filter",
            make_address_family_advanced_document(FlowAddressFamily::ipv6)
        );
        file_workflow_controller.setAdvancedFlowFilterUnsavedOpenDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterOpenUnsavedDecision::save_and_open;
        });
        file_workflow_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(ipv6_filter_path.wstring());
        });
        file_workflow_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(read_text_file_text(tcp_filter_path).find("flow_protocol.include = tcp\n") != std::string::npos);
        UI_EXPECT(file_workflow_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_ipv6_open"));
        UI_EXPECT(file_workflow_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(file_workflow_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(file_workflow_flow_model, QStringLiteral("IPv6")) >= 0);

        MainController bounded_open_controller {};
        UI_EXPECT(open_capture_and_wait(app, bounded_open_controller, file_workflow_capture_path));
        auto* bounded_open_flow_model = qobject_cast<FlowListModel*>(bounded_open_controller.flowModel());
        UI_REQUIRE(bounded_open_flow_model != nullptr);
        bounded_open_controller.useAdvancedFlowFilter();
        bounded_open_controller.beginAdvancedFlowFilterEdit();

        const auto exact_limit_filter_path = write_temp_sized_advanced_filter_service_document(
            "pfl_ui_exact_limit.filter",
            pfl::session_detail::kAdvancedFlowFilterMaxFileBytes
        );
        bounded_open_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(exact_limit_filter_path.wstring());
        });
        bounded_open_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(bounded_open_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_exact_limit"));
        UI_EXPECT(bounded_open_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(bounded_open_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(bounded_open_flow_model->visibleFlowCount() == 0);

        const auto oversized_filter_path = write_temp_sized_advanced_filter_service_document(
            "pfl_ui_oversized.filter",
            pfl::session_detail::kAdvancedFlowFilterMaxFileBytes + 1U
        );
        bounded_open_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(oversized_filter_path.wstring());
        });
        bounded_open_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(bounded_open_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_exact_limit"));
        UI_EXPECT(bounded_open_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(bounded_open_flow_model->visibleFlowCount() == 0);
        UI_EXPECT(bounded_open_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("file is too large")));
        UI_EXPECT(bounded_open_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("maximum 1 MiB")));
        UI_EXPECT(!bounded_open_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("Unknown")));

        MainController custom_save_controller {};
        UI_EXPECT(open_capture_and_wait(app, custom_save_controller, file_workflow_capture_path));
        auto* custom_save_flow_model = qobject_cast<FlowListModel*>(custom_save_controller.flowModel());
        UI_REQUIRE(custom_save_flow_model != nullptr);
        custom_save_controller.useAdvancedFlowFilter();
        custom_save_controller.beginAdvancedFlowFilterEdit();
        custom_save_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        UI_EXPECT(custom_save_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(custom_save_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));

        bool saw_custom_suggested_name = false;
        custom_save_controller.setAdvancedFlowFilterSaveAsFileChooserForTests([&](const QString& suggested_file_name) {
            saw_custom_suggested_name = (suggested_file_name == QStringLiteral("advanced-filter.filter"));
            return QString {};
        });
        UI_EXPECT(!custom_save_controller.saveAdvancedFlowFilterFileAs());
        UI_EXPECT(saw_custom_suggested_name);
        UI_EXPECT(custom_save_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(custom_save_flow_model->visibleFlowCount() == 3);

        const auto custom_saved_path = std::filesystem::temp_directory_path() / "pfl_ui_custom_saved.filter";
        std::filesystem::remove(custom_saved_path);
        custom_save_controller.setAdvancedFlowFilterSaveAsFileChooserForTests([&](const QString& suggested_file_name) {
            saw_custom_suggested_name = (suggested_file_name == QStringLiteral("advanced-filter.filter"));
            return QString::fromStdWString(custom_saved_path.wstring());
        });
        UI_EXPECT(custom_save_controller.saveAdvancedFlowFilterFile());
        UI_EXPECT(saw_custom_suggested_name);
        UI_EXPECT(custom_save_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_custom_saved"));
        UI_EXPECT(custom_save_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(read_text_file_text(custom_saved_path).find("flow_protocol.include = udp\n") != std::string::npos);
        UI_EXPECT(custom_save_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_protocol(custom_save_flow_model, QStringLiteral("UDP")) >= 0);

        MainController protocol_path_file_controller {};
        UI_EXPECT(open_capture_and_wait(app, protocol_path_file_controller, file_workflow_capture_path));
        auto* protocol_path_file_flow_model = qobject_cast<FlowListModel*>(protocol_path_file_controller.flowModel());
        UI_REQUIRE(protocol_path_file_flow_model != nullptr);
        protocol_path_file_controller.useAdvancedFlowFilter();
        protocol_path_file_controller.applyAdvancedFlowFilterDocument(
            make_protocol_path_identifier_file_workflow_document()
        );
        const auto protocol_path_saved_path =
            std::filesystem::temp_directory_path() / "pfl_ui_protocol_path_round_trip.filter";
        std::filesystem::remove(protocol_path_saved_path);
        protocol_path_file_controller.setAdvancedFlowFilterSaveAsFileChooserForTests([&](const QString&) {
            return QString::fromStdWString(protocol_path_saved_path.wstring());
        });
        UI_EXPECT(protocol_path_file_controller.saveAdvancedFlowFilterFile());
        UI_EXPECT(protocol_path_file_controller.advancedFlowFilterDisplayName()
            == QStringLiteral("pfl_ui_protocol_path_round_trip"));
        UI_EXPECT(protocol_path_file_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));
        UI_EXPECT(read_text_file_text(protocol_path_saved_path).find("Geneve(vni=100)") != std::string::npos);
        UI_EXPECT(read_text_file_text(protocol_path_saved_path).find("GTP-U(teid=0x01020304)") != std::string::npos);

        protocol_path_file_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(protocol_path_saved_path.wstring());
        });
        protocol_path_file_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(protocol_path_file_controller.advancedFlowFilterDisplayName()
            == QStringLiteral("pfl_ui_protocol_path_round_trip"));
        UI_EXPECT(protocol_path_file_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(protocol_path_file_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));
        UI_EXPECT(protocol_path_file_flow_model->visibleFlowCount() == 0);
        protocol_path_file_controller.beginAdvancedFlowFilterEdit();
        UI_REQUIRE(protocol_path_file_controller.advancedFlowFilterProtocolPathRows(false).size() == 2);
        const auto saved_prefix_row = advanced_filter_row_at(
            protocol_path_file_controller.advancedFlowFilterProtocolPathRows(false),
            0
        );
        const auto saved_exact_row = advanced_filter_row_at(
            protocol_path_file_controller.advancedFlowFilterProtocolPathRows(false),
            1
        );
        UI_EXPECT(saved_prefix_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("Geneve")));
        UI_EXPECT(saved_prefix_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("100")));
        UI_EXPECT(saved_exact_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("GTP-U")));
        UI_EXPECT(saved_exact_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("01020304")));
        UI_EXPECT(saved_prefix_row.value(QStringLiteral("statusText")).toString()
            == QStringLiteral("Not present in current capture"));
        UI_EXPECT(saved_exact_row.value(QStringLiteral("statusText")).toString()
            == QStringLiteral("Not present in current capture"));
        protocol_path_file_controller.cancelAdvancedFlowFilterEdit();

        const auto tcp_reopen_path = write_temp_advanced_filter_document(
            "pfl_ui_reopen_tcp.filter",
            make_flow_protocol_advanced_document(ProtocolId::tcp)
        );
        const auto ipv6_reopen_path = write_temp_advanced_filter_document(
            "pfl_ui_reopen_ipv6.filter",
            make_address_family_advanced_document(FlowAddressFamily::ipv6)
        );
        custom_save_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(ipv6_reopen_path.wstring());
        });
        custom_save_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(custom_save_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_reopen_ipv6"));
        custom_save_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        custom_save_controller.setAdvancedFlowFilterUnsavedOpenDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterOpenUnsavedDecision::cancel;
        });
        custom_save_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(tcp_reopen_path.wstring());
        });
        custom_save_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(custom_save_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_reopen_ipv6 *"));
        UI_EXPECT(custom_save_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(custom_save_flow_model, QStringLiteral("IPv6")) >= 0);
    });

    run_ui_section("advanced_flow_filter_clear_workflow", [&]() {
        const auto clear_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_clear_workflow.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 93, 0, 1), ipv4(10, 93, 0, 2), 51001, 80)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 93, 0, 3), ipv4(10, 93, 0, 4), 53000, 53)},
                {300U, make_ethernet_ipv6_udp_with_hop_by_hop_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
                    54000,
                    443
                )},
            })
        );

        constexpr int flow_protocol_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::flow_protocol);

        const auto draft_clear_unsaved_available = [](MainController& controller) {
            auto* editor = controller.advancedFlowFilterEditor();
            return editor != nullptr && editor->property("draftClearUnsavedChangesAvailable").toBool();
        };
        const auto draft_clear_all_available = [](MainController& controller) {
            auto* editor = controller.advancedFlowFilterEditor();
            return editor != nullptr && editor->property("draftClearAllAvailable").toBool();
        };
        const auto has_unsynchronized_buffered_changes = [](MainController& controller) {
            auto* editor = controller.advancedFlowFilterEditor();
            return editor != nullptr && editor->property("hasUnsynchronizedBufferedChanges").toBool();
        };

        MainController clear_controller {};
        UI_EXPECT(open_capture_and_wait(app, clear_controller, clear_capture_path));
        auto* clear_flow_model = qobject_cast<FlowListModel*>(clear_controller.flowModel());
        UI_REQUIRE(clear_flow_model != nullptr);
        clear_controller.useAdvancedFlowFilter();
        UI_EXPECT(!clear_controller.advancedFlowFilterClearAvailable());

        clear_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!draft_clear_unsaved_available(clear_controller));
        UI_EXPECT(!draft_clear_all_available(clear_controller));
        clear_controller.cancelAdvancedFlowFilterEdit();

        clear_controller.applyAdvancedFlowFilterDocument(make_flow_protocol_advanced_document(ProtocolId::udp));
        UI_EXPECT(clear_controller.advancedFlowFilterClearAvailable());
        UI_EXPECT(clear_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(clear_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));

        clear_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(!file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::cancel;
        });
        clear_controller.clearAdvancedFlowFilter();
        UI_EXPECT(clear_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(clear_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(clear_flow_model->visibleFlowCount() == 2);

        clear_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(!file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::discard_and_clear;
        });
        clear_controller.clearAdvancedFlowFilter();
        UI_EXPECT(clear_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(clear_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(!clear_controller.advancedFlowFilterClearAvailable());
        UI_EXPECT(clear_flow_model->visibleFlowCount() == 3);

        clear_controller.applyAdvancedFlowFilterDocument(make_flow_protocol_advanced_document(ProtocolId::udp));
        const auto custom_clear_saved_path =
            std::filesystem::temp_directory_path() / "pfl_ui_custom_clear_saved.filter";
        std::filesystem::remove(custom_clear_saved_path);
        clear_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(!file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::save_as_and_clear;
        });
        clear_controller.setAdvancedFlowFilterSaveAsFileChooserForTests([&](const QString&) {
            return QString::fromStdWString(custom_clear_saved_path.wstring());
        });
        clear_controller.clearAdvancedFlowFilter();
        UI_EXPECT(std::filesystem::exists(custom_clear_saved_path));
        UI_EXPECT(read_text_file_text(custom_clear_saved_path).find("flow_protocol.include = udp\n") != std::string::npos);
        UI_EXPECT(clear_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(clear_flow_model->visibleFlowCount() == 3);

        clear_controller.applyAdvancedFlowFilterDocument(make_flow_protocol_advanced_document(ProtocolId::udp));
        clear_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(!file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::save_as_and_clear;
        });
        clear_controller.setAdvancedFlowFilterSaveAsFileChooserForTests([&](const QString&) {
            return QString {};
        });
        clear_controller.clearAdvancedFlowFilter();
        UI_EXPECT(clear_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(clear_flow_model->visibleFlowCount() == 2);

        const auto file_backed_path = write_temp_advanced_filter_document(
            "pfl_ui_clear_file_backed.filter",
            make_flow_protocol_advanced_document(ProtocolId::tcp)
        );
        const auto original_file_backed_text = read_text_file_text(file_backed_path);

        MainController file_backed_controller {};
        UI_EXPECT(open_capture_and_wait(app, file_backed_controller, clear_capture_path));
        auto* file_backed_flow_model = qobject_cast<FlowListModel*>(file_backed_controller.flowModel());
        UI_REQUIRE(file_backed_flow_model != nullptr);
        file_backed_controller.useAdvancedFlowFilter();
        file_backed_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(file_backed_path.wstring());
        });
        file_backed_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed"));
        UI_EXPECT(file_backed_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 1);

        bool clear_confirmation_called = false;
        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool) {
            clear_confirmation_called = true;
            return MainController::AdvancedFlowFilterClearDecision::cancel;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(!clear_confirmation_called);
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(file_backed_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(!file_backed_controller.advancedFlowFilterClearAvailable());
        UI_EXPECT(std::filesystem::exists(file_backed_path));
        UI_EXPECT(read_text_file_text(file_backed_path) == original_file_backed_text);
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 3);

        file_backed_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(file_backed_path.wstring());
        });
        file_backed_controller.openAdvancedFlowFilterFile();
        file_backed_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!draft_clear_unsaved_available(file_backed_controller));
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            false);
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        UI_EXPECT(draft_clear_unsaved_available(file_backed_controller));
        UI_EXPECT(draft_clear_all_available(file_backed_controller));
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed *"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 1);
        file_backed_controller.clearAdvancedFlowFilterUnsavedChanges();
        UI_EXPECT(!draft_clear_unsaved_available(file_backed_controller));
        UI_EXPECT(draft_clear_all_available(file_backed_controller));
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(advanced_filter_option_checked(
            file_backed_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("TCP")));
        UI_EXPECT(!advanced_filter_option_checked(
            file_backed_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        file_backed_controller.cancelAdvancedFlowFilterEdit();
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 1);

        file_backed_controller.beginAdvancedFlowFilterEdit();
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            false);
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        file_backed_controller.addAdvancedFlowFilterPortRow(false);
        file_backed_controller.setAdvancedFlowFilterPortRowRangeEnabled(false, 0, true);
        file_backed_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("8000"));
        UI_EXPECT(draft_clear_unsaved_available(file_backed_controller));
        UI_EXPECT(draft_clear_all_available(file_backed_controller));
        UI_EXPECT(has_unsynchronized_buffered_changes(file_backed_controller));
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed *"));
        bool unsynchronized_clear_prompt_invoked = false;
        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            unsynchronized_clear_prompt_invoked = true;
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::cancel;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(unsynchronized_clear_prompt_invoked);
        UI_EXPECT(file_backed_controller.advancedFlowFilterPortRows(false).size() == 1);
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 1);
        file_backed_controller.clearAdvancedFlowFilterUnsavedChanges();
        UI_EXPECT(file_backed_controller.advancedFlowFilterPortRows(false).isEmpty());
        UI_EXPECT(file_backed_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(!draft_clear_unsaved_available(file_backed_controller));
        UI_EXPECT(draft_clear_all_available(file_backed_controller));
        UI_EXPECT(!has_unsynchronized_buffered_changes(file_backed_controller));
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 1);

        file_backed_controller.beginAdvancedFlowFilterEdit();
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            false);
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::cancel;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed *"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 1);

        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::discard_and_clear;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(file_backed_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(read_text_file_text(file_backed_path) == original_file_backed_text);

        file_backed_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(file_backed_path.wstring());
        });
        file_backed_controller.openAdvancedFlowFilterFile();
        file_backed_controller.beginAdvancedFlowFilterEdit();
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            false);
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::save_and_clear;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(read_text_file_text(file_backed_path).find("flow_protocol.include = udp\n") != std::string::npos);
        UI_EXPECT(read_text_file_text(file_backed_path).find("flow_protocol.include = tcp\n") == std::string::npos);
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(file_backed_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 3);

        file_backed_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(file_backed_path.wstring());
        });
        file_backed_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 2);
        file_backed_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!advanced_filter_option_checked(
            file_backed_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("TCP")));
        UI_EXPECT(advanced_filter_option_checked(
            file_backed_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            true);
        file_backed_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed *"));
        UI_EXPECT(advanced_filter_option_checked(
            file_backed_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("TCP")));
        UI_EXPECT(advanced_filter_option_checked(
            file_backed_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 2);
        file_backed_controller.addAdvancedFlowFilterPortRow(false);
        file_backed_controller.setAdvancedFlowFilterPortRowRangeEnabled(false, 0, true);
        file_backed_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("9000"));
        bool file_backed_validation_clear_invoked = false;
        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            file_backed_validation_clear_invoked = true;
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::save_and_clear;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(file_backed_validation_clear_invoked);
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed *"));
        UI_EXPECT(file_backed_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("Range rules require both From and To values")));
        UI_EXPECT(read_text_file_text(file_backed_path).find("flow_protocol.include = udp\n") != std::string::npos);
        UI_EXPECT(read_text_file_text(file_backed_path).find("flow_protocol.include = tcp\n") == std::string::npos);
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 2);

        file_backed_controller.setAdvancedFlowFilterPortRowSecondaryText(false, 0, QStringLiteral("9100"));
        bool file_backed_save_failure_clear_invoked = false;
        file_backed_controller.setAdvancedFlowFilterSaveErrorForTests([&](const std::filesystem::path&) -> std::optional<QString> {
            return QStringLiteral("Injected save failure.");
        });
        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            file_backed_save_failure_clear_invoked = true;
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::save_and_clear;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(file_backed_save_failure_clear_invoked);
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("pfl_ui_clear_file_backed *"));
        UI_EXPECT(file_backed_controller.advancedFlowFilterEditorValidationText() == QStringLiteral("Injected save failure."));
        UI_EXPECT(read_text_file_text(file_backed_path).find("flow_protocol.include = udp\n") != std::string::npos);
        UI_EXPECT(read_text_file_text(file_backed_path).find("flow_protocol.include = tcp\n") == std::string::npos);
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 2);
        file_backed_controller.setAdvancedFlowFilterSaveErrorForTests(
            std::function<std::optional<QString>(const std::filesystem::path&)> {}
        );

        file_backed_controller.setAdvancedFlowFilterPortRowSecondaryText(false, 0, QStringLiteral("9200"));
        file_backed_controller.setAdvancedFlowFilterClearDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterClearDecision::discard_and_clear;
        });
        file_backed_controller.clearAdvancedFlowFilter();
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(file_backed_flow_model->visibleFlowCount() == 3);
        file_backed_controller.cancelAdvancedFlowFilterEdit();
        UI_EXPECT(file_backed_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));
        UI_EXPECT(file_backed_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));

        MainController unsynchronized_open_controller {};
        UI_EXPECT(open_capture_and_wait(app, unsynchronized_open_controller, clear_capture_path));
        auto* unsynchronized_open_flow_model = qobject_cast<FlowListModel*>(unsynchronized_open_controller.flowModel());
        UI_REQUIRE(unsynchronized_open_flow_model != nullptr);
        unsynchronized_open_controller.useAdvancedFlowFilter();
        unsynchronized_open_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(file_backed_path.wstring());
        });
        unsynchronized_open_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(unsynchronized_open_controller.advancedFlowFilterDisplayName()
            == QStringLiteral("pfl_ui_clear_file_backed"));
        UI_EXPECT(unsynchronized_open_flow_model->visibleFlowCount() == 2);
        unsynchronized_open_controller.beginAdvancedFlowFilterEdit();
        unsynchronized_open_controller.addAdvancedFlowFilterPortRow(false);
        unsynchronized_open_controller.setAdvancedFlowFilterPortRowRangeEnabled(false, 0, true);
        unsynchronized_open_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("7000"));
        UI_EXPECT(draft_clear_unsaved_available(unsynchronized_open_controller));
        UI_EXPECT(draft_clear_all_available(unsynchronized_open_controller));
        UI_EXPECT(has_unsynchronized_buffered_changes(unsynchronized_open_controller));
        UI_EXPECT(unsynchronized_open_controller.advancedFlowFilterDisplayName()
            == QStringLiteral("pfl_ui_clear_file_backed *"));

        bool unsynchronized_open_prompt_invoked = false;
        const auto unsynchronized_open_target_path = write_temp_advanced_filter_document(
            "pfl_ui_unsynchronized_open_target.filter",
            make_address_family_advanced_document(FlowAddressFamily::ipv6)
        );
        unsynchronized_open_controller.setAdvancedFlowFilterUnsavedOpenDecisionForTests([&](const bool file_backed_dirty) {
            unsynchronized_open_prompt_invoked = true;
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterOpenUnsavedDecision::save_and_open;
        });
        unsynchronized_open_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(unsynchronized_open_target_path.wstring());
        });
        unsynchronized_open_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(unsynchronized_open_prompt_invoked);
        UI_EXPECT(unsynchronized_open_controller.advancedFlowFilterDisplayName()
            == QStringLiteral("pfl_ui_clear_file_backed *"));
        UI_EXPECT(unsynchronized_open_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("Range rules require both From and To values")));
        UI_REQUIRE(unsynchronized_open_controller.advancedFlowFilterPortRows(false).size() == 1);
        UI_EXPECT(advanced_filter_row_at(unsynchronized_open_controller.advancedFlowFilterPortRows(false), 0)
            .value(QStringLiteral("primaryText")).toString() == QStringLiteral("7000"));
        UI_EXPECT(advanced_filter_row_at(unsynchronized_open_controller.advancedFlowFilterPortRows(false), 0)
            .value(QStringLiteral("secondaryText")).toString().isEmpty());
        UI_EXPECT(unsynchronized_open_flow_model->visibleFlowCount() == 2);

        unsynchronized_open_controller.setAdvancedFlowFilterUnsavedOpenDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(file_backed_dirty);
            return MainController::AdvancedFlowFilterOpenUnsavedDecision::discard_and_open;
        });
        unsynchronized_open_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(unsynchronized_open_controller.advancedFlowFilterDisplayName()
            == QStringLiteral("pfl_ui_unsynchronized_open_target"));
        UI_EXPECT(unsynchronized_open_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(!has_unsynchronized_buffered_changes(unsynchronized_open_controller));
        UI_EXPECT(unsynchronized_open_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(unsynchronized_open_flow_model, QStringLiteral("IPv6")) >= 0);
    });

    run_ui_section("advanced_flow_filter_settings_editor_include_exclude_and_multi_section", [&]() {
        const auto include_exclude_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_settings_include_exclude.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 72, 0, 1), ipv4(10, 72, 0, 2), 51001, 80)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 72, 0, 3), ipv4(10, 72, 0, 4), 53000, 53)},
                {300U, make_ethernet_ipv6_udp_with_hop_by_hop_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
                    54000,
                    443
                )},
            })
        );

        MainController include_exclude_controller {};
        UI_EXPECT(open_capture_and_wait(app, include_exclude_controller, include_exclude_capture_path));
        auto* include_exclude_flow_model = qobject_cast<FlowListModel*>(include_exclude_controller.flowModel());
        UI_REQUIRE(include_exclude_flow_model != nullptr);
        constexpr int address_family_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::address_family);
        constexpr int flow_protocol_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::flow_protocol);
        constexpr int ports_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::ports);
        constexpr int ip_addresses_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::ip_addresses);

        include_exclude_controller.useAdvancedFlowFilter();
        include_exclude_controller.beginAdvancedFlowFilterEdit();
        include_exclude_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            true);
        include_exclude_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            false,
            true);
        include_exclude_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            true,
            true);
        UI_EXPECT(include_exclude_controller.advancedFlowFilterSectionHasExclusions(flow_protocol_section_id));
        UI_EXPECT(advanced_filter_option_checked(
            include_exclude_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("TCP")));
        UI_EXPECT(advanced_filter_option_checked(
            include_exclude_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        UI_EXPECT(advanced_filter_option_checked(
            include_exclude_controller.advancedFlowFilterExcludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_protocol(include_exclude_flow_model, QStringLiteral("TCP")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(include_exclude_flow_model, QStringLiteral("UDP")) < 0);

        auto include_exclude_window = load_main_qml_component(include_exclude_controller);
        auto* include_exclude_settings_button =
            named_object(include_exclude_window.object.get(), "advancedFlowFilterSettingsButton");
        auto* include_exclude_settings_dialog =
            named_object(include_exclude_window.object.get(), "advancedFlowFilterSettingsDialog");
        UI_REQUIRE(include_exclude_settings_button != nullptr);
        UI_REQUIRE(include_exclude_settings_dialog != nullptr);

        UI_REQUIRE(QMetaObject::invokeMethod(include_exclude_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return include_exclude_settings_dialog->property("visible").toBool()
                && popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExclusionsToggleButton") != nullptr
                && popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExclusionsSection") != nullptr
                && popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolIncludeTcpCheckBox") != nullptr
                && popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExcludeUdpCheckBox") != nullptr;
        }));

        auto* flow_protocol_exclusions_toggle =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExclusionsToggleButton");
        auto* flow_protocol_exclusions_section =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExclusionsSection");
        auto* flow_protocol_hide_exclusions_button =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolHideExclusionsButton");
        auto* flow_protocol_include_tcp_checkbox =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolIncludeTcpCheckBox");
        auto* flow_protocol_exclude_udp_checkbox =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExcludeUdpCheckBox");
        UI_REQUIRE(flow_protocol_exclusions_toggle != nullptr);
        UI_REQUIRE(flow_protocol_exclusions_section != nullptr);
        UI_REQUIRE(flow_protocol_hide_exclusions_button != nullptr);
        UI_REQUIRE(flow_protocol_include_tcp_checkbox != nullptr);
        UI_REQUIRE(flow_protocol_exclude_udp_checkbox != nullptr);
        UI_EXPECT(flow_protocol_exclusions_section->property("visible").toBool());
        UI_EXPECT(flow_protocol_exclude_udp_checkbox->property("checked").toBool());

        UI_REQUIRE(QMetaObject::invokeMethod(flow_protocol_hide_exclusions_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!flow_protocol_exclusions_section->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(flow_protocol_include_tcp_checkbox, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!flow_protocol_exclusions_section->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(flow_protocol_include_tcp_checkbox, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!flow_protocol_exclusions_section->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(include_exclude_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);

        const auto flow_protocol_reload_path = write_temp_advanced_filter_document(
            "pfl_ui_polish_flow_protocol_reload.filter",
            make_flow_protocol_include_exclude_advanced_document()
        );
        const auto ports_reload_path = write_temp_advanced_filter_document(
            "pfl_ui_polish_ports_reload.filter",
            make_ports_include_exclude_advanced_document()
        );
        include_exclude_controller.setAdvancedFlowFilterUnsavedOpenDecisionForTests([&](const bool file_backed_dirty) {
            UI_EXPECT(!file_backed_dirty);
            return MainController::AdvancedFlowFilterOpenUnsavedDecision::discard_and_open;
        });
        include_exclude_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(flow_protocol_reload_path.wstring());
        });
        include_exclude_controller.openAdvancedFlowFilterFile();
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 1);

        UI_REQUIRE(QMetaObject::invokeMethod(include_exclude_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            auto* section = popup_visual_item(
                include_exclude_settings_dialog,
                "advancedFlowFilterFlowProtocolExclusionsSection"
            );
            auto* content = popup_visual_item(
                include_exclude_settings_dialog,
                "advancedFlowFilterFlowProtocolContent"
            );
            return include_exclude_settings_dialog->property("visible").toBool()
                && content != nullptr
                && content->property("visible").toBool()
                && section != nullptr
                && section->property("visible").toBool();
        }));
        flow_protocol_exclusions_toggle =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExclusionsToggleButton");
        flow_protocol_exclusions_section =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolExclusionsSection");
        flow_protocol_hide_exclusions_button =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolHideExclusionsButton");
        auto* flow_protocol_content =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterFlowProtocolContent");
        UI_REQUIRE(flow_protocol_exclusions_toggle != nullptr);
        UI_REQUIRE(flow_protocol_exclusions_section != nullptr);
        UI_REQUIRE(flow_protocol_hide_exclusions_button != nullptr);
        UI_REQUIRE(flow_protocol_content != nullptr);
        UI_EXPECT(flow_protocol_content->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(flow_protocol_hide_exclusions_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!flow_protocol_exclusions_section->property("visible").toBool());

        include_exclude_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(ports_reload_path.wstring());
        });
        include_exclude_controller.openAdvancedFlowFilterFile();
        auto* ports_collapse_button =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterPortsCollapseButton");
        auto* ports_content =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterPortsContent");
        UI_REQUIRE(ports_collapse_button != nullptr);
        UI_REQUIRE(ports_content != nullptr);
        UI_EXPECT(wait_until(app, [&]() {
            auto* content = popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterPortsContent");
            auto* section = popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterPortsExclusionsSection");
            return content != nullptr
                && content->property("visible").toBool()
                && section != nullptr
                && section->property("visible").toBool();
        }));
        auto* ports_exclusions_section =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterPortsExclusionsSection");
        auto* ports_exclude_row =
            popup_visual_item(include_exclude_settings_dialog, "advancedFlowFilterPortsExcludeRow0PrimaryTextField");
        UI_REQUIRE(ports_exclusions_section != nullptr);
        UI_REQUIRE(ports_exclude_row != nullptr);
        UI_EXPECT(ports_content->property("visible").toBool());
        UI_EXPECT(ports_exclusions_section->property("visible").toBool());
        UI_EXPECT(ports_exclude_row->property("text").toString() == QStringLiteral("53"));
        UI_REQUIRE(QMetaObject::invokeMethod(include_exclude_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);
        include_exclude_controller.setAdvancedFlowFilterUnsavedOpenDecisionForTests(
            std::function<MainController::AdvancedFlowFilterOpenUnsavedDecision(bool)> {}
        );
        include_exclude_controller.setAdvancedFlowFilterOpenFileChooserForTests([&]() {
            return QString::fromStdWString(flow_protocol_reload_path.wstring());
        });
        include_exclude_controller.openAdvancedFlowFilterFile();

        include_exclude_controller.beginAdvancedFlowFilterEdit();
        include_exclude_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::tcp),
            false,
            false);
        include_exclude_controller.setAdvancedFlowFilterOptionChecked(
            flow_protocol_section_id,
            static_cast<int>(ProtocolId::udp),
            true,
            false);
        include_exclude_controller.setAdvancedFlowFilterOptionChecked(
            address_family_section_id,
            static_cast<int>(FlowAddressFamily::ipv6),
            false,
            true);
        UI_EXPECT(advanced_filter_option_checked(
            include_exclude_controller.advancedFlowFilterIncludeOptions(address_family_section_id),
            QStringLiteral("IPv6")));
        UI_EXPECT(!advanced_filter_option_checked(
            include_exclude_controller.advancedFlowFilterIncludeOptions(address_family_section_id),
            QStringLiteral("IPv4")));
        UI_EXPECT(advanced_filter_option_checked(
            include_exclude_controller.advancedFlowFilterIncludeOptions(flow_protocol_section_id),
            QStringLiteral("UDP")));
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(include_exclude_flow_model, QStringLiteral("IPv6")) >= 0);
        UI_EXPECT(find_flow_index_by_family(include_exclude_flow_model, QStringLiteral("IPv4")) < 0);
        UI_EXPECT(find_flow_index_by_protocol(include_exclude_flow_model, QStringLiteral("UDP")) >= 0);
        UI_EXPECT(include_exclude_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));

        include_exclude_controller.applyAdvancedFlowFilterDocument({});
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!include_exclude_flow_model->hasAdvancedFlowIndexFilter());

        include_exclude_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!include_exclude_controller.advancedFlowFilterSectionHasExclusions(ports_section_id));
        include_exclude_controller.addAdvancedFlowFilterPortRow(false);
        include_exclude_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("443"));
        include_exclude_controller.addAdvancedFlowFilterPortRow(false);
        include_exclude_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 1, QStringLiteral("53"));
        include_exclude_controller.addAdvancedFlowFilterPortRow(true);
        include_exclude_controller.setAdvancedFlowFilterPortRowScope(
            true,
            0,
            static_cast<int>(pfl::session_detail::AdvancedFlowFilterPortScope::endpoint_b)
        );
        include_exclude_controller.setAdvancedFlowFilterPortRowPrimaryText(true, 0, QStringLiteral("53"));
        UI_EXPECT(include_exclude_controller.advancedFlowFilterSectionHasExclusions(ports_section_id));
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(include_exclude_flow_model, QStringLiteral("IPv6")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(include_exclude_flow_model, QStringLiteral("UDP")) >= 0);

        include_exclude_controller.applyAdvancedFlowFilterDocument({});
        include_exclude_controller.beginAdvancedFlowFilterEdit();
        include_exclude_controller.addAdvancedFlowFilterPortRow(false);
        include_exclude_controller.setAdvancedFlowFilterPortRowRangeEnabled(false, 0, true);
        include_exclude_controller.setAdvancedFlowFilterPortRowPrimaryText(false, 0, QStringLiteral("53000"));
        include_exclude_controller.setAdvancedFlowFilterPortRowSecondaryText(false, 0, QStringLiteral("54000"));
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_family(include_exclude_flow_model, QStringLiteral("IPv4")) >= 0);
        UI_EXPECT(find_flow_index_by_family(include_exclude_flow_model, QStringLiteral("IPv6")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(include_exclude_flow_model, QStringLiteral("TCP")) < 0);

        include_exclude_controller.applyAdvancedFlowFilterDocument({});
        include_exclude_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!include_exclude_controller.advancedFlowFilterSectionHasExclusions(ip_addresses_section_id));
        include_exclude_controller.addAdvancedFlowFilterAddressRow(false);
        include_exclude_controller.setAdvancedFlowFilterAddressRowSubnetEnabled(false, 0, true);
        include_exclude_controller.setAdvancedFlowFilterAddressRowAddressText(false, 0, QStringLiteral("10.72.0.0"));
        include_exclude_controller.setAdvancedFlowFilterAddressRowPrefixText(false, 0, QStringLiteral("24"));
        include_exclude_controller.addAdvancedFlowFilterAddressRow(true);
        include_exclude_controller.setAdvancedFlowFilterAddressRowScope(
            true,
            0,
            static_cast<int>(pfl::session_detail::AdvancedFlowFilterEndpointScope::endpoint_b)
        );
        include_exclude_controller.setAdvancedFlowFilterAddressRowAddressText(true, 0, QStringLiteral("10.72.0.4"));
        UI_EXPECT(include_exclude_controller.advancedFlowFilterSectionHasExclusions(ip_addresses_section_id));
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_protocol(include_exclude_flow_model, QStringLiteral("TCP")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(include_exclude_flow_model, QStringLiteral("UDP")) < 0);

        include_exclude_controller.applyAdvancedFlowFilterDocument({});
        include_exclude_controller.beginAdvancedFlowFilterEdit();
        include_exclude_controller.addAdvancedFlowFilterAddressRow(false);
        include_exclude_controller.setAdvancedFlowFilterAddressRowAddressText(
            false,
            0,
            QStringLiteral("2001:0db8:0072:0000:0000:0000:0000:0001")
        );
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(include_exclude_flow_model, QStringLiteral("IPv6")) >= 0);

        include_exclude_controller.beginAdvancedFlowFilterEdit();
        include_exclude_controller.setAdvancedFlowFilterSectionEnabled(ip_addresses_section_id, false);
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 3);

        include_exclude_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!include_exclude_controller.advancedFlowFilterSectionEnabled(ip_addresses_section_id));
        UI_EXPECT(advanced_filter_row_at(
            include_exclude_controller.advancedFlowFilterAddressRows(false),
            0
        ).value(QStringLiteral("addressText")).toString() == QHostAddress(QStringLiteral("2001:0db8:0072:0000:0000:0000:0000:0001")).toString());
        include_exclude_controller.setAdvancedFlowFilterSectionEnabled(ip_addresses_section_id, true);
        UI_EXPECT(include_exclude_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(include_exclude_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(include_exclude_flow_model, QStringLiteral("IPv6")) >= 0);
    });

    run_ui_section("advanced_flow_filter_settings_editor_traffic", [&]() {
        using TrafficMetric = pfl::AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficMetric;
        using TrafficUnit = pfl::AdvancedFlowFilterEditorModel::AdvancedFlowFilterTrafficUnit;

        const auto traffic_filter_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_traffic.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 81, 0, 1), ipv4(10, 81, 0, 2), 51001, 80, 24, 0x18)},
                {200U, make_ethernet_ipv4_udp_packet_with_payload(ipv4(10, 81, 0, 3), ipv4(10, 81, 0, 4), 53000, 53, 48)},
                {300U, make_ethernet_ipv4_udp_packet_with_payload(ipv4(10, 81, 0, 3), ipv4(10, 81, 0, 4), 53000, 53, 48)},
                {400U, make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 81, 0, 5), ipv4(10, 81, 0, 6), 54000, 443, 64, 0x18)},
                {500U, make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 81, 0, 5), ipv4(10, 81, 0, 6), 54000, 443, 64, 0x18)},
                {600U, make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 81, 0, 5), ipv4(10, 81, 0, 6), 54000, 443, 64, 0x18)},
            })
        );

        MainController traffic_controller {};
        UI_EXPECT(open_capture_and_wait(app, traffic_controller, traffic_filter_capture_path));
        auto* traffic_flow_model = qobject_cast<FlowListModel*>(traffic_controller.flowModel());
        auto* traffic_editor = advanced_filter_editor(traffic_controller);
        UI_REQUIRE(traffic_flow_model != nullptr);
        UI_REQUIRE(traffic_editor != nullptr);

        constexpr int traffic_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::traffic);
        constexpr int time_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::time);
        constexpr auto packet_count_metric = static_cast<int>(TrafficMetric::packet_count);
        constexpr auto original_bytes_metric = static_cast<int>(TrafficMetric::original_bytes);
        constexpr auto captured_bytes_metric = static_cast<int>(TrafficMetric::captured_bytes);
        constexpr auto a_to_b_packets_metric = static_cast<int>(TrafficMetric::a_to_b_packets);
        constexpr auto b_to_a_packets_metric = static_cast<int>(TrafficMetric::b_to_a_packets);
        constexpr auto a_to_b_original_bytes_metric = static_cast<int>(TrafficMetric::a_to_b_original_bytes);
        constexpr auto b_to_a_original_bytes_metric = static_cast<int>(TrafficMetric::b_to_a_original_bytes);
        constexpr auto max_original_packet_size_metric = static_cast<int>(TrafficMetric::max_original_packet_size);
        constexpr auto max_captured_packet_size_metric = static_cast<int>(TrafficMetric::max_captured_packet_size);
        traffic_controller.useAdvancedFlowFilter();
        UI_EXPECT(traffic_controller.advancedFlowFilterSectionEnabled(traffic_section_id));

        auto traffic_window = load_main_qml_component(traffic_controller);
        auto* traffic_qml_window = qobject_cast<QQuickWindow*>(traffic_window.object.get());
        auto* traffic_settings_button =
            named_object(traffic_window.object.get(), "advancedFlowFilterSettingsButton");
        auto* traffic_settings_dialog =
            named_object(traffic_window.object.get(), "advancedFlowFilterSettingsDialog");
        UI_REQUIRE(traffic_qml_window != nullptr);
        UI_REQUIRE(traffic_settings_button != nullptr);
        UI_REQUIRE(traffic_settings_dialog != nullptr);

        UI_REQUIRE(QMetaObject::invokeMethod(traffic_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return traffic_settings_dialog->property("visible").toBool()
                && popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficCollapseButton") != nullptr
                && popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficContent") != nullptr
                && popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficAdditionalToggleButton") != nullptr
                && popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficAdditionalSection") != nullptr;
        }));

        auto* traffic_collapse_button =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficCollapseButton");
        auto* traffic_content =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficContent");
        auto* traffic_additional_toggle_button =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficAdditionalToggleButton");
        auto* traffic_additional_section =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficAdditionalSection");
        auto* traffic_direction_helper =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficDirectionHelperText");
        auto* traffic_packet_distribution_group =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficPacketDistributionGroup");
        auto* traffic_data_distribution_group =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficDataDistributionGroup");
        auto* traffic_directional_packets_group =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficDirectionalPacketsGroup");
        auto* traffic_directional_original_bytes_group =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficDirectionalOriginalBytesGroup");
        auto* traffic_packet_count_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterPacketCountMinTextField");
        auto* traffic_original_bytes_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterOriginalBytesMinTextField");
        auto* traffic_captured_bytes_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterCapturedBytesMinTextField");
        auto* traffic_max_original_packet_size_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterMaxOriginalPacketSizeMinTextField");
        UI_REQUIRE(traffic_collapse_button != nullptr);
        UI_REQUIRE(traffic_content != nullptr);
        UI_REQUIRE(traffic_additional_toggle_button != nullptr);
        UI_REQUIRE(traffic_additional_section != nullptr);
        UI_REQUIRE(traffic_direction_helper != nullptr);
        UI_REQUIRE(traffic_packet_distribution_group != nullptr);
        UI_REQUIRE(traffic_data_distribution_group != nullptr);
        UI_REQUIRE(traffic_directional_packets_group != nullptr);
        UI_REQUIRE(traffic_directional_original_bytes_group != nullptr);
        UI_REQUIRE(traffic_packet_count_field != nullptr);
        UI_REQUIRE(traffic_original_bytes_field != nullptr);
        UI_REQUIRE(traffic_captured_bytes_field != nullptr);
        UI_REQUIRE(traffic_max_original_packet_size_field != nullptr);

        if (!traffic_content->property("visible").toBool()) {
            UI_REQUIRE(QMetaObject::invokeMethod(traffic_collapse_button, "click"));
            app.processEvents(QEventLoop::AllEvents, 25);
        }
        UI_EXPECT(traffic_content->property("visible").toBool());
        UI_EXPECT(traffic_packet_count_field->isVisible());
        UI_EXPECT(traffic_original_bytes_field->isVisible());
        UI_EXPECT(traffic_captured_bytes_field->isVisible());
        UI_EXPECT(traffic_additional_toggle_button->isVisible());
        UI_EXPECT(!traffic_additional_section->property("visible").toBool());
        UI_EXPECT(!traffic_direction_helper->isVisible());
        UI_EXPECT(!traffic_packet_distribution_group->isVisible());
        UI_EXPECT(!traffic_data_distribution_group->isVisible());
        UI_EXPECT(!traffic_directional_packets_group->isVisible());
        UI_EXPECT(!traffic_directional_original_bytes_group->isVisible());

        UI_REQUIRE(QMetaObject::invokeMethod(traffic_additional_toggle_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return traffic_additional_section->property("visible").toBool() &&
                traffic_max_original_packet_size_field->isVisible() &&
                traffic_direction_helper->isVisible() &&
                traffic_packet_distribution_group->isVisible() &&
                traffic_data_distribution_group->isVisible() &&
                traffic_directional_packets_group->isVisible() &&
                traffic_directional_original_bytes_group->isVisible();
        }));

        UI_REQUIRE(QMetaObject::invokeMethod(traffic_additional_toggle_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!traffic_additional_section->property("visible").toBool());
        UI_EXPECT(!traffic_direction_helper->isVisible());
        UI_EXPECT(!traffic_packet_distribution_group->isVisible());
        UI_EXPECT(!traffic_data_distribution_group->isVisible());
        UI_EXPECT(!traffic_directional_packets_group->isVisible());
        UI_EXPECT(!traffic_directional_original_bytes_group->isVisible());
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);

        traffic_controller.beginAdvancedFlowFilterEdit();
        traffic_editor->setTrafficMinText(packet_count_metric, QStringLiteral("2"));
        traffic_editor->setTrafficMaxText(packet_count_metric, QStringLiteral("2"));
        UI_EXPECT(traffic_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));
        traffic_controller.cancelAdvancedFlowFilterEdit();
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!traffic_flow_model->hasAdvancedFlowIndexFilter());

        traffic_controller.applyAdvancedFlowFilterDocument({});
        traffic_controller.beginAdvancedFlowFilterEdit();
        auto original_bytes_row = advanced_filter_metric_row_at(
            traffic_editor->commonTrafficRows(),
            original_bytes_metric
        );
        const auto captured_bytes_row = advanced_filter_metric_row_at(
            traffic_editor->commonTrafficRows(),
            captured_bytes_metric
        );
        const auto duration_row = traffic_editor->timeDurationRow();
        auto max_original_row = advanced_filter_metric_row_at(
            traffic_editor->additionalTrafficRows(),
            max_original_packet_size_metric
        );
        const auto max_captured_row = advanced_filter_metric_row_at(
            traffic_editor->additionalTrafficRows(),
            max_captured_packet_size_metric
        );
        UI_EXPECT(original_bytes_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::kib));
        UI_EXPECT(captured_bytes_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::kib));
        UI_EXPECT(duration_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::seconds));
        UI_EXPECT(max_original_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::bytes));
        UI_EXPECT(max_captured_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::bytes));
        UI_EXPECT(original_bytes_row.value(QStringLiteral("unitOptions")).toList().size() == 5);
        UI_EXPECT(max_original_row.value(QStringLiteral("unitOptions")).toList().size() == 2);
        UI_EXPECT(max_captured_row.value(QStringLiteral("unitOptions")).toList().size() == 2);
        UI_EXPECT(advanced_filter_option_present(
            traffic_editor->packetDistributionIncludeOptions(),
            QStringLiteral("Mostly A -> B")));
        UI_EXPECT(advanced_filter_option_present(
            traffic_editor->packetDistributionIncludeOptions(),
            QStringLiteral("Balanced")));
        UI_EXPECT(advanced_filter_option_present(
            traffic_editor->packetDistributionIncludeOptions(),
            QStringLiteral("Mostly B -> A")));
        UI_EXPECT(advanced_filter_option_present(
            traffic_editor->dataDistributionIncludeOptions(),
            QStringLiteral("Mostly A -> B")));
        const auto a_to_b_packets_row = advanced_filter_metric_row_at(
            traffic_editor->directionalPacketTrafficRows(),
            a_to_b_packets_metric
        );
        const auto b_to_a_packets_row = advanced_filter_metric_row_at(
            traffic_editor->directionalPacketTrafficRows(),
            b_to_a_packets_metric
        );
        const auto a_to_b_original_bytes_row = advanced_filter_metric_row_at(
            traffic_editor->directionalOriginalByteTrafficRows(),
            a_to_b_original_bytes_metric
        );
        const auto b_to_a_original_bytes_row = advanced_filter_metric_row_at(
            traffic_editor->directionalOriginalByteTrafficRows(),
            b_to_a_original_bytes_metric
        );
        UI_EXPECT(a_to_b_packets_row.value(QStringLiteral("hasUnitSelector")).toBool() == false);
        UI_EXPECT(a_to_b_packets_row.value(QStringLiteral("unitText")).toString() == QStringLiteral("packets"));
        UI_EXPECT(b_to_a_packets_row.value(QStringLiteral("hasUnitSelector")).toBool() == false);
        UI_EXPECT(a_to_b_original_bytes_row.value(QStringLiteral("hasUnitSelector")).toBool());
        UI_EXPECT(a_to_b_original_bytes_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::kib));
        UI_EXPECT(b_to_a_original_bytes_row.value(QStringLiteral("hasUnitSelector")).toBool());
        traffic_controller.cancelAdvancedFlowFilterEdit();

        traffic_controller.beginAdvancedFlowFilterEdit();
        traffic_editor->setTrafficMinText(packet_count_metric, QStringLiteral("2"));
        UI_EXPECT(traffic_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_protocol(traffic_flow_model, QStringLiteral("UDP")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(traffic_flow_model, QStringLiteral("TCP")) >= 0);
        UI_EXPECT(traffic_flow_model->hasAdvancedFlowIndexFilter());

        traffic_controller.applyAdvancedFlowFilterDocument({});
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return traffic_settings_dialog->property("visible").toBool();
        }));
        if (!traffic_content->property("visible").toBool()) {
            UI_REQUIRE(QMetaObject::invokeMethod(traffic_collapse_button, "click"));
            app.processEvents(QEventLoop::AllEvents, 25);
        }
        UI_EXPECT(!traffic_additional_section->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_additional_toggle_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return traffic_additional_section->property("visible").toBool() &&
                popup_visual_item(
                    traffic_settings_dialog,
                    "advancedFlowFilterTrafficPacketDistributionIncludeMostlyAToBCheckBox"
                ) != nullptr &&
                popup_visual_item(traffic_settings_dialog, "advancedFlowFilterAToBPacketsMinTextField") != nullptr &&
                popup_visual_item(traffic_settings_dialog, "advancedFlowFilterBToAPacketsMaxTextField") != nullptr;
        }));
        auto* mostly_a_to_b_checkbox = popup_visual_item(
            traffic_settings_dialog,
            "advancedFlowFilterTrafficPacketDistributionIncludeMostlyAToBCheckBox"
        );
        auto* balanced_exclude_checkbox = popup_visual_item(
            traffic_settings_dialog,
            "advancedFlowFilterTrafficDataDistributionExcludeBalancedCheckBox"
        );
        auto* a_to_b_packets_min_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterAToBPacketsMinTextField");
        auto* b_to_a_packets_max_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterBToAPacketsMaxTextField");
        UI_REQUIRE(mostly_a_to_b_checkbox != nullptr);
        UI_REQUIRE(balanced_exclude_checkbox != nullptr);
        UI_REQUIRE(a_to_b_packets_min_field != nullptr);
        UI_REQUIRE(b_to_a_packets_max_field != nullptr);

        UI_REQUIRE(QMetaObject::invokeMethod(mostly_a_to_b_checkbox, "click"));
        UI_REQUIRE(QMetaObject::invokeMethod(balanced_exclude_checkbox, "click"));
        UI_EXPECT(type_text_into_field(
            app,
            traffic_qml_window,
            a_to_b_packets_min_field,
            QStringLiteral("3")));
        UI_EXPECT(type_text_into_field(
            app,
            traffic_qml_window,
            b_to_a_packets_max_field,
            QStringLiteral("0")));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(traffic_controller.advancedFlowFilterRuleCountText() == QStringLiteral("4 rules"));
        UI_EXPECT(wait_until(app, [&]() {
            return mostly_a_to_b_checkbox->property("checked").toBool()
                && balanced_exclude_checkbox->property("checked").toBool()
                && a_to_b_packets_min_field->property("text").toString() == QStringLiteral("3")
                && b_to_a_packets_max_field->property("text").toString() == QStringLiteral("0");
        }));
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_additional_toggle_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!traffic_additional_section->property("visible").toBool());
        auto* traffic_apply_button =
            named_object(traffic_settings_dialog, "advancedFlowFilterApplyButton");
        UI_REQUIRE(traffic_apply_button != nullptr);
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_apply_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return !traffic_settings_dialog->property("visible").toBool();
        }));
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_protocol(traffic_flow_model, QStringLiteral("TCP")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(traffic_flow_model, QStringLiteral("UDP")) < 0);

        UI_REQUIRE(QMetaObject::invokeMethod(traffic_settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return traffic_settings_dialog->property("visible").toBool();
        }));
        traffic_content =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficContent");
        traffic_additional_toggle_button =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficAdditionalToggleButton");
        traffic_additional_section =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficAdditionalSection");
        UI_REQUIRE(traffic_content != nullptr);
        UI_REQUIRE(traffic_additional_toggle_button != nullptr);
        UI_REQUIRE(traffic_additional_section != nullptr);
        if (!traffic_content->property("visible").toBool()) {
            traffic_collapse_button =
                popup_visual_item(traffic_settings_dialog, "advancedFlowFilterTrafficCollapseButton");
            UI_REQUIRE(traffic_collapse_button != nullptr);
            UI_REQUIRE(QMetaObject::invokeMethod(traffic_collapse_button, "click"));
            app.processEvents(QEventLoop::AllEvents, 25);
        }
        UI_EXPECT(!traffic_additional_section->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_additional_toggle_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return traffic_additional_section->property("visible").toBool() &&
                popup_visual_item(
                    traffic_settings_dialog,
                    "advancedFlowFilterTrafficPacketDistributionIncludeMostlyAToBCheckBox"
                ) != nullptr &&
                popup_visual_item(traffic_settings_dialog, "advancedFlowFilterAToBPacketsMinTextField") != nullptr &&
                popup_visual_item(traffic_settings_dialog, "advancedFlowFilterBToAPacketsMaxTextField") != nullptr;
        }));
        mostly_a_to_b_checkbox = popup_visual_item(
            traffic_settings_dialog,
            "advancedFlowFilterTrafficPacketDistributionIncludeMostlyAToBCheckBox"
        );
        a_to_b_packets_min_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterAToBPacketsMinTextField");
        b_to_a_packets_max_field =
            popup_visual_item(traffic_settings_dialog, "advancedFlowFilterBToAPacketsMaxTextField");
        UI_REQUIRE(mostly_a_to_b_checkbox != nullptr);
        UI_REQUIRE(a_to_b_packets_min_field != nullptr);
        UI_REQUIRE(b_to_a_packets_max_field != nullptr);
        UI_EXPECT(mostly_a_to_b_checkbox->property("checked").toBool());
        UI_EXPECT(a_to_b_packets_min_field->property("text").toString() == QStringLiteral("3"));
        UI_EXPECT(b_to_a_packets_max_field->property("text").toString() == QStringLiteral("0"));
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_additional_toggle_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(!traffic_additional_section->property("visible").toBool());
        UI_REQUIRE(QMetaObject::invokeMethod(traffic_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);

        traffic_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(advanced_filter_option_checked(
            traffic_editor->packetDistributionIncludeOptions(),
            QStringLiteral("Mostly A -> B")));
        UI_EXPECT(advanced_filter_option_checked(
            traffic_editor->dataDistributionExcludeOptions(),
            QStringLiteral("Balanced")));
        UI_EXPECT(advanced_filter_metric_row_at(
            traffic_editor->directionalPacketTrafficRows(),
            a_to_b_packets_metric
        ).value(QStringLiteral("minText")).toString() == QStringLiteral("3"));
        UI_EXPECT(advanced_filter_metric_row_at(
            traffic_editor->directionalPacketTrafficRows(),
            b_to_a_packets_metric
        ).value(QStringLiteral("maxText")).toString() == QStringLiteral("0"));
        traffic_controller.setAdvancedFlowFilterSectionEnabled(traffic_section_id, false);
        UI_EXPECT(traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(traffic_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));

        traffic_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!traffic_controller.advancedFlowFilterSectionEnabled(traffic_section_id));
        UI_EXPECT(advanced_filter_option_checked(
            traffic_editor->packetDistributionIncludeOptions(),
            QStringLiteral("Mostly A -> B")));
        UI_EXPECT(advanced_filter_metric_row_at(
            traffic_editor->directionalPacketTrafficRows(),
            a_to_b_packets_metric
        ).value(QStringLiteral("minText")).toString() == QStringLiteral("3"));
        traffic_controller.setAdvancedFlowFilterSectionEnabled(traffic_section_id, true);
        UI_EXPECT(traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(traffic_controller.advancedFlowFilterRuleCountText() == QStringLiteral("4 rules"));

        traffic_controller.beginAdvancedFlowFilterEdit();
        traffic_editor->setTrafficMaxText(a_to_b_packets_metric, QStringLiteral("2"));
        UI_EXPECT(!traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("A -> B packets minimum must not exceed maximum.")));
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_protocol(traffic_flow_model, QStringLiteral("UDP")) < 0);
        UI_EXPECT(find_flow_index_by_protocol(traffic_flow_model, QStringLiteral("TCP")) >= 0);
        traffic_controller.cancelAdvancedFlowFilterEdit();

        traffic_controller.applyAdvancedFlowFilterDocument({});
        traffic_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(traffic_editor->setTrafficUnit(
            original_bytes_metric,
            static_cast<int>(TrafficUnit::mib)));
        traffic_editor->setTrafficMinText(original_bytes_metric, QStringLiteral("10"));
        UI_EXPECT(traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 0);

        traffic_controller.beginAdvancedFlowFilterEdit();
        original_bytes_row = advanced_filter_metric_row_at(
            traffic_editor->commonTrafficRows(),
            original_bytes_metric
        );
        UI_EXPECT(original_bytes_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::mib));
        UI_EXPECT(original_bytes_row.value(QStringLiteral("minText")).toString() == QStringLiteral("10"));
        traffic_editor->setTrafficMinText(original_bytes_metric, QStringLiteral("11"));
        traffic_controller.cancelAdvancedFlowFilterEdit();

        traffic_controller.beginAdvancedFlowFilterEdit();
        original_bytes_row = advanced_filter_metric_row_at(
            traffic_editor->commonTrafficRows(),
            original_bytes_metric
        );
        UI_EXPECT(original_bytes_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::mib));
        UI_EXPECT(original_bytes_row.value(QStringLiteral("minText")).toString() == QStringLiteral("10"));
        traffic_controller.cancelAdvancedFlowFilterEdit();

        pfl::session_detail::AdvancedFlowFilterDocument traffic_document {};
        traffic_document.configured_spec.aggregate.original_bytes =
            pfl::session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t> {
                .min = 10485761ULL,
                .max = 10485761ULL,
            };
        traffic_controller.applyAdvancedFlowFilterDocument(traffic_document);
        traffic_controller.beginAdvancedFlowFilterEdit();
        original_bytes_row = advanced_filter_metric_row_at(
            traffic_editor->commonTrafficRows(),
            original_bytes_metric
        );
        UI_EXPECT(original_bytes_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::bytes));
        UI_EXPECT(original_bytes_row.value(QStringLiteral("minText")).toString() == QStringLiteral("10485761"));
        UI_EXPECT(original_bytes_row.value(QStringLiteral("maxText")).toString() == QStringLiteral("10485761"));
        traffic_controller.cancelAdvancedFlowFilterEdit();

        traffic_document = {};
        traffic_document.configured_spec.time.duration_us =
            pfl::session_detail::AdvancedFlowFilterInclusiveRange<std::uint64_t> {
                .max = 7200000000ULL,
            };
        traffic_controller.applyAdvancedFlowFilterDocument(traffic_document);
        traffic_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(traffic_controller.advancedFlowFilterSectionEnabled(time_section_id));
        const auto loaded_duration_row = traffic_editor->timeDurationRow();
        UI_EXPECT(loaded_duration_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::hours));
        UI_EXPECT(loaded_duration_row.value(QStringLiteral("maxText")).toString() == QStringLiteral("2"));
        traffic_controller.cancelAdvancedFlowFilterEdit();

        traffic_document = {};
        traffic_document.configured_spec.aggregate.max_original_packet_length =
            pfl::session_detail::AdvancedFlowFilterInclusiveRange<std::uint32_t> {
                .min = 10485760U,
                .max = 10485760U,
            };
        traffic_controller.applyAdvancedFlowFilterDocument(traffic_document);
        traffic_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(traffic_editor->trafficAdditionalFiltersExpandedSuggested());
        max_original_row = advanced_filter_metric_row_at(
            traffic_editor->additionalTrafficRows(),
            max_original_packet_size_metric
        );
        UI_EXPECT(max_original_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::kib));
        UI_EXPECT(max_original_row.value(QStringLiteral("minText")).toString() == QStringLiteral("10240"));
        UI_EXPECT(max_original_row.value(QStringLiteral("maxText")).toString() == QStringLiteral("10240"));
        traffic_controller.setAdvancedFlowFilterSectionEnabled(traffic_section_id, false);
        UI_EXPECT(traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(traffic_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));

        traffic_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!traffic_controller.advancedFlowFilterSectionEnabled(traffic_section_id));
        max_original_row = advanced_filter_metric_row_at(
            traffic_editor->additionalTrafficRows(),
            max_original_packet_size_metric
        );
        UI_EXPECT(max_original_row.value(QStringLiteral("selectedUnit")).toInt()
            == static_cast<int>(TrafficUnit::kib));
        UI_EXPECT(max_original_row.value(QStringLiteral("minText")).toString() == QStringLiteral("10240"));
        traffic_controller.setAdvancedFlowFilterSectionEnabled(traffic_section_id, true);
        UI_EXPECT(traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 0);
        UI_EXPECT(traffic_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));

        traffic_controller.applyAdvancedFlowFilterDocument({});
        traffic_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!traffic_editor->setTrafficUnit(
            max_original_packet_size_metric,
            static_cast<int>(TrafficUnit::gib)));
        UI_EXPECT(traffic_editor->setTrafficUnit(
            max_original_packet_size_metric,
            static_cast<int>(TrafficUnit::kib)));
        traffic_editor->setTrafficMinText(max_original_packet_size_metric, QStringLiteral("5000000"));
        UI_EXPECT(!traffic_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(traffic_controller.advancedFlowFilterEditorValidationText().contains(
            QStringLiteral("Maximum original packet size minimum is too large")));
        UI_EXPECT(traffic_flow_model->visibleFlowCount() == 3);
        traffic_controller.cancelAdvancedFlowFilterEdit();
    });

    run_ui_section("advanced_flow_filter_settings_editor_service", [&]() {
        using ServiceKind = pfl::session_detail::AdvancedFlowFilterServicePredicateKind;

        const auto http_payload = make_http_request_payload();
        const auto dns_payload = make_dns_query_payload();
        const auto service_filter_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_service.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 82, 0, 1), ipv4(10, 82, 0, 2), 51001, 80, http_payload, 0x18)},
                {200U, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 82, 0, 3), ipv4(10, 82, 0, 4), 53000, 53, dns_payload)},
                {300U, make_ethernet_ipv4_tcp_packet_with_payload(
                    ipv4(10, 82, 0, 5), ipv4(10, 82, 0, 6), 54000, 443, 32, 0x18)},
            })
        );

        MainController service_controller {};
        UI_EXPECT(open_capture_and_wait(app, service_controller, service_filter_capture_path));
        auto* service_flow_model = qobject_cast<FlowListModel*>(service_controller.flowModel());
        auto* service_editor = advanced_filter_editor(service_controller);
        UI_REQUIRE(service_flow_model != nullptr);
        UI_REQUIRE(service_editor != nullptr);

        constexpr int service_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::service);
        constexpr auto known_kind = static_cast<int>(ServiceKind::known);
        constexpr auto unknown_kind = static_cast<int>(ServiceKind::unknown);
        constexpr auto equals_kind = static_cast<int>(ServiceKind::equals);
        constexpr auto starts_with_kind = static_cast<int>(ServiceKind::starts_with);

        service_controller.useAdvancedFlowFilter();

        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->addServiceTextRow(false);
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(service_flow_model->visibleFlowCount() == 3);

        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->setServiceStateChecked(false, known_kind, true);
        service_editor->addServiceTextRow(false);
        service_editor->setServiceTextRowText(false, 0, QStringLiteral("ui.example"));
        UI_EXPECT(service_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));
        service_controller.cancelAdvancedFlowFilterEdit();
        UI_EXPECT(service_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));
        UI_EXPECT(service_flow_model->visibleFlowCount() == 3);

        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->setServiceStateChecked(false, known_kind, true);
        UI_EXPECT(service_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) >= 0);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("api.example")) >= 0);

        service_controller.applyAdvancedFlowFilterDocument({});
        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->setServiceStateChecked(false, unknown_kind, true);
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) < 0);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("api.example")) < 0);

        service_controller.applyAdvancedFlowFilterDocument({});
        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->setServiceStateChecked(false, known_kind, true);
        service_editor->addServiceTextRow(false);
        service_editor->setServiceTextRowText(false, 0, QStringLiteral("ui.example"));
        UI_EXPECT(service_editor->serviceTextRulesEditable(false));
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) >= 0);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("api.example")) < 0);

        service_controller.applyAdvancedFlowFilterDocument({});
        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->addServiceTextRow(false);
        service_editor->setServiceTextRowText(false, 0, QStringLiteral("example"));
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) >= 0);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("api.example")) >= 0);

        service_controller.applyAdvancedFlowFilterDocument({});
        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->addServiceTextRow(false);
        service_editor->setServiceTextRowText(false, 0, QStringLiteral("example"));
        service_editor->setServiceStateChecked(false, unknown_kind, true);
        UI_EXPECT(!service_editor->serviceTextRulesEditable(false));
        UI_EXPECT(service_editor->serviceTextRulesEditable(true));
        auto contradictory_include_row = advanced_filter_row_at(service_editor->serviceTextRows(false), 0);
        UI_EXPECT(contradictory_include_row.value(QStringLiteral("text")).toString() == QStringLiteral("example"));
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_controller.advancedFlowFilterEditorValidationText().isEmpty());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 0);
        service_editor->removeServiceTextRow(false, 0);
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) < 0);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("api.example")) < 0);

        service_controller.applyAdvancedFlowFilterDocument({});
        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->addServiceTextRow(false);
        service_editor->setServiceTextRowKind(false, 0, starts_with_kind);
        service_editor->setServiceTextRowText(false, 0, QStringLiteral("ui."));
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) >= 0);

        service_controller.applyAdvancedFlowFilterDocument({});
        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->addServiceTextRow(false);
        service_editor->setServiceTextRowKind(false, 0, equals_kind);
        service_editor->setServiceTextRowText(false, 0, QStringLiteral("API.EXAMPLE"));
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("api.example")) >= 0);

        service_controller.beginAdvancedFlowFilterEdit();
        auto service_include_row = advanced_filter_row_at(service_editor->serviceTextRows(false), 0);
        UI_EXPECT(service_include_row.value(QStringLiteral("kind")).toInt() == equals_kind);
        UI_EXPECT(!service_include_row.value(QStringLiteral("caseSensitive")).toBool());
        service_editor->setServiceTextRowCaseSensitive(false, 0, true);
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 0);

        service_controller.applyAdvancedFlowFilterDocument({});
        service_controller.beginAdvancedFlowFilterEdit();
        service_editor->setServiceStateChecked(true, unknown_kind, true);
        service_editor->addServiceTextRow(true);
        service_editor->setServiceTextRowKind(true, 0, equals_kind);
        service_editor->setServiceTextRowText(true, 0, QStringLiteral("api.example"));
        UI_EXPECT(service_editor->serviceTextRulesEditable(true));
        UI_EXPECT(service_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));
        UI_EXPECT(service_controller.advancedFlowFilterSectionHasExclusions(service_section_id));
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) >= 0);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("api.example")) < 0);

        service_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(service_controller.advancedFlowFilterSectionHasExclusions(service_section_id));
        UI_EXPECT(service_editor->serviceStateChecked(true, unknown_kind));
        auto service_exclude_row = advanced_filter_row_at(service_editor->serviceTextRows(true), 0);
        UI_EXPECT(service_exclude_row.value(QStringLiteral("text")).toString() == QStringLiteral("api.example"));
        service_editor->setServiceTextRowText(true, 0, QStringLiteral("ui.example"));
        service_controller.cancelAdvancedFlowFilterEdit();

        service_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(service_controller.advancedFlowFilterSectionHasExclusions(service_section_id));
        UI_EXPECT(service_editor->serviceStateChecked(true, unknown_kind));
        service_exclude_row = advanced_filter_row_at(service_editor->serviceTextRows(true), 0);
        UI_EXPECT(service_exclude_row.value(QStringLiteral("text")).toString() == QStringLiteral("api.example"));
        service_controller.setAdvancedFlowFilterSectionEnabled(service_section_id, false);
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(service_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));

        service_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!service_controller.advancedFlowFilterSectionEnabled(service_section_id));
        UI_EXPECT(service_editor->serviceStateChecked(true, unknown_kind));
        service_exclude_row = advanced_filter_row_at(service_editor->serviceTextRows(true), 0);
        UI_EXPECT(service_exclude_row.value(QStringLiteral("text")).toString() == QStringLiteral("api.example"));
        service_controller.setAdvancedFlowFilterSectionEnabled(service_section_id, true);
        UI_EXPECT(service_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(service_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_service_hint(service_flow_model, QStringLiteral("ui.example")) >= 0);
    });

    run_ui_section("advanced_flow_filter_settings_editor_protocol_path", [&]() {
        using MatchKind = pfl::session_detail::AdvancedFlowFilterProtocolPathMatchKind;

        constexpr int protocol_path_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::protocol_path);
        const auto selector_capture_path =
            ui_test_root() / "data" / "parsing" / "vxlan" / "10_vxlan_same_inner_tuple_different_vni.pcap";
        const auto applicability_capture_path =
            ui_test_root() / "data" / "parsing" / "vxlan" / "13_vxlan_inner_vlan_ipv4_tcp.pcap";

        MainController protocol_path_editor_controller {};
        UI_EXPECT(open_capture_and_wait(app, protocol_path_editor_controller, selector_capture_path));
        protocol_path_editor_controller.useAdvancedFlowFilter();

        auto* protocol_path_editor_flow_model =
            qobject_cast<FlowListModel*>(protocol_path_editor_controller.flowModel());
        auto* protocol_path_stats_model =
            qobject_cast<ProtocolPathStatsModel*>(protocol_path_editor_controller.protocolPathStatsModel());
        auto* protocol_path_selector =
            qobject_cast<pfl::AdvancedFlowFilterProtocolPathSelectorModel*>(
                protocol_path_editor_controller.advancedFlowFilterProtocolPathSelector());
        auto* protocol_path_selector_stats_model =
            protocol_path_selector != nullptr
                ? qobject_cast<ProtocolPathStatsModel*>(protocol_path_selector->statsModel())
                : nullptr;
        UI_REQUIRE(protocol_path_editor_flow_model != nullptr);
        UI_REQUIRE(protocol_path_stats_model != nullptr);
        UI_REQUIRE(protocol_path_selector != nullptr);
        UI_REQUIRE(protocol_path_selector_stats_model != nullptr);

        auto main_window = load_main_qml_component(protocol_path_editor_controller);
        auto* settings_button = named_object(main_window.object.get(), "advancedFlowFilterSettingsButton");
        auto* advanced_settings_dialog = named_object(main_window.object.get(), "advancedFlowFilterSettingsDialog");
        auto* selector_dialog = named_object(main_window.object.get(), "advancedFlowFilterProtocolPathSelectorDialog");
        UI_REQUIRE(settings_button != nullptr);
        UI_REQUIRE(advanced_settings_dialog != nullptr);
        UI_REQUIRE(selector_dialog != nullptr);

        UI_REQUIRE(QMetaObject::invokeMethod(settings_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return advanced_settings_dialog->property("visible").toBool()
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterProtocolPathSection") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterProtocolPathEnabledCheckBox") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterProtocolPathAddIncludeButton") != nullptr
                && popup_visual_item(advanced_settings_dialog, "advancedFlowFilterProtocolPathExclusionsToggleButton") != nullptr;
        }));

        auto* add_include_button =
            popup_visual_item(advanced_settings_dialog, "advancedFlowFilterProtocolPathAddIncludeButton");
        UI_REQUIRE(add_include_button != nullptr);
        UI_REQUIRE(QMetaObject::invokeMethod(add_include_button, "click"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(wait_until(app, [&]() {
            return selector_dialog->property("visible").toBool()
                && popup_visual_item(selector_dialog, "advancedFlowFilterProtocolPathSelectorListView") != nullptr
                && popup_visual_item(selector_dialog, "advancedFlowFilterProtocolPathKindOverviewModeButton") != nullptr
                && popup_visual_item(selector_dialog, "advancedFlowFilterProtocolPathIdentityTreeModeButton") != nullptr
                && popup_visual_item(selector_dialog, "advancedFlowFilterProtocolPathTerminalPathsModeButton") != nullptr
                && named_object(selector_dialog, "advancedFlowFilterProtocolPathSelectorCancelButton") != nullptr
                && named_object(selector_dialog, "advancedFlowFilterProtocolPathSelectorSelectButton") != nullptr;
        }));
        protocol_path_selector->setMode(static_cast<int>(ProtocolPathStatisticsMode::identity_tree));
        const auto selector_identity_row = find_protocol_path_stats_row_by_path_text(
            protocol_path_selector_stats_model,
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4"));
        UI_REQUIRE(selector_identity_row >= 0);
        const auto selector_identity_node_id = protocol_path_selector_stats_model->data(
            protocol_path_selector_stats_model->index(selector_identity_row, 0),
            ProtocolPathStatsModel::NodeIdRole).toULongLong();
        protocol_path_selector->selectNode(selector_identity_node_id);
        UI_EXPECT(protocol_path_selector->selectionAvailable());
        UI_REQUIRE(QMetaObject::invokeMethod(selector_dialog, "tryAcceptSelection"));
        UI_EXPECT(wait_until(app, [&]() {
            return !selector_dialog->property("visible").toBool();
        }));
        auto selector_include_row = advanced_filter_row_at(
            protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(false),
            0);
        UI_EXPECT(selector_include_row.value(QStringLiteral("mode")).toInt()
            == static_cast<int>(ProtocolPathStatisticsMode::identity_tree));
        UI_EXPECT(selector_include_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("200")));
        UI_REQUIRE(QMetaObject::invokeMethod(advanced_settings_dialog, "close"));
        app.processEvents(QEventLoop::AllEvents, 25);

        const int protocol_path_statistics_section =
            static_cast<int>(MainController::StatisticsOptionalSection::protocol_path);
        protocol_path_editor_controller.setCurrentTabIndex(2);
        protocol_path_editor_controller.setStatisticsSectionExpanded(protocol_path_statistics_section, true);
        protocol_path_editor_controller.setStatisticsMode(1);
        protocol_path_stats_model->expandAll();
        const auto baseline_identity_row = find_protocol_path_stats_row_by_path_text(
            protocol_path_stats_model,
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)"));
        UI_REQUIRE(baseline_identity_row >= 0);
        const auto baseline_identity_node_id = protocol_path_stats_model->data(
            protocol_path_stats_model->index(baseline_identity_row, 0),
            ProtocolPathStatsModel::NodeIdRole).toULongLong();
        protocol_path_stats_model->selectNode(baseline_identity_node_id);
        const auto baseline_statistics_mode = protocol_path_editor_controller.statisticsMode();
        const auto baseline_statistics_row_count = protocol_path_stats_model->rowCount();
        UI_EXPECT(protocol_path_stats_model->selectedNodeId() == baseline_identity_node_id);

        protocol_path_editor_controller.beginAdvancedFlowFilterEdit();

        protocol_path_editor_controller.beginAdvancedFlowFilterProtocolPathSelection(false, -1);
        protocol_path_selector->setMode(static_cast<int>(ProtocolPathStatisticsMode::kind_overview));
        const auto kind_vxlan_row = find_protocol_path_stats_row_by_path_text(
            protocol_path_selector_stats_model,
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN"));
        UI_REQUIRE(kind_vxlan_row >= 0);
        const auto kind_vxlan_node_id = protocol_path_selector_stats_model->data(
            protocol_path_selector_stats_model->index(kind_vxlan_row, 0),
            ProtocolPathStatsModel::NodeIdRole).toULongLong();
        protocol_path_selector->selectNode(kind_vxlan_node_id);
        const auto kind_predicate = protocol_path_selector->selectedPredicate();
        UI_REQUIRE(kind_predicate.has_value());
        UI_EXPECT(kind_predicate->match_kind == MatchKind::path_prefix);
        UI_EXPECT(!protocol_path_layers_have_identifiers(kind_predicate->layers));
        UI_EXPECT(protocol_path_editor_controller.applyAdvancedFlowFilterProtocolPathSelection());
        auto include_row = advanced_filter_row_at(
            protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(false),
            0);
        UI_EXPECT(include_row.value(QStringLiteral("mode")).toInt()
            == static_cast<int>(ProtocolPathStatisticsMode::kind_overview));
        UI_EXPECT(include_row.value(QStringLiteral("modeLabel")).toString() == QStringLiteral("Kind"));
        UI_EXPECT(include_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("VXLAN")));
        UI_EXPECT(!include_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("VNI")));
        UI_EXPECT(!include_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("200")));
        UI_EXPECT(include_row.value(QStringLiteral("statusText")).toString().isEmpty());
        UI_EXPECT(protocol_path_editor_controller.statisticsMode() == baseline_statistics_mode);
        UI_EXPECT(protocol_path_stats_model->selectedNodeId() == baseline_identity_node_id);
        UI_EXPECT(protocol_path_stats_model->rowCount() == baseline_statistics_row_count);

        protocol_path_editor_controller.beginAdvancedFlowFilterProtocolPathSelection(false, 0);
        UI_EXPECT(protocol_path_selector->mode() == static_cast<int>(ProtocolPathStatisticsMode::kind_overview));
        protocol_path_selector->setMode(static_cast<int>(ProtocolPathStatisticsMode::identity_tree));
        const auto identity_vni_200_row = find_protocol_path_stats_row_by_path_text(
            protocol_path_selector_stats_model,
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4"));
        UI_REQUIRE(identity_vni_200_row >= 0);
        const auto identity_vni_200_node_id = protocol_path_selector_stats_model->data(
            protocol_path_selector_stats_model->index(identity_vni_200_row, 0),
            ProtocolPathStatsModel::NodeIdRole).toULongLong();
        protocol_path_selector->selectNode(identity_vni_200_node_id);
        const auto identity_predicate = protocol_path_selector->selectedPredicate();
        UI_REQUIRE(identity_predicate.has_value());
        UI_EXPECT(identity_predicate->match_kind == MatchKind::path_prefix);
        UI_EXPECT(protocol_path_layers_have_identifiers(identity_predicate->layers));
        const auto* identity_vxlan_layer =
            find_protocol_path_predicate_layer(*identity_predicate, pfl::ProtocolLayerKind::vxlan);
        UI_REQUIRE(identity_vxlan_layer != nullptr);
        UI_REQUIRE(identity_vxlan_layer->identifier.has_value());
        UI_EXPECT(identity_vxlan_layer->identifier->kind == pfl::ProtocolLayerIdentifierKind::vxlan_vni);
        UI_EXPECT(identity_vxlan_layer->identifier->value == 200U);
        UI_EXPECT(protocol_path_editor_controller.applyAdvancedFlowFilterProtocolPathSelection());
        include_row = advanced_filter_row_at(
            protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(false),
            0);
        UI_EXPECT(include_row.value(QStringLiteral("mode")).toInt()
            == static_cast<int>(ProtocolPathStatisticsMode::identity_tree));
        UI_EXPECT(include_row.value(QStringLiteral("modeLabel")).toString() == QStringLiteral("Identity"));
        UI_EXPECT(include_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("VXLAN")));
        UI_EXPECT(include_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("VNI")));
        UI_EXPECT(include_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("200")));
        UI_EXPECT(include_row.value(QStringLiteral("statusText")).toString().isEmpty());

        protocol_path_editor_controller.beginAdvancedFlowFilterProtocolPathSelection(false, 0);
        UI_EXPECT(protocol_path_selector->mode() == static_cast<int>(ProtocolPathStatisticsMode::identity_tree));

        protocol_path_editor_controller.beginAdvancedFlowFilterProtocolPathSelection(true, -1);
        protocol_path_selector->setMode(static_cast<int>(ProtocolPathStatisticsMode::terminal_paths));
        const auto terminal_vni_100_row = find_protocol_path_stats_row_by_path_text(
            protocol_path_selector_stats_model,
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"));
        UI_REQUIRE(terminal_vni_100_row >= 0);
        const auto terminal_vni_100_node_id = protocol_path_selector_stats_model->data(
            protocol_path_selector_stats_model->index(terminal_vni_100_row, 0),
            ProtocolPathStatsModel::NodeIdRole).toULongLong();
        protocol_path_selector->selectNode(terminal_vni_100_node_id);
        const auto terminal_predicate = protocol_path_selector->selectedPredicate();
        UI_REQUIRE(terminal_predicate.has_value());
        UI_EXPECT(terminal_predicate->match_kind == MatchKind::exact_path);
        UI_EXPECT(protocol_path_layers_have_identifiers(terminal_predicate->layers));
        UI_EXPECT(protocol_path_editor_controller.applyAdvancedFlowFilterProtocolPathSelection());
        auto exclude_row = advanced_filter_row_at(
            protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(true),
            0);
        UI_EXPECT(exclude_row.value(QStringLiteral("mode")).toInt()
            == static_cast<int>(ProtocolPathStatisticsMode::terminal_paths));
        UI_EXPECT(exclude_row.value(QStringLiteral("modeLabel")).toString() == QStringLiteral("Terminal"));
        UI_EXPECT(exclude_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("VXLAN")));
        UI_EXPECT(exclude_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("VNI")));
        UI_EXPECT(exclude_row.value(QStringLiteral("compactText")).toString().contains(QStringLiteral("100")));
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterSectionHasExclusions(protocol_path_section_id));

        UI_EXPECT(protocol_path_editor_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(protocol_path_editor_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(protocol_path_editor_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));
        UI_EXPECT(protocol_path_editor_flow_model->rowCount() == 1);
        const auto visible_protocol_path_index = protocol_path_editor_flow_model->index(0, 0);
        UI_EXPECT(
            protocol_path_editor_flow_model->data(visible_protocol_path_index, FlowListModel::ProtocolPathTextRole)
                .toString() ==
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP"));

        protocol_path_editor_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterSectionEnabled(protocol_path_section_id));
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterSectionHasExclusions(protocol_path_section_id));
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(false).size() == 1);
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(true).size() == 1);
        protocol_path_editor_controller.setAdvancedFlowFilterSectionEnabled(protocol_path_section_id, false);
        UI_EXPECT(protocol_path_editor_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(!protocol_path_editor_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(protocol_path_editor_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterRuleCountText() == QStringLiteral("0 rules"));

        protocol_path_editor_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!protocol_path_editor_controller.advancedFlowFilterSectionEnabled(protocol_path_section_id));
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(false).size() == 1);
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(true).size() == 1);
        protocol_path_editor_controller.setAdvancedFlowFilterSectionEnabled(protocol_path_section_id, true);
        protocol_path_editor_controller.removeAdvancedFlowFilterProtocolPathRow(true, 0);
        UI_EXPECT(!protocol_path_editor_controller.advancedFlowFilterSectionHasExclusions(protocol_path_section_id));
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        protocol_path_editor_controller.cancelAdvancedFlowFilterEdit();

        protocol_path_editor_controller.beginAdvancedFlowFilterEdit();
        UI_EXPECT(!protocol_path_editor_controller.advancedFlowFilterSectionEnabled(protocol_path_section_id));
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(true).size() == 1);
        protocol_path_editor_controller.setAdvancedFlowFilterSectionEnabled(protocol_path_section_id, true);
        protocol_path_editor_controller.removeAdvancedFlowFilterProtocolPathRow(true, 0);
        UI_EXPECT(protocol_path_editor_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(protocol_path_editor_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));

        UI_EXPECT(open_capture_and_wait(app, protocol_path_editor_controller, applicability_capture_path));
        UI_EXPECT(protocol_path_editor_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::advanced));
        UI_EXPECT(protocol_path_editor_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(protocol_path_editor_flow_model->visibleFlowCount() == 0);
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));
        UI_EXPECT(protocol_path_editor_controller.advancedFlowFilterDisplayName() == QStringLiteral("Custom filter"));

        protocol_path_editor_controller.beginAdvancedFlowFilterEdit();
        include_row = advanced_filter_row_at(
            protocol_path_editor_controller.advancedFlowFilterProtocolPathRows(false),
            0);
        UI_EXPECT(include_row.value(QStringLiteral("mode")).toInt()
            == static_cast<int>(ProtocolPathStatisticsMode::identity_tree));
        UI_EXPECT(include_row.value(QStringLiteral("statusText")).toString()
            == QStringLiteral("Not present in current capture"));
        protocol_path_editor_controller.cancelAdvancedFlowFilterEdit();
    });

    run_ui_section("advanced_flow_filter_settings_editor_contains_layer", [&]() {
        using MatchKind = pfl::session_detail::AdvancedFlowFilterProtocolPathMatchKind;
        using IdentifierMode = pfl::AdvancedFlowFilterEditorModel::AdvancedFlowFilterContainsLayerIdentifierMode;

        constexpr int contains_layer_section_id =
            static_cast<int>(MainController::AdvancedFlowFilterFiniteSection::contains_layer);
        const auto selector_capture_path =
            ui_test_root() / "data" / "parsing" / "vxlan" / "10_vxlan_same_inner_tuple_different_vni.pcap";
        const auto applicability_capture_path =
            ui_test_root() / "data" / "parsing" / "vxlan" / "13_vxlan_inner_vlan_ipv4_tcp.pcap";

        MainController contains_layer_controller {};
        UI_EXPECT(open_capture_and_wait(app, contains_layer_controller, selector_capture_path));
        contains_layer_controller.useAdvancedFlowFilter();

        auto* contains_layer_flow_model = qobject_cast<FlowListModel*>(contains_layer_controller.flowModel());
        auto* contains_layer_editor = advanced_filter_editor(contains_layer_controller);
        UI_REQUIRE(contains_layer_flow_model != nullptr);
        UI_REQUIRE(contains_layer_editor != nullptr);

        UI_EXPECT(contains_layer_controller.advancedFlowFilterSectionEnabled(contains_layer_section_id));
        UI_EXPECT(!contains_layer_controller.advancedFlowFilterSectionHasExclusions(contains_layer_section_id));
        UI_EXPECT(contains_layer_editor->containsLayerRows(false).isEmpty());
        UI_EXPECT(!contains_layer_editor->containsLayerOptions().isEmpty());
        UI_EXPECT(contains_layer_editor->containsLayerIdentifierModeOptions().size() == 2);
        {
            QStringList option_labels {};
            for (const auto& option : contains_layer_editor->containsLayerOptions()) {
                option_labels.push_back(option.toMap().value(QStringLiteral("label")).toString());
            }
            UI_EXPECT(option_labels.contains(QStringLiteral("VLAN")));
            UI_EXPECT(option_labels.contains(QStringLiteral("VXLAN")));
            UI_EXPECT(option_labels.contains(QStringLiteral("GTP-U")));
            UI_EXPECT(!option_labels.contains(QStringLiteral("TCP")));
            UI_EXPECT(!option_labels.contains(QStringLiteral("IPv4")));
            UI_EXPECT(!option_labels.contains(QStringLiteral("Ethernet II")));
        }

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        contains_layer_editor->addContainsLayerRow(false);
        auto include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        UI_EXPECT(include_row.value(QStringLiteral("identifierMode")).toInt()
            == static_cast<int>(IdentifierMode::any));
        UI_EXPECT(include_row.value(QStringLiteral("exactValueText")).toString().isEmpty());
        UI_EXPECT(include_row.value(QStringLiteral("layerLabel")).toString() == QStringLiteral("VLAN"));
        contains_layer_editor->setContainsLayerRowKind(false, 0, static_cast<int>(pfl::ProtocolLayerKind::vxlan));
        include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        UI_EXPECT(include_row.value(QStringLiteral("layerLabel")).toString() == QStringLiteral("VXLAN"));
        UI_EXPECT(include_row.value(QStringLiteral("identifierLabel")).toString() == QStringLiteral("VNI"));
        UI_EXPECT(include_row.value(QStringLiteral("exactValuePlaceholder")).toString() == QStringLiteral("200"));
        UI_EXPECT(include_row.value(QStringLiteral("compactText")).toString() == QStringLiteral("VXLAN / Any"));
        UI_EXPECT(include_row.value(QStringLiteral("statusText")).toString().isEmpty());
        UI_EXPECT(contains_layer_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(visible_flow_protocol_paths(contains_layer_flow_model).contains(
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP")));
        UI_EXPECT(visible_flow_protocol_paths(contains_layer_flow_model).contains(
            QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP")));

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        contains_layer_editor->setContainsLayerRowIdentifierMode(false, 0, static_cast<int>(IdentifierMode::exact));
        contains_layer_editor->setContainsLayerRowExactValueText(false, 0, QStringLiteral("200"));
        include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        UI_EXPECT(include_row.value(QStringLiteral("exactValueText")).toString() == QStringLiteral("200"));
        UI_EXPECT(include_row.value(QStringLiteral("compactText")).toString() == QStringLiteral("VXLAN / VNI 200"));
        contains_layer_editor->setContainsLayerRowIdentifierMode(false, 0, static_cast<int>(IdentifierMode::any));
        UI_EXPECT(advanced_filter_row_at(
            contains_layer_editor->containsLayerRows(false),
            0
        ).value(QStringLiteral("exactValueText")).toString() == QStringLiteral("200"));
        contains_layer_editor->setContainsLayerRowIdentifierMode(false, 0, static_cast<int>(IdentifierMode::exact));
        include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        UI_EXPECT(include_row.value(QStringLiteral("exactValueText")).toString() == QStringLiteral("200"));
        contains_layer_editor->setContainsLayerRowExactValueText(false, 0, QStringLiteral(""));
        UI_EXPECT(!contains_layer_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(contains_layer_controller.advancedFlowFilterEditorValidationText().contains(QStringLiteral("value is required")));
        contains_layer_editor->setContainsLayerRowExactValueText(false, 0, QStringLiteral("0x1000000"));
        UI_EXPECT(!contains_layer_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(contains_layer_controller.advancedFlowFilterEditorValidationText().contains(QStringLiteral("out of range")));
        contains_layer_editor->setContainsLayerRowExactValueText(false, 0, QStringLiteral("200"));
        UI_EXPECT(contains_layer_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(visible_flow_protocol_paths(contains_layer_flow_model).first()
            == QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP"));
        UI_EXPECT(contains_layer_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        contains_layer_editor->setContainsLayerRowKind(false, 0, static_cast<int>(pfl::ProtocolLayerKind::geneve));
        contains_layer_editor->setContainsLayerRowIdentifierMode(false, 0, static_cast<int>(IdentifierMode::any));
        contains_layer_editor->addContainsLayerRow(true);
        contains_layer_editor->setContainsLayerRowKind(true, 0, static_cast<int>(pfl::ProtocolLayerKind::vxlan));
        contains_layer_editor->setContainsLayerRowIdentifierMode(true, 0, static_cast<int>(IdentifierMode::exact));
        contains_layer_editor->setContainsLayerRowExactValueText(true, 0, QStringLiteral("100"));
        contains_layer_controller.cancelAdvancedFlowFilterEdit();

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        UI_EXPECT(include_row.value(QStringLiteral("layerLabel")).toString() == QStringLiteral("VXLAN"));
        UI_EXPECT(include_row.value(QStringLiteral("identifierMode")).toInt()
            == static_cast<int>(IdentifierMode::exact));
        UI_EXPECT(include_row.value(QStringLiteral("exactValueText")).toString() == QStringLiteral("200"));
        UI_EXPECT(!contains_layer_controller.advancedFlowFilterSectionHasExclusions(contains_layer_section_id));
        contains_layer_controller.cancelAdvancedFlowFilterEdit();

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        contains_layer_editor->setContainsLayerRowIdentifierMode(false, 0, static_cast<int>(IdentifierMode::any));
        contains_layer_editor->addContainsLayerRow(true);
        contains_layer_editor->setContainsLayerRowKind(true, 0, static_cast<int>(pfl::ProtocolLayerKind::vxlan));
        contains_layer_editor->setContainsLayerRowIdentifierMode(true, 0, static_cast<int>(IdentifierMode::exact));
        contains_layer_editor->setContainsLayerRowExactValueText(true, 0, QStringLiteral("100"));
        UI_EXPECT(contains_layer_controller.advancedFlowFilterSectionHasExclusions(contains_layer_section_id));
        UI_EXPECT(contains_layer_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(visible_flow_protocol_paths(contains_layer_flow_model).first().contains(QStringLiteral("VXLAN(vni=200)")));
        UI_EXPECT(contains_layer_controller.advancedFlowFilterRuleCountText() == QStringLiteral("2 rules"));

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        auto exclude_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(true), 0);
        UI_EXPECT(include_row.value(QStringLiteral("statusText")).toString().isEmpty());
        UI_EXPECT(exclude_row.value(QStringLiteral("statusText")).toString().isEmpty());
        contains_layer_controller.cancelAdvancedFlowFilterEdit();

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        contains_layer_editor->removeContainsLayerRow(true, 0);
        contains_layer_editor->setContainsLayerRowIdentifierMode(false, 0, static_cast<int>(IdentifierMode::exact));
        contains_layer_editor->setContainsLayerRowExactValueText(false, 0, QStringLiteral("200"));
        UI_EXPECT(contains_layer_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(open_capture_and_wait(app, contains_layer_controller, applicability_capture_path));
        UI_EXPECT(contains_layer_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::advanced));
        UI_EXPECT(contains_layer_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 0);

        contains_layer_controller.beginAdvancedFlowFilterEdit();
        include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        UI_EXPECT(include_row.value(QStringLiteral("statusText")).toString()
            == QStringLiteral("Not present in current capture"));
        contains_layer_editor->setContainsLayerRowIdentifierMode(false, 0, static_cast<int>(IdentifierMode::any));
        include_row = advanced_filter_row_at(contains_layer_editor->containsLayerRows(false), 0);
        UI_EXPECT(include_row.value(QStringLiteral("statusText")).toString().isEmpty());
        UI_EXPECT(contains_layer_controller.applyAdvancedFlowFilterEdit());
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 1);

        auto exact_vni_100_prefix = pfl::session_detail::AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = MatchKind::path_prefix,
            .layers = {
                {.kind = pfl::ProtocolLayerKind::ethernet_ii, .identifier = std::nullopt},
                {.kind = pfl::ProtocolLayerKind::ipv4, .identifier = std::nullopt},
                {.kind = pfl::ProtocolLayerKind::udp, .identifier = std::nullopt},
                {.kind = pfl::ProtocolLayerKind::vxlan,
                 .identifier = pfl::ProtocolLayerIdentifier {
                     .kind = pfl::ProtocolLayerIdentifierKind::vxlan_vni,
                     .value = 100U,
                 }},
                {.kind = pfl::ProtocolLayerKind::ethernet_ii, .identifier = std::nullopt},
                {.kind = pfl::ProtocolLayerKind::ipv4, .identifier = std::nullopt},
            },
        };
        auto contains_vni_200 = pfl::session_detail::AdvancedFlowFilterProtocolPathPredicate {
            .match_kind = MatchKind::contains_layer,
            .layers = {{
                .kind = pfl::ProtocolLayerKind::vxlan,
                .identifier = pfl::ProtocolLayerIdentifier {
                    .kind = pfl::ProtocolLayerIdentifierKind::vxlan_vni,
                    .value = 200U,
                },
            }},
        };
        pfl::session_detail::AdvancedFlowFilterDocument independence_document {};
        independence_document.configured_spec.protocol_path.include.push_back(exact_vni_100_prefix);
        independence_document.configured_spec.protocol_path.include.push_back(contains_vni_200);

        UI_EXPECT(open_capture_and_wait(app, contains_layer_controller, selector_capture_path));
        contains_layer_controller.applyAdvancedFlowFilterDocument(independence_document);
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 0);

        independence_document.section_states.protocol_path = false;
        independence_document.section_states.contains_layer = true;
        contains_layer_controller.applyAdvancedFlowFilterDocument(independence_document);
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(visible_flow_protocol_paths(contains_layer_flow_model).first().contains(QStringLiteral("VXLAN(vni=200)")));

        independence_document.section_states.protocol_path = true;
        independence_document.section_states.contains_layer = false;
        contains_layer_controller.applyAdvancedFlowFilterDocument(independence_document);
        UI_EXPECT(contains_layer_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(visible_flow_protocol_paths(contains_layer_flow_model).first().contains(QStringLiteral("VXLAN(vni=100)")));
    });

    run_ui_section("advanced_flow_filter_controller_execution", [&]() {
        const auto ipv6_udp_flow_packet = make_ethernet_ipv6_udp_with_hop_by_hop_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
            54000,
            443
        );
        const auto advanced_filter_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_execution.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 61, 0, 1), ipv4(10, 61, 0, 2), 51001, 80)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 61, 0, 3), ipv4(10, 61, 0, 4), 53000, 53)},
                {300U, ipv6_udp_flow_packet},
            })
        );
        const auto advanced_filter_reopen_capture_path = write_temp_pcap(
            "pfl_ui_advanced_filter_reopen.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 62, 0, 1), ipv4(10, 62, 0, 2), 54001, 443)},
            })
        );

        MainController advanced_execution_controller {};
        UI_EXPECT(open_capture_and_wait(app, advanced_execution_controller, advanced_filter_capture_path));
        auto* advanced_execution_flow_model = qobject_cast<FlowListModel*>(advanced_execution_controller.flowModel());
        auto* advanced_execution_stats_model =
            qobject_cast<ProtocolPathStatsModel*>(advanced_execution_controller.protocolPathStatsModel());
        UI_REQUIRE(advanced_execution_flow_model != nullptr);
        UI_REQUIRE(advanced_execution_stats_model != nullptr);
        UI_EXPECT(advanced_execution_flow_model->totalFlowCount() == 3);
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!advanced_execution_flow_model->hasAdvancedFlowIndexFilter());

        advanced_execution_controller.useAdvancedFlowFilter();
        UI_EXPECT(advanced_execution_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::advanced));
        UI_EXPECT(!advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!advanced_execution_flow_model->hasActiveFlowFilter());

        advanced_execution_controller.applyAdvancedFlowFilterDocument(
            make_address_family_advanced_document(FlowAddressFamily::ipv6)
        );
        UI_EXPECT(advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv6")) >= 0);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv4")) < 0);
        UI_EXPECT(advanced_execution_controller.advancedFlowFilterRuleCountText() == QStringLiteral("1 rule"));

        advanced_execution_controller.applyAdvancedFlowFilterDocument(
            make_flow_protocol_advanced_document(ProtocolId::udp)
        );
        UI_EXPECT(advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(advanced_execution_flow_model->hasActiveFlowFilter());
        UI_EXPECT(find_flow_index_by_protocol(advanced_execution_flow_model, QStringLiteral("UDP")) >= 0);
        UI_EXPECT(find_flow_index_by_protocol(advanced_execution_flow_model, QStringLiteral("TCP")) < 0);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv6")) >= 0);

        advanced_execution_controller.setFlowFilterText(QStringLiteral("53000"));
        UI_EXPECT(advanced_execution_controller.flowFilterText() == QStringLiteral("53000"));
        UI_EXPECT(advanced_execution_flow_model->filterText().isEmpty());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_protocol(advanced_execution_flow_model, QStringLiteral("TCP")) < 0);

        advanced_execution_controller.useSimpleFlowFilter();
        UI_EXPECT(advanced_execution_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::simple));
        UI_EXPECT(advanced_execution_flow_model->filterText() == QStringLiteral("53000"));
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv4")) >= 0);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv6")) < 0);
        UI_EXPECT(!advanced_execution_flow_model->hasAdvancedFlowIndexFilter());

        advanced_execution_controller.useAdvancedFlowFilter();
        UI_EXPECT(advanced_execution_flow_model->filterText().isEmpty());
        UI_EXPECT(advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_protocol(advanced_execution_flow_model, QStringLiteral("TCP")) < 0);

        advanced_execution_controller.applyAdvancedFlowFilterDocument(
            make_disabled_flow_protocol_advanced_document(ProtocolId::udp)
        );
        UI_EXPECT(!advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 3);
        UI_EXPECT(!advanced_execution_flow_model->hasActiveFlowFilter());

        advanced_execution_controller.applyAdvancedFlowFilterDocument(
            make_flow_protocol_advanced_document(ProtocolId::udp)
        );
        const int selected_ipv6_flow_index = find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv6"));
        UI_REQUIRE(selected_ipv6_flow_index >= 0);
        advanced_execution_controller.setSelectedFlowIndex(selected_ipv6_flow_index);
        UI_EXPECT(advanced_execution_controller.selectedFlowIndex() == selected_ipv6_flow_index);
        advanced_execution_controller.setCurrentTabIndex(2);
        advanced_execution_controller.setStatisticsSectionExpanded(protocol_path_section, true);
        advanced_execution_stats_model->expandAll();
        const auto ipv4_row = find_protocol_path_stats_row_by_path_text(
            advanced_execution_stats_model,
            QStringLiteral("EthernetII -> IPv4")
        );
        UI_REQUIRE(ipv4_row >= 0);
        const auto ipv4_node_id = advanced_execution_stats_model->data(
            advanced_execution_stats_model->index(ipv4_row, 0),
            ProtocolPathStatsModel::NodeIdRole
        ).toULongLong();
        advanced_execution_stats_model->selectNode(ipv4_node_id);
        advanced_execution_controller.showSelectedProtocolPathFlows();
        UI_EXPECT(advanced_execution_controller.hasProtocolPathFlowFilter());
        UI_EXPECT(advanced_execution_flow_model->hasAllowedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 1);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv4")) >= 0);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv6")) < 0);
        UI_EXPECT(advanced_execution_controller.selectedFlowIndex() == -1);

        advanced_execution_controller.clearProtocolPathFlowFilter();
        UI_EXPECT(!advanced_execution_controller.hasProtocolPathFlowFilter());
        UI_EXPECT(!advanced_execution_flow_model->hasAllowedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 2);
        UI_EXPECT(find_flow_index_by_family(advanced_execution_flow_model, QStringLiteral("IPv6")) >= 0);

        UI_EXPECT(open_capture_and_wait(app, advanced_execution_controller, advanced_filter_reopen_capture_path));
        UI_EXPECT(advanced_execution_controller.flowFilterMode()
            == static_cast<int>(MainController::FlowFilterMode::advanced));
        UI_EXPECT(advanced_execution_controller.flowFilterText() == QStringLiteral("53000"));
        UI_EXPECT(advanced_execution_flow_model->filterText().isEmpty());
        UI_EXPECT(advanced_execution_flow_model->totalFlowCount() == 1);
        UI_EXPECT(advanced_execution_flow_model->visibleFlowCount() == 0);
        UI_EXPECT(advanced_execution_flow_model->hasAdvancedFlowIndexFilter());
        UI_EXPECT(advanced_execution_flow_model->hasActiveFlowFilter());
        UI_EXPECT(advanced_execution_flow_model->filteredFlowCountText() == QStringLiteral("Filtered to 0 of 1 flows."));
    });

    protocol_path_and_text_controller.setStatisticsMode(0);
    protocol_path_and_text_stats_model->expandAll();
    const auto kind_vxlan_row = find_protocol_path_stats_row_by_path_text(
        protocol_path_and_text_stats_model,
        QStringLiteral("EthernetII -> IPv4 -> UDP -> VXLAN")
    );
    UI_REQUIRE(kind_vxlan_row >= 0);
    const auto kind_vxlan_node_id = protocol_path_and_text_stats_model->data(
        protocol_path_and_text_stats_model->index(kind_vxlan_row, 0),
        ProtocolPathStatsModel::NodeIdRole
    ).toULongLong();
    protocol_path_and_text_stats_model->selectNode(kind_vxlan_node_id);
    protocol_path_and_text_controller.showSelectedProtocolPathFlows();
    UI_EXPECT(protocol_path_and_text_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->rowCount() == 2);
    UI_EXPECT(protocol_path_and_text_flow_model->hasActiveFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 2);
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText() == QStringLiteral("Filtered to 2 of 2 flows."));
    UI_EXPECT((protocol_path_and_text_flow_model->visibleFlowIndices() == std::vector<int> {0, 1}));
    UI_EXPECT(wait_until(app, [&]() {
        auto* label = named_object(protocol_path_and_text_flow_table.object.get(), "flowFilterStatusLabel");
        return label != nullptr &&
            label->property("visible").toBool() &&
            label->property("text").toString() == QStringLiteral("Filtered to 2 of 2 flows.");
    }));

    protocol_path_and_text_controller.setSelectedFlowIndex(1);
    UI_EXPECT(protocol_path_and_text_controller.selectedFlowIndex() == 1);
    protocol_path_and_text_controller.setFlowFilterText(QStringLiteral("10001"));
    UI_EXPECT(protocol_path_and_text_controller.flowFilterText() == QStringLiteral("10001"));
    UI_EXPECT(protocol_path_and_text_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->rowCount() == 1);
    UI_EXPECT(protocol_path_and_text_flow_model->totalFlowCount() == 2);
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 1);
    UI_EXPECT(protocol_path_and_text_flow_model->hasActiveFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));
    UI_EXPECT((protocol_path_and_text_flow_model->visibleFlowIndices() == std::vector<int> {0}));
    UI_EXPECT(protocol_path_and_text_controller.selectedFlowIndex() == -1);
    UI_EXPECT(wait_until(app, [&]() {
        auto* label = named_object(protocol_path_and_text_flow_table.object.get(), "flowFilterStatusLabel");
        return label != nullptr &&
            label->property("visible").toBool() &&
            label->property("text").toString() == QStringLiteral("Filtered to 1 of 2 flows.");
    }));

    protocol_path_and_text_controller.sortFlows(3);
    UI_EXPECT(protocol_path_and_text_flow_model->totalFlowCount() == 2);
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 1);
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

    protocol_path_and_text_controller.setFlowFilterText(QStringLiteral("no-such-flow"));
    UI_EXPECT(protocol_path_and_text_controller.flowFilterText() == QStringLiteral("no-such-flow"));
    UI_EXPECT(protocol_path_and_text_flow_model->rowCount() == 0);
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 0);
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));
    UI_EXPECT(wait_until(app, [&]() {
        auto* label = named_object(protocol_path_and_text_flow_table.object.get(), "flowFilterStatusLabel");
        return label != nullptr &&
            label->property("visible").toBool() &&
            label->property("text").toString() == QStringLiteral("Filtered to 0 of 2 flows.");
    }));

    protocol_path_and_text_controller.setFlowFilterText(QStringLiteral("10001"));

    protocol_path_and_text_controller.clearProtocolPathFlowFilter();
    UI_EXPECT(!protocol_path_and_text_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_and_text_controller.flowFilterText() == QStringLiteral("10001"));
    UI_EXPECT(protocol_path_and_text_flow_model->rowCount() == 1);
    UI_EXPECT(protocol_path_and_text_flow_model->hasActiveFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 1);
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));
    UI_EXPECT((protocol_path_and_text_flow_model->visibleFlowIndices() == std::vector<int> {0}));

    protocol_path_and_text_controller.setFlowFilterText(QString());
    UI_EXPECT(protocol_path_and_text_controller.flowFilterText().isEmpty());
    UI_EXPECT(protocol_path_and_text_flow_model->rowCount() == 2);
    UI_EXPECT(!protocol_path_and_text_flow_model->hasActiveFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 2);
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText().isEmpty());
    UI_EXPECT(wait_until(app, [&]() {
        auto* label = named_object(protocol_path_and_text_flow_table.object.get(), "flowFilterStatusLabel");
        return label != nullptr && !label->property("visible").toBool();
    }));

    protocol_path_filter_controller.showSelectedProtocolPathFlows();
    UI_EXPECT(protocol_path_filter_controller.hasProtocolPathFlowFilter());
    protocol_path_filter_controller.useAdvancedFlowFilter();
    UI_EXPECT(protocol_path_filter_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_filter_flow_model->rowCount() == 1);
    protocol_path_filter_controller.useSimpleFlowFilter();
    UI_EXPECT(protocol_path_filter_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_filter_flow_model->rowCount() == 1);
    UI_EXPECT(open_capture_and_wait(app, protocol_path_filter_controller, protocol_path_capture_path));
    UI_EXPECT(!protocol_path_filter_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_filter_controller.protocolPathFlowFilterText().isEmpty());

    protocol_path_and_text_controller.setFlowFilterText(QStringLiteral("10001"));
    UI_EXPECT(protocol_path_and_text_controller.flowFilterText() == QStringLiteral("10001"));
    protocol_path_and_text_controller.showSelectedProtocolPathFlows();
    UI_EXPECT(protocol_path_and_text_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(open_capture_and_wait(app, protocol_path_and_text_controller, protocol_path_capture_path));
    UI_EXPECT(!protocol_path_and_text_controller.hasProtocolPathFlowFilter());
    UI_EXPECT(protocol_path_and_text_controller.flowFilterText() == QStringLiteral("10001"));
    UI_EXPECT(protocol_path_and_text_flow_model->totalFlowCount() == 1);
    UI_EXPECT(protocol_path_and_text_flow_model->visibleFlowCount() == 0);
    UI_EXPECT(protocol_path_and_text_flow_model->hasActiveFlowFilter());
    UI_EXPECT(protocol_path_and_text_flow_model->filteredFlowCountText() == QStringLiteral("Filtered to 0 of 1 flows."));
    UI_EXPECT(wait_until(app, [&]() {
        auto* label = named_object(protocol_path_and_text_flow_table.object.get(), "flowFilterStatusLabel");
        return label != nullptr &&
            label->property("visible").toBool() &&
            label->property("text").toString() == QStringLiteral("Filtered to 0 of 1 flows.");
    }));

    MainController unrecognized_filter_controller {};
    UI_EXPECT(open_capture_and_wait(app, unrecognized_filter_controller, nonzero_unrecognized_capture_path));
    auto* unrecognized_filter_flow_model = qobject_cast<FlowListModel*>(unrecognized_filter_controller.flowModel());
    UI_REQUIRE(unrecognized_filter_flow_model != nullptr);
    UI_EXPECT(unrecognized_filter_controller.unrecognizedPacketCount() > 0U);
    UI_EXPECT(unrecognized_filter_flow_model->totalFlowCount() ==
        static_cast<int>(unrecognized_filter_controller.flowCount()));
    unrecognized_filter_controller.setFlowFilterText(QStringLiteral("UDP"));
    UI_EXPECT(unrecognized_filter_flow_model->hasActiveFlowFilter());
    UI_EXPECT(unrecognized_filter_flow_model->filteredFlowCountText() ==
        QStringLiteral("Filtered to %1 of %2 flows.")
            .arg(unrecognized_filter_flow_model->visibleFlowCount())
            .arg(unrecognized_filter_flow_model->totalFlowCount()));

    run_ui_section("flow_list_model_view_state_notifications", [&]() {
        FlowListModel model {};
        int view_state_changed_count = 0;
        QObject::connect(&model, &FlowListModel::viewStateChanged, [&]() {
            ++view_state_changed_count;
        });

        const auto make_row = [](
            const std::size_t index,
            const QString& protocol,
            const QString& service,
            const std::uint64_t packets,
            const bool has_fragmented_packets = false,
            const std::uint64_t fragmented_packet_count = 0U
        ) {
            return FlowRow {
                .index = index,
                .family = FlowAddressFamily::ipv4,
                .key = ConnectionKeyV4 {},
                .protocol_path_id = kInvalidProtocolPathId,
                .protocol_text = protocol.toStdString(),
                .protocol_hint = {},
                .service_hint = service.toStdString(),
                .has_fragmented_packets = has_fragmented_packets,
                .fragmented_packet_count = fragmented_packet_count,
                .address_a = "10.0.0.1",
                .port_a = 1000U,
                .endpoint_a = "10.0.0.1:1000",
                .address_b = "10.0.0.2",
                .port_b = 2000U,
                .endpoint_b = "10.0.0.2:2000",
                .packet_count = packets,
                .total_bytes = packets * 100U,
            };
        };

        const std::vector<FlowRow> rows {
            make_row(0U, QStringLiteral("TCP"), QStringLiteral("alpha"), 2U),
            make_row(1U, QStringLiteral("UDP"), QStringLiteral("beta"), 17U, true, 77U),
        };

        model.refresh(rows);
        UI_EXPECT(view_state_changed_count > 0);
        UI_EXPECT(model.totalFlowCount() == 2);
        UI_EXPECT(model.visibleFlowCount() == 2);
        UI_EXPECT(!model.hasActiveFlowFilter());
        UI_EXPECT(model.filteredFlowCountText().isEmpty());

        const auto after_refresh = view_state_changed_count;
        model.setFilterText(QStringLiteral("TCP"));
        UI_EXPECT(view_state_changed_count > after_refresh);
        UI_EXPECT(model.totalFlowCount() == 2);
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.hasActiveFlowFilter());
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_protocol_match = view_state_changed_count;
        model.setFilterText(QStringLiteral("frag"));
        UI_EXPECT(view_state_changed_count > after_protocol_match);
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));

        const auto after_fragment_keyword = view_state_changed_count;
        model.setFilterText(QStringLiteral("77"));
        UI_EXPECT(view_state_changed_count > after_fragment_keyword);
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));

        const auto after_fragment_count = view_state_changed_count;
        model.setFilterText(QStringLiteral("17"));
        UI_EXPECT(view_state_changed_count > after_fragment_count);
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));

        const auto after_packet_count = view_state_changed_count;
        model.setFilterText(QStringLiteral("1700"));
        UI_EXPECT(view_state_changed_count > after_packet_count);
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));

        const auto after_byte_count = view_state_changed_count;
        model.setFilterText(QStringLiteral("TCP"));
        UI_EXPECT(view_state_changed_count > after_byte_count);
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_text_filter = view_state_changed_count;
        model.setAllowedFlowIndices(std::vector<int> {0, 1});
        UI_EXPECT(view_state_changed_count > after_text_filter);
        UI_EXPECT(model.hasActiveFlowFilter());
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_allowed_filter = view_state_changed_count;
        model.setAllowedFlowIndices(std::vector<int> {1});
        UI_EXPECT(view_state_changed_count > after_allowed_filter);
        UI_EXPECT(model.hasActiveFlowFilter());
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));

        const auto after_allowed_replacement = view_state_changed_count;
        model.clearAllowedFlowIndices();
        UI_EXPECT(view_state_changed_count > after_allowed_replacement);
        UI_EXPECT(model.hasActiveFlowFilter());
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));
        UI_EXPECT(!model.hasAllowedFlowIndexFilter());

        const auto after_clearing_allowed = view_state_changed_count;
        model.setFilterText(QString());
        UI_EXPECT(view_state_changed_count > after_clearing_allowed);
        UI_EXPECT(!model.hasActiveFlowFilter());
        UI_EXPECT(model.visibleFlowCount() == 2);
        UI_EXPECT(model.filteredFlowCountText().isEmpty());

        const auto after_clearing_text = view_state_changed_count;
        model.setAllowedFlowIndices(std::vector<int> {1});
        UI_EXPECT(view_state_changed_count > after_clearing_text);
        UI_EXPECT(model.hasActiveFlowFilter());
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_allowed_only = view_state_changed_count;
        model.setSortKey(FlowListModel::SortKey::packets);
        UI_EXPECT(view_state_changed_count > after_allowed_only);
        UI_EXPECT(model.totalFlowCount() == 2);
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_sort_key = view_state_changed_count;
        model.setAdvancedFilterFlowIndices(std::vector<int> {0, 1});
        UI_EXPECT(view_state_changed_count > after_sort_key);
        UI_EXPECT(model.hasAdvancedFlowIndexFilter());
        UI_EXPECT(model.hasActiveFlowFilter());
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_advanced_passthrough = view_state_changed_count;
        model.setAdvancedFilterFlowIndices(std::vector<int> {0});
        UI_EXPECT(view_state_changed_count > after_advanced_passthrough);
        UI_EXPECT(model.hasAdvancedFlowIndexFilter());
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));

        const auto after_advanced_intersection = view_state_changed_count;
        model.clearAllowedFlowIndices();
        UI_EXPECT(view_state_changed_count > after_advanced_intersection);
        UI_EXPECT(model.hasAdvancedFlowIndexFilter());
        UI_EXPECT(!model.hasAllowedFlowIndexFilter());
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_clearing_statistics_filter = view_state_changed_count;
        model.setFilterText(QStringLiteral("UDP"));
        UI_EXPECT(view_state_changed_count > after_clearing_statistics_filter);
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(model.hasActiveFlowFilter());
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 0 of 2 flows."));

        const auto after_text_and_advanced = view_state_changed_count;
        model.clearAdvancedFilterFlowIndices();
        UI_EXPECT(view_state_changed_count > after_text_and_advanced);
        UI_EXPECT(!model.hasAdvancedFlowIndexFilter());
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_clearing_advanced = view_state_changed_count;
        model.setSortAscending(false);
        UI_EXPECT(view_state_changed_count > after_clearing_advanced);
        UI_EXPECT(model.totalFlowCount() == 2);
        UI_EXPECT(model.visibleFlowCount() == 1);
        UI_EXPECT(model.filteredFlowCountText() == QStringLiteral("Filtered to 1 of 2 flows."));

        const auto after_sort_direction = view_state_changed_count;
        model.resetViewState();
        UI_EXPECT(view_state_changed_count > after_sort_direction);
        UI_EXPECT(model.totalFlowCount() == 2);
        UI_EXPECT(model.visibleFlowCount() == 2);
        UI_EXPECT(!model.hasActiveFlowFilter());
        UI_EXPECT(model.filteredFlowCountText().isEmpty());

        const auto after_reset_view_state = view_state_changed_count;
        model.clear();
        UI_EXPECT(view_state_changed_count > after_reset_view_state);
        UI_EXPECT(model.totalFlowCount() == 0);
        UI_EXPECT(model.visibleFlowCount() == 0);
        UI_EXPECT(!model.hasActiveFlowFilter());
        UI_EXPECT(model.filteredFlowCountText().isEmpty());
    });

    const auto possible_hint_capture_path = write_temp_pcap(
        "pfl_ui_possible_tls_quic_settings.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 21, 0, 1), ipv4(10, 21, 0, 2), 43001, 443, 24, 0x18)},
            {200, make_ethernet_ipv4_udp_packet_with_payload(ipv4(10, 21, 0, 3), ipv4(10, 21, 0, 4), 43002, 443, 24)},
            {300, make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 21, 0, 5), ipv4(10, 21, 0, 6), 43003, 444, 24, 0x18)},
        })
    );

    MainController possible_hint_controller {};
    UI_EXPECT(!possible_hint_controller.usePossibleTlsQuic());
    UI_EXPECT(open_capture_and_wait(app, possible_hint_controller, possible_hint_capture_path));
    auto* possible_hint_flow_model = qobject_cast<FlowListModel*>(possible_hint_controller.flowModel());
    UI_EXPECT(possible_hint_flow_model != nullptr);
    UI_EXPECT(possible_hint_flow_model->rowCount() == 3);
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible TLS")) < 0);
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible QUIC")) < 0);
    UI_EXPECT(possible_hint_controller.protocolHintsSectionState() == section_not_requested);
    UI_EXPECT(possible_hint_controller.protocolHintDistribution().isEmpty());

    possible_hint_controller.setUsePossibleTlsQuic(true);
    UI_EXPECT(possible_hint_controller.usePossibleTlsQuic());
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible TLS")) >= 0);
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible QUIC")) >= 0);
    UI_EXPECT(possible_hint_controller.protocolHintDistribution().isEmpty());

    possible_hint_controller.setCurrentTabIndex(2);
    UI_EXPECT(possible_hint_controller.protocolHintsSectionState() == section_not_requested);
    possible_hint_controller.setStatisticsSectionExpanded(protocol_hints_section, true);
    UI_EXPECT(possible_hint_controller.protocolHintsSectionState() == section_ready);
    auto possible_tls_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Possible TLS"));
    auto possible_quic_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Possible QUIC"));
    auto unknown_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Unknown"));
    UI_EXPECT(possible_tls_row.value(QStringLiteral("flows")).toULongLong() == 1U);
    UI_EXPECT(possible_quic_row.value(QStringLiteral("flows")).toULongLong() == 1U);
    UI_EXPECT(unknown_row.value(QStringLiteral("flows")).toULongLong() == 1U);

    possible_hint_controller.setUsePossibleTlsQuic(false);
    UI_EXPECT(!possible_hint_controller.usePossibleTlsQuic());
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible TLS")) < 0);
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible QUIC")) < 0);
    UI_EXPECT(possible_hint_controller.protocolHintsSectionState() == section_ready);
    unknown_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Unknown"));
    UI_EXPECT(unknown_row.value(QStringLiteral("flows")).toULongLong() == 3U);

    const auto expect_checksum_fixture_summary = [&](const std::filesystem::path& fixture_path,
                                                     const QStringList& expected_snippets,
                                                     const QStringList& forbidden_snippets = {}) {
        MainController controller {};
        controller.setValidateSelectedPacketChecksums(true);
        UI_EXPECT(open_capture_and_wait(app, controller, fixture_path));
        controller.setSelectedFlowIndex(0);

        auto* packet_model = qobject_cast<PacketListModel*>(controller.packetModel());
        auto* details_model = qobject_cast<PacketDetailsViewModel*>(controller.packetDetailsModel());
        UI_EXPECT(packet_model != nullptr);
        UI_EXPECT(details_model != nullptr);
        UI_EXPECT(packet_model->rowCount() == 1);

        const auto packet_index = packet_model->data(packet_model->index(0, 0), PacketListModel::PacketIndexRole).toULongLong();
        controller.setSelectedPacketIndex(packet_index);
        const auto summary = details_model->summaryText();
        for (const auto& expected : expected_snippets) {
            UI_EXPECT(summary.contains(expected));
        }
        for (const auto& forbidden : forbidden_snippets) {
            UI_EXPECT(!summary.contains(forbidden));
        }
    };

    run_ui_section("capture_reload_resets_selected_flow_stream_state", [&]() {
        const auto http_fixture_path = ui_test_root() / "data" / "parsing" / "http" / "http_get_1.pcap";
        const auto tls_fixture_path = ui_test_root() / "data" / "parsing" / "tls" / "ipv4_tls_constricted_1.pcap";

        MainController controller {};
        UI_EXPECT(open_capture_and_wait(app, controller, http_fixture_path));

        auto* flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
        auto* stream_model = qobject_cast<StreamListModel*>(controller.streamModel());
        UI_EXPECT(flow_model != nullptr);
        UI_EXPECT(stream_model != nullptr);
        UI_EXPECT(flow_model->rowCount() >= 1);

        controller.setFlowDetailsTabIndex(1);
        controller.setSelectedFlowIndex(0);
        UI_EXPECT(wait_until(app, [&controller, stream_model]() {
            return !controller.streamLoading() && stream_model->rowCount() > 0;
        }));

        const auto first_stream_label = stream_model->data(stream_model->index(0, 0), StreamListModel::LabelRole).toString();
        UI_EXPECT(!first_stream_label.isEmpty());

        UI_EXPECT(open_capture_and_wait(app, controller, tls_fixture_path));
        UI_EXPECT(controller.selectedFlowIndex() == -1);
        UI_EXPECT(!controller.streamLoading());
        UI_EXPECT(flow_model->rowCount() >= 1);
        UI_EXPECT(stream_model->rowCount() == 0);

        controller.setFlowDetailsTabIndex(1);
        controller.setSelectedFlowIndex(0);
        UI_EXPECT(wait_until(app, [&controller, stream_model]() {
            return !controller.streamLoading() && stream_model->rowCount() > 0;
        }));

        const auto second_stream_label = stream_model->data(stream_model->index(0, 0), StreamListModel::LabelRole).toString();
        UI_EXPECT(second_stream_label.contains(QStringLiteral("TLS")));
        UI_EXPECT(second_stream_label != first_stream_label);
    });

    run_ui_section("stream_view_bubble_colors", [&]() {
        auto stream_view = load_qml_component("src/ui/qml/components/StreamView.qml", "StreamView");
        const auto forward_direction = stream_view.object->property("forwardDirection").toString();
        const auto reverse_direction = stream_view.object->property("reverseDirection").toString();

        QVariant bubble_color {};
        UI_EXPECT(QMetaObject::invokeMethod(
            stream_view.object.get(),
            "bubbleColor",
            Q_RETURN_ARG(QVariant, bubble_color),
            Q_ARG(QVariant, QVariant(forward_direction)),
            Q_ARG(QVariant, QVariant(false))
        ));
        UI_EXPECT(bubble_color.toString() == QStringLiteral("#eefaf2"));
        UI_EXPECT(QMetaObject::invokeMethod(
            stream_view.object.get(),
            "bubbleColor",
            Q_RETURN_ARG(QVariant, bubble_color),
            Q_ARG(QVariant, QVariant(reverse_direction)),
            Q_ARG(QVariant, QVariant(false))
        ));
        UI_EXPECT(bubble_color.toString() == QStringLiteral("#eef6ff"));
        UI_EXPECT(QMetaObject::invokeMethod(
            stream_view.object.get(),
            "bubbleBorderColor",
            Q_RETURN_ARG(QVariant, bubble_color),
            Q_ARG(QVariant, QVariant(forward_direction)),
            Q_ARG(QVariant, QVariant(true))
        ));
        UI_EXPECT(bubble_color.toString() == QStringLiteral("#79b38a"));
        UI_EXPECT(QMetaObject::invokeMethod(
            stream_view.object.get(),
            "bubbleBorderColor",
            Q_RETURN_ARG(QVariant, bubble_color),
            Q_ARG(QVariant, QVariant(reverse_direction)),
            Q_ARG(QVariant, QVariant(true))
        ));
        UI_EXPECT(bubble_color.toString() == QStringLiteral("#7ca9de"));
    });

    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "tcp" / "ipv4_tcp_valid_checksum_1.pcap",
        {QStringLiteral("IPv4 checksum: valid"), QStringLiteral("TCP checksum: valid")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "tcp" / "ipv4_tcp_bad_checksum_1.pcap",
        {QStringLiteral("IPv4 checksum: valid"), QStringLiteral("TCP checksum: invalid"), QStringLiteral("TCP checksum is invalid.")},
        {QStringLiteral("TCP checksum: valid")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "tcp" / "ipv4_bad_ip_checksum_1.pcap",
        {QStringLiteral("IPv4 checksum: invalid"), QStringLiteral("TCP checksum: valid"), QStringLiteral("IPv4 checksum is invalid.")},
        {QStringLiteral("IPv4 checksum: valid")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "udp" / "ipv4_udp_valid_checksum_1.pcap",
        {QStringLiteral("IPv4 checksum: valid"), QStringLiteral("UDP checksum: valid")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "udp" / "ipv4_udp_bad_checksum_1.pcap",
        {QStringLiteral("IPv4 checksum: valid"), QStringLiteral("UDP checksum: invalid"), QStringLiteral("UDP checksum is invalid.")},
        {QStringLiteral("UDP checksum: valid")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "udp" / "ipv4_udp_checksum_zero_1.pcap",
        {
            QStringLiteral("IPv4 checksum: valid"),
            QStringLiteral("UDP checksum: not checked"),
            QStringLiteral("UDP checksum note: UDP checksum is not present in this IPv4 packet.")
        },
        {QStringLiteral("UDP checksum is invalid.")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "udp" / "ipv6_udp_bad_checksum_1.pcap",
        {QStringLiteral("UDP checksum: invalid"), QStringLiteral("UDP checksum is invalid.")},
        {QStringLiteral("IPv4 checksum:")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "udp" / "ipv6_udp_checksum_zero_1.pcap",
        {
            QStringLiteral("UDP checksum: invalid"),
            QStringLiteral("UDP checksum note: UDP checksum is required for IPv6 packets."),
            QStringLiteral("UDP checksum is invalid. UDP checksum is required for IPv6 packets.")
        }
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "tcp" / "ipv4_pre_offload_like_tcp_1.pcap",
        {
            QStringLiteral("IPv4 total length is unavailable; packet was parsed using captured bytes only"),
            QStringLiteral("Header interpretation is conservative (possible pre-offload packet)"),
            QStringLiteral("IPv4 checksum: unavailable"),
            QStringLiteral("IPv4 checksum note: Possible pre-offload packet; IPv4 checksum may be incomplete or not finalized."),
            QStringLiteral("TCP checksum: unavailable"),
            QStringLiteral("TCP checksum note: Possible pre-offload packet; TCP checksum may be incomplete or not finalized.")
        },
        {QStringLiteral("Packet is truncated in capture")}
    );
    expect_checksum_fixture_summary(
        ui_test_root() / "data" / "parsing" / "udp" / "udp_truncated_manual_1.pcap",
        {
            QStringLiteral("Packet is truncated in capture"),
            QStringLiteral("Captured Length: 60"),
            QStringLiteral("Original Length: 142"),
            QStringLiteral("IPv4 checksum: valid"),
            QStringLiteral("UDP checksum: unavailable"),
            QStringLiteral("UDP checksum note: Packet is truncated in capture; full UDP datagram bytes are unavailable.")
        }
    );

    MainController stream_controller {};
    UI_EXPECT(open_capture_and_wait(app, stream_controller, moved_capture_path));
    stream_controller.setFlowDetailsTabIndex(1);
    auto* stream_flow_model = qobject_cast<FlowListModel*>(stream_controller.flowModel());
    auto* stream_model = qobject_cast<StreamListModel*>(stream_controller.streamModel());
    UI_EXPECT(stream_flow_model != nullptr);
    UI_EXPECT(stream_model != nullptr);
    UI_EXPECT(stream_model->rowCount() == 0);

    const int http_stream_flow_index = find_flow_index_by_protocol_hint(stream_flow_model, QStringLiteral("HTTP"));
    const int dns_stream_flow_index = find_flow_index_by_protocol_hint(stream_flow_model, QStringLiteral("DNS"));
    UI_EXPECT(http_stream_flow_index >= 0);
    UI_EXPECT(dns_stream_flow_index >= 0);

    stream_controller.setSelectedFlowIndex(http_stream_flow_index);
    UI_EXPECT(stream_model->rowCount() == 1);
    UI_EXPECT(stream_controller.selectedStreamItemIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::DirectionTextRole).toString() == QString::fromUtf8("A\xE2\x86\x92" "B"));
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::LabelRole).toString() == QStringLiteral("HTTP GET /"));
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::ByteCountRole).toUInt() == make_http_request_payload().size());
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::PacketCountRole).toUInt() == 1U);

    const auto http_stream_item_index = stream_model->data(stream_model->index(0, 0), StreamListModel::StreamItemIndexRole).toULongLong();
    stream_controller.setSelectedStreamItemIndex(http_stream_item_index);
    UI_EXPECT(stream_controller.selectedStreamItemIndex() == http_stream_item_index);
    auto* stream_details_model = qobject_cast<PacketDetailsViewModel*>(stream_controller.packetDetailsModel());
    UI_EXPECT(stream_details_model != nullptr);
    UI_EXPECT(stream_details_model->detailsTitle() == QStringLiteral("Stream Item Details"));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Label: HTTP GET /")));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Source packet: #1")));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Details source: Stream item")));
    UI_EXPECT(stream_details_model->payloadTabTitle() == QStringLiteral("Item Data"));
    UI_EXPECT(stream_details_model->streamItemDataAvailable());
    UI_EXPECT(!stream_details_model->streamItemDataText().isEmpty());
    UI_EXPECT(stream_details_model->streamItemDataStatusText().contains(QStringLiteral("Available:")));
    const auto http_stream_layers = stream_details_model->summaryLayers();
    const auto http_stream_layer = find_top_level_summary_layer(http_stream_layers, QStringLiteral("http"));
    UI_EXPECT(!http_stream_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(http_stream_layer, QStringLiteral("Method")) == QStringLiteral("GET"));
    UI_EXPECT(find_summary_field_value(http_stream_layer, QStringLiteral("Target")) == QStringLiteral("/"));

    stream_controller.setSelectedPacketIndex(0);
    UI_EXPECT(stream_controller.selectedPacketIndex() == 0U);
    UI_EXPECT(stream_details_model->detailsTitle() == QStringLiteral("Packet Details"));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Packet number in file: 1")));
    UI_EXPECT(stream_details_model->payloadTabTitle() == QStringLiteral("Payload"));
    UI_EXPECT(stream_details_model->streamItemDataText().isEmpty());

    stream_controller.setSelectedFlowIndex(dns_stream_flow_index);
    UI_EXPECT(stream_model->rowCount() == 1);
    UI_EXPECT(stream_controller.selectedStreamItemIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(stream_controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());
    const auto dns_stream_label =
        stream_model->data(stream_model->index(0, 0), StreamListModel::LabelRole).toString();
    UI_EXPECT(dns_stream_label.startsWith(QStringLiteral("DNS Query")));
    UI_EXPECT(dns_stream_label.contains(QStringLiteral("A")));
    UI_EXPECT(dns_stream_label.contains(QStringLiteral("api.example")));
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::ByteCountRole).toUInt() == make_dns_query_payload().size());
    const auto dns_stream_item_index = stream_model->data(
        stream_model->index(0, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    stream_controller.setSelectedStreamItemIndex(dns_stream_item_index);
    UI_EXPECT(stream_details_model->detailsTitle() == QStringLiteral("Stream Item Details"));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Details source: Packet fallback")));
    const auto dns_stream_layers = stream_details_model->summaryLayers();
    const auto dns_stream_layer = find_top_level_summary_layer(dns_stream_layers, QStringLiteral("dns"));
    UI_EXPECT(!dns_stream_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(dns_stream_layer, QStringLiteral("Message Type")) == QStringLiteral("Query"));
    UI_EXPECT(find_summary_field_value(dns_stream_layer, QStringLiteral("QType")) == QStringLiteral("A (1)"));
    UI_EXPECT(stream_details_model->payloadTabTitle() == QStringLiteral("Item Data"));
    auto* dns_packet_model = qobject_cast<PacketListModel*>(stream_controller.packetModel());
    UI_EXPECT(dns_packet_model != nullptr);
    UI_EXPECT(dns_packet_model->rowCount() == 1);
    const auto dns_packet_index = dns_packet_model->data(dns_packet_model->index(0, 0), PacketListModel::PacketIndexRole).toULongLong();
    stream_controller.setSelectedPacketIndex(dns_packet_index);
    UI_EXPECT(stream_details_model->payloadTabTitle() == QStringLiteral("Payload"));
    UI_EXPECT(packet_byte_view_labels(stream_details_model).contains(QStringLiteral("DNS Message")));
    stream_controller.selectPacketByteView(QStringLiteral("dns:0:0"));
    UI_EXPECT(stream_details_model->selectedPacketByteViewId() == QStringLiteral("dns:0:0"));
    UI_EXPECT(stream_details_model->selectedPacketByteViewText().contains(QStringLiteral("12 34 01 00")));

    stream_controller.setSelectedFlowIndex(-1);
    UI_EXPECT(stream_model->rowCount() == 0);

    const auto arp_stream_fixture_path = ui_test_root() / "data" / "parsing" / "arp" / "03_arp_request_reply_ipv4.pcap";
    MainController arp_stream_controller {};
    UI_EXPECT(open_capture_and_wait(app, arp_stream_controller, arp_stream_fixture_path));
    arp_stream_controller.setFlowDetailsTabIndex(1);
    arp_stream_controller.setSelectedFlowIndex(0);
    auto* arp_stream_model = qobject_cast<StreamListModel*>(arp_stream_controller.streamModel());
    auto* arp_stream_details_model = qobject_cast<PacketDetailsViewModel*>(arp_stream_controller.packetDetailsModel());
    UI_EXPECT(arp_stream_model != nullptr);
    UI_EXPECT(arp_stream_details_model != nullptr);
    UI_EXPECT(arp_stream_model->rowCount() == 2);
    UI_EXPECT(arp_stream_model->data(arp_stream_model->index(0, 0), StreamListModel::LabelRole).toString().contains(QStringLiteral("Who has 10.10.12.1? Tell 10.10.12.2")));
    UI_EXPECT(arp_stream_model->data(arp_stream_model->index(1, 0), StreamListModel::LabelRole).toString().contains(QStringLiteral("10.10.12.1 is at 02:00:00:00:00:01")));
    const auto arp_stream_item_index = arp_stream_model->data(
        arp_stream_model->index(0, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    arp_stream_controller.setSelectedStreamItemIndex(arp_stream_item_index);
    UI_EXPECT(arp_stream_details_model->detailsTitle() == QStringLiteral("Stream Item Details"));
    UI_EXPECT(arp_stream_details_model->summaryText().contains(QStringLiteral("Message: ARP Request")));
    UI_EXPECT(arp_stream_details_model->summaryText().contains(QStringLiteral("Who has 10.10.12.1? Tell 10.10.12.2")));
    UI_EXPECT(arp_stream_details_model->summaryText().contains(QStringLiteral("Source packet: #1")));
    UI_EXPECT(arp_stream_details_model->payloadTabTitle() == QStringLiteral("Item Data"));
    UI_EXPECT(arp_stream_details_model->streamItemDataAvailable());
    UI_EXPECT(arp_stream_details_model->streamItemDataStatusText().contains(QStringLiteral("Packet-backed")));
    UI_EXPECT(arp_stream_details_model->streamItemDataText().contains(QStringLiteral("00 01 08 00 06 04 00 01")));
    const auto arp_stream_layers = arp_stream_details_model->summaryLayers();
    const auto arp_stream_layer = find_top_level_summary_layer(arp_stream_layers, QStringLiteral("arp"));
    UI_EXPECT(!arp_stream_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(arp_stream_layer, QStringLiteral("Message")) == QStringLiteral("ARP Request"));
    UI_EXPECT(find_summary_field_value(arp_stream_layer, QStringLiteral("Detail")) == QStringLiteral("Who has 10.10.12.1? Tell 10.10.12.2"));

    const auto split_tls_record = make_tls_handshake_record(0x02U, {0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    const auto split_tls_payload_a = std::vector<std::uint8_t>(split_tls_record.begin(), split_tls_record.begin() + 7);
    const auto split_tls_payload_b = std::vector<std::uint8_t>(split_tls_record.begin() + 7, split_tls_record.end());
    const auto split_tls_capture_path = write_temp_pcap(
        "pfl_ui_stream_split_tls.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(10, 50, 0, 1), ipv4(10, 50, 0, 2), 54000, 443, split_tls_payload_a, 0x18)},
            {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(10, 50, 0, 1), ipv4(10, 50, 0, 2), 54000, 443, split_tls_payload_b, 0x18)},
        })
    );

    MainController split_tls_controller {};
    UI_EXPECT(open_capture_and_wait(app, split_tls_controller, split_tls_capture_path));
    split_tls_controller.setFlowDetailsTabIndex(1);
    split_tls_controller.setSelectedFlowIndex(0);
    auto* split_tls_stream_model = qobject_cast<StreamListModel*>(split_tls_controller.streamModel());
    UI_EXPECT(split_tls_stream_model != nullptr);
    UI_EXPECT(split_tls_stream_model->rowCount() == 1);
    const auto split_tls_stream_item_index = split_tls_stream_model->data(split_tls_stream_model->index(0, 0), StreamListModel::StreamItemIndexRole).toULongLong();
    split_tls_controller.setSelectedStreamItemIndex(split_tls_stream_item_index);
    auto* split_tls_details_model = qobject_cast<PacketDetailsViewModel*>(split_tls_controller.packetDetailsModel());
    UI_EXPECT(split_tls_details_model != nullptr);
    UI_EXPECT(split_tls_details_model->summaryText().contains(QStringLiteral("Label: TLS ServerHello")));
    UI_EXPECT(split_tls_details_model->summaryText().contains(QStringLiteral("Source packets: #1,#2")));
    UI_EXPECT(split_tls_details_model->summaryText().contains(QStringLiteral("Details source: Stream item")));
    UI_EXPECT(!split_tls_details_model->summaryLayers().isEmpty());
    const auto split_tls_layers = split_tls_details_model->summaryLayers();
    const auto split_tls_item_layer = find_top_level_summary_layer(split_tls_layers, QStringLiteral("stream_item"));
    const auto split_tls_record_layer = find_top_level_summary_layer(split_tls_layers, QStringLiteral("tls"));
    UI_EXPECT(!split_tls_item_layer.isEmpty());
    UI_EXPECT(!split_tls_record_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(split_tls_item_layer, QStringLiteral("Label")) == QStringLiteral("TLS ServerHello"));
    UI_EXPECT(find_summary_field_value(split_tls_item_layer, QStringLiteral("Source packets")) == QStringLiteral("#1,#2"));
    UI_EXPECT(find_summary_field_value(split_tls_record_layer, QStringLiteral("Record Type")) == QStringLiteral("Handshake"));
    UI_EXPECT(find_summary_field_value(split_tls_record_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ServerHello"));
    UI_EXPECT(split_tls_details_model->payloadTabTitle() == QStringLiteral("Item Data"));
    UI_EXPECT(split_tls_details_model->streamItemDataAvailable());
    UI_EXPECT(split_tls_details_model->streamItemDataStatusText().contains(QStringLiteral("Reassembled from 2 TCP segments")));
    UI_EXPECT(split_tls_details_model->streamItemDataText().contains(QStringLiteral("16 03 03 00 0a 02 00 00 06")));

    const auto tls_constricted_stream_fixture_path = ui_test_root() / "data" / "parsing" / "tls" / "ipv4_tls_constricted_1.pcap";
    MainController tls_constricted_stream_controller {};
    UI_EXPECT(open_capture_and_wait(app, tls_constricted_stream_controller, tls_constricted_stream_fixture_path));
    auto* tls_constricted_flow_model = qobject_cast<FlowListModel*>(tls_constricted_stream_controller.flowModel());
    auto* tls_constricted_stream_packet_model = qobject_cast<PacketListModel*>(tls_constricted_stream_controller.packetModel());
    auto* tls_constricted_stream_model = qobject_cast<StreamListModel*>(tls_constricted_stream_controller.streamModel());
    auto* tls_constricted_stream_details_model = qobject_cast<PacketDetailsViewModel*>(tls_constricted_stream_controller.packetDetailsModel());
    UI_EXPECT(tls_constricted_flow_model != nullptr);
    UI_EXPECT(tls_constricted_stream_packet_model != nullptr);
    UI_EXPECT(tls_constricted_stream_model != nullptr);
    UI_EXPECT(tls_constricted_stream_details_model != nullptr);
    UI_EXPECT(tls_constricted_flow_model->rowCount() >= 1);
    tls_constricted_stream_controller.setFlowDetailsTabIndex(1);
    const int tls_constricted_flow_index = find_flow_index_by_packet_count(tls_constricted_flow_model, 14U);
    UI_EXPECT(tls_constricted_flow_index >= 0);
    const int tls_constricted_flow_row = tls_constricted_flow_model->rowForFlowIndex(tls_constricted_flow_index);
    UI_EXPECT(tls_constricted_flow_row >= 0);

    tls_constricted_stream_controller.setSelectedFlowIndex(tls_constricted_flow_index);
    UI_EXPECT(wait_until(app, [&tls_constricted_stream_controller, tls_constricted_stream_model]() {
        return !tls_constricted_stream_controller.streamLoading() &&
            tls_constricted_stream_model->rowCount() >= 10;
    }));
    UI_EXPECT(tls_constricted_stream_model->rowCount() >= 10);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(0, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS ClientHello"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(0, 0), StreamListModel::ByteCountRole).toUInt() == 666U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(0, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #4"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(1, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS ServerHello"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(1, 0), StreamListModel::ByteCountRole).toUInt() == 127U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(1, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #6"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(2, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS ChangeCipherSpec"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(2, 0), StreamListModel::ByteCountRole).toUInt() == 6U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(2, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #6"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(3, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS AppData"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(3, 0), StreamListModel::ByteCountRole).toUInt() == 3061U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(3, 0), StreamListModel::PacketCountRole).toUInt() == 2U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(3, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packets #6,#7"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(3, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(4, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS ChangeCipherSpec"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(4, 0), StreamListModel::ByteCountRole).toUInt() == 6U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(4, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #9"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(5, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS AppData"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(5, 0), StreamListModel::ByteCountRole).toUInt() == 58U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(5, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #9"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(6, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS AppData"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(6, 0), StreamListModel::ByteCountRole).toUInt() == 1007U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(6, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #10"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(6, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(7, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS AppData"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(7, 0), StreamListModel::ByteCountRole).toUInt() == 450U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(7, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #12"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(8, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS AppData"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(8, 0), StreamListModel::ByteCountRole).toUInt() == 478U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(8, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #12"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(9, 0), StreamListModel::LabelRole).toString() == QStringLiteral("TLS AppData"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(9, 0), StreamListModel::ByteCountRole).toUInt() == 87U);
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(9, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #14"));
    UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(9, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    for (int row = 0; row < tls_constricted_stream_model->rowCount(); ++row) {
        UI_EXPECT(tls_constricted_stream_model->data(tls_constricted_stream_model->index(row, 0), StreamListModel::LabelRole).toString() != QStringLiteral("TLS Gap"));
    }

    const auto tls_constricted_stream_item_index = tls_constricted_stream_model->data(
        tls_constricted_stream_model->index(3, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    tls_constricted_stream_controller.setSelectedStreamItemIndex(tls_constricted_stream_item_index);
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Label: TLS AppData")));
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Source packets: #6,#7")));
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Constricted contributions:")));
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("#6 contributed 8 / 2787 bytes")));
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("#7 contributed 8 / 274 bytes")));
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Constricted packet #6: captured 199 / original 2978 bytes.")));
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Constricted packet #7: captured 66 / original 332 bytes.")));
    UI_EXPECT(!tls_constricted_stream_details_model->summaryLayers().isEmpty());
    const auto tls_constricted_layers = tls_constricted_stream_details_model->summaryLayers();
    const auto tls_constricted_item_layer = find_top_level_summary_layer(tls_constricted_layers, QStringLiteral("stream_item"));
    const auto tls_constricted_record_layer = find_top_level_summary_layer(tls_constricted_layers, QStringLiteral("tls"));
    UI_EXPECT(!tls_constricted_item_layer.isEmpty());
    UI_EXPECT(!tls_constricted_record_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(tls_constricted_item_layer, QStringLiteral("Source packets")) == QStringLiteral("#6,#7"));
    UI_EXPECT(find_summary_field_value(tls_constricted_record_layer, QStringLiteral("Status")) == QStringLiteral("Constricted item"));
    UI_EXPECT(find_summary_field_value(tls_constricted_record_layer, QStringLiteral("Available Bytes")) == QStringLiteral("3061"));
    UI_EXPECT(find_summary_field_value(tls_constricted_record_layer, QStringLiteral("Record Type")).isEmpty());
    UI_EXPECT(find_summary_field_value(tls_constricted_record_layer, QStringLiteral("Record Length")).isEmpty());

    const auto tls_constricted_single_item_index = tls_constricted_stream_model->data(
        tls_constricted_stream_model->index(6, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    tls_constricted_stream_controller.setSelectedStreamItemIndex(tls_constricted_single_item_index);
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Constricted contribution: #10 contributed 8 / 1007 bytes")));
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Constricted packet #10: captured 62 / original 1061 bytes.")));

    const auto tls_constricted_packet_fourteen_item_index = tls_constricted_stream_model->data(
        tls_constricted_stream_model->index(9, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    tls_constricted_stream_controller.setSelectedStreamItemIndex(tls_constricted_packet_fourteen_item_index);
    UI_EXPECT(tls_constricted_stream_details_model->summaryText().contains(QStringLiteral("Constricted packet #14: captured 66 / original 145 bytes.")));

    tls_constricted_stream_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&tls_constricted_stream_controller]() {
        return !tls_constricted_stream_controller.analysisLoading() && tls_constricted_stream_controller.analysisAvailable();
    }));
    UI_EXPECT(tls_constricted_stream_controller.analysisProtocolHint() == QStringLiteral("TLS"));
    const auto tls_constricted_analysis_preview = tls_constricted_stream_controller.analysisSequencePreview();
    UI_EXPECT(tls_constricted_analysis_preview.size() == 14);
    UI_REQUIRE(tls_constricted_analysis_preview.size() >= 6);
    const auto tls_constricted_sequence_packet_six = tls_constricted_analysis_preview[5].toMap();
    UI_EXPECT(tls_constricted_sequence_packet_six.value(QStringLiteral("capturedLength")).toUInt() == 199U);
    UI_EXPECT(tls_constricted_sequence_packet_six.value(QStringLiteral("originalLength")).toUInt() == 2978U);
    UI_EXPECT(tls_constricted_sequence_packet_six.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("2920"));

    const auto tls_capture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "tls" / "tls_client_hello_1.pcap";
    MainController tls_details_controller {};
    UI_EXPECT(open_capture_and_wait(app, tls_details_controller, tls_capture_path));
    tls_details_controller.setSelectedFlowIndex(0);
    tls_details_controller.setSelectedPacketIndex(0);
    auto* tls_details_model = qobject_cast<PacketDetailsViewModel*>(tls_details_controller.packetDetailsModel());
    UI_EXPECT(tls_details_model != nullptr);
    const auto tls_packet_layers = tls_details_model->summaryLayers();
    const auto tls_packet_layer = find_top_level_summary_layer(tls_packet_layers, QStringLiteral("tls"));
    UI_EXPECT(!tls_packet_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(tls_packet_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));
    UI_EXPECT(find_summary_field_value(tls_packet_layer, QStringLiteral("SNI")) == QStringLiteral("auth.split.io"));
    UI_EXPECT(packet_byte_view_labels(tls_details_model).contains(QStringLiteral("TLS Handshake Record")));
    UI_EXPECT(packet_byte_view_labels(tls_details_model).contains(QStringLiteral("TLS Handshake Message, ClientHello")));
    tls_details_controller.selectPacketByteView(QStringLiteral("tls_handshake:0:0"));
    UI_EXPECT(tls_details_model->selectedPacketByteViewId() == QStringLiteral("tls_handshake:0:0"));
    UI_EXPECT(tls_details_model->selectedPacketByteViewText().contains(QStringLiteral("03 03")));

    const auto gtpu_nested_data_fixture_path =
        ui_test_root() / "data" / "parsing" / "gtpu" / "32_gtpu_inner_ipv4_udp_data.pcap";
    MainController gtpu_nested_data_controller {};
    UI_EXPECT(open_capture_and_wait(app, gtpu_nested_data_controller, gtpu_nested_data_fixture_path));
    gtpu_nested_data_controller.setSelectedFlowIndex(0);
    gtpu_nested_data_controller.setSelectedPacketIndex(0);
    auto* gtpu_nested_data_details_model =
        qobject_cast<PacketDetailsViewModel*>(gtpu_nested_data_controller.packetDetailsModel());
    UI_EXPECT(gtpu_nested_data_details_model != nullptr);
    UI_EXPECT(!gtpu_nested_data_details_model->summaryLayers().isEmpty());
    const auto gtpu_nested_data_layers = gtpu_nested_data_details_model->summaryLayers();
    const auto gtpu_inner_udp_layer =
        find_top_level_summary_layer(gtpu_nested_data_layers, QStringLiteral("udp-inner"));
    const auto gtpu_data_layer =
        find_top_level_summary_layer(gtpu_nested_data_layers, QStringLiteral("data"));
    UI_EXPECT(!gtpu_inner_udp_layer.isEmpty());
    UI_EXPECT(!gtpu_data_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(gtpu_data_layer, QStringLiteral("Data Length")) == QStringLiteral("48 bytes"));
    UI_EXPECT(packet_byte_view_labels(gtpu_nested_data_details_model).count(QStringLiteral("Data")) == 1);
    gtpu_nested_data_controller.selectPacketByteView(QStringLiteral("data:0:0"));
    UI_EXPECT(gtpu_nested_data_details_model->selectedPacketByteViewId() == QStringLiteral("data:0:0"));
    UI_EXPECT(gtpu_nested_data_details_model->selectedPacketByteViewStatusText().contains(QStringLiteral("Available: 48 bytes")));
    UI_EXPECT(gtpu_nested_data_details_model->selectedPacketByteViewText().contains(
        QStringLiteral("49 4e 4e 45 52 2d 55 44 50 2d 44 41 54 41")));

    const auto split_tls_fixture_capture_path =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "tls" / "tls_1_3_split_client_hello_10.pcap";
    MainController split_tls_packet_controller {};
    UI_EXPECT(open_capture_and_wait(app, split_tls_packet_controller, split_tls_fixture_capture_path));
    auto* split_tls_flow_model = qobject_cast<FlowListModel*>(split_tls_packet_controller.flowModel());
    auto* split_tls_packet_model = qobject_cast<PacketListModel*>(split_tls_packet_controller.packetModel());
    auto* split_tls_packet_details_model = qobject_cast<PacketDetailsViewModel*>(split_tls_packet_controller.packetDetailsModel());
    UI_EXPECT(split_tls_flow_model != nullptr);
    UI_EXPECT(split_tls_packet_model != nullptr);
    UI_EXPECT(split_tls_packet_details_model != nullptr);
    UI_EXPECT(wait_until(app, [&]() {
        return split_tls_flow_model->rowCount() >= 1;
    }));
    const int split_tls_flow_index = find_flow_index_by_protocol_hint(split_tls_flow_model, QStringLiteral("TLS"));
    UI_EXPECT(split_tls_flow_index >= 0);
    const int split_tls_flow_row = split_tls_flow_model->rowForFlowIndex(split_tls_flow_index);
    UI_EXPECT(split_tls_flow_row >= 0);
    UI_EXPECT(split_tls_flow_model->data(
        split_tls_flow_model->index(split_tls_flow_row, 0),
        FlowListModel::ServiceHintRole
    ).toString() == QStringLiteral("www.youtube.com"));
    split_tls_packet_controller.setSelectedFlowIndex(split_tls_flow_index);
    UI_EXPECT(wait_until(app, [&]() {
        return !split_tls_packet_controller.packetsLoading() &&
            split_tls_packet_model->rowCount() >= 5;
    }));
    UI_EXPECT(split_tls_flow_model->data(
        split_tls_flow_model->index(split_tls_flow_row, 0),
        FlowListModel::ServiceHintRole
    ).toString() == QStringLiteral("www.youtube.com"));
    const int split_tls_packet4_row = find_packet_row_by_flow_row_number(split_tls_packet_model, 4U);
    const int split_tls_packet5_row = find_packet_row_by_flow_row_number(split_tls_packet_model, 5U);
    UI_EXPECT(split_tls_packet4_row >= 0);
    UI_EXPECT(split_tls_packet5_row >= 0);

    const auto split_tls_packet4_index = split_tls_packet_model->data(
        split_tls_packet_model->index(split_tls_packet4_row, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    const auto split_tls_packet5_index = split_tls_packet_model->data(
        split_tls_packet_model->index(split_tls_packet5_row, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();

    split_tls_packet_controller.setSelectedPacketIndex(split_tls_packet4_index);
    UI_EXPECT(!split_tls_packet_details_model->summaryLayers().isEmpty());
    const auto split_tls_packet4_layers = split_tls_packet_details_model->summaryLayers();
    const auto split_tls_packet4_tls_layer = find_top_level_summary_layer(split_tls_packet4_layers, QStringLiteral("tls"));
    const auto split_tls_packet4_reassembled_layer = find_top_level_summary_layer(split_tls_packet4_layers, QStringLiteral("tls_reassembled"));
    UI_EXPECT(!split_tls_packet4_tls_layer.isEmpty());
    UI_EXPECT(!split_tls_packet4_reassembled_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(split_tls_packet4_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));
    UI_EXPECT(find_summary_field_value(split_tls_packet4_reassembled_layer, QStringLiteral("Status")) ==
        QStringLiteral("Continues in a later loaded packet"));
    UI_EXPECT(find_summary_field_value(split_tls_packet4_reassembled_layer, QStringLiteral("Contributing Flow Packets")) ==
        QStringLiteral("4, 5"));
    UI_EXPECT(packet_byte_view_labels(split_tls_packet_details_model).contains(
        QStringLiteral("TLS Handshake Record (Reassembled)")));
    UI_EXPECT(packet_byte_view_labels(split_tls_packet_details_model).contains(
        QStringLiteral("TLS Handshake Message, ClientHello (Reassembled)")));
    split_tls_packet_controller.selectPacketByteView(QStringLiteral("tls_handshake:0:0"));
    UI_EXPECT(split_tls_packet_details_model->selectedPacketByteViewId() == QStringLiteral("tls_handshake:0:0"));
    UI_EXPECT(split_tls_packet_details_model->selectedPacketByteViewStatusText().contains(
        QStringLiteral("Reassembled from 2 TCP segments")));

    split_tls_packet_controller.setSelectedPacketIndex(split_tls_packet5_index);
    UI_EXPECT(!split_tls_packet_details_model->summaryLayers().isEmpty());
    const auto split_tls_packet5_layers = split_tls_packet_details_model->summaryLayers();
    const auto split_tls_packet5_tls_layer = find_top_level_summary_layer(split_tls_packet5_layers, QStringLiteral("tls"));
    const auto split_tls_packet5_reassembled_layer = find_top_level_summary_layer(split_tls_packet5_layers, QStringLiteral("tls_reassembled"));
    UI_EXPECT(!split_tls_packet5_tls_layer.isEmpty());
    UI_EXPECT(!split_tls_packet5_reassembled_layer.isEmpty());
    UI_EXPECT(find_summary_field_value(split_tls_packet5_reassembled_layer, QStringLiteral("Status")) ==
        QStringLiteral("Reassembled in this packet"));
    UI_EXPECT(find_summary_field_value(split_tls_packet5_tls_layer, QStringLiteral("Handshake Type")) == QStringLiteral("ClientHello"));
    UI_EXPECT(find_summary_field_value(split_tls_packet5_tls_layer, QStringLiteral("SNI")) ==
        QStringLiteral("www.youtube.com"));
    UI_EXPECT(packet_byte_view_labels(split_tls_packet_details_model).contains(
        QStringLiteral("TLS Handshake Record (Reassembled)")));
    UI_EXPECT(packet_byte_view_labels(split_tls_packet_details_model).contains(
        QStringLiteral("TLS Handshake Message, ClientHello (Reassembled)")));
    split_tls_packet_controller.selectPacketByteView(QStringLiteral("tls_handshake:0:0"));
    UI_EXPECT(split_tls_packet_details_model->selectedPacketByteViewId() == QStringLiteral("tls_handshake:0:0"));
    UI_EXPECT(split_tls_packet_details_model->selectedPacketByteViewStatusText().contains(
        QStringLiteral("Reassembled from 2 TCP segments")));

    const auto full_truncated_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 34567, 8080, make_http_request_payload(), 0x18);
    const auto captured_truncated_packet = std::vector<std::uint8_t>(full_truncated_packet.begin(), full_truncated_packet.end() - 4);
    const auto truncated_capture_path = write_temp_pcap(
        "pfl_ui_truncated_packet.pcap",
        make_classic_pcap_with_lengths(100U, captured_truncated_packet, static_cast<std::uint32_t>(full_truncated_packet.size()))
    );

    MainController truncated_controller {};
    UI_EXPECT(open_capture_and_wait(app, truncated_controller, truncated_capture_path));
    truncated_controller.setSelectedFlowIndex(0);
    auto* truncated_packet_model = qobject_cast<PacketListModel*>(truncated_controller.packetModel());
    UI_EXPECT(truncated_packet_model != nullptr);
    UI_EXPECT(truncated_packet_model->rowCount() == 1);
    const auto truncated_index = truncated_packet_model->index(0, 0);
    UI_EXPECT(truncated_packet_model->data(truncated_index, PacketListModel::CapturedLengthRole).toUInt() == captured_truncated_packet.size());
    UI_EXPECT(truncated_packet_model->data(truncated_index, PacketListModel::OriginalLengthRole).toUInt() == full_truncated_packet.size());

    truncated_controller.setSelectedPacketIndex(0);
    auto* truncated_details_model = qobject_cast<PacketDetailsViewModel*>(truncated_controller.packetDetailsModel());
    UI_EXPECT(truncated_details_model != nullptr);
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Warnings")));
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Packet is truncated in capture")));
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Captured Length: %1").arg(captured_truncated_packet.size())));
    UI_EXPECT(truncated_details_model->summaryText().contains(QStringLiteral("Original Length: %1").arg(full_truncated_packet.size())));

    const auto expect_packet_payload_row = [](PacketListModel* model,
                                              const int row,
                                              const std::uint32_t expected_payload_length,
                                              const std::uint32_t expected_captured_length,
                                              const std::uint32_t expected_original_length) {
        const auto model_index = model->index(row, 0);
        UI_EXPECT(model_index.isValid());
        UI_EXPECT(model->data(model_index, PacketListModel::PayloadLengthRole).toUInt() == expected_payload_length);
        UI_EXPECT(model->data(model_index, PacketListModel::CapturedLengthRole).toUInt() == expected_captured_length);
        UI_EXPECT(model->data(model_index, PacketListModel::OriginalLengthRole).toUInt() == expected_original_length);
    };

    const auto expect_quic_packet_eight_stream_label = [&](const std::filesystem::path& fixture_path,
                                                           const QString& expected_label,
                                                           const QString& forbidden_label) {
        MainController controller {};
        UI_EXPECT(open_capture_and_wait(app, controller, fixture_path));

        auto* flow_model = qobject_cast<FlowListModel*>(controller.flowModel());
        auto* stream_model = qobject_cast<StreamListModel*>(controller.streamModel());
        UI_EXPECT(flow_model != nullptr);
        UI_EXPECT(stream_model != nullptr);
        UI_EXPECT(flow_model->rowCount() >= 1);
        const int quic_flow_index = find_flow_index_by_protocol_hint(flow_model, QStringLiteral("QUIC"));
        UI_EXPECT(quic_flow_index >= 0);
        const int quic_flow_row = flow_model->rowForFlowIndex(quic_flow_index);
        UI_EXPECT(quic_flow_row >= 0);
        UI_EXPECT(flow_model->data(flow_model->index(quic_flow_row, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("QUIC"));

        controller.setFlowDetailsTabIndex(1);
        controller.setSelectedFlowIndex(quic_flow_index);
        UI_EXPECT(wait_until(app, [&controller, stream_model]() {
            return !controller.streamLoading() && stream_model->rowCount() > 0;
        }));

        const int packet_eight_row = find_stream_row_by_source_packets_text(stream_model, QStringLiteral("packet #8"));
        UI_EXPECT(packet_eight_row >= 0);
        UI_EXPECT(stream_model->data(stream_model->index(packet_eight_row, 0), StreamListModel::LabelRole).toString() == expected_label);
        UI_EXPECT(stream_model->data(stream_model->index(packet_eight_row, 0), StreamListModel::LabelRole).toString() != forbidden_label);
    };

    // Correct packet-number handling lets packet #8 decrypt to an ACK item.
    expect_quic_packet_eight_stream_label(
        ui_test_root() / "data" / "parsing" / "quic" / "quic_initial_ack_decrypt_ok_1.pcap",
        QStringLiteral("QUIC Initial: ACK"),
        QStringLiteral("QUIC Initial")
    );

    // The intentionally wrong packet number keeps packet #8 on the coarse fallback label.
    expect_quic_packet_eight_stream_label(
        ui_test_root() / "data" / "parsing" / "quic" / "quic_initial_ack_wrong_pkn_1.pcap",
        QStringLiteral("QUIC Initial"),
        QStringLiteral("QUIC Initial: ACK")
    );

    // Use a checked-in decryptable Initial fixture here rather than synthetic plaintext bytes
    // so StreamListModel label/byte-count projection stays aligned with production QUIC semantics.
    const auto quic_constricted_fixture_path = ui_test_root() / "data" / "parsing" / "quic" / "quic_constricted_1.pcap";
    MainController quic_constricted_controller {};
    UI_EXPECT(open_capture_and_wait(app, quic_constricted_controller, quic_constricted_fixture_path));
    auto* quic_constricted_flow_model = qobject_cast<FlowListModel*>(quic_constricted_controller.flowModel());
    UI_EXPECT(quic_constricted_flow_model != nullptr);
    const int quic_constricted_flow_index = find_flow_index_by_packet_count(quic_constricted_flow_model, 18U);
    UI_EXPECT(quic_constricted_flow_index >= 0);
    UI_EXPECT(quic_constricted_flow_model->rowForFlowIndex(quic_constricted_flow_index) >= 0);
    quic_constricted_controller.setSelectedFlowIndex(quic_constricted_flow_index);
    auto* quic_constricted_packet_model = qobject_cast<PacketListModel*>(quic_constricted_controller.packetModel());
    auto* quic_constricted_details_model = qobject_cast<PacketDetailsViewModel*>(quic_constricted_controller.packetDetailsModel());
    UI_EXPECT(quic_constricted_packet_model != nullptr);
    UI_EXPECT(quic_constricted_details_model != nullptr);
    UI_EXPECT(quic_constricted_packet_model->rowCount() == 18);
    expect_packet_payload_row(quic_constricted_packet_model, 0, 1252U, 1294U, 1294U);
    expect_packet_payload_row(quic_constricted_packet_model, 10, 42U, 84U, 84U);
    expect_packet_payload_row(quic_constricted_packet_model, 12, 677U, 686U, 723U);
    expect_packet_payload_row(quic_constricted_packet_model, 14, 131U, 150U, 173U);
    expect_packet_payload_row(quic_constricted_packet_model, 15, 78U, 74U, 120U);
    expect_packet_payload_row(quic_constricted_packet_model, 16, 766U, 74U, 808U);
    expect_packet_payload_row(quic_constricted_packet_model, 17, 736U, 74U, 778U);
    quic_constricted_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&quic_constricted_controller]() {
        return !quic_constricted_controller.analysisLoading() && quic_constricted_controller.analysisAvailable();
    }));
    const auto quic_constricted_preview = quic_constricted_controller.analysisSequencePreview();
    UI_EXPECT(quic_constricted_preview.size() == 18);
    UI_REQUIRE(quic_constricted_preview.size() >= 17);
    const auto quic_preview_packet_thirteen = quic_constricted_preview[12].toMap();
    UI_EXPECT(quic_preview_packet_thirteen.value(QStringLiteral("capturedLength")).toUInt() == 686U);
    UI_EXPECT(quic_preview_packet_thirteen.value(QStringLiteral("originalLength")).toUInt() == 723U);
    UI_EXPECT(quic_preview_packet_thirteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("677"));
    const auto quic_preview_packet_seventeen = quic_constricted_preview[16].toMap();
    UI_EXPECT(quic_preview_packet_seventeen.value(QStringLiteral("capturedLength")).toUInt() == 74U);
    UI_EXPECT(quic_preview_packet_seventeen.value(QStringLiteral("originalLength")).toUInt() == 808U);
    UI_EXPECT(quic_preview_packet_seventeen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("766"));

    const auto quic_packet_thirteen_index = quic_constricted_packet_model->data(
        quic_constricted_packet_model->index(12, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    quic_constricted_controller.setSelectedPacketIndex(quic_packet_thirteen_index);
    const auto quic_truncated_summary = quic_constricted_details_model->summaryText();
    UI_EXPECT(quic_truncated_summary.contains(QStringLiteral("Real Payload Length: 640")));
    UI_EXPECT(quic_truncated_summary.contains(QStringLiteral("Original Payload Length: 677")));

    const auto quic_packet_one_index = quic_constricted_packet_model->data(
        quic_constricted_packet_model->index(0, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    quic_constricted_controller.setSelectedPacketIndex(quic_packet_one_index);
    const auto quic_non_truncated_summary = quic_constricted_details_model->summaryText();
    UI_EXPECT(quic_non_truncated_summary.contains(QStringLiteral("Payload Length: 1252")));
    UI_EXPECT(!quic_non_truncated_summary.contains(QStringLiteral("Real Payload Length:")));
    UI_EXPECT(!quic_non_truncated_summary.contains(QStringLiteral("Original Payload Length:")));
    UI_EXPECT(quic_constricted_flow_model->rowForFlowIndex(quic_constricted_flow_index) >= 0);

    quic_constricted_controller.setFlowDetailsTabIndex(1);
    auto* quic_constricted_stream_model = qobject_cast<StreamListModel*>(quic_constricted_controller.streamModel());
    UI_EXPECT(quic_constricted_stream_model != nullptr);
    UI_EXPECT(quic_constricted_stream_model->rowCount() == 21);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(0, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: CRYPTO"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(0, 0), StreamListModel::ByteCountRole).toUInt() == 855U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(0, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #1"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(0, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(1, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: CRYPTO"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(1, 0), StreamListModel::ByteCountRole).toUInt() == 99U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(1, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #1"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(1, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(2, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: CRYPTO"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(2, 0), StreamListModel::ByteCountRole).toUInt() == 950U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(2, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #2"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(2, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(3, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: ACK"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(3, 0), StreamListModel::ByteCountRole).toUInt() == 6U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(3, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #3"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(3, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(4, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: ACK"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(4, 0), StreamListModel::ByteCountRole).toUInt() == 6U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(4, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #4"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(4, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(5, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: CRYPTO"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(5, 0), StreamListModel::ByteCountRole).toUInt() == 1170U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(5, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #5"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(5, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(6, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: CRYPTO"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(6, 0), StreamListModel::ByteCountRole).toUInt() == 5U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(6, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #6"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(6, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(7, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: CRYPTO"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(7, 0), StreamListModel::ByteCountRole).toUInt() == 15U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(7, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #7"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(7, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(8, 0), StreamListModel::LabelRole).toString() == QStringLiteral("QUIC Initial: ACK"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(8, 0), StreamListModel::ByteCountRole).toUInt() == 6U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(8, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #8"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(8, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(9, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Handshake"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(9, 0), StreamListModel::ByteCountRole).toUInt() == 1252U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(9, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #9"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(9, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(10, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Handshake"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(10, 0), StreamListModel::ByteCountRole).toUInt() == 1252U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(10, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #10"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(10, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(11, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Handshake"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(11, 0), StreamListModel::ByteCountRole).toUInt() == 42U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(11, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #11"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(11, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(12, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Handshake"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(12, 0), StreamListModel::ByteCountRole).toUInt() == 1252U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(12, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #12"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(12, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(13, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Handshake"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(13, 0), StreamListModel::ByteCountRole).toUInt() == 608U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(13, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #13"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(13, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(14, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Protected payload"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(14, 0), StreamListModel::ByteCountRole).toUInt() == 69U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(14, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #13"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(14, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(15, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Handshake"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(15, 0), StreamListModel::ByteCountRole).toUInt() == 43U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(15, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #14"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(15, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(16, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Handshake"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(16, 0), StreamListModel::ByteCountRole).toUInt() == 76U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(16, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #15"));
    UI_EXPECT(!quic_constricted_stream_model->data(quic_constricted_stream_model->index(16, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(17, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Protected payload"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(17, 0), StreamListModel::ByteCountRole).toUInt() == 55U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(17, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #15"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(17, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(18, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Protected payload"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(18, 0), StreamListModel::ByteCountRole).toUInt() == 78U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(18, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #16"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(18, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(19, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Protected payload"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(19, 0), StreamListModel::ByteCountRole).toUInt() == 766U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(19, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #17"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(19, 0), StreamListModel::HasConstrictedContributionRole).toBool());
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(20, 0), StreamListModel::LabelRole).toString() == QStringLiteral("Protected payload"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(20, 0), StreamListModel::ByteCountRole).toUInt() == 736U);
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(20, 0), StreamListModel::SourcePacketsTextRole).toString() == QStringLiteral("packet #18"));
    UI_EXPECT(quic_constricted_stream_model->data(quic_constricted_stream_model->index(20, 0), StreamListModel::HasConstrictedContributionRole).toBool());

    const auto quic_constricted_stream_item_index = quic_constricted_stream_model->data(
        quic_constricted_stream_model->index(14, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    quic_constricted_controller.setSelectedStreamItemIndex(quic_constricted_stream_item_index);
    UI_EXPECT(quic_constricted_details_model->summaryText().contains(QStringLiteral("Constricted contribution: #13 contributed 32 / 69 bytes")));
    UI_EXPECT(quic_constricted_details_model->payloadTabTitle() == QStringLiteral("Item Data"));
    UI_EXPECT(quic_constricted_details_model->streamItemDataStatusText().contains(QStringLiteral("Available:")));

    const auto ipv6_quic_constricted_fixture_path = ui_test_root() / "data" / "parsing" / "quic" / "ipv6_quic_constricted_1.pcap";
    MainController ipv6_quic_constricted_controller {};
    UI_EXPECT(open_capture_and_wait(app, ipv6_quic_constricted_controller, ipv6_quic_constricted_fixture_path));
    auto* ipv6_quic_constricted_flow_model = qobject_cast<FlowListModel*>(ipv6_quic_constricted_controller.flowModel());
    UI_EXPECT(ipv6_quic_constricted_flow_model != nullptr);
    const int ipv6_quic_constricted_flow_index = find_flow_index_by_packet_count(ipv6_quic_constricted_flow_model, 16U);
    UI_EXPECT(ipv6_quic_constricted_flow_index >= 0);
    const int ipv6_quic_constricted_flow_row = ipv6_quic_constricted_flow_model->rowForFlowIndex(ipv6_quic_constricted_flow_index);
    UI_EXPECT(ipv6_quic_constricted_flow_row >= 0);
    UI_EXPECT(ipv6_quic_constricted_flow_model->data(ipv6_quic_constricted_flow_model->index(ipv6_quic_constricted_flow_row, 0), FlowListModel::FamilyRole).toString() == QStringLiteral("IPv6"));
    UI_EXPECT(ipv6_quic_constricted_flow_model->data(ipv6_quic_constricted_flow_model->index(ipv6_quic_constricted_flow_row, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("QUIC"));
    UI_EXPECT(ipv6_quic_constricted_flow_model->data(ipv6_quic_constricted_flow_model->index(ipv6_quic_constricted_flow_row, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("www.instagram.com"));
    UI_EXPECT(ipv6_quic_constricted_flow_model->data(ipv6_quic_constricted_flow_model->index(ipv6_quic_constricted_flow_row, 0), FlowListModel::AddressARole).toString().contains(QLatin1Char(':')));
    UI_EXPECT(ipv6_quic_constricted_flow_model->data(ipv6_quic_constricted_flow_model->index(ipv6_quic_constricted_flow_row, 0), FlowListModel::AddressBRole).toString().contains(QLatin1Char(':')));
    UI_EXPECT(ipv6_quic_constricted_flow_model->data(ipv6_quic_constricted_flow_model->index(ipv6_quic_constricted_flow_row, 0), FlowListModel::PortARole).toUInt() == 443U ||
              ipv6_quic_constricted_flow_model->data(ipv6_quic_constricted_flow_model->index(ipv6_quic_constricted_flow_row, 0), FlowListModel::PortBRole).toUInt() == 443U);

    ipv6_quic_constricted_controller.setSelectedFlowIndex(ipv6_quic_constricted_flow_index);
    auto* ipv6_quic_constricted_packet_model = qobject_cast<PacketListModel*>(ipv6_quic_constricted_controller.packetModel());
    auto* ipv6_quic_constricted_details_model = qobject_cast<PacketDetailsViewModel*>(ipv6_quic_constricted_controller.packetDetailsModel());
    UI_EXPECT(ipv6_quic_constricted_packet_model != nullptr);
    UI_EXPECT(ipv6_quic_constricted_details_model != nullptr);
    UI_EXPECT(ipv6_quic_constricted_packet_model->rowCount() == 16);
    expect_packet_payload_row(ipv6_quic_constricted_packet_model, 0, 1232U, 1294U, 1294U);
    expect_packet_payload_row(ipv6_quic_constricted_packet_model, 7, 80U, 94U, 142U);
    expect_packet_payload_row(ipv6_quic_constricted_packet_model, 9, 203U, 170U, 265U);
    expect_packet_payload_row(ipv6_quic_constricted_packet_model, 10, 64U, 94U, 126U);
    expect_packet_payload_row(ipv6_quic_constricted_packet_model, 11, 348U, 94U, 410U);
    expect_packet_payload_row(ipv6_quic_constricted_packet_model, 12, 3755U, 3790U, 3817U);
    expect_packet_payload_row(ipv6_quic_constricted_packet_model, 15, 160U, 94U, 222U);

    ipv6_quic_constricted_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&ipv6_quic_constricted_controller]() {
        return !ipv6_quic_constricted_controller.analysisLoading() && ipv6_quic_constricted_controller.analysisAvailable();
    }));
    UI_EXPECT(ipv6_quic_constricted_controller.analysisProtocolHint() == QStringLiteral("QUIC"));
    const auto ipv6_quic_constricted_preview = ipv6_quic_constricted_controller.analysisSequencePreview();
    UI_EXPECT(ipv6_quic_constricted_preview.size() == 16);
    UI_REQUIRE(ipv6_quic_constricted_preview.size() >= 16);
    const auto ipv6_quic_preview_packet_one = ipv6_quic_constricted_preview[0].toMap();
    UI_EXPECT(ipv6_quic_preview_packet_one.value(QStringLiteral("capturedLength")).toUInt() == 1294U);
    UI_EXPECT(ipv6_quic_preview_packet_one.value(QStringLiteral("originalLength")).toUInt() == 1294U);
    UI_EXPECT(ipv6_quic_preview_packet_one.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("1232"));
    const auto ipv6_quic_preview_packet_eight = ipv6_quic_constricted_preview[7].toMap();
    UI_EXPECT(ipv6_quic_preview_packet_eight.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_quic_preview_packet_eight.value(QStringLiteral("originalLength")).toUInt() == 142U);
    UI_EXPECT(ipv6_quic_preview_packet_eight.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("80"));
    const auto ipv6_quic_preview_packet_ten = ipv6_quic_constricted_preview[9].toMap();
    UI_EXPECT(ipv6_quic_preview_packet_ten.value(QStringLiteral("capturedLength")).toUInt() == 170U);
    UI_EXPECT(ipv6_quic_preview_packet_ten.value(QStringLiteral("originalLength")).toUInt() == 265U);
    UI_EXPECT(ipv6_quic_preview_packet_ten.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("203"));
    const auto ipv6_quic_preview_packet_eleven = ipv6_quic_constricted_preview[10].toMap();
    UI_EXPECT(ipv6_quic_preview_packet_eleven.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_quic_preview_packet_eleven.value(QStringLiteral("originalLength")).toUInt() == 126U);
    UI_EXPECT(ipv6_quic_preview_packet_eleven.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("64"));
    const auto ipv6_quic_preview_packet_twelve = ipv6_quic_constricted_preview[11].toMap();
    UI_EXPECT(ipv6_quic_preview_packet_twelve.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_quic_preview_packet_twelve.value(QStringLiteral("originalLength")).toUInt() == 410U);
    UI_EXPECT(ipv6_quic_preview_packet_twelve.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("348"));
    const auto ipv6_quic_preview_packet_thirteen = ipv6_quic_constricted_preview[12].toMap();
    UI_EXPECT(ipv6_quic_preview_packet_thirteen.value(QStringLiteral("capturedLength")).toUInt() == 3790U);
    UI_EXPECT(ipv6_quic_preview_packet_thirteen.value(QStringLiteral("originalLength")).toUInt() == 3817U);
    UI_EXPECT(ipv6_quic_preview_packet_thirteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("3755"));
    const auto ipv6_quic_preview_packet_sixteen = ipv6_quic_constricted_preview[15].toMap();
    UI_EXPECT(ipv6_quic_preview_packet_sixteen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_quic_preview_packet_sixteen.value(QStringLiteral("originalLength")).toUInt() == 222U);
    UI_EXPECT(ipv6_quic_preview_packet_sixteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("160"));

    ipv6_quic_constricted_controller.setFlowDetailsTabIndex(1);
    auto* ipv6_quic_constricted_stream_model = qobject_cast<StreamListModel*>(ipv6_quic_constricted_controller.streamModel());
    UI_EXPECT(ipv6_quic_constricted_stream_model != nullptr);
    UI_EXPECT(ipv6_quic_constricted_stream_model->rowCount() == 27);

    const auto expect_ipv6_quic_stream_row = [&](const int row,
                                                 const QString& expected_label,
                                                 const uint expected_bytes,
                                                 const QString& expected_packets,
                                                 const bool expected_constricted) {
        UI_EXPECT(ipv6_quic_constricted_stream_model->data(ipv6_quic_constricted_stream_model->index(row, 0), StreamListModel::LabelRole).toString() == expected_label);
        UI_EXPECT(ipv6_quic_constricted_stream_model->data(ipv6_quic_constricted_stream_model->index(row, 0), StreamListModel::ByteCountRole).toUInt() == expected_bytes);
        UI_EXPECT(ipv6_quic_constricted_stream_model->data(ipv6_quic_constricted_stream_model->index(row, 0), StreamListModel::SourcePacketsTextRole).toString() == expected_packets);
        UI_EXPECT(ipv6_quic_constricted_stream_model->data(ipv6_quic_constricted_stream_model->index(row, 0), StreamListModel::HasConstrictedContributionRole).toBool() == expected_constricted);
    };

    expect_ipv6_quic_stream_row(0, QStringLiteral("QUIC Initial: CRYPTO"), 820U, QStringLiteral("packet #1"), false);
    expect_ipv6_quic_stream_row(1, QStringLiteral("QUIC Initial: CRYPTO"), 111U, QStringLiteral("packet #1"), false);
    expect_ipv6_quic_stream_row(2, QStringLiteral("QUIC Initial: CRYPTO"), 928U, QStringLiteral("packet #2"), false);
    expect_ipv6_quic_stream_row(3, QStringLiteral("QUIC Initial: CRYPTO"), 820U, QStringLiteral("packet #3"), false);
    expect_ipv6_quic_stream_row(4, QStringLiteral("QUIC Initial: CRYPTO"), 111U, QStringLiteral("packet #3"), false);
    expect_ipv6_quic_stream_row(5, QStringLiteral("QUIC Initial: CRYPTO"), 928U, QStringLiteral("packet #4"), false);
    expect_ipv6_quic_stream_row(6, QStringLiteral("QUIC Initial: CRYPTO"), 1182U, QStringLiteral("packet #5"), false);
    expect_ipv6_quic_stream_row(7, QStringLiteral("QUIC Initial: ACK"), 6U, QStringLiteral("packet #5"), false);
    expect_ipv6_quic_stream_row(8, QStringLiteral("QUIC Initial: ACK"), 9U, QStringLiteral("packet #6"), false);
    expect_ipv6_quic_stream_row(9, QStringLiteral("Handshake"), 1232U, QStringLiteral("packet #7"), false);
    expect_ipv6_quic_stream_row(10, QStringLiteral("Handshake"), 1232U, QStringLiteral("packet #7"), false);
    expect_ipv6_quic_stream_row(11, QStringLiteral("Handshake"), 1232U, QStringLiteral("packet #7"), false);
    expect_ipv6_quic_stream_row(12, QStringLiteral("Handshake"), 661U, QStringLiteral("packet #7"), false);
    expect_ipv6_quic_stream_row(13, QStringLiteral("Protected payload"), 80U, QStringLiteral("packet #8"), true);
    expect_ipv6_quic_stream_row(14, QStringLiteral("Handshake"), 46U, QStringLiteral("packet #9"), false);
    expect_ipv6_quic_stream_row(15, QStringLiteral("Handshake"), 76U, QStringLiteral("packet #10"), false);
    expect_ipv6_quic_stream_row(16, QStringLiteral("Protected payload"), 127U, QStringLiteral("packet #10"), true);
    expect_ipv6_quic_stream_row(17, QStringLiteral("Protected payload"), 64U, QStringLiteral("packet #11"), true);
    expect_ipv6_quic_stream_row(18, QStringLiteral("Protected payload"), 348U, QStringLiteral("packet #12"), true);
    expect_ipv6_quic_stream_row(19, QStringLiteral("QUIC Initial: ACK"), 6U, QStringLiteral("packet #13"), false);
    expect_ipv6_quic_stream_row(20, QStringLiteral("Handshake"), 1232U, QStringLiteral("packet #13"), false);
    expect_ipv6_quic_stream_row(21, QStringLiteral("Handshake"), 1232U, QStringLiteral("packet #13"), false);
    expect_ipv6_quic_stream_row(22, QStringLiteral("Protected payload"), 59U, QStringLiteral("packet #13"), true);
    expect_ipv6_quic_stream_row(23, QStringLiteral("Handshake"), 86U, QStringLiteral("packet #14"), false);
    expect_ipv6_quic_stream_row(24, QStringLiteral("Protected payload"), 36U, QStringLiteral("packet #14"), false);
    expect_ipv6_quic_stream_row(25, QStringLiteral("Handshake"), 42U, QStringLiteral("packet #15"), false);
    expect_ipv6_quic_stream_row(26, QStringLiteral("Protected payload"), 160U, QStringLiteral("packet #16"), true);

    for (int row = 0; row < ipv6_quic_constricted_stream_model->rowCount(); ++row) {
        const auto label = ipv6_quic_constricted_stream_model->data(ipv6_quic_constricted_stream_model->index(row, 0), StreamListModel::LabelRole).toString();
        UI_EXPECT(!label.contains(QStringLiteral("PADDING")));
        UI_EXPECT(label != QStringLiteral("QUIC Initial"));
    }

    const auto ipv6_quic_stream_item_index = ipv6_quic_constricted_stream_model->data(
        ipv6_quic_constricted_stream_model->index(13, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    ipv6_quic_constricted_controller.setSelectedStreamItemIndex(ipv6_quic_stream_item_index);
    UI_EXPECT(ipv6_quic_constricted_details_model->summaryText().contains(QStringLiteral("Constricted contribution: #8 contributed 32 / 80 bytes")));
    UI_EXPECT(ipv6_quic_constricted_details_model->payloadTabTitle() == QStringLiteral("Item Data"));
    UI_EXPECT(ipv6_quic_constricted_details_model->streamItemDataStatusText().contains(QStringLiteral("Available:")));

    const auto tls_constricted_fixture_path = ui_test_root() / "data" / "parsing" / "tls" / "ipv4_tls_constricted_1.pcap";
    MainController tls_constricted_controller {};
    UI_EXPECT(open_capture_and_wait(app, tls_constricted_controller, tls_constricted_fixture_path));
    auto* tls_constricted_packet_flow_model = qobject_cast<FlowListModel*>(tls_constricted_controller.flowModel());
    auto* tls_constricted_packet_model = qobject_cast<PacketListModel*>(tls_constricted_controller.packetModel());
    auto* tls_constricted_details_model = qobject_cast<PacketDetailsViewModel*>(tls_constricted_controller.packetDetailsModel());
    UI_EXPECT(tls_constricted_packet_flow_model != nullptr);
    UI_EXPECT(tls_constricted_packet_model != nullptr);
    UI_EXPECT(tls_constricted_details_model != nullptr);
    UI_EXPECT(tls_constricted_packet_flow_model->rowCount() >= 1);
    tls_constricted_controller.setFlowDetailsTabIndex(1);
    auto* tls_constricted_packet_stream_model = qobject_cast<StreamListModel*>(tls_constricted_controller.streamModel());
    UI_EXPECT(tls_constricted_packet_stream_model != nullptr);
    const int tls_constricted_packet_flow_index = find_flow_index_by_packet_count(tls_constricted_packet_flow_model, 14U);
    UI_EXPECT(tls_constricted_packet_flow_index >= 0);
    UI_EXPECT(tls_constricted_packet_flow_model->rowForFlowIndex(tls_constricted_packet_flow_index) >= 0);
    tls_constricted_controller.setFlowDetailsTabIndex(0);
    tls_constricted_controller.setSelectedFlowIndex(tls_constricted_packet_flow_index);
    UI_EXPECT(wait_until(app, [&tls_constricted_controller, tls_constricted_packet_model]() {
        return !tls_constricted_controller.packetsLoading() &&
            tls_constricted_packet_model->rowCount() >= 14;
    }));
    UI_EXPECT(tls_constricted_packet_model->rowCount() >= 14);
    expect_packet_payload_row(tls_constricted_packet_model, 3, 666U, 720U, 720U);
    expect_packet_payload_row(tls_constricted_packet_model, 5, 2920U, 199U, 2978U);
    expect_packet_payload_row(tls_constricted_packet_model, 6, 274U, 66U, 332U);
    expect_packet_payload_row(tls_constricted_packet_model, 8, 64U, 68U, 118U);
    expect_packet_payload_row(tls_constricted_packet_model, 9, 1007U, 62U, 1061U);
    expect_packet_payload_row(tls_constricted_packet_model, 11, 928U, 516U, 986U);
    expect_packet_payload_row(tls_constricted_packet_model, 13, 87U, 66U, 145U);
    tls_constricted_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&tls_constricted_controller]() {
        return !tls_constricted_controller.analysisLoading() && tls_constricted_controller.analysisAvailable();
    }));
    const auto tls_constricted_preview = tls_constricted_controller.analysisSequencePreview();
    UI_EXPECT(tls_constricted_preview.size() == 14);
    UI_REQUIRE(tls_constricted_preview.size() >= 6);
    const auto tls_preview_packet_six = tls_constricted_preview[5].toMap();
    UI_EXPECT(tls_preview_packet_six.value(QStringLiteral("capturedLength")).toUInt() == 199U);
    UI_EXPECT(tls_preview_packet_six.value(QStringLiteral("originalLength")).toUInt() == 2978U);
    UI_EXPECT(tls_preview_packet_six.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("2920"));

    const auto tls_packet_six_index = tls_constricted_packet_model->data(
        tls_constricted_packet_model->index(5, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    tls_constricted_controller.setSelectedPacketIndex(tls_packet_six_index);
    const auto tls_truncated_summary = tls_constricted_details_model->summaryText();
    UI_EXPECT(tls_truncated_summary.contains(QStringLiteral("Real Payload Length: 141")));
    UI_EXPECT(tls_truncated_summary.contains(QStringLiteral("Original Payload Length: 2920")));

    const auto tls_packet_four_index = tls_constricted_packet_model->data(
        tls_constricted_packet_model->index(3, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    tls_constricted_controller.setSelectedPacketIndex(tls_packet_four_index);
    const auto tls_non_truncated_summary = tls_constricted_details_model->summaryText();
    UI_EXPECT(tls_non_truncated_summary.contains(QStringLiteral("Payload Length: 666")));
    UI_EXPECT(!tls_non_truncated_summary.contains(QStringLiteral("Real Payload Length:")));
    UI_EXPECT(!tls_non_truncated_summary.contains(QStringLiteral("Original Payload Length:")));

    const auto ipv6_tls_constricted_fixture_path = ui_test_root() / "data" / "parsing" / "tls" / "ipv6_tls_constricted_1.pcap";
    MainController ipv6_tls_constricted_controller {};
    UI_EXPECT(open_capture_and_wait(app, ipv6_tls_constricted_controller, ipv6_tls_constricted_fixture_path));
    auto* ipv6_tls_constricted_flow_model = qobject_cast<FlowListModel*>(ipv6_tls_constricted_controller.flowModel());
    UI_EXPECT(ipv6_tls_constricted_flow_model != nullptr);
    const int ipv6_tls_constricted_flow_index = find_flow_index_by_packet_count(ipv6_tls_constricted_flow_model, 19U);
    UI_EXPECT(ipv6_tls_constricted_flow_index >= 0);
    const int ipv6_tls_constricted_flow_row = ipv6_tls_constricted_flow_model->rowForFlowIndex(ipv6_tls_constricted_flow_index);
    UI_EXPECT(ipv6_tls_constricted_flow_row >= 0);
    UI_EXPECT(ipv6_tls_constricted_flow_model->data(ipv6_tls_constricted_flow_model->index(ipv6_tls_constricted_flow_row, 0), FlowListModel::FamilyRole).toString() == QStringLiteral("IPv6"));
    UI_EXPECT(ipv6_tls_constricted_flow_model->data(ipv6_tls_constricted_flow_model->index(ipv6_tls_constricted_flow_row, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("TLS"));
    UI_EXPECT(ipv6_tls_constricted_flow_model->data(ipv6_tls_constricted_flow_model->index(ipv6_tls_constricted_flow_row, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("www.youtube.com"));
    UI_EXPECT(ipv6_tls_constricted_flow_model->data(ipv6_tls_constricted_flow_model->index(ipv6_tls_constricted_flow_row, 0), FlowListModel::AddressARole).toString().contains(QLatin1Char(':')));
    UI_EXPECT(ipv6_tls_constricted_flow_model->data(ipv6_tls_constricted_flow_model->index(ipv6_tls_constricted_flow_row, 0), FlowListModel::AddressBRole).toString().contains(QLatin1Char(':')));
    UI_EXPECT(ipv6_tls_constricted_flow_model->data(ipv6_tls_constricted_flow_model->index(ipv6_tls_constricted_flow_row, 0), FlowListModel::PortARole).toUInt() == 443U ||
              ipv6_tls_constricted_flow_model->data(ipv6_tls_constricted_flow_model->index(ipv6_tls_constricted_flow_row, 0), FlowListModel::PortBRole).toUInt() == 443U);

    ipv6_tls_constricted_controller.setSelectedFlowIndex(ipv6_tls_constricted_flow_index);
    auto* ipv6_tls_constricted_packet_model = qobject_cast<PacketListModel*>(ipv6_tls_constricted_controller.packetModel());
    auto* ipv6_tls_constricted_details_model = qobject_cast<PacketDetailsViewModel*>(ipv6_tls_constricted_controller.packetDetailsModel());
    UI_EXPECT(ipv6_tls_constricted_packet_model != nullptr);
    UI_EXPECT(ipv6_tls_constricted_details_model != nullptr);
    UI_EXPECT(ipv6_tls_constricted_packet_model->rowCount() == 19);
    expect_packet_payload_row(ipv6_tls_constricted_packet_model, 3, 1890U, 1976U, 1976U);
    expect_packet_payload_row(ipv6_tls_constricted_packet_model, 15, 64U, 100U, 150U);
    expect_packet_payload_row(ipv6_tls_constricted_packet_model, 16, 92U, 94U, 178U);
    expect_packet_payload_row(ipv6_tls_constricted_packet_model, 17, 362U, 94U, 448U);
    expect_packet_payload_row(ipv6_tls_constricted_packet_model, 18, 62U, 94U, 148U);

    ipv6_tls_constricted_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&ipv6_tls_constricted_controller]() {
        return !ipv6_tls_constricted_controller.analysisLoading() && ipv6_tls_constricted_controller.analysisAvailable();
    }));
    UI_EXPECT(ipv6_tls_constricted_controller.analysisProtocolHint() == QStringLiteral("TLS"));
    UI_EXPECT(ipv6_tls_constricted_controller.analysisServiceHint() == QStringLiteral("www.youtube.com"));
    const auto ipv6_tls_constricted_preview = ipv6_tls_constricted_controller.analysisSequencePreview();
    UI_EXPECT(ipv6_tls_constricted_preview.size() == 19);
    UI_REQUIRE(ipv6_tls_constricted_preview.size() >= 19);
    const auto ipv6_tls_preview_packet_four = ipv6_tls_constricted_preview[3].toMap();
    UI_EXPECT(ipv6_tls_preview_packet_four.value(QStringLiteral("capturedLength")).toUInt() == 1976U);
    UI_EXPECT(ipv6_tls_preview_packet_four.value(QStringLiteral("originalLength")).toUInt() == 1976U);
    UI_EXPECT(ipv6_tls_preview_packet_four.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("1890"));
    const auto ipv6_tls_preview_packet_sixteen = ipv6_tls_constricted_preview[15].toMap();
    UI_EXPECT(ipv6_tls_preview_packet_sixteen.value(QStringLiteral("capturedLength")).toUInt() == 100U);
    UI_EXPECT(ipv6_tls_preview_packet_sixteen.value(QStringLiteral("originalLength")).toUInt() == 150U);
    UI_EXPECT(ipv6_tls_preview_packet_sixteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("64"));
    const auto ipv6_tls_preview_packet_seventeen = ipv6_tls_constricted_preview[16].toMap();
    UI_EXPECT(ipv6_tls_preview_packet_seventeen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_preview_packet_seventeen.value(QStringLiteral("originalLength")).toUInt() == 178U);
    UI_EXPECT(ipv6_tls_preview_packet_seventeen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("92"));
    const auto ipv6_tls_preview_packet_eighteen = ipv6_tls_constricted_preview[17].toMap();
    UI_EXPECT(ipv6_tls_preview_packet_eighteen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_preview_packet_eighteen.value(QStringLiteral("originalLength")).toUInt() == 448U);
    UI_EXPECT(ipv6_tls_preview_packet_eighteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("362"));
    const auto ipv6_tls_preview_packet_nineteen = ipv6_tls_constricted_preview[18].toMap();
    UI_EXPECT(ipv6_tls_preview_packet_nineteen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_preview_packet_nineteen.value(QStringLiteral("originalLength")).toUInt() == 148U);
    UI_EXPECT(ipv6_tls_preview_packet_nineteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("62"));

    const auto ipv6_tls_packet_four_index = ipv6_tls_constricted_packet_model->data(
        ipv6_tls_constricted_packet_model->index(3, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_constricted_controller.setSelectedPacketIndex(ipv6_tls_packet_four_index);
    const auto ipv6_tls_packet_four_summary = ipv6_tls_constricted_details_model->summaryText();
    UI_EXPECT(ipv6_tls_packet_four_summary.contains(QStringLiteral("Payload Length: 1890")));
    UI_EXPECT(!ipv6_tls_packet_four_summary.contains(QStringLiteral("Real Payload Length:")));
    UI_EXPECT(!ipv6_tls_packet_four_summary.contains(QStringLiteral("Original Payload Length:")));

    const auto ipv6_tls_packet_sixteen_index = ipv6_tls_constricted_packet_model->data(
        ipv6_tls_constricted_packet_model->index(15, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_constricted_controller.setSelectedPacketIndex(ipv6_tls_packet_sixteen_index);
    const auto ipv6_tls_packet_sixteen_summary = ipv6_tls_constricted_details_model->summaryText();
    UI_EXPECT(ipv6_tls_packet_sixteen_summary.contains(QStringLiteral("Real Payload Length: 14")));
    UI_EXPECT(ipv6_tls_packet_sixteen_summary.contains(QStringLiteral("Original Payload Length: 64")));

    const auto ipv6_tls_packet_seventeen_index = ipv6_tls_constricted_packet_model->data(
        ipv6_tls_constricted_packet_model->index(16, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_constricted_controller.setSelectedPacketIndex(ipv6_tls_packet_seventeen_index);
    const auto ipv6_tls_packet_seventeen_summary = ipv6_tls_constricted_details_model->summaryText();
    UI_EXPECT(ipv6_tls_packet_seventeen_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_packet_seventeen_summary.contains(QStringLiteral("Original Payload Length: 92")));

    const auto ipv6_tls_packet_eighteen_index = ipv6_tls_constricted_packet_model->data(
        ipv6_tls_constricted_packet_model->index(17, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_constricted_controller.setSelectedPacketIndex(ipv6_tls_packet_eighteen_index);
    const auto ipv6_tls_packet_eighteen_summary = ipv6_tls_constricted_details_model->summaryText();
    UI_EXPECT(ipv6_tls_packet_eighteen_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_packet_eighteen_summary.contains(QStringLiteral("Original Payload Length: 362")));

    const auto ipv6_tls_packet_nineteen_index = ipv6_tls_constricted_packet_model->data(
        ipv6_tls_constricted_packet_model->index(18, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_constricted_controller.setSelectedPacketIndex(ipv6_tls_packet_nineteen_index);
    const auto ipv6_tls_packet_nineteen_summary = ipv6_tls_constricted_details_model->summaryText();
    UI_EXPECT(ipv6_tls_packet_nineteen_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_packet_nineteen_summary.contains(QStringLiteral("Original Payload Length: 62")));

    ipv6_tls_constricted_controller.setFlowDetailsTabIndex(1);
    auto* ipv6_tls_constricted_stream_model = qobject_cast<StreamListModel*>(ipv6_tls_constricted_controller.streamModel());
    UI_EXPECT(ipv6_tls_constricted_stream_model != nullptr);
    UI_EXPECT(ipv6_tls_constricted_stream_model->rowCount() == 9);

    const auto expect_ipv6_tls_stream_row = [&](const int row,
                                                const QString& expected_label,
                                                const uint expected_bytes,
                                                const QString& expected_packets,
                                                const bool expected_constricted) {
        UI_EXPECT(ipv6_tls_constricted_stream_model->data(ipv6_tls_constricted_stream_model->index(row, 0), StreamListModel::LabelRole).toString() == expected_label);
        UI_EXPECT(ipv6_tls_constricted_stream_model->data(ipv6_tls_constricted_stream_model->index(row, 0), StreamListModel::ByteCountRole).toUInt() == expected_bytes);
        UI_EXPECT(ipv6_tls_constricted_stream_model->data(ipv6_tls_constricted_stream_model->index(row, 0), StreamListModel::SourcePacketsTextRole).toString() == expected_packets);
        UI_EXPECT(ipv6_tls_constricted_stream_model->data(ipv6_tls_constricted_stream_model->index(row, 0), StreamListModel::HasConstrictedContributionRole).toBool() == expected_constricted);
    };

    expect_ipv6_tls_stream_row(0, QStringLiteral("TLS ClientHello"), 1890U, QStringLiteral("packet #4"), false);
    expect_ipv6_tls_stream_row(1, QStringLiteral("TLS ServerHello"), 1215U, QStringLiteral("packets #6,#8"), false);
    expect_ipv6_tls_stream_row(2, QStringLiteral("TLS ChangeCipherSpec"), 6U, QStringLiteral("packet #8"), false);
    expect_ipv6_tls_stream_row(3, QStringLiteral("TLS AppData"), 6485U, QStringLiteral("packets #8,#9,#10,#14"), false);
    expect_ipv6_tls_stream_row(4, QStringLiteral("TLS ChangeCipherSpec"), 6U, QStringLiteral("packet #16"), false);
    expect_ipv6_tls_stream_row(5, QStringLiteral("TLS AppData"), 58U, QStringLiteral("packet #16"), true);
    expect_ipv6_tls_stream_row(6, QStringLiteral("TLS AppData"), 92U, QStringLiteral("packet #17"), true);
    expect_ipv6_tls_stream_row(7, QStringLiteral("TLS AppData"), 362U, QStringLiteral("packet #18"), true);
    expect_ipv6_tls_stream_row(8, QStringLiteral("TLS AppData"), 62U, QStringLiteral("packet #19"), true);

    for (int row = 0; row < ipv6_tls_constricted_stream_model->rowCount(); ++row) {
        UI_EXPECT(ipv6_tls_constricted_stream_model->data(ipv6_tls_constricted_stream_model->index(row, 0), StreamListModel::LabelRole).toString() != QStringLiteral("TLS Gap"));
        UI_EXPECT(ipv6_tls_constricted_stream_model->data(ipv6_tls_constricted_stream_model->index(row, 0), StreamListModel::LabelRole).toString() != QStringLiteral("TCP Payload"));
    }

    const auto ipv6_tls_stream_item_index = ipv6_tls_constricted_stream_model->data(
        ipv6_tls_constricted_stream_model->index(5, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    ipv6_tls_constricted_controller.setSelectedStreamItemIndex(ipv6_tls_stream_item_index);
    UI_EXPECT(ipv6_tls_constricted_details_model->summaryText().contains(QStringLiteral("Label: TLS AppData")));
    UI_EXPECT(ipv6_tls_constricted_details_model->summaryText().contains(QStringLiteral("Source packet: #16")));
    UI_EXPECT(ipv6_tls_constricted_details_model->summaryText().contains(QStringLiteral("Constricted contribution: #16 contributed 8 / 58 bytes")));
    UI_EXPECT(ipv6_tls_constricted_details_model->summaryText().contains(QStringLiteral("Constricted packet #16: captured 100 / original 150 bytes.")));

    const auto ipv6_tls_strong_constricted_fixture_path = ui_test_root() / "data" / "parsing" / "tls" / "ipv6_tls_strong_constrict_1.pcap";
    MainController ipv6_tls_strong_constricted_controller {};
    UI_EXPECT(open_capture_and_wait(app, ipv6_tls_strong_constricted_controller, ipv6_tls_strong_constricted_fixture_path));
    auto* ipv6_tls_strong_flow_model = qobject_cast<FlowListModel*>(ipv6_tls_strong_constricted_controller.flowModel());
    UI_EXPECT(ipv6_tls_strong_flow_model != nullptr);
    const int ipv6_tls_strong_flow_index = find_flow_index_by_packet_count(ipv6_tls_strong_flow_model, 19U);
    UI_EXPECT(ipv6_tls_strong_flow_index >= 0);
    const int ipv6_tls_strong_flow_row = ipv6_tls_strong_flow_model->rowForFlowIndex(ipv6_tls_strong_flow_index);
    UI_EXPECT(ipv6_tls_strong_flow_row >= 0);
    UI_EXPECT(ipv6_tls_strong_flow_model->data(ipv6_tls_strong_flow_model->index(ipv6_tls_strong_flow_row, 0), FlowListModel::FamilyRole).toString() == QStringLiteral("IPv6"));
    UI_EXPECT(ipv6_tls_strong_flow_model->data(ipv6_tls_strong_flow_model->index(ipv6_tls_strong_flow_row, 0), FlowListModel::ProtocolHintRole).toString() == QStringLiteral("TLS"));
    UI_EXPECT(ipv6_tls_strong_flow_model->data(ipv6_tls_strong_flow_model->index(ipv6_tls_strong_flow_row, 0), FlowListModel::ServiceHintRole).toString() == QStringLiteral("www.youtube.com"));
    UI_EXPECT(ipv6_tls_strong_flow_model->data(ipv6_tls_strong_flow_model->index(ipv6_tls_strong_flow_row, 0), FlowListModel::AddressARole).toString().contains(QLatin1Char(':')));
    UI_EXPECT(ipv6_tls_strong_flow_model->data(ipv6_tls_strong_flow_model->index(ipv6_tls_strong_flow_row, 0), FlowListModel::AddressBRole).toString().contains(QLatin1Char(':')));

    ipv6_tls_strong_constricted_controller.setSelectedFlowIndex(ipv6_tls_strong_flow_index);
    auto* ipv6_tls_strong_packet_model = qobject_cast<PacketListModel*>(ipv6_tls_strong_constricted_controller.packetModel());
    auto* ipv6_tls_strong_details_model = qobject_cast<PacketDetailsViewModel*>(ipv6_tls_strong_constricted_controller.packetDetailsModel());
    UI_EXPECT(ipv6_tls_strong_packet_model != nullptr);
    UI_EXPECT(ipv6_tls_strong_details_model != nullptr);
    UI_EXPECT(ipv6_tls_strong_packet_model->rowCount() == 19);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 3, 1890U, 1976U, 1976U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 7, 1208U, 107U, 1294U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 8, 2416U, 94U, 2502U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 9, 2416U, 94U, 2502U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 13, 458U, 94U, 544U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 15, 64U, 100U, 150U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 16, 92U, 94U, 178U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 17, 362U, 94U, 448U);
    expect_packet_payload_row(ipv6_tls_strong_packet_model, 18, 62U, 94U, 148U);

    ipv6_tls_strong_constricted_controller.sendSelectedFlowToAnalysis();
    UI_EXPECT(wait_until(app, [&ipv6_tls_strong_constricted_controller]() {
        return !ipv6_tls_strong_constricted_controller.analysisLoading() && ipv6_tls_strong_constricted_controller.analysisAvailable();
    }));
    UI_EXPECT(ipv6_tls_strong_constricted_controller.analysisProtocolHint() == QStringLiteral("TLS"));
    UI_EXPECT(ipv6_tls_strong_constricted_controller.analysisServiceHint() == QStringLiteral("www.youtube.com"));
    const auto ipv6_tls_strong_preview = ipv6_tls_strong_constricted_controller.analysisSequencePreview();
    UI_EXPECT(ipv6_tls_strong_preview.size() == 19);
    UI_REQUIRE(ipv6_tls_strong_preview.size() >= 19);
    const auto ipv6_tls_strong_preview_packet_four = ipv6_tls_strong_preview[3].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_four.value(QStringLiteral("capturedLength")).toUInt() == 1976U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_four.value(QStringLiteral("originalLength")).toUInt() == 1976U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_four.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("1890"));
    const auto ipv6_tls_strong_preview_packet_eight = ipv6_tls_strong_preview[7].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_eight.value(QStringLiteral("capturedLength")).toUInt() == 107U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_eight.value(QStringLiteral("originalLength")).toUInt() == 1294U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_eight.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("1208"));
    const auto ipv6_tls_strong_preview_packet_nine = ipv6_tls_strong_preview[8].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_nine.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_nine.value(QStringLiteral("originalLength")).toUInt() == 2502U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_nine.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("2416"));
    const auto ipv6_tls_strong_preview_packet_ten = ipv6_tls_strong_preview[9].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_ten.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_ten.value(QStringLiteral("originalLength")).toUInt() == 2502U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_ten.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("2416"));
    const auto ipv6_tls_strong_preview_packet_fourteen = ipv6_tls_strong_preview[13].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_fourteen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_fourteen.value(QStringLiteral("originalLength")).toUInt() == 544U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_fourteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("458"));
    const auto ipv6_tls_strong_preview_packet_sixteen = ipv6_tls_strong_preview[15].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_sixteen.value(QStringLiteral("capturedLength")).toUInt() == 100U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_sixteen.value(QStringLiteral("originalLength")).toUInt() == 150U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_sixteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("64"));
    const auto ipv6_tls_strong_preview_packet_seventeen = ipv6_tls_strong_preview[16].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_seventeen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_seventeen.value(QStringLiteral("originalLength")).toUInt() == 178U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_seventeen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("92"));
    const auto ipv6_tls_strong_preview_packet_eighteen = ipv6_tls_strong_preview[17].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_eighteen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_eighteen.value(QStringLiteral("originalLength")).toUInt() == 448U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_eighteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("362"));
    const auto ipv6_tls_strong_preview_packet_nineteen = ipv6_tls_strong_preview[18].toMap();
    UI_EXPECT(ipv6_tls_strong_preview_packet_nineteen.value(QStringLiteral("capturedLength")).toUInt() == 94U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_nineteen.value(QStringLiteral("originalLength")).toUInt() == 148U);
    UI_EXPECT(ipv6_tls_strong_preview_packet_nineteen.value(QStringLiteral("transportPayloadText")).toString() == QStringLiteral("62"));

    const auto ipv6_tls_strong_packet_four_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(3, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_four_index);
    const auto ipv6_tls_strong_packet_four_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_four_summary.contains(QStringLiteral("Payload Length: 1890")));
    UI_EXPECT(!ipv6_tls_strong_packet_four_summary.contains(QStringLiteral("Real Payload Length:")));
    UI_EXPECT(!ipv6_tls_strong_packet_four_summary.contains(QStringLiteral("Original Payload Length:")));

    const auto ipv6_tls_strong_packet_eight_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(7, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_eight_index);
    const auto ipv6_tls_strong_packet_eight_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_eight_summary.contains(QStringLiteral("Real Payload Length: 21")));
    UI_EXPECT(ipv6_tls_strong_packet_eight_summary.contains(QStringLiteral("Original Payload Length: 1208")));

    const auto ipv6_tls_strong_packet_nine_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(8, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_nine_index);
    const auto ipv6_tls_strong_packet_nine_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_nine_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_strong_packet_nine_summary.contains(QStringLiteral("Original Payload Length: 2416")));

    const auto ipv6_tls_strong_packet_ten_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(9, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_ten_index);
    const auto ipv6_tls_strong_packet_ten_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_ten_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_strong_packet_ten_summary.contains(QStringLiteral("Original Payload Length: 2416")));

    const auto ipv6_tls_strong_packet_fourteen_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(13, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_fourteen_index);
    const auto ipv6_tls_strong_packet_fourteen_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_fourteen_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_strong_packet_fourteen_summary.contains(QStringLiteral("Original Payload Length: 458")));

    const auto ipv6_tls_strong_packet_sixteen_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(15, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_sixteen_index);
    const auto ipv6_tls_strong_packet_sixteen_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_sixteen_summary.contains(QStringLiteral("Real Payload Length: 14")));
    UI_EXPECT(ipv6_tls_strong_packet_sixteen_summary.contains(QStringLiteral("Original Payload Length: 64")));

    const auto ipv6_tls_strong_packet_seventeen_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(16, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_seventeen_index);
    const auto ipv6_tls_strong_packet_seventeen_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_seventeen_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_strong_packet_seventeen_summary.contains(QStringLiteral("Original Payload Length: 92")));

    const auto ipv6_tls_strong_packet_eighteen_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(17, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_eighteen_index);
    const auto ipv6_tls_strong_packet_eighteen_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_eighteen_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_strong_packet_eighteen_summary.contains(QStringLiteral("Original Payload Length: 362")));

    const auto ipv6_tls_strong_packet_nineteen_index = ipv6_tls_strong_packet_model->data(
        ipv6_tls_strong_packet_model->index(18, 0),
        PacketListModel::PacketIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedPacketIndex(ipv6_tls_strong_packet_nineteen_index);
    const auto ipv6_tls_strong_packet_nineteen_summary = ipv6_tls_strong_details_model->summaryText();
    UI_EXPECT(ipv6_tls_strong_packet_nineteen_summary.contains(QStringLiteral("Real Payload Length: 8")));
    UI_EXPECT(ipv6_tls_strong_packet_nineteen_summary.contains(QStringLiteral("Original Payload Length: 62")));

    ipv6_tls_strong_constricted_controller.setFlowDetailsTabIndex(1);
    auto* ipv6_tls_strong_stream_model = qobject_cast<StreamListModel*>(ipv6_tls_strong_constricted_controller.streamModel());
    UI_EXPECT(ipv6_tls_strong_stream_model != nullptr);
    UI_EXPECT(ipv6_tls_strong_stream_model->rowCount() == 9);

    const auto expect_ipv6_tls_strong_stream_row = [&](const int row,
                                                       const QString& expected_label,
                                                       const uint expected_bytes,
                                                       const QString& expected_packets,
                                                       const bool expected_constricted) {
        UI_EXPECT(ipv6_tls_strong_stream_model->data(ipv6_tls_strong_stream_model->index(row, 0), StreamListModel::LabelRole).toString() == expected_label);
        UI_EXPECT(ipv6_tls_strong_stream_model->data(ipv6_tls_strong_stream_model->index(row, 0), StreamListModel::ByteCountRole).toUInt() == expected_bytes);
        UI_EXPECT(ipv6_tls_strong_stream_model->data(ipv6_tls_strong_stream_model->index(row, 0), StreamListModel::SourcePacketsTextRole).toString() == expected_packets);
        UI_EXPECT(ipv6_tls_strong_stream_model->data(ipv6_tls_strong_stream_model->index(row, 0), StreamListModel::HasConstrictedContributionRole).toBool() == expected_constricted);
    };

    expect_ipv6_tls_strong_stream_row(0, QStringLiteral("TLS ClientHello"), 1890U, QStringLiteral("packet #4"), false);
    expect_ipv6_tls_strong_stream_row(1, QStringLiteral("TLS ServerHello"), 1215U, QStringLiteral("packets #6,#8"), false);
    expect_ipv6_tls_strong_stream_row(2, QStringLiteral("TLS ChangeCipherSpec"), 6U, QStringLiteral("packet #8"), false);
    expect_ipv6_tls_strong_stream_row(3, QStringLiteral("TLS AppData"), 6485U, QStringLiteral("packets #8,#9,#10,#14"), true);
    expect_ipv6_tls_strong_stream_row(4, QStringLiteral("TLS ChangeCipherSpec"), 6U, QStringLiteral("packet #16"), false);
    expect_ipv6_tls_strong_stream_row(5, QStringLiteral("TLS AppData"), 58U, QStringLiteral("packet #16"), true);
    expect_ipv6_tls_strong_stream_row(6, QStringLiteral("TLS AppData"), 92U, QStringLiteral("packet #17"), true);
    expect_ipv6_tls_strong_stream_row(7, QStringLiteral("TLS AppData"), 362U, QStringLiteral("packet #18"), true);
    expect_ipv6_tls_strong_stream_row(8, QStringLiteral("TLS AppData"), 62U, QStringLiteral("packet #19"), true);

    for (int row = 0; row < ipv6_tls_strong_stream_model->rowCount(); ++row) {
        UI_EXPECT(ipv6_tls_strong_stream_model->data(ipv6_tls_strong_stream_model->index(row, 0), StreamListModel::LabelRole).toString() != QStringLiteral("TLS Gap"));
        UI_EXPECT(ipv6_tls_strong_stream_model->data(ipv6_tls_strong_stream_model->index(row, 0), StreamListModel::LabelRole).toString() != QStringLiteral("TCP Payload"));
    }

    const auto ipv6_tls_strong_stream_item_index = ipv6_tls_strong_stream_model->data(
        ipv6_tls_strong_stream_model->index(3, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    ipv6_tls_strong_constricted_controller.setSelectedStreamItemIndex(ipv6_tls_strong_stream_item_index);
    UI_EXPECT(ipv6_tls_strong_details_model->summaryText().contains(QStringLiteral("Label: TLS AppData")));
    UI_EXPECT(ipv6_tls_strong_details_model->summaryText().contains(QStringLiteral("Source packets: #8,#9,#10,#14")));
    UI_EXPECT(ipv6_tls_strong_details_model->summaryText().contains(QStringLiteral("Constricted contributions:")));
    UI_EXPECT(ipv6_tls_strong_details_model->summaryText().contains(QStringLiteral("#8 contributed 8 / 1195 bytes")));
    UI_EXPECT(ipv6_tls_strong_details_model->summaryText().contains(QStringLiteral("#9 contributed 8 / 2416 bytes")));
    UI_EXPECT(ipv6_tls_strong_details_model->summaryText().contains(QStringLiteral("#10 contributed 8 / 2416 bytes")));
    UI_EXPECT(ipv6_tls_strong_details_model->summaryText().contains(QStringLiteral("#14 contributed 8 / 458 bytes")));

    const auto fragmented_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 6, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10});
    const auto fragmented_capture_path = write_temp_pcap(
        "pfl_ui_fragmented_packet.pcap",
        make_classic_pcap({
            {100, fragmented_packet},
            {200, make_ethernet_ipv4_tcp_packet(ipv4(192, 0, 2, 10), ipv4(192, 0, 2, 20), 2222, 443)},
        })
    );

    MainController fragmented_controller {};
    UI_EXPECT(open_capture_and_wait(app, fragmented_controller, fragmented_capture_path));
    auto* fragmented_flow_model = qobject_cast<FlowListModel*>(fragmented_controller.flowModel());
    UI_EXPECT(fragmented_flow_model != nullptr);
    UI_EXPECT(fragmented_flow_model->rowCount() == 2);

    bool saw_fragmented_flow = false;
    for (int row = 0; row < fragmented_flow_model->rowCount(); ++row) {
        const auto index = fragmented_flow_model->index(row, 0);
        if (fragmented_flow_model->data(index, FlowListModel::HasFragmentedPacketsRole).toBool()) {
            saw_fragmented_flow = true;
            UI_EXPECT(fragmented_flow_model->data(index, FlowListModel::FragmentedPacketCountRole).toString() == QStringLiteral("1"));
            fragmented_controller.setSelectedFlowIndex(
                fragmented_flow_model->data(index, FlowListModel::FlowIndexRole).toInt()
            );
            break;
        }
    }
    UI_EXPECT(saw_fragmented_flow);

    auto* fragmented_packet_model = qobject_cast<PacketListModel*>(fragmented_controller.packetModel());
    UI_EXPECT(fragmented_packet_model != nullptr);
    UI_EXPECT(fragmented_packet_model->rowCount() == 1);
    UI_EXPECT(fragmented_packet_model->data(fragmented_packet_model->index(0, 0), PacketListModel::IsIpFragmentedRole).toBool());

    fragmented_controller.setSelectedPacketIndex(0);
    auto* fragmented_details_model = qobject_cast<PacketDetailsViewModel*>(fragmented_controller.packetDetailsModel());
    UI_EXPECT(fragmented_details_model != nullptr);
    UI_EXPECT(fragmented_details_model->summaryText().contains(QStringLiteral("Warnings")));
    UI_EXPECT(fragmented_details_model->summaryText().contains(QStringLiteral("Packet is IP-fragmented")));


    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> heavy_selected_flow_packets {};
    heavy_selected_flow_packets.reserve(66);
    for (std::uint32_t packetIndex = 0; packetIndex < 65U; ++packetIndex) {
        heavy_selected_flow_packets.push_back({
            1000U + packetIndex,
            make_ethernet_ipv4_tcp_packet(ipv4(198, 51, 100, 1), ipv4(198, 51, 100, 2), 55000, 443)
        });
    }
    for (std::uint32_t packetIndex = 0; packetIndex < 30U; ++packetIndex) {
        heavy_selected_flow_packets.push_back({
            2000U + packetIndex,
            make_ethernet_ipv4_udp_packet(ipv4(198, 51, 100, 10), ipv4(198, 51, 100, 20), 53000, 53)
        });
    }

    const auto heavy_selected_flow_capture_path = write_temp_pcap(
        "pfl_ui_selected_flow_scalability.pcap",
        make_classic_pcap(heavy_selected_flow_packets)
    );

    MainController packet_loading_controller {};
    UI_EXPECT(open_capture_and_wait(app, packet_loading_controller, heavy_selected_flow_capture_path));
    auto* packet_loading_flow_model = qobject_cast<FlowListModel*>(packet_loading_controller.flowModel());
    auto* packet_loading_packet_model = qobject_cast<PacketListModel*>(packet_loading_controller.packetModel());
    auto* packet_loading_details_model = qobject_cast<PacketDetailsViewModel*>(packet_loading_controller.packetDetailsModel());
    UI_EXPECT(packet_loading_flow_model != nullptr);
    UI_EXPECT(packet_loading_packet_model != nullptr);
    UI_EXPECT(packet_loading_details_model != nullptr);

    const int heavy_flow_index = find_flow_index_by_packet_count(packet_loading_flow_model, 65U);
    const int small_flow_index = find_flow_index_by_packet_count(packet_loading_flow_model, 30U);
    UI_EXPECT(heavy_flow_index >= 0);
    UI_EXPECT(small_flow_index >= 0);

    packet_loading_controller.setSelectedFlowIndex(heavy_flow_index);
    UI_EXPECT(packet_loading_controller.loadedPacketRowCount() == 30U);
    UI_EXPECT(packet_loading_controller.totalPacketRowCount() == 65U);
    UI_EXPECT(packet_loading_controller.packetsPartiallyLoaded());
    UI_EXPECT(packet_loading_controller.canLoadMorePackets());
    UI_EXPECT(!packet_loading_controller.packetsLoading());
    UI_EXPECT(packet_loading_packet_model->rowCount() == 30);
    UI_EXPECT(packet_loading_packet_model->data(packet_loading_packet_model->index(0, 0), PacketListModel::RowNumberRole).toUInt() == 1U);
    UI_EXPECT(packet_loading_packet_model->data(packet_loading_packet_model->index(29, 0), PacketListModel::RowNumberRole).toUInt() == 30U);

    packet_loading_controller.loadMorePackets();
    UI_EXPECT(packet_loading_controller.loadedPacketRowCount() == 60U);
    UI_EXPECT(packet_loading_controller.totalPacketRowCount() == 65U);
    UI_EXPECT(packet_loading_controller.packetsPartiallyLoaded());
    UI_EXPECT(packet_loading_controller.canLoadMorePackets());
    UI_EXPECT(packet_loading_packet_model->rowCount() == 60);
    UI_EXPECT(packet_loading_packet_model->data(packet_loading_packet_model->index(30, 0), PacketListModel::RowNumberRole).toUInt() == 31U);
    UI_EXPECT(packet_loading_packet_model->data(packet_loading_packet_model->index(59, 0), PacketListModel::RowNumberRole).toUInt() == 60U);

    packet_loading_controller.setSelectedPacketIndex(10U);
    UI_EXPECT(packet_loading_controller.selectedPacketIndex() == 10U);
    UI_EXPECT(packet_loading_details_model->summaryText().contains(QStringLiteral("Packet number in file: 11")));

    packet_loading_controller.setSelectedFlowIndex(small_flow_index);
    UI_EXPECT(packet_loading_controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(packet_loading_controller.loadedPacketRowCount() == 30U);
    UI_EXPECT(packet_loading_controller.totalPacketRowCount() == 30U);
    UI_EXPECT(!packet_loading_controller.packetsPartiallyLoaded());
    UI_EXPECT(!packet_loading_controller.canLoadMorePackets());
    UI_EXPECT(packet_loading_packet_model->rowCount() == 30);
    UI_EXPECT(packet_loading_packet_model->data(packet_loading_packet_model->index(0, 0), PacketListModel::RowNumberRole).toUInt() == 1U);
    UI_EXPECT(packet_loading_packet_model->data(packet_loading_packet_model->index(29, 0), PacketListModel::RowNumberRole).toUInt() == 30U);
    UI_EXPECT(packet_loading_details_model->summaryText().isEmpty());


    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> heavy_stream_packets {};
    heavy_stream_packets.reserve(32);
    for (std::uint32_t packetIndex = 0; packetIndex < 31U; ++packetIndex) {
        heavy_stream_packets.push_back({
            3000U + packetIndex,
            make_ethernet_ipv4_tcp_packet_with_payload(ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 20), 56000, 8443, 6, 0x18)
        });
    }
    for (std::uint32_t packetIndex = 0; packetIndex < 15U; ++packetIndex) {
        heavy_stream_packets.push_back({
            4000U + packetIndex,
            make_ethernet_ipv4_tcp_packet_with_payload(ipv4(203, 0, 113, 30), ipv4(203, 0, 113, 40), 57000, 9443, 6, 0x18)
        });
    }

    const auto heavy_stream_capture_path = write_temp_pcap(
        "pfl_ui_stream_scalability.pcap",
        make_classic_pcap(heavy_stream_packets)
    );

    MainController stream_loading_controller {};
    UI_EXPECT(open_capture_and_wait(app, stream_loading_controller, heavy_stream_capture_path));
    stream_loading_controller.setFlowDetailsTabIndex(1);
    auto* stream_loading_flow_model = qobject_cast<FlowListModel*>(stream_loading_controller.flowModel());
    auto* stream_loading_stream_model = qobject_cast<StreamListModel*>(stream_loading_controller.streamModel());
    auto* stream_loading_details_model = qobject_cast<PacketDetailsViewModel*>(stream_loading_controller.packetDetailsModel());
    UI_EXPECT(stream_loading_flow_model != nullptr);
    UI_EXPECT(stream_loading_stream_model != nullptr);
    UI_EXPECT(stream_loading_details_model != nullptr);

    const int heavy_stream_flow_index = find_flow_index_by_packet_count(stream_loading_flow_model, 31U);
    const int small_stream_flow_index = find_flow_index_by_packet_count(stream_loading_flow_model, 15U);
    UI_EXPECT(heavy_stream_flow_index >= 0);
    UI_EXPECT(small_stream_flow_index >= 0);

    stream_loading_controller.setSelectedFlowIndex(heavy_stream_flow_index);
    const auto initial_heavy_loaded = stream_loading_controller.loadedStreamItemCount();
    UI_EXPECT(initial_heavy_loaded > 0U);
    UI_EXPECT(initial_heavy_loaded <= 15U);
    UI_EXPECT(stream_loading_controller.totalStreamItemCount() == 0U);
    UI_EXPECT(stream_loading_controller.streamPartiallyLoaded());
    UI_EXPECT(stream_loading_controller.canLoadMoreStreamItems());
    UI_EXPECT(!stream_loading_controller.streamLoading());
    UI_EXPECT(stream_loading_stream_model->rowCount() == static_cast<int>(initial_heavy_loaded));
    UI_EXPECT(stream_loading_stream_model->data(stream_loading_stream_model->index(0, 0), StreamListModel::StreamItemIndexRole).toULongLong() == 1U);
    UI_EXPECT(stream_loading_stream_model->data(stream_loading_stream_model->index(stream_loading_stream_model->rowCount() - 1, 0), StreamListModel::StreamItemIndexRole).toULongLong() == initial_heavy_loaded);

    stream_loading_controller.loadMoreStreamItems();
    const auto expanded_heavy_loaded = stream_loading_controller.loadedStreamItemCount();
    UI_EXPECT(expanded_heavy_loaded >= initial_heavy_loaded);
    UI_EXPECT(expanded_heavy_loaded <= 30U);
    UI_EXPECT(!stream_loading_controller.streamLoading());
    UI_EXPECT(stream_loading_stream_model->rowCount() == static_cast<int>(expanded_heavy_loaded));
    UI_EXPECT(stream_loading_stream_model->data(stream_loading_stream_model->index(0, 0), StreamListModel::StreamItemIndexRole).toULongLong() == 1U);
    UI_EXPECT(stream_loading_stream_model->data(stream_loading_stream_model->index(stream_loading_stream_model->rowCount() - 1, 0), StreamListModel::StreamItemIndexRole).toULongLong() == expanded_heavy_loaded);
    if (stream_loading_controller.canLoadMoreStreamItems()) {
        UI_EXPECT(stream_loading_controller.streamPartiallyLoaded());
        UI_EXPECT(stream_loading_controller.totalStreamItemCount() == 0U);
    } else {
        UI_EXPECT(!stream_loading_controller.streamPartiallyLoaded());
        UI_EXPECT(stream_loading_controller.totalStreamItemCount() == expanded_heavy_loaded);
    }

    const auto selected_heavy_stream_item = std::min<qulonglong>(5U, expanded_heavy_loaded);
    stream_loading_controller.setSelectedStreamItemIndex(selected_heavy_stream_item);
    UI_EXPECT(stream_loading_controller.selectedStreamItemIndex() == selected_heavy_stream_item);
    UI_EXPECT(stream_loading_details_model->detailsTitle() == QStringLiteral("Stream Item Details"));

    stream_loading_controller.setSelectedFlowIndex(small_stream_flow_index);
    const auto small_loaded = stream_loading_controller.loadedStreamItemCount();
    UI_EXPECT(stream_loading_controller.selectedStreamItemIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(small_loaded > 0U);
    UI_EXPECT(small_loaded <= 15U);
    UI_EXPECT(stream_loading_controller.totalStreamItemCount() == small_loaded);
    UI_EXPECT(!stream_loading_controller.streamPartiallyLoaded());
    UI_EXPECT(!stream_loading_controller.canLoadMoreStreamItems());
    UI_EXPECT(stream_loading_stream_model->rowCount() == static_cast<int>(small_loaded));
    UI_EXPECT(stream_loading_stream_model->data(stream_loading_stream_model->index(0, 0), StreamListModel::StreamItemIndexRole).toULongLong() == 1U);
    UI_EXPECT(stream_loading_stream_model->data(stream_loading_stream_model->index(stream_loading_stream_model->rowCount() - 1, 0), StreamListModel::StreamItemIndexRole).toULongLong() == small_loaded);
    UI_EXPECT(stream_loading_details_model->summaryText().isEmpty());

    {
        std::vector<pfl::tests::ClassicPcapCapturedRecord> cancel_packets {};
        cancel_packets.reserve(1500);
        for (std::uint32_t packetIndex = 0; packetIndex < 1500U; ++packetIndex) {
            cancel_packets.push_back(pfl::tests::ClassicPcapCapturedRecord {
                .ts_usec = 5000U + packetIndex,
                .captured_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(203, 0, 113, 50), ipv4(203, 0, 113, 60), 61000, 61001,
                    std::vector<std::uint8_t>{static_cast<std::uint8_t>(packetIndex & 0xFFU)}
                ),
                .original_length = 200U,
            });
        }

        const auto cancel_capture_path = write_temp_pcap(
            "pfl_ui_smart_export_cancel.pcap",
            make_classic_pcap_with_captured_lengths(cancel_packets)
        );
        const auto cancel_output_directory = std::filesystem::temp_directory_path() / "pfl_ui_smart_export_cancel_output";
        std::filesystem::remove_all(cancel_output_directory);

        MainController cancel_export_controller {};
        UI_EXPECT(open_capture_and_wait(app, cancel_export_controller, cancel_capture_path));
        UI_EXPECT(cancel_export_controller.browseSmartExportFlows(
            1,
            3,
            0,
            QStringLiteral(""),
            QStringLiteral(""),
            QString::fromStdWString(cancel_output_directory.wstring()),
            QStringLiteral("128"),
            false,
            false,
            QStringLiteral("")
        ));
        UI_EXPECT(cancel_export_controller.smartExportInProgress());
        cancel_export_controller.cancelSmartExport();
        UI_EXPECT(cancel_export_controller.smartExportCancelRequested());
        UI_EXPECT(wait_for_smart_export_to_finish(app, cancel_export_controller));
        UI_EXPECT(!cancel_export_controller.smartExportInProgress());
        UI_EXPECT(!cancel_export_controller.smartExportCancelRequested());
        UI_EXPECT(cancel_export_controller.statusText() == QStringLiteral("Smart export cancelled."));

        const auto retry_output_directory = std::filesystem::temp_directory_path() / "pfl_ui_smart_export_retry_output";
        std::filesystem::remove_all(retry_output_directory);
        UI_EXPECT(cancel_export_controller.browseSmartExportFlows(
            1,
            3,
            0,
            QStringLiteral(""),
            QStringLiteral(""),
            QString::fromStdWString(retry_output_directory.wstring()),
            QStringLiteral("128"),
            false,
            false,
            QStringLiteral("")
        ));
        UI_EXPECT(wait_for_smart_export_to_finish(app, cancel_export_controller));
        UI_EXPECT(!cancel_export_controller.smartExportInProgress());

        cancel_export_controller.useSimpleFlowFilter();
        UI_EXPECT(!cancel_export_controller.smartExportCurrentFilterAvailable());
        cancel_export_controller.setFlowFilterText(QStringLiteral("203.0.113.50"));
        UI_EXPECT(cancel_export_controller.smartExportCurrentFilterAvailable());
        cancel_export_controller.useAdvancedFlowFilter();
        cancel_export_controller.applyAdvancedFlowFilterDocument(make_flow_protocol_advanced_document(ProtocolId::udp));
        UI_EXPECT(cancel_export_controller.smartExportCurrentFilterAvailable());
        cancel_export_controller.applyAdvancedFlowFilterDocument(make_disabled_flow_protocol_advanced_document(ProtocolId::udp));
        UI_EXPECT(!cancel_export_controller.smartExportCurrentFilterAvailable());
        UI_EXPECT(!cancel_export_controller.browseSmartExportFlows(
            1,
            4,
            0,
            QStringLiteral(""),
            QStringLiteral(""),
            QString::fromStdWString(retry_output_directory.wstring()),
            QStringLiteral("128"),
            false,
            false,
            QStringLiteral("")
        ));
        UI_EXPECT(cancel_export_controller.statusText() ==
            QStringLiteral("Current-filter smart export requires a non-empty Simple Filter or an Advanced Filter with at least one active rule."));
    }

    run_quic_fixture_reference_tests(app, ui_test_root() / "fixtures" / "quic_fixture_01_expectations.json");
    run_quic_fixture_reference_tests(app, ui_test_root() / "fixtures" / "quic_fixture_02_expectations.json");
    } catch (const pfl::tests::TestFailure& failure) {
        record_failure_message(failure.what());
    } catch (const std::exception& exception) {
        record_failure_message(std::string {"ui test main threw unexpected exception: "} + exception.what());
    } catch (...) {
        record_failure_message("ui test main threw unknown exception");
    }

    if (has_recorded_failures()) {
        std::ostringstream builder {};
        builder << "FAILED: " << recorded_failures().size() << " expectation(s)\n";
        for (const auto& failure : recorded_failures()) {
            builder << failure.message << '\n';
        }
        emit_test_output(builder.str());
        return 1;
    }

    emit_test_output("All tests passed.\n");
    return 0;
}


































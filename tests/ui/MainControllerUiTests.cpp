#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <QApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QQmlComponent>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickStyle>
#include <QVariantMap>

#include "app/session/CaptureSession.h"
#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "cli/CliImportMode.h"
#include "ui/app/FlowListModel.h"
#include "ui/app/MainController.h"
#include "ui/app/PacketDetailsViewModel.h"
#include "ui/app/PacketListModel.h"
#include "ui/app/StreamListModel.h"

namespace {

void expect_true(const bool condition, const char* expression, const char* file, const int line) {
    if (condition) {
        return;
    }

    throw std::runtime_error(std::string(file) + ':' + std::to_string(line) + " expectation failed: " + expression);
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

#define UI_EXPECT(expr) expect_true((expr), #expr, __FILE__, __LINE__)

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
};

LoadedQmlObject load_flow_analysis_pane_component() {
    auto engine = std::make_unique<QQmlEngine>();
    const auto project_root = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
    const auto component_path = project_root / "src" / "ui" / "qml" / "components" / "FlowAnalysisPane.qml";
    QQmlComponent component(engine.get(), QUrl::fromLocalFile(QString::fromStdWString(component_path.wstring())));
    if (component.status() != QQmlComponent::Ready) {
        throw std::runtime_error(component.errorString().toStdString());
    }

    QObject* object = component.create();
    if (object == nullptr) {
        throw std::runtime_error("Failed to create FlowAnalysisPane component");
    }

    return LoadedQmlObject {
        .engine = std::move(engine),
        .object = std::unique_ptr<QObject>(object),
    };
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
        return QStringLiteral("1400-1499");
    }
    if (captured_length <= 2499U) {
        return QStringLiteral("1500-2499");
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

int find_flow_index_by_protocol_hint(pfl::FlowListModel* model, const QString& hint) {
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto index = model->index(row, 0);
        if (model->data(index, pfl::FlowListModel::ProtocolHintRole).toString() == hint) {
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

    return -1;
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

std::filesystem::path ui_test_root() {
    return std::filesystem::path(__FILE__).parent_path().parent_path();
}

QJsonObject load_json_object(const std::filesystem::path& path) {
    QFile file(QString::fromStdWString(path.wstring()));
    UI_EXPECT(file.open(QIODevice::ReadOnly));
    const auto document = QJsonDocument::fromJson(file.readAll());
    UI_EXPECT(!document.isNull());
    UI_EXPECT(document.isObject());
    return document.object();
}

std::vector<std::uint64_t> expected_packet_indices(const QJsonArray& packet_numbers) {
    std::vector<std::uint64_t> indices {};
    indices.reserve(static_cast<std::size_t>(packet_numbers.size()));
    for (const auto& value : packet_numbers) {
        const auto packet_number = value.toInteger();
        UI_EXPECT(packet_number > 0);
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

QString packet_direction_for_number(const std::vector<pfl::PacketRow>& packet_rows, const std::uint64_t packet_number) {
    const auto packet_index = packet_number - 1U;
    const auto it = std::find_if(packet_rows.begin(), packet_rows.end(), [packet_index](const pfl::PacketRow& row) {
        return row.packet_index == packet_index;
    });
    UI_EXPECT(it != packet_rows.end());
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

void run_quic_fixture_reference_tests(QApplication& app) {
    const auto spec_path = ui_test_root() / "fixtures" / "quic_fixture_01_expectations.json";
    const auto spec = load_json_object(spec_path);
    const auto fixture_relative_path = spec.value(QStringLiteral("fixture_relative_path")).toString();
    UI_EXPECT(!fixture_relative_path.isEmpty());

    const auto fixture_path = ui_test_root() / fixture_relative_path.toStdString();

    pfl::MainController controller {};
    UI_EXPECT(open_capture_and_wait(app, controller, fixture_path));

    auto* details_model = qobject_cast<pfl::PacketDetailsViewModel*>(controller.packetDetailsModel());
    auto* stream_model = qobject_cast<pfl::StreamListModel*>(controller.streamModel());
    UI_EXPECT(details_model != nullptr);
    UI_EXPECT(stream_model != nullptr);
    controller.setFlowDetailsTabIndex(1);
    controller.setSelectedFlowIndex(0);

    pfl::CaptureSession session {};
    UI_EXPECT(session.open_capture(fixture_path));

    const auto packet_rows = session.list_flow_packets(0);
    UI_EXPECT(packet_rows.size() == static_cast<std::size_t>(spec.value(QStringLiteral("packet_count")).toInteger()));

    for (const auto& packet_value : spec.value(QStringLiteral("packet_expectations")).toArray()) {
        const auto packet_expectation = packet_value.toObject();
        const auto packet_number = static_cast<std::uint64_t>(packet_expectation.value(QStringLiteral("packet_number")).toInteger());
        UI_EXPECT(packet_number > 0U);
        UI_EXPECT(packet_direction_for_number(packet_rows, packet_number) == packet_expectation.value(QStringLiteral("direction")).toString());

        controller.setSelectedPacketIndex(packet_number - 1U);
        UI_EXPECT(details_model->detailsTitle() == QStringLiteral("Packet Details"));

        const auto protocol_text = details_model->protocolText();
        UI_EXPECT(text_contains_required_fragments(protocol_text, packet_expectation.value(QStringLiteral("detail_required_substrings")).toArray()));
        UI_EXPECT(text_omits_forbidden_fragments(protocol_text, packet_expectation.value(QStringLiteral("detail_forbidden_substrings")).toArray()));
    }

    const auto stream_rows = session.list_flow_stream_items(0);

    const auto stream_sequence = spec.value(QStringLiteral("stream_sequence")).toArray();
    UI_EXPECT(controller.loadedStreamItemCount() == static_cast<qulonglong>(stream_sequence.size()));
    UI_EXPECT(controller.totalStreamItemCount() == static_cast<qulonglong>(stream_sequence.size()));
    UI_EXPECT(!controller.streamPartiallyLoaded());
    UI_EXPECT(!controller.canLoadMoreStreamItems());
    UI_EXPECT(stream_model->rowCount() == stream_sequence.size());
    bool sawProtectedPayloadInUi = false;
    for (int row = 0; row < stream_model->rowCount(); ++row) {
        if (stream_model->data(stream_model->index(row, 0), pfl::StreamListModel::LabelRole).toString() ==
            QStringLiteral("QUIC Protected Payload")) {
            sawProtectedPayloadInUi = true;
            break;
        }
    }
    UI_EXPECT(sawProtectedPayloadInUi);
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
            UI_EXPECT(row != nullptr);
            UI_EXPECT(row->protocol_text.empty() == !stream_expectation.value(QStringLiteral("expects_protocol_text")).toBool());
            UI_EXPECT(row->payload_hex_text.empty() == !stream_expectation.value(QStringLiteral("expects_payload_hex_text")).toBool());

            const auto protocol_text = QString::fromStdString(row->protocol_text);
            UI_EXPECT(text_contains_required_fragments(protocol_text, stream_expectation.value(QStringLiteral("detail_required_substrings")).toArray()));
            UI_EXPECT(text_omits_forbidden_fragments(protocol_text, stream_expectation.value(QStringLiteral("detail_forbidden_substrings")).toArray()));
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
}

}  // namespace

int main(int argc, char* argv[]) {
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    QApplication app(argc, argv);

    using namespace pfl;
    using namespace pfl::tests;

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

    UI_EXPECT(controller.tcpFlowCount() + controller.udpFlowCount() + controller.otherFlowCount() == controller.flowCount());
    UI_EXPECT(controller.tcpPacketCount() + controller.udpPacketCount() + controller.otherPacketCount() == controller.packetCount());
    UI_EXPECT(controller.tcpTotalBytes() + controller.udpTotalBytes() + controller.otherTotalBytes() == controller.totalBytes());
    UI_EXPECT(controller.ipv4FlowCount() + controller.ipv6FlowCount() == controller.flowCount());
    UI_EXPECT(controller.ipv4PacketCount() + controller.ipv6PacketCount() == controller.packetCount());
    UI_EXPECT(controller.ipv4TotalBytes() + controller.ipv6TotalBytes() == controller.totalBytes());

    UI_EXPECT(controller.statusText().isEmpty());

    {
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
        pane.object->setProperty("rateGraphAvailable", true);
        pane.object->setProperty("rateGraphStatusText", QStringLiteral(""));
        pane.object->setProperty("rateGraphWindowText", QStringLiteral("Window: 10 ms (auto)"));
        pane.object->setProperty("rateSeriesAToBModel", QVariantList {
            QVariantMap {{QStringLiteral("xUs"), 0ULL}, {QStringLiteral("xSeconds"), 0.0}, {QStringLiteral("dataPerSecond"), 30000.0}, {QStringLiteral("packetsPerSecond"), 200.0}},
            QVariantMap {{QStringLiteral("xUs"), 10000ULL}, {QStringLiteral("xSeconds"), 0.01}, {QStringLiteral("dataPerSecond"), 10000.0}, {QStringLiteral("packetsPerSecond"), 100.0}},
        });
        pane.object->setProperty("rateSeriesBToAModel", QVariantList {
            QVariantMap {{QStringLiteral("xUs"), 0ULL}, {QStringLiteral("xSeconds"), 0.0}, {QStringLiteral("dataPerSecond"), 5000.0}, {QStringLiteral("packetsPerSecond"), 50.0}},
            QVariantMap {{QStringLiteral("xUs"), 10000ULL}, {QStringLiteral("xSeconds"), 0.01}, {QStringLiteral("dataPerSecond"), 7500.0}, {QStringLiteral("packetsPerSecond"), 75.0}},
        });
        pane.object->setProperty("sequencePreviewModel", QVariantList {
            QVariantMap {
                {QStringLiteral("packetNumber"), 1U},
                {QStringLiteral("direction"), QStringLiteral("A->B")},
                {QStringLiteral("deltaTimeText"), QStringLiteral("0.000 ms")},
                {QStringLiteral("capturedLength"), 100U},
                {QStringLiteral("payloadLength"), 46U},
                {QStringLiteral("timestampText"), QStringLiteral("00:00:01.000000")},
            },
            QVariantMap {
                {QStringLiteral("packetNumber"), 2U},
                {QStringLiteral("direction"), QStringLiteral("B->A")},
                {QStringLiteral("deltaTimeText"), QStringLiteral("250.000 ms")},
                {QStringLiteral("capturedLength"), 200U},
                {QStringLiteral("payloadLength"), 146U},
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
        UI_EXPECT(named_object(pane.object.get(), "interArrivalHistogramMaxLabel") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "interArrivalHistogramMaxLabel")->property("text").toString() == QStringLiteral("max: 4"));
        UI_EXPECT(pane.object->property("packetSizeHistogramMode").toInt() == 0);
        UI_EXPECT(pane.object->property("interArrivalHistogramMode").toInt() == 0);
        UI_EXPECT(named_object(pane.object.get(), "packetSizeHistogramModeAllButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "interArrivalHistogramModeAllButton") != nullptr);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 3);
        UI_EXPECT(pane.object->property("displayedInterArrivalHistogramTotal").toInt() == 4);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateWindowLabel") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateWindowLabel")->property("text").toString() == QStringLiteral("Window: 10 ms (auto)"));
        UI_EXPECT(named_object(pane.object.get(), "analysisRateMetricDataButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateMetricPacketsButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateDirectionAToBButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateDirectionBToAButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateDirectionBothButton") != nullptr);
        UI_EXPECT(named_object(pane.object.get(), "analysisRateGraphCanvas") != nullptr);
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
        pane.object->setProperty("packetSizeHistogramMode", 1);
        pane.object->setProperty("interArrivalHistogramMode", 2);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 2);
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
        pane.object->setProperty("rateGraphAvailable", false);
        pane.object->setProperty("rateGraphStatusText", QStringLiteral("Flow too short for rate graph"));
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(item_visible(pane.object.get(), "analysisRateGraphFallbackLabel"));
    }

    MainController idle_cancel_controller {};
    idle_cancel_controller.cancelOpen();
    UI_EXPECT(!idle_cancel_controller.isOpening());
    UI_EXPECT(idle_cancel_controller.statusText().isEmpty());
    UI_EXPECT(controller.captureOpenMode() == kCliFastImportModeIndex);
    controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(controller.captureOpenMode() == kCliDeepImportModeIndex);
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

    UI_EXPECT(controller.tcpFlowCount() + controller.udpFlowCount() + controller.otherFlowCount() == controller.flowCount());
    UI_EXPECT(controller.tcpPacketCount() + controller.udpPacketCount() + controller.otherPacketCount() == controller.packetCount());
    UI_EXPECT(controller.tcpTotalBytes() + controller.udpTotalBytes() + controller.otherTotalBytes() == controller.totalBytes());
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
    UI_EXPECT(std::filesystem::exists(saved_index_path));
    UI_EXPECT(controller.statusText() == QStringLiteral("Analysis index saved successfully."));
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
    UI_EXPECT(controller.analysisTimelineFirstPacketTime() == QStringLiteral("00:00:01.000100"));
    UI_EXPECT(controller.analysisTimelineLastPacketTime() == QStringLiteral("00:00:01.000100"));
    UI_EXPECT(controller.analysisTimelineLargestGapText() == QStringLiteral("0 us"));
    UI_EXPECT(controller.analysisTimelinePacketCountConsidered() == 1U);
    UI_EXPECT(controller.analysisTimelinePacketCountConsideredText() == QStringLiteral("1"));
    UI_EXPECT(controller.analysisTotalPackets() == 1U);
    UI_EXPECT(controller.analysisTotalPacketsText() == QStringLiteral("1"));
    UI_EXPECT(controller.analysisTotalBytes() == static_cast<qulonglong>(http_flow.size()));
    UI_EXPECT(controller.analysisTotalBytesText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisEndpointSummaryText() == expected_endpoint_summary_for_flow(*analysis_flow_model, analysis_http_flow_index));
    UI_EXPECT(controller.analysisDurationText() == QStringLiteral("0 us"));
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
    UI_EXPECT(controller.analysisMaxPacketSizeAToBText() == QStringLiteral("%1 B").arg(http_flow.size()));
    UI_EXPECT(controller.analysisMaxPacketSizeBToAText().isEmpty());
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
    UI_EXPECT(controller.analysisSequencePreview().size() == 1);
    const auto first_sequence_row = controller.analysisSequencePreview().front().toMap();
    UI_EXPECT(first_sequence_row.value(QStringLiteral("packetNumber")).toULongLong() == 1U);
    UI_EXPECT(first_sequence_row.value(QStringLiteral("direction")).toString() == QStringLiteral("A->B"));
    UI_EXPECT(first_sequence_row.value(QStringLiteral("deltaTimeText")).toString() == QStringLiteral("0.000 ms"));
    UI_EXPECT(first_sequence_row.value(QStringLiteral("capturedLength")).toUInt() == static_cast<uint>(http_flow.size()));
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
    UI_EXPECT(histogram_packet_count(directional_histogram_controller.analysisPacketSizeHistogramAToB(), "1400-1499") == 1U);
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
    {
        auto pane = load_flow_analysis_pane_component();
        pane.object->setProperty("analysisAvailable", true);
        pane.object->setProperty("hasActiveFlow", true);
        pane.object->setProperty("packetSizeHistogramAllModel", directional_histogram_controller.analysisPacketSizeHistogramAll());
        pane.object->setProperty("packetSizeHistogramAToBModel", directional_histogram_controller.analysisPacketSizeHistogramAToB());
        pane.object->setProperty("packetSizeHistogramBToAModel", directional_histogram_controller.analysisPacketSizeHistogramBToA());
        pane.object->setProperty("interArrivalHistogramAllModel", directional_histogram_controller.analysisInterArrivalHistogramAll());
        pane.object->setProperty("interArrivalHistogramAToBModel", directional_histogram_controller.analysisInterArrivalHistogramAToB());
        pane.object->setProperty("interArrivalHistogramBToAModel", directional_histogram_controller.analysisInterArrivalHistogramBToA());
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("packetSizeHistogramMode").toInt() == 0);
        UI_EXPECT(pane.object->property("interArrivalHistogramMode").toInt() == 0);
        pane.object->setProperty("packetSizeHistogramMode", 2);
        pane.object->setProperty("interArrivalHistogramMode", 1);
        app.processEvents(QEventLoop::AllEvents, 25);
        UI_EXPECT(pane.object->property("displayedPacketSizeHistogramTotal").toInt() == 2);
        UI_EXPECT(pane.object->property("displayedInterArrivalHistogramTotal").toInt() == 1);
    }
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
    UI_EXPECT(sequence_csv_lines.front() == "flow_packet_index,packet_index,direction,timestamp,delta_us,captured_length,payload_length,tcp_flags,protocol_hint");

    const auto first_export_row = split_csv_line(sequence_csv_lines[1]);
    UI_EXPECT(first_export_row.size() == 9U);
    UI_EXPECT(first_export_row[0] == "1");
    UI_EXPECT(first_export_row[1] == "0");
    UI_EXPECT(first_export_row[2] == "A->B");
    UI_EXPECT(first_export_row[3] == "00:00:01.000100");
    UI_EXPECT(first_export_row[4] == "0");
    UI_EXPECT(first_export_row[5] == std::to_string(sequence_packet_a.size()));
    UI_EXPECT(first_export_row[6] == "12");
    UI_EXPECT(first_export_row[7] == "SYN");
    UI_EXPECT(first_export_row[8].empty());

    const auto second_export_row = split_csv_line(sequence_csv_lines[2]);
    UI_EXPECT(second_export_row.size() == 9U);
    UI_EXPECT(second_export_row[0] == "2");
    UI_EXPECT(second_export_row[1] == "1");
    UI_EXPECT(second_export_row[2] == "B->A");
    UI_EXPECT(second_export_row[3] == "00:00:02.000250");
    UI_EXPECT(second_export_row[4] == "1000150");
    UI_EXPECT(second_export_row[7] == "ACK|SYN");
    UI_EXPECT(second_export_row[8].empty());

    const auto third_export_row = split_csv_line(sequence_csv_lines[3]);
    UI_EXPECT(third_export_row.size() == 9U);
    UI_EXPECT(third_export_row[0] == "3");
    UI_EXPECT(third_export_row[1] == "2");
    UI_EXPECT(third_export_row[2] == "A->B");
    UI_EXPECT(third_export_row[3] == "00:00:03.000500");
    UI_EXPECT(third_export_row[4] == "1000250");
    UI_EXPECT(third_export_row[7] == "ACK|PSH");
    UI_EXPECT(third_export_row[8].empty());

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

    controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(open_index_and_wait(app, controller, index_path));
    UI_EXPECT(controller.captureOpenMode() == kCliDeepImportModeIndex);
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
    UI_EXPECT(!partial_controller.canSaveIndex());
    UI_EXPECT(partial_controller.partialOpen());
    UI_EXPECT(partial_controller.openErrorText().isEmpty());
    UI_EXPECT(partial_controller.statusText().contains(QStringLiteral("Capture opened partially.")));
    UI_EXPECT(partial_controller.statusText().contains(QStringLiteral("Results are incomplete.")));
    UI_EXPECT(partial_controller.partialOpenWarningText().contains(QStringLiteral("Capture opened partially.")));
    auto* partial_packet_model = qobject_cast<PacketListModel*>(partial_controller.packetModel());
    UI_EXPECT(partial_packet_model != nullptr);
    partial_controller.setSelectedFlowIndex(0);
    UI_EXPECT(partial_packet_model->rowCount() == 1);
    UI_EXPECT(!partial_controller.saveAnalysisIndex(QString::fromStdWString((std::filesystem::temp_directory_path() / "pfl_ui_partial_should_not_save.idx").wstring())));
    UI_EXPECT(partial_controller.statusText() == QStringLiteral("Saving an index from a partial capture is not supported yet."));
    UI_EXPECT(partial_controller.statusIsError());
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
    UI_EXPECT(quic_flow_model->data(quic_flow_model->index(0, 0), FlowListModel::ServiceHintRole).toString().isEmpty());
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
    UI_EXPECT(quic_details_model->detailsTitle() == QStringLiteral("Packet Details"));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("QUIC")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("Packet Type: Initial")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("bag.itunes.apple.com")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("TLS Handshake Type: ClientHello")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("Cipher Suites:")));

    quic_controller.setFlowDetailsTabIndex(1);
    UI_EXPECT(quic_stream_model->rowCount() >= 1);
    const auto find_quic_initial_like_row = [](StreamListModel* model) {
        for (int row = 0; row < model->rowCount(); ++row) {
            const auto label = model->data(model->index(row, 0), StreamListModel::LabelRole).toString();
            if (label == QStringLiteral("QUIC CRYPTO") || label == QStringLiteral("QUIC Initial")) {
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
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("QUIC")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("Packet Type: Initial")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("bag.itunes.apple.com")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("TLS Handshake Type: ClientHello")));
    UI_EXPECT(quic_details_model->protocolText().contains(QStringLiteral("Cipher Suites:")));

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
    UI_EXPECT(quic_youtube_details_model->protocolText().contains(QStringLiteral("Packet Type: Initial")));
    UI_EXPECT(quic_youtube_details_model->protocolText().contains(QStringLiteral("www.youtube.com")));
    UI_EXPECT(quic_youtube_details_model->protocolText().contains(QStringLiteral("TLS Handshake Type: ClientHello")));

    quic_youtube_controller.setFlowDetailsTabIndex(1);
    const int quic_youtube_initial_row = find_quic_initial_like_row(quic_youtube_stream_model);
    UI_EXPECT(quic_youtube_initial_row >= 0);
    const auto quic_youtube_stream_item_index = quic_youtube_stream_model->data(
        quic_youtube_stream_model->index(quic_youtube_initial_row, 0),
        StreamListModel::StreamItemIndexRole
    ).toULongLong();
    quic_youtube_controller.setSelectedStreamItemIndex(quic_youtube_stream_item_index);
    UI_EXPECT(quic_youtube_details_model->protocolText().contains(QStringLiteral("Packet Type: Initial")));
    UI_EXPECT(quic_youtube_details_model->protocolText().contains(QStringLiteral("www.youtube.com")));
    UI_EXPECT(quic_youtube_details_model->protocolText().contains(QStringLiteral("TLS Handshake Type: ClientHello")));

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
    UI_EXPECT(quic_tiktok_details_model->protocolText().contains(QStringLiteral("Packet Type: Initial")));
    UI_EXPECT(quic_tiktok_details_model->protocolText().contains(QStringLiteral("log22-normal-useast1a.tiktokv.com")));
    UI_EXPECT(quic_tiktok_details_model->protocolText().contains(QStringLiteral("TLS Handshake Type: ClientHello")));
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

    retransmit_controller.setSelectedFlowIndex(retransmit_flow_model->data(retransmit_flow_model->index(0, 0), FlowListModel::FlowIndexRole).toInt());
    auto* retransmit_packet_model = qobject_cast<PacketListModel*>(retransmit_controller.packetModel());
    UI_EXPECT(retransmit_packet_model != nullptr);
    UI_EXPECT(retransmit_packet_model->rowCount() == 2);
    UI_EXPECT(!retransmit_packet_model->data(retransmit_packet_model->index(0, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());
    UI_EXPECT(retransmit_packet_model->data(retransmit_packet_model->index(1, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());

    retransmit_controller.setSelectedFlowIndex(retransmit_flow_model->data(retransmit_flow_model->index(1, 0), FlowListModel::FlowIndexRole).toInt());
    UI_EXPECT(retransmit_packet_model->rowCount() == 2);
    UI_EXPECT(!retransmit_packet_model->data(retransmit_packet_model->index(0, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());
    UI_EXPECT(!retransmit_packet_model->data(retransmit_packet_model->index(1, 0), PacketListModel::SuspectedTcpRetransmissionRole).toBool());

    controller.setSelectedPacketIndex(0);
    auto* details_model = qobject_cast<PacketDetailsViewModel*>(controller.packetDetailsModel());
    UI_EXPECT(details_model != nullptr);
    UI_EXPECT(details_model->hasPacket());
    UI_EXPECT(details_model->summaryText().contains(QStringLiteral("Packet index in file: 0")));
    UI_EXPECT(details_model->payloadText().contains(QStringLiteral("47 45 54 20 2f")));
    UI_EXPECT(!details_model->protocolText().isEmpty());

    controller.setCurrentTabIndex(2);
    controller.drillDownToEndpoint(QStringLiteral("10.0.0.1:1111"));

    UI_EXPECT(controller.currentTabIndex() == 0);
    UI_EXPECT(controller.flowFilterText() == QStringLiteral("10.0.0.1:1111"));
    UI_EXPECT(controller.selectedFlowIndex() == -1);
    UI_EXPECT(!controller.canExportSelectedFlow());
    UI_EXPECT(controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(details_model->payloadText().isEmpty());
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
    auto possible_tls_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Possible TLS"));
    auto possible_quic_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Possible QUIC"));
    auto unknown_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Unknown"));
    UI_EXPECT(possible_tls_row.value(QStringLiteral("flows")).toULongLong() == 0U);
    UI_EXPECT(possible_quic_row.value(QStringLiteral("flows")).toULongLong() == 0U);
    UI_EXPECT(unknown_row.value(QStringLiteral("flows")).toULongLong() == 3U);

    possible_hint_controller.setUsePossibleTlsQuic(true);
    UI_EXPECT(possible_hint_controller.usePossibleTlsQuic());
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible TLS")) >= 0);
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible QUIC")) >= 0);
    possible_tls_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Possible TLS"));
    possible_quic_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Possible QUIC"));
    unknown_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Unknown"));
    UI_EXPECT(possible_tls_row.value(QStringLiteral("flows")).toULongLong() == 1U);
    UI_EXPECT(possible_quic_row.value(QStringLiteral("flows")).toULongLong() == 1U);
    UI_EXPECT(unknown_row.value(QStringLiteral("flows")).toULongLong() == 1U);

    possible_hint_controller.setUsePossibleTlsQuic(false);
    UI_EXPECT(!possible_hint_controller.usePossibleTlsQuic());
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible TLS")) < 0);
    UI_EXPECT(find_flow_index_by_protocol_hint(possible_hint_flow_model, QStringLiteral("Possible QUIC")) < 0);
    unknown_row = find_protocol_distribution_row(possible_hint_controller.protocolHintDistribution(), QStringLiteral("Unknown"));
    UI_EXPECT(unknown_row.value(QStringLiteral("flows")).toULongLong() == 3U);

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
    UI_EXPECT(stream_details_model->summaryText().contains(QString::fromUtf8("Direction: A\xE2\x86\x92" "B")));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Label: HTTP GET /")));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Packets: 1")));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Source packets: 1")));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Details source: Stream item")));
    UI_EXPECT(stream_details_model->payloadText().contains(QStringLiteral("47 45 54 20 2f")));
    UI_EXPECT(stream_details_model->protocolText().contains(QStringLiteral("HTTP")));
    UI_EXPECT(stream_details_model->protocolText().contains(QStringLiteral("Method: GET")));
    UI_EXPECT(stream_details_model->protocolText().contains(QStringLiteral("Path: /")));
    UI_EXPECT(stream_details_model->protocolText().contains(QStringLiteral("Host:")));

    stream_controller.setSelectedPacketIndex(0);
    UI_EXPECT(stream_controller.selectedPacketIndex() == 0U);
    UI_EXPECT(stream_details_model->detailsTitle() == QStringLiteral("Packet Details"));
    UI_EXPECT(stream_details_model->summaryText().contains(QStringLiteral("Packet index in file: 0")));

    stream_controller.setSelectedFlowIndex(dns_stream_flow_index);
    UI_EXPECT(stream_model->rowCount() == 1);
    UI_EXPECT(stream_controller.selectedStreamItemIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(stream_controller.selectedPacketIndex() == std::numeric_limits<qulonglong>::max());
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::LabelRole).toString() == QStringLiteral("UDP Payload"));
    UI_EXPECT(stream_model->data(stream_model->index(0, 0), StreamListModel::ByteCountRole).toUInt() == make_dns_query_payload().size());

    stream_controller.setSelectedFlowIndex(-1);
    UI_EXPECT(stream_model->rowCount() == 0);

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
    UI_EXPECT(split_tls_details_model->summaryText().contains(QStringLiteral("Packets: 2")));
    UI_EXPECT(split_tls_details_model->summaryText().contains(QStringLiteral("Source packets: 1\u20132")));
    UI_EXPECT(split_tls_details_model->summaryText().contains(QStringLiteral("Details source: Stream item")));

    const auto tls_capture_path = std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "tls" / "tls_client_hello_1.pcap";
    MainController deep_controller {};
    deep_controller.setCaptureOpenMode(kCliDeepImportModeIndex);
    UI_EXPECT(open_capture_and_wait(app, deep_controller, tls_capture_path));
    deep_controller.setSelectedFlowIndex(0);
    deep_controller.setSelectedPacketIndex(0);
    auto* deep_details_model = qobject_cast<PacketDetailsViewModel*>(deep_controller.packetDetailsModel());
    UI_EXPECT(deep_details_model != nullptr);
    UI_EXPECT(deep_details_model->protocolText().contains(QStringLiteral("TLS")));
    UI_EXPECT(deep_details_model->protocolText().contains(QStringLiteral("auth.split.io")));

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
    UI_EXPECT(packet_loading_details_model->summaryText().contains(QStringLiteral("Packet index in file: 10")));

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

    run_quic_fixture_reference_tests(app);

    return 0;
}


































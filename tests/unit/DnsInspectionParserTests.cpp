#include <array>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/services/DnsInspectionParser.h"
#include "core/services/PacketPayloadService.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

std::vector<std::uint8_t> require_fixture_transport_payload(
    const std::filesystem::path& relative_path,
    const std::uint64_t packet_index = 0U
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path), CaptureImportOptions {}));
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    const auto packet_bytes = session.read_packet_data(*packet);
    PacketPayloadService payload_service {};
    const auto payload = payload_service.extract_transport_payload(packet_bytes, packet->data_link_type);
    PFL_REQUIRE(!payload.empty());
    return payload;
}

void expect_a_rdata(const DnsRdata& rdata, const std::array<std::uint8_t, 4>& expected) {
    PFL_EXPECT(rdata.kind == DnsRdataKind::a);
    PFL_EXPECT(rdata.parse_status == DnsRdataParseStatus::parsed);
    PFL_EXPECT(rdata.address_size == 4U);
    for (std::size_t index = 0U; index < expected.size(); ++index) {
        PFL_EXPECT(rdata.address_bytes[index] == expected[index]);
    }
}

void expect_aaaa_rdata(const DnsRdata& rdata, const std::array<std::uint8_t, 16>& expected) {
    PFL_EXPECT(rdata.kind == DnsRdataKind::aaaa);
    PFL_EXPECT(rdata.parse_status == DnsRdataParseStatus::parsed);
    PFL_EXPECT(rdata.address_size == 16U);
    for (std::size_t index = 0U; index < expected.size(); ++index) {
        PFL_EXPECT(rdata.address_bytes[index] == expected[index]);
    }
}

}  // namespace

void run_dns_inspection_parser_tests() {
    DnsInspectionParser parser {};

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/03_dns_ipv4_a_query.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.transaction_id == 0x1001U);
        PFL_EXPECT(!message.is_response);
        PFL_EXPECT(message.declared_question_count == 1U);
        PFL_EXPECT(message.questions.size() == 1U);
        PFL_EXPECT(message.questions[0].name == "a-query.example.test");
        PFL_EXPECT(message.questions[0].type == 1U);
        PFL_EXPECT(message.questions[0].raw_class == 1U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/04_dns_ipv4_a_response_compressed.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.is_response);
        PFL_EXPECT(message.questions.size() == 1U);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.answers[0].name == "www.example.test");
        PFL_EXPECT(message.answers[0].ttl == 300U);
        expect_a_rdata(message.answers[0].rdata, {192U, 0U, 2U, 44U});
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/06_dns_ipv6_aaaa_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        expect_aaaa_rdata(
            message.answers[0].rdata,
            {0x20U, 0x01U, 0x0dU, 0xb8U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x44U});
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/07_dns_ipv4_cname_response_compressed.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.answers[0].name == "alias.example.test");
        PFL_EXPECT(message.answers[0].rdata.kind == DnsRdataKind::cname);
        PFL_EXPECT(message.answers[0].rdata.parse_status == DnsRdataParseStatus::parsed);
        PFL_EXPECT(message.answers[0].rdata.name == "real.example.test");
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/08_dns_ipv4_multiple_answers_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.declared_answer_count == 2U);
        PFL_EXPECT(message.answers.size() == 2U);
        expect_a_rdata(message.answers[0].rdata, {192U, 0U, 2U, 80U});
        expect_a_rdata(message.answers[1].rdata, {192U, 0U, 2U, 81U});
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/09_dns_ipv4_nxdomain_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.is_response);
        PFL_EXPECT(message.response_code == 3U);
        PFL_EXPECT(message.declared_answer_count == 0U);
        PFL_EXPECT(message.answers.empty());
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/11_dns_ipv4_ptr_query.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.questions.size() == 1U);
        PFL_EXPECT(message.questions[0].name == "44.2.0.192.in-addr.arpa");
        PFL_EXPECT(message.questions[0].type == 12U);
        PFL_EXPECT(message.questions[0].raw_class == 1U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/10_dns_ipv4_https_query.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.questions.size() == 1U);
        PFL_EXPECT(message.questions[0].type == 65U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/12_dns_ipv4_srv_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.answers[0].rdata.kind == DnsRdataKind::srv);
        PFL_EXPECT(message.answers[0].rdata.parse_status == DnsRdataParseStatus::parsed);
        PFL_EXPECT(message.answers[0].rdata.srv_priority == 0U);
        PFL_EXPECT(message.answers[0].rdata.srv_weight == 0U);
        PFL_EXPECT(message.answers[0].rdata.srv_port == 12345U);
        PFL_EXPECT(message.answers[0].rdata.srv_target == "service-host.example.test");
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/13_dns_ipv4_txt_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.answers[0].rdata.kind == DnsRdataKind::txt);
        PFL_EXPECT(message.answers[0].rdata.parse_status == DnsRdataParseStatus::parsed);
        PFL_EXPECT(message.answers[0].rdata.txt_chunks.size() == 2U);
        PFL_EXPECT(std::string(
            reinterpret_cast<const char*>(message.answers[0].rdata.txt_chunks[0].bytes.data()),
            message.answers[0].rdata.txt_chunks[0].bytes.size()) == "path=/demo");
        PFL_EXPECT(std::string(
            reinterpret_cast<const char*>(message.answers[0].rdata.txt_chunks[1].bytes.data()),
            message.answers[0].rdata.txt_chunks[1].bytes.size()) == "ver=1");
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/17_dns_ipv4_unknown_rr_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.answers[0].type == 65280U);
        PFL_EXPECT(message.answers[0].rdlength == 4U);
        PFL_EXPECT(message.answers[0].rdata.kind == DnsRdataKind::opaque);
        PFL_EXPECT(message.answers[0].rdata.parse_status == DnsRdataParseStatus::not_supported);
        PFL_EXPECT(message.answers[0].rdata.opaque_bytes == std::vector<std::uint8_t>({0xDEU, 0xADU, 0xBEU, 0xEFU}));
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/14_dns_ipv4_truncated_message.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::truncated);
        PFL_EXPECT(message.transaction_id == 0x4001U);
        PFL_EXPECT(message.declared_question_count == 1U);
        PFL_EXPECT(message.questions.empty());
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/15_dns_ipv4_malformed_pointer_oob.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::malformed);
        PFL_EXPECT(message.declared_question_count == 1U);
        PFL_EXPECT(message.questions.empty());
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/dns/16_dns_ipv4_malformed_pointer_loop.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::malformed);
        PFL_EXPECT(message.declared_question_count == 1U);
        PFL_EXPECT(message.questions.empty());
    }

    {
        const auto message = parser.inspect(std::span<const std::uint8_t> {});
        PFL_EXPECT(message.status == DnsInspectionStatus::not_enough_header);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/01_mdns_ipv4_ptr_query.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.questions.size() == 1U);
        PFL_EXPECT(message.questions[0].name == "_demo-service._tcp.local");
        PFL_EXPECT(message.questions[0].type == 12U);
        PFL_EXPECT(message.questions[0].raw_class == 1U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/02_mdns_ipv6_ptr_query.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.questions.size() == 1U);
        PFL_EXPECT(message.questions[0].name == "_demo-service._tcp.local");
        PFL_EXPECT(message.questions[0].type == 12U);
        PFL_EXPECT(message.questions[0].raw_class == 1U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/04_mdns_ipv4_dns_sd_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.additionals.size() == 3U);
        PFL_EXPECT(message.answers[0].rdata.kind == DnsRdataKind::ptr);
        PFL_EXPECT(message.answers[0].rdata.name == "Example Device._demo-service._tcp.local");
        PFL_EXPECT(message.additionals[0].rdata.kind == DnsRdataKind::srv);
        PFL_EXPECT(message.additionals[0].rdata.srv_target == "example-device.local");
        PFL_EXPECT(message.additionals[1].rdata.kind == DnsRdataKind::txt);
        PFL_EXPECT(message.additionals[1].rdata.txt_chunks.size() == 2U);
        expect_a_rdata(message.additionals[2].rdata, {192U, 0U, 2U, 44U});
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/03_mdns_ipv4_ptr_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.answers[0].rdata.kind == DnsRdataKind::ptr);
        PFL_EXPECT(message.answers[0].rdata.parse_status == DnsRdataParseStatus::parsed);
        PFL_EXPECT(message.answers[0].rdata.name == "Example Device._demo-service._tcp.local");
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/05_mdns_ipv6_dns_sd_response_aaaa.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.additionals.size() == 3U);
        expect_aaaa_rdata(
            message.additionals[2].rdata,
            {0x20U, 0x01U, 0x0dU, 0xb8U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x44U});
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/06_mdns_ipv4_multiple_questions.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.declared_question_count == 2U);
        PFL_EXPECT(message.questions.size() == 2U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/07_mdns_ipv4_multiple_answers.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.declared_answer_count == 2U);
        PFL_EXPECT(message.answers.size() == 2U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/08_mdns_ipv4_cache_flush_response.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.answers.size() == 1U);
        PFL_EXPECT(message.answers[0].raw_class == 0x8001U);
    }

    {
        const auto payload = require_fixture_transport_payload("parsing/mdns/09_mdns_ipv4_qu_question.pcap");
        const auto message = parser.inspect(payload);
        PFL_EXPECT(message.status == DnsInspectionStatus::complete);
        PFL_EXPECT(message.questions.size() == 1U);
        PFL_EXPECT(message.questions[0].raw_class == 0x8001U);
    }
}

}  // namespace pfl::tests

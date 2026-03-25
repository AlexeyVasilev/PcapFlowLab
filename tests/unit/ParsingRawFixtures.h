#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace pfl::tests::legacy_raw_fixtures {

namespace http_get_1_data {
#include "legacy_parsing_fixtures/http/parsing_HTTP_request_get_1.h"
}

namespace http_answer_2_data {
#include "legacy_parsing_fixtures/http/parsing_HTTP_answer_2.h"
}

namespace dns_request_1_data {
#include "legacy_parsing_fixtures/dns/parsing_dns_request_1.h"
}

namespace dns_response_2_data {
#include "legacy_parsing_fixtures/dns/parsing_dns_response_2.h"
}

namespace tls_1_2_client_hello_1_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_2_ClientHello_1.h"
}

namespace tls_1_2_change_cipher_spec_2_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_2_ChangeCipherSpec_2.h"
}

namespace tls_1_2_app_data_3_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_2_AppData_3.h"
}

namespace tls_1_2_server_hello_4_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_2_ServerHello_4.h"
}

namespace tls_1_2_new_session_ticket_9_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_2_NewSessinTicket_andOther_9.h"
}

namespace tls_1_3_client_hello_5_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_3_ClientHello_5.h"
}

namespace tls_1_3_server_hello_6_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_3_ServerHello_6.h"
}

namespace tls_1_3_app_data_7_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_3_AppData_7.h"
}

namespace tls_1_3_change_cipher_spec_8_data {
#include "legacy_parsing_fixtures/tls/parsing_TLS_1_3_ChangeCipherSpec_8.h"
}

namespace quic_initial_ch_1_data {
#include "legacy_parsing_fixtures/quic/parsing_initial_CH_1.h"
}

namespace quic_initial_sh_2_data {
#include "legacy_parsing_fixtures/quic/parsing_initial_SH_2.h"
}

namespace quic_handshake_3_data {
#include "legacy_parsing_fixtures/quic/parsing_handshake_3.h"
}

namespace quic_protected_payload_4_data {
#include "legacy_parsing_fixtures/quic/parsing_protected_payload_4.h"
}

inline std::span<const std::uint8_t> http_get_1() {
    return {http_get_1_data::Packet_HTTP_GET_Request, sizeof(http_get_1_data::Packet_HTTP_GET_Request)};
}

inline std::span<const std::uint8_t> http_answer_2() {
    return {http_answer_2_data::Packet_HTTP_Response, sizeof(http_answer_2_data::Packet_HTTP_Response)};
}

inline std::span<const std::uint8_t> dns_request_1() {
    return {dns_request_1_data::Packet_DNS_Request, sizeof(dns_request_1_data::Packet_DNS_Request)};
}

inline std::span<const std::uint8_t> dns_response_2() {
    return {dns_response_2_data::Packet_DNS_Response, sizeof(dns_response_2_data::Packet_DNS_Response)};
}

inline std::span<const std::uint8_t> tls_1_2_client_hello_1() {
    return {tls_1_2_client_hello_1_data::Packet_TLS_ClientHello, sizeof(tls_1_2_client_hello_1_data::Packet_TLS_ClientHello)};
}

inline std::span<const std::uint8_t> tls_1_2_change_cipher_spec_2() {
    return {tls_1_2_change_cipher_spec_2_data::Packet_TLS_ChangeCipherSpec, sizeof(tls_1_2_change_cipher_spec_2_data::Packet_TLS_ChangeCipherSpec)};
}

inline std::span<const std::uint8_t> tls_1_2_app_data_3() {
    return {tls_1_2_app_data_3_data::Packet_TLS_AppData, sizeof(tls_1_2_app_data_3_data::Packet_TLS_AppData)};
}

inline std::span<const std::uint8_t> tls_1_2_server_hello_4() {
    return {tls_1_2_server_hello_4_data::Packet_TLS_ServerHello, sizeof(tls_1_2_server_hello_4_data::Packet_TLS_ServerHello)};
}

inline std::span<const std::uint8_t> tls_1_2_new_session_ticket_9() {
    return {tls_1_2_new_session_ticket_9_data::Packet_TLS12_NewSessionTicket, sizeof(tls_1_2_new_session_ticket_9_data::Packet_TLS12_NewSessionTicket)};
}

inline std::span<const std::uint8_t> tls_1_3_client_hello_5() {
    return {tls_1_3_client_hello_5_data::Packet_TLS13_ClientHello, sizeof(tls_1_3_client_hello_5_data::Packet_TLS13_ClientHello)};
}

inline std::span<const std::uint8_t> tls_1_3_server_hello_6() {
    return {tls_1_3_server_hello_6_data::Packet_TLS13_ServerHello, sizeof(tls_1_3_server_hello_6_data::Packet_TLS13_ServerHello)};
}

inline std::span<const std::uint8_t> tls_1_3_app_data_7() {
    return {tls_1_3_app_data_7_data::Packet_TLS13_AppData, sizeof(tls_1_3_app_data_7_data::Packet_TLS13_AppData)};
}

inline std::span<const std::uint8_t> tls_1_3_change_cipher_spec_8() {
    return {tls_1_3_change_cipher_spec_8_data::Packet_TLS13_ChangeCipherSpec, sizeof(tls_1_3_change_cipher_spec_8_data::Packet_TLS13_ChangeCipherSpec)};
}

inline std::span<const std::uint8_t> quic_initial_ch_1() {
    return {quic_initial_ch_1_data::Packet_1, sizeof(quic_initial_ch_1_data::Packet_1)};
}

inline std::span<const std::uint8_t> quic_initial_sh_2() {
    return {quic_initial_sh_2_data::Packet_1, sizeof(quic_initial_sh_2_data::Packet_1)};
}

inline std::span<const std::uint8_t> quic_handshake_3() {
    return {quic_handshake_3_data::Packet_1, sizeof(quic_handshake_3_data::Packet_1)};
}

inline std::span<const std::uint8_t> quic_protected_payload_4() {
    return {quic_protected_payload_4_data::Packet_1, sizeof(quic_protected_payload_4_data::Packet_1)};
}

}  // namespace pfl::tests::legacy_raw_fixtures

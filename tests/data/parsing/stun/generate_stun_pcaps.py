from __future__ import annotations

import argparse
import ipaddress
import zlib
from pathlib import Path

try:
    from scapy.all import Ether, IP, IPv6, PcapWriter, Raw, UDP
except ImportError as error:
    raise SystemExit("Scapy is required to generate STUN fixtures: pip install scapy") from error


CLIENT_MAC = "02:00:00:00:42:01"
SERVER_MAC = "02:00:00:00:42:02"
CLIENT_IP = "192.0.2.30"
SERVER_IP = "192.0.2.40"
CLIENT_IPV6 = "2001:db8:1::30"
SERVER_IPV6 = "2001:db8:1::40"
CLIENT_PORT = 51000
STUN_PORT = 3478
NON_STANDARD_STUN_PORT = 45678
MAGIC_COOKIE = b"\x21\x12\xa4\x42"
BAD_MAGIC_COOKIE = b"\x21\x12\xa4\x43"
MAGIC_COOKIE_INT = 0x2112A442
TRANSACTION_ID = bytes.fromhex("101112132021222330313233")
BASE_TIME = 1_700_200_000.0

BINDING_METHOD = 0x001
CLASS_REQUEST = 0
CLASS_INDICATION = 1
CLASS_SUCCESS_RESPONSE = 2
CLASS_ERROR_RESPONSE = 3

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_MESSAGE_INTEGRITY_SHA256 = 0x001C
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_PRIORITY = 0x0024
ATTR_USE_CANDIDATE = 0x0025
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
ATTR_ICE_CONTROLLED = 0x8029
ATTR_ICE_CONTROLLING = 0x802A
ATTR_UNKNOWN_REQUIRED = 0x1234
ATTR_UNKNOWN_OPTIONAL = 0x8123


def stun_message(message_type: int, *, message_length: int = 0, cookie: bytes = MAGIC_COOKIE) -> bytes:
    return message_type.to_bytes(2, "big") + message_length.to_bytes(2, "big") + cookie + TRANSACTION_ID


def make_udp_packet(
    *,
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ip_id: int,
    timestamp_offset: int,
):
    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, id=ip_id, ttl=64)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=payload)
    )
    packet.time = BASE_TIME + timestamp_offset
    return packet


def write_pcap(path: Path, packets: list) -> None:
    writer = PcapWriter(str(path), linktype=1, append=False, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def legacy_fixtures_01_06() -> dict[str, list]:
    binding_request = stun_message(0x0001)
    success_response = stun_message(0x0101)
    bad_cookie_request = stun_message(0x0001, cookie=BAD_MAGIC_COOKIE)
    invalid_top_bits = stun_message(0x8001)
    declared_length_mismatch = stun_message(0x0001, message_length=4)

    return {
        "01_stun_binding_request_3478.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=binding_request,
                ip_id=0x4201,
                timestamp_offset=1,
            )
        ],
        "02_stun_binding_request_response.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=binding_request,
                ip_id=0x4202,
                timestamp_offset=2,
            ),
            make_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=CLIENT_MAC,
                src_ip=SERVER_IP,
                dst_ip=CLIENT_IP,
                src_port=STUN_PORT,
                dst_port=CLIENT_PORT,
                payload=success_response,
                ip_id=0x4203,
                timestamp_offset=3,
            ),
        ],
        "03_stun_binding_request_nonstandard_port.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=NON_STANDARD_STUN_PORT,
                payload=binding_request,
                ip_id=0x4204,
                timestamp_offset=4,
            )
        ],
        "04_stun_bad_magic_cookie.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=bad_cookie_request,
                ip_id=0x4205,
                timestamp_offset=5,
            )
        ],
        "05_stun_invalid_top_bits.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=invalid_top_bits,
                ip_id=0x4206,
                timestamp_offset=6,
            )
        ],
        "06_stun_declared_length_mismatch.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=declared_length_mismatch,
                ip_id=0x4207,
                timestamp_offset=7,
            )
        ],
    }


def stun_message_type(method: int, message_class: int) -> int:
    if not 0 <= method <= 0x0FFF:
        raise ValueError("STUN method must fit 12 bits")
    if not 0 <= message_class <= 0x03:
        raise ValueError("STUN class must fit 2 bits")
    return (
        (method & 0x000F) |
        ((method & 0x0070) << 1) |
        ((method & 0x0F80) << 2) |
        ((message_class & 0x01) << 4) |
        ((message_class & 0x02) << 7)
    )


def padding_for(value_length: int) -> bytes:
    return b"\x00" * ((4 - (value_length % 4)) % 4)


def stun_attribute(attribute_type: int, value: bytes) -> bytes:
    return attribute_type.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value + padding_for(len(value))


def stun_header(message_type: int, transaction_id: bytes, body_length: int) -> bytes:
    if len(transaction_id) != 12:
        raise ValueError("STUN transaction ID must be 12 bytes")
    return message_type.to_bytes(2, "big") + body_length.to_bytes(2, "big") + MAGIC_COOKIE + transaction_id


def stun_message_from_attributes(message_type: int, transaction_id: bytes, attributes: list[bytes]) -> bytes:
    body = b"".join(attributes)
    return stun_header(message_type, transaction_id, len(body)) + body


def add_fingerprint(message_type: int, transaction_id: bytes, attributes: list[bytes]) -> bytes:
    body_before_fingerprint = b"".join(attributes)
    body_length_with_fingerprint = len(body_before_fingerprint) + 8
    crc_input = stun_header(message_type, transaction_id, body_length_with_fingerprint) + body_before_fingerprint
    fingerprint = (zlib.crc32(crc_input) & 0xFFFFFFFF) ^ 0x5354554E
    return (
        stun_header(message_type, transaction_id, body_length_with_fingerprint) +
        body_before_fingerprint +
        stun_attribute(ATTR_FINGERPRINT, fingerprint.to_bytes(4, "big"))
    )


def text_attribute(attribute_type: int, value: str) -> bytes:
    return stun_attribute(attribute_type, value.encode("utf-8"))


def uint32_attribute(attribute_type: int, value: int) -> bytes:
    return stun_attribute(attribute_type, value.to_bytes(4, "big"))


def uint64_attribute(attribute_type: int, value: int) -> bytes:
    return stun_attribute(attribute_type, value.to_bytes(8, "big"))


def mapped_address_attribute(attribute_type: int, address: str, port: int) -> bytes:
    ip = ipaddress.ip_address(address)
    family = 0x01 if ip.version == 4 else 0x02
    value = b"\x00" + bytes([family]) + port.to_bytes(2, "big") + ip.packed
    return stun_attribute(attribute_type, value)


def xor_mapped_address_attribute(address: str, port: int, transaction_id: bytes) -> bytes:
    ip = ipaddress.ip_address(address)
    x_port = port ^ (MAGIC_COOKIE_INT >> 16)
    if ip.version == 4:
        x_address = (int(ip) ^ MAGIC_COOKIE_INT).to_bytes(4, "big")
        family = 0x01
    else:
        mask = MAGIC_COOKIE + transaction_id
        x_address = bytes(byte ^ mask[index] for index, byte in enumerate(ip.packed))
        family = 0x02
    value = b"\x00" + bytes([family]) + x_port.to_bytes(2, "big") + x_address
    return stun_attribute(ATTR_XOR_MAPPED_ADDRESS, value)


def message_integrity_value() -> bytes:
    return bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213")


def message_integrity_sha256_value() -> bytes:
    return bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")


def transaction_id(hex_text: str) -> bytes:
    value = bytes.fromhex(hex_text)
    if len(value) != 12:
        raise ValueError("STUN transaction ID must be 12 bytes")
    return value


def make_ipv6_udp_packet(
    *,
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    timestamp_offset: int,
):
    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst=dst_ip, hlim=64)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=payload)
    )
    packet.time = BASE_TIME + timestamp_offset
    return packet


def error_code_attribute(code: int, reason: str) -> bytes:
    error_class = code // 100
    number = code % 100
    value = b"\x00\x00" + bytes([error_class, number]) + reason.encode("utf-8")
    return stun_attribute(ATTR_ERROR_CODE, value)


def malformed_username_attribute() -> bytes:
    return ATTR_USERNAME.to_bytes(2, "big") + (8).to_bytes(2, "big") + b"abcd"


def structured_fixtures_07_11() -> dict[str, list]:
    binding_request_type = stun_message_type(BINDING_METHOD, CLASS_REQUEST)
    binding_success_type = stun_message_type(BINDING_METHOD, CLASS_SUCCESS_RESPONSE)
    binding_error_type = stun_message_type(BINDING_METHOD, CLASS_ERROR_RESPONSE)

    tx_07 = transaction_id("070707070707070707070707")
    tx_08 = transaction_id("080808080808080808080808")
    tx_09 = transaction_id("090909090909090909090909")
    tx_10 = transaction_id("101010101010101010101010")
    tx_11 = transaction_id("111111111111111111111111")

    fixture_07_request = add_fingerprint(
        binding_request_type,
        tx_07,
        [
            text_attribute(ATTR_USERNAME, "remote:local"),
            uint32_attribute(ATTR_PRIORITY, 1845501695),
            uint64_attribute(ATTR_ICE_CONTROLLING, 0x1122334455667788),
            stun_attribute(ATTR_USE_CANDIDATE, b""),
            stun_attribute(ATTR_MESSAGE_INTEGRITY, message_integrity_value()),
        ],
    )
    fixture_07_response = add_fingerprint(
        binding_success_type,
        tx_07,
        [
            xor_mapped_address_attribute("203.0.113.25", 54321, tx_07),
            text_attribute(ATTR_SOFTWARE, "PFL STUN fixture"),
            stun_attribute(ATTR_MESSAGE_INTEGRITY_SHA256, message_integrity_sha256_value()),
        ],
    )

    fixture_08_response = stun_message_from_attributes(
        binding_success_type,
        tx_08,
        [
            xor_mapped_address_attribute("2001:db8:ffff::25", 54321, tx_08),
            mapped_address_attribute(ATTR_MAPPED_ADDRESS, "2001:db8:ffff::26", 54322),
        ],
    )

    fixture_09_response = stun_message_from_attributes(
        binding_error_type,
        tx_09,
        [
            error_code_attribute(401, "Unauthorized"),
            text_attribute(ATTR_REALM, "example.org"),
            text_attribute(ATTR_NONCE, "pfl-stun-nonce-0001"),
            text_attribute(ATTR_SOFTWARE, "PFL STUN fixture"),
        ],
    )

    fixture_10_request = stun_message_from_attributes(
        binding_request_type,
        tx_10,
        [
            text_attribute(ATTR_USERNAME, "pad-nine!"),
            uint64_attribute(ATTR_ICE_CONTROLLED, 0x8877665544332211),
            stun_attribute(ATTR_UNKNOWN_REQUIRED, bytes.fromhex("12345678")),
            stun_attribute(ATTR_UNKNOWN_OPTIONAL, bytes.fromhex("812345")),
        ],
    )

    fixture_11_request = stun_header(binding_request_type, tx_11, 8) + malformed_username_attribute()

    return {
        "07_stun_binding_ice_exchange.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=fixture_07_request,
                ip_id=0x4208,
                timestamp_offset=8,
            ),
            make_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=CLIENT_MAC,
                src_ip=SERVER_IP,
                dst_ip=CLIENT_IP,
                src_port=STUN_PORT,
                dst_port=CLIENT_PORT,
                payload=fixture_07_response,
                ip_id=0x4209,
                timestamp_offset=9,
            ),
        ],
        "08_stun_binding_success_xor_mapped_ipv6.pcap": [
            make_ipv6_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=CLIENT_MAC,
                src_ip=SERVER_IPV6,
                dst_ip=CLIENT_IPV6,
                src_port=STUN_PORT,
                dst_port=CLIENT_PORT,
                payload=fixture_08_response,
                timestamp_offset=10,
            )
        ],
        "09_stun_binding_error_response.pcap": [
            make_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=CLIENT_MAC,
                src_ip=SERVER_IP,
                dst_ip=CLIENT_IP,
                src_port=STUN_PORT,
                dst_port=CLIENT_PORT,
                payload=fixture_09_response,
                ip_id=0x420A,
                timestamp_offset=11,
            )
        ],
        "10_stun_attribute_padding_and_unknown.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=fixture_10_request,
                ip_id=0x420B,
                timestamp_offset=12,
            )
        ],
        "11_stun_malformed_attribute_length.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_IP,
                dst_ip=SERVER_IP,
                src_port=CLIENT_PORT,
                dst_port=STUN_PORT,
                payload=fixture_11_request,
                ip_id=0x420C,
                timestamp_offset=13,
            )
        ],
    }


def fixtures() -> dict[str, list]:
    return legacy_fixtures_01_06() | structured_fixtures_07_11()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate deterministic STUN parsing fixtures.")
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory where .pcap files will be written. Defaults to this script's fixture directory.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing fixture files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_paths: list[Path] = []
    for filename, packets in fixtures().items():
        path = output_dir / filename
        if path.exists() and not args.force:
            raise SystemExit(f"{path} already exists; rerun with --force to overwrite.")
        write_pcap(path, packets)
        generated_paths.append(path)

    for path in generated_paths:
        print(path.as_posix())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

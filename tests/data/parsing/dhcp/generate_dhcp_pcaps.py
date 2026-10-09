#!/usr/bin/env python3
"""Generate deterministic DHCPv4 parsing fixtures 01-11.

Fixtures 01-06 preserve the historical detection-fixture recipe from the
legacy local generator. Fixtures 07-11 are target structured-inspection byte
contracts. Keep those construction paths intentionally separate so future
structured fixture changes cannot silently alter the legacy regression
artifacts.
"""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from scapy.all import Ether, IP, PcapWriter, Raw, UDP
except ImportError as error:
    raise SystemExit("Scapy is required to generate DHCP fixtures: pip install scapy") from error


CLIENT_MAC = "02:00:00:00:40:01"
SERVER_MAC = "02:00:00:00:40:fe"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

CLIENT_ASSIGNED_IP = "192.0.2.100"
SERVER_IP = "192.0.2.1"
INITIAL_CLIENT_IP = "0.0.0.0"
BROADCAST_IP = "255.255.255.255"

LEGACY_XID = 0x3903F326
STRUCTURED_XID_07_08 = 0x3903F327
STRUCTURED_XID_09 = 0x3903F329
STRUCTURED_XID_10 = 0x3903F32A
STRUCTURED_XID_11 = 0x3903F32B

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
MAGIC_COOKIE = b"\x63\x82\x53\x63"
BAD_MAGIC_COOKIE = b"\x63\x82\x53\x62"
BASE_TIME = 1_700_000_000.0

OPT_PAD = 0
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOST_NAME = 12
OPT_DOMAIN_NAME = 15
OPT_BROADCAST_ADDRESS = 28
OPT_REQUESTED_IP_ADDRESS = 50
OPT_IP_ADDRESS_LEASE_TIME = 51
OPT_OPTION_OVERLOAD = 52
OPT_DHCP_MESSAGE_TYPE = 53
OPT_SERVER_IDENTIFIER = 54
OPT_PARAMETER_REQUEST_LIST = 55
OPT_MESSAGE = 56
OPT_MAXIMUM_DHCP_MESSAGE_SIZE = 57
OPT_RENEWAL_TIME_VALUE = 58
OPT_REBINDING_TIME_VALUE = 59
OPT_VENDOR_CLASS_IDENTIFIER = 60
OPT_CLIENT_IDENTIFIER = 61
OPT_TFTP_SERVER_NAME = 66
OPT_BOOTFILE_NAME = 67
OPT_UNKNOWN_200 = 200
OPT_END = 255

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5


def ipv4_bytes(value: str) -> bytes:
    return bytes(int(part, 10) for part in value.split("."))


def mac_bytes(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def option(code: int, payload: bytes) -> bytes:
    if code in (OPT_PAD, OPT_END):
        raise ValueError("Pad and End use dedicated helpers")
    if len(payload) > 255:
        raise ValueError("DHCP option payload too large")
    return bytes([code, len(payload)]) + payload


def pad_option() -> bytes:
    return bytes([OPT_PAD])


def end_option() -> bytes:
    return bytes([OPT_END])


def server_identifier() -> bytes:
    return option(OPT_SERVER_IDENTIFIER, ipv4_bytes(SERVER_IP))


def lease_time(seconds: int) -> bytes:
    return option(OPT_IP_ADDRESS_LEASE_TIME, seconds.to_bytes(4, "big"))


def parameter_request_list() -> bytes:
    return option(OPT_PARAMETER_REQUEST_LIST, bytes([1, 3, 6, 15]))


def dhcp_options(message_type: int, *extra_options: bytes) -> bytes:
    return option(OPT_DHCP_MESSAGE_TYPE, bytes([message_type])) + b"".join(extra_options) + end_option()


def legacy_bootp_payload(
    *,
    op: int,
    flags: int = 0,
    ciaddr: str = "0.0.0.0",
    yiaddr: str = "0.0.0.0",
    siaddr: str = "0.0.0.0",
    giaddr: str = "0.0.0.0",
    cookie: bytes = MAGIC_COOKIE,
    options: bytes = b"",
) -> bytes:
    header = bytearray(236)
    header[0] = op
    header[1] = 1  # Ethernet
    header[2] = 6  # MAC length
    header[4:8] = LEGACY_XID.to_bytes(4, "big")
    header[10:12] = flags.to_bytes(2, "big")
    header[12:16] = ipv4_bytes(ciaddr)
    header[16:20] = ipv4_bytes(yiaddr)
    header[20:24] = ipv4_bytes(siaddr)
    header[24:28] = ipv4_bytes(giaddr)
    header[28:34] = mac_bytes(CLIENT_MAC)
    return bytes(header) + cookie + options


def bootp_text_field(value: str, size: int) -> bytes:
    encoded = value.encode("ascii")
    if len(encoded) >= size:
        raise ValueError("BOOTP text field must leave room for a NUL terminator")
    return encoded + b"\x00" + bytes(size - len(encoded) - 1)


def overloaded_field(options: bytes, size: int) -> bytes:
    if len(options) > size:
        raise ValueError("overloaded DHCP option field exceeds fixed BOOTP field size")
    return options + bytes(size - len(options))


def bootp_payload(
    *,
    op: int,
    xid: int,
    secs: int = 0,
    flags: int = 0,
    ciaddr: str = "0.0.0.0",
    yiaddr: str = "0.0.0.0",
    siaddr: str = "0.0.0.0",
    giaddr: str = "0.0.0.0",
    chaddr: str = CLIENT_MAC,
    sname: bytes | None = None,
    file: bytes | None = None,
    options: bytes = b"",
) -> bytes:
    sname_bytes = sname if sname is not None else bytes(64)
    file_bytes = file if file is not None else bytes(128)
    if len(sname_bytes) != 64:
        raise ValueError("BOOTP sname field must be exactly 64 bytes")
    if len(file_bytes) != 128:
        raise ValueError("BOOTP file field must be exactly 128 bytes")

    header = bytearray(236)
    header[0] = op
    header[1] = 1
    header[2] = 6
    header[3] = 0
    header[4:8] = xid.to_bytes(4, "big")
    header[8:10] = secs.to_bytes(2, "big")
    header[10:12] = flags.to_bytes(2, "big")
    header[12:16] = ipv4_bytes(ciaddr)
    header[16:20] = ipv4_bytes(yiaddr)
    header[20:24] = ipv4_bytes(siaddr)
    header[24:28] = ipv4_bytes(giaddr)
    header[28:34] = mac_bytes(chaddr)
    header[44:108] = sname_bytes
    header[108:236] = file_bytes
    return bytes(header) + MAGIC_COOKIE + options


def text_option(code: int, value: str) -> bytes:
    return option(code, value.encode("ascii"))


def ipv4_option(code: int, value: str) -> bytes:
    return option(code, ipv4_bytes(value))


def ipv4_list_option(code: int, values: list[str]) -> bytes:
    return option(code, b"".join(ipv4_bytes(value) for value in values))


def u16_option(code: int, value: int) -> bytes:
    return option(code, value.to_bytes(2, "big"))


def u32_option(code: int, value: int) -> bytes:
    return option(code, value.to_bytes(4, "big"))


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
    discover_payload = legacy_bootp_payload(
        op=1,
        flags=0x8000,
        options=dhcp_options(DHCP_DISCOVER, parameter_request_list()),
    )
    offer_payload = legacy_bootp_payload(
        op=2,
        yiaddr=CLIENT_ASSIGNED_IP,
        siaddr=SERVER_IP,
        options=dhcp_options(DHCP_OFFER, server_identifier(), lease_time(3600)),
    )
    request_payload = legacy_bootp_payload(
        op=1,
        ciaddr=CLIENT_ASSIGNED_IP,
        options=dhcp_options(DHCP_REQUEST, server_identifier()),
    )
    ack_payload = legacy_bootp_payload(
        op=2,
        yiaddr=CLIENT_ASSIGNED_IP,
        siaddr=SERVER_IP,
        options=dhcp_options(DHCP_ACK, server_identifier(), lease_time(3600)),
    )
    bad_cookie_payload = legacy_bootp_payload(
        op=1,
        flags=0x8000,
        cookie=BAD_MAGIC_COOKIE,
        options=dhcp_options(DHCP_DISCOVER, parameter_request_list()),
    )
    wrong_ports_payload = discover_payload
    truncated_payload = legacy_bootp_payload(op=1, flags=0x8000, cookie=b"\x63\x82\x53")

    return {
        "01_dhcp_discover_broadcast.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=INITIAL_CLIENT_IP,
                dst_ip=BROADCAST_IP,
                src_port=DHCP_CLIENT_PORT,
                dst_port=DHCP_SERVER_PORT,
                payload=discover_payload,
                ip_id=0x4001,
                timestamp_offset=1,
            )
        ],
        "02_dhcp_offer_broadcast.pcap": [
            make_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=SERVER_IP,
                dst_ip=BROADCAST_IP,
                src_port=DHCP_SERVER_PORT,
                dst_port=DHCP_CLIENT_PORT,
                payload=offer_payload,
                ip_id=0x4002,
                timestamp_offset=2,
            )
        ],
        "03_dhcp_request_ack_bidirectional.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_ASSIGNED_IP,
                dst_ip=SERVER_IP,
                src_port=DHCP_CLIENT_PORT,
                dst_port=DHCP_SERVER_PORT,
                payload=request_payload,
                ip_id=0x4003,
                timestamp_offset=3,
            ),
            make_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=CLIENT_MAC,
                src_ip=SERVER_IP,
                dst_ip=CLIENT_ASSIGNED_IP,
                src_port=DHCP_SERVER_PORT,
                dst_port=DHCP_CLIENT_PORT,
                payload=ack_payload,
                ip_id=0x4004,
                timestamp_offset=4,
            ),
        ],
        "04_dhcp_bad_magic_cookie.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=INITIAL_CLIENT_IP,
                dst_ip=BROADCAST_IP,
                src_port=DHCP_CLIENT_PORT,
                dst_port=DHCP_SERVER_PORT,
                payload=bad_cookie_payload,
                ip_id=0x4005,
                timestamp_offset=5,
            )
        ],
        "05_dhcp_valid_payload_wrong_ports.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=INITIAL_CLIENT_IP,
                dst_ip=BROADCAST_IP,
                src_port=1068,
                dst_port=1067,
                payload=wrong_ports_payload,
                ip_id=0x4006,
                timestamp_offset=6,
            )
        ],
        "06_dhcp_truncated_before_magic_cookie.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=INITIAL_CLIENT_IP,
                dst_ip=BROADCAST_IP,
                src_port=DHCP_CLIENT_PORT,
                dst_port=DHCP_SERVER_PORT,
                payload=truncated_payload,
                ip_id=0x4007,
                timestamp_offset=7,
            )
        ],
    }


def structured_fixtures_07_11() -> dict[str, list]:
    fixture_07_payload = bootp_payload(
        op=1,
        xid=STRUCTURED_XID_07_08,
        secs=7,
        flags=0x8000,
        options=b"".join(
            [
                option(OPT_DHCP_MESSAGE_TYPE, bytes([DHCP_DISCOVER])),
                text_option(OPT_HOST_NAME, "pfl-client"),
                ipv4_option(OPT_REQUESTED_IP_ADDRESS, CLIENT_ASSIGNED_IP),
                option(
                    OPT_PARAMETER_REQUEST_LIST,
                    bytes([1, 3, 6, 15, 28, 51, 54, 58, 59]),
                ),
                option(OPT_CLIENT_IDENTIFIER, bytes([1]) + mac_bytes(CLIENT_MAC)),
                u16_option(OPT_MAXIMUM_DHCP_MESSAGE_SIZE, 1500),
                text_option(OPT_VENDOR_CLASS_IDENTIFIER, "PFL-DHCP-Client"),
                end_option(),
            ]
        ),
    )
    fixture_08_payload = bootp_payload(
        op=2,
        xid=STRUCTURED_XID_07_08,
        flags=0x8000,
        yiaddr=CLIENT_ASSIGNED_IP,
        siaddr=SERVER_IP,
        sname=bootp_text_field("dhcp-server", 64),
        file=bootp_text_field("pxelinux.0", 128),
        options=b"".join(
            [
                option(OPT_DHCP_MESSAGE_TYPE, bytes([DHCP_OFFER])),
                ipv4_option(OPT_SUBNET_MASK, "255.255.255.0"),
                ipv4_list_option(OPT_ROUTER, [SERVER_IP, "192.0.2.254"]),
                ipv4_list_option(OPT_DNS, ["192.0.2.53", "192.0.2.54"]),
                text_option(OPT_DOMAIN_NAME, "example.test"),
                ipv4_option(OPT_BROADCAST_ADDRESS, "192.0.2.255"),
                u32_option(OPT_IP_ADDRESS_LEASE_TIME, 3600),
                u32_option(OPT_RENEWAL_TIME_VALUE, 1800),
                u32_option(OPT_REBINDING_TIME_VALUE, 3150),
                server_identifier(),
                text_option(OPT_MESSAGE, "PFL offer"),
                end_option(),
            ]
        ),
    )
    fixture_09_payload = bootp_payload(
        op=2,
        xid=STRUCTURED_XID_09,
        yiaddr=CLIENT_ASSIGNED_IP,
        siaddr=SERVER_IP,
        sname=overloaded_field(
            text_option(OPT_TFTP_SERVER_NAME, "tftp.example.test") + end_option(),
            64,
        ),
        file=overloaded_field(
            text_option(OPT_BOOTFILE_NAME, "bootx64.efi") + end_option(),
            128,
        ),
        options=b"".join(
            [
                option(OPT_DHCP_MESSAGE_TYPE, bytes([DHCP_ACK])),
                option(OPT_OPTION_OVERLOAD, bytes([3])),
                server_identifier(),
                end_option(),
            ]
        ),
    )
    fixture_10_payload = bootp_payload(
        op=1,
        xid=STRUCTURED_XID_10,
        ciaddr=CLIENT_ASSIGNED_IP,
        options=b"".join(
            [
                option(OPT_DHCP_MESSAGE_TYPE, bytes([DHCP_REQUEST])),
                pad_option(),
                pad_option(),
                option(OPT_UNKNOWN_200, bytes.fromhex("123456")),
                text_option(OPT_HOST_NAME, "pad-client"),
                end_option(),
                option(OPT_DHCP_MESSAGE_TYPE, bytes([DHCP_ACK])),
                text_option(OPT_MESSAGE, "ignored-tail"),
            ]
        ),
    )
    fixture_11_payload = bootp_payload(
        op=1,
        xid=STRUCTURED_XID_11,
        flags=0x8000,
        options=option(OPT_DHCP_MESSAGE_TYPE, bytes([DHCP_DISCOVER])) +
        bytes([OPT_HOST_NAME, 10]) +
        b"bad",
    )

    return {
        "07_dhcp_structured_discover.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=INITIAL_CLIENT_IP,
                dst_ip=BROADCAST_IP,
                src_port=DHCP_CLIENT_PORT,
                dst_port=DHCP_SERVER_PORT,
                payload=fixture_07_payload,
                ip_id=0x4008,
                timestamp_offset=8,
            )
        ],
        "08_dhcp_structured_offer.pcap": [
            make_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=SERVER_IP,
                dst_ip=BROADCAST_IP,
                src_port=DHCP_SERVER_PORT,
                dst_port=DHCP_CLIENT_PORT,
                payload=fixture_08_payload,
                ip_id=0x4009,
                timestamp_offset=9,
            )
        ],
        "09_dhcp_option_overload.pcap": [
            make_udp_packet(
                src_mac=SERVER_MAC,
                dst_mac=CLIENT_MAC,
                src_ip=SERVER_IP,
                dst_ip=CLIENT_ASSIGNED_IP,
                src_port=DHCP_SERVER_PORT,
                dst_port=DHCP_CLIENT_PORT,
                payload=fixture_09_payload,
                ip_id=0x400A,
                timestamp_offset=10,
            )
        ],
        "10_dhcp_padding_unknown_end.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=SERVER_MAC,
                src_ip=CLIENT_ASSIGNED_IP,
                dst_ip=SERVER_IP,
                src_port=DHCP_CLIENT_PORT,
                dst_port=DHCP_SERVER_PORT,
                payload=fixture_10_payload,
                ip_id=0x400B,
                timestamp_offset=11,
            )
        ],
        "11_dhcp_malformed_option_length.pcap": [
            make_udp_packet(
                src_mac=CLIENT_MAC,
                dst_mac=BROADCAST_MAC,
                src_ip=INITIAL_CLIENT_IP,
                dst_ip=BROADCAST_IP,
                src_port=DHCP_CLIENT_PORT,
                dst_port=DHCP_SERVER_PORT,
                payload=fixture_11_payload,
                ip_id=0x400C,
                timestamp_offset=12,
            )
        ],
    }


def fixtures() -> dict[str, list]:
    return legacy_fixtures_01_06() | structured_fixtures_07_11()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate deterministic DHCPv4 parsing fixtures.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory where .pcap files will be written. Defaults to this generator's directory.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing fixture files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir
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

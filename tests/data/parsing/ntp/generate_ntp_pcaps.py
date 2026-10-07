#!/usr/bin/env python3
"""Generate deterministic NTP parsing fixtures 01-15.

Fixtures 01-10 preserve the historical detection-fixture recipe. Fixtures
11-15 are newer structured-inspection byte contracts. Keep those construction
paths intentionally separate so changes to future structured fixtures cannot
silently alter the legacy regression artifacts.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import Ether, IP, PcapWriter, Raw, UDP
except ImportError as error:
    raise SystemExit("Scapy is required to generate NTP fixtures: pip install scapy") from error


CLIENT_MAC = "02:00:00:00:49:01"
SERVER_MAC = "02:00:00:00:49:02"
CLIENT_IP = "192.0.2.170"
SERVER_IP = "192.0.2.180"
CLIENT_PORT = 59000
NTP_PORT = 123
NON_STANDARD_NTP_PORT = 30123

LEGACY_BASE_TIME = 1_701_100_000.0
STRUCTURED_BASE_TIME = 1_767_320_645.0

REFERENCE_ID_RATE = b"RATE"
REFERENCE_ID_TEST = b"TEST"
REFERENCE_ID_GPS = b"GPS\x00"
REFERENCE_ID_192_0_2_1 = b"\xc0\x00\x02\x01"

NTP_EPOCH = datetime(1900, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Fixture:
    filename: str
    packets: list


def ntp_first_byte(*, leap_indicator: int, version: int, mode: int) -> int:
    return ((leap_indicator & 0x03) << 6) | ((version & 0x07) << 3) | (mode & 0x07)


def legacy_ntp_timestamp(seconds: int, fraction: int = 0) -> bytes:
    return ((seconds & 0xFFFFFFFF) << 32 | (fraction & 0xFFFFFFFF)).to_bytes(8, "big")


def build_legacy_ntp_header(
    *,
    leap_indicator: int = 0,
    version: int,
    mode: int,
    stratum: int,
    poll: int = 6,
    precision: int = -20,
    root_delay: int = 0,
    root_dispersion: int = 0,
    reference_id: bytes = b"\x00\x00\x00\x00",
    reference_timestamp: int = 0,
    originate_timestamp: int = 0,
    receive_timestamp: int = 0,
    transmit_timestamp: int,
) -> bytes:
    if len(reference_id) != 4:
        raise ValueError("NTP Reference ID must be exactly 4 bytes")

    return (
        bytes(
            [
                ntp_first_byte(leap_indicator=leap_indicator, version=version, mode=mode),
                stratum & 0xFF,
                poll & 0xFF,
                precision & 0xFF,
            ]
        )
        + (root_delay & 0xFFFFFFFF).to_bytes(4, "big")
        + (root_dispersion & 0xFFFFFFFF).to_bytes(4, "big")
        + reference_id
        + legacy_ntp_timestamp(reference_timestamp)
        + legacy_ntp_timestamp(originate_timestamp)
        + legacy_ntp_timestamp(receive_timestamp)
        + legacy_ntp_timestamp(transmit_timestamp)
    )


def build_structured_ntp_header(
    *,
    leap_indicator: int,
    version: int,
    mode: int,
    stratum: int,
    poll: int,
    precision: int,
    root_delay: int,
    root_dispersion: int,
    reference_id: bytes = b"\x00\x00\x00\x00",
    reference_timestamp: int = 0,
    originate_timestamp: int = 0,
    receive_timestamp: int = 0,
    transmit_timestamp: int = 0,
) -> bytes:
    if len(reference_id) != 4:
        raise ValueError("NTP Reference ID must be exactly 4 bytes")

    return (
        bytes(
            [
                ntp_first_byte(leap_indicator=leap_indicator, version=version, mode=mode),
                stratum & 0xFF,
                poll & 0xFF,
                precision & 0xFF,
            ]
        )
        + signed_u32(root_delay)
        + unsigned_u32(root_dispersion)
        + reference_id
        + timestamp_bytes(reference_timestamp)
        + timestamp_bytes(originate_timestamp)
        + timestamp_bytes(receive_timestamp)
        + timestamp_bytes(transmit_timestamp)
    )


def signed_u32(value: int) -> bytes:
    if not -(1 << 31) <= value < (1 << 31):
        raise ValueError("signed uint32 field value is out of range")
    return (value & 0xFFFFFFFF).to_bytes(4, "big")


def unsigned_u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("unsigned uint32 field value is out of range")
    return value.to_bytes(4, "big")


def timestamp_bytes(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("NTP timestamp must fit uint64")
    return value.to_bytes(8, "big")


def fixed_16_16(numerator: int, denominator: int = 1, *, signed: bool) -> int:
    raw_numerator = numerator * 65536
    if raw_numerator % denominator != 0:
        raise ValueError("fixture fixed-point value is not exactly representable")
    raw = raw_numerator // denominator
    if signed:
        if not -(1 << 31) <= raw < (1 << 31):
            raise ValueError("signed 16.16 value is out of range")
    elif not 0 <= raw <= 0xFFFFFFFF:
        raise ValueError("unsigned 16.16 value is out of range")
    return raw


def utc(year: int, month: int, day: int, hour: int, minute: int, second: int) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def ntp_seconds_era0(dt: datetime) -> int:
    if dt.tzinfo is None:
        raise ValueError("NTP fixture timestamps must be timezone-aware UTC datetimes")
    delta = dt.astimezone(timezone.utc) - NTP_EPOCH
    seconds = delta.days * 86400 + delta.seconds
    if seconds < 0 or seconds > 0xFFFFFFFF:
        raise ValueError("datetime is outside NTP Era 0 and must not be silently wrapped")
    return seconds


def ntp_timestamp_era0(dt: datetime, fraction: int = 0) -> int:
    return raw_ntp_timestamp(ntp_seconds_era0(dt), fraction)


def raw_ntp_timestamp(seconds: int, fraction: int) -> int:
    if not 0 <= seconds <= 0xFFFFFFFF:
        raise ValueError("NTP timestamp seconds must fit uint32")
    if not 0 <= fraction <= 0xFFFFFFFF:
        raise ValueError("NTP timestamp fraction must fit uint32")
    return (seconds << 32) | fraction


def legacy_client_request_payload(*, version: int, transmit_timestamp: int) -> bytes:
    return build_legacy_ntp_header(
        version=version,
        mode=3,
        stratum=0,
        poll=6,
        precision=-20,
        transmit_timestamp=transmit_timestamp,
    )


def legacy_server_response_payload(
    *,
    version: int,
    stratum: int,
    reference_id: bytes = REFERENCE_ID_TEST,
    reference_timestamp: int,
    originate_timestamp: int,
    receive_timestamp: int,
    transmit_timestamp: int,
    leap_indicator: int = 0,
    mode: int = 4,
) -> bytes:
    return build_legacy_ntp_header(
        leap_indicator=leap_indicator,
        version=version,
        mode=mode,
        stratum=stratum,
        poll=6,
        precision=-20,
        root_delay=0x00010000,
        root_dispersion=0x00020000,
        reference_id=reference_id,
        reference_timestamp=reference_timestamp,
        originate_timestamp=originate_timestamp,
        receive_timestamp=receive_timestamp,
        transmit_timestamp=transmit_timestamp,
    )


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
    ttl: int,
    packet_time: float,
):
    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, id=ip_id, ttl=ttl)
        / UDP(sport=src_port, dport=dst_port)
        / Raw(load=payload)
    )
    packet.time = packet_time
    return packet


def client_to_server_packet(*, dst_port: int, payload: bytes, ip_id: int, packet_time: float):
    return make_udp_packet(
        src_mac=CLIENT_MAC,
        dst_mac=SERVER_MAC,
        src_ip=CLIENT_IP,
        dst_ip=SERVER_IP,
        src_port=CLIENT_PORT,
        dst_port=dst_port,
        payload=payload,
        ip_id=ip_id,
        ttl=64,
        packet_time=packet_time,
    )


def server_to_client_packet(*, src_port: int, payload: bytes, ip_id: int, packet_time: float):
    return make_udp_packet(
        src_mac=SERVER_MAC,
        dst_mac=CLIENT_MAC,
        src_ip=SERVER_IP,
        dst_ip=CLIENT_IP,
        src_port=src_port,
        dst_port=CLIENT_PORT,
        payload=payload,
        ip_id=ip_id,
        ttl=64,
        packet_time=packet_time,
    )


def legacy_time(offset: int) -> float:
    return LEGACY_BASE_TIME + offset


def structured_time(offset: int) -> float:
    return STRUCTURED_BASE_TIME + offset


def build_legacy_fixtures_01_10() -> list[Fixture]:
    ntpv4_client = legacy_client_request_payload(version=4, transmit_timestamp=0xE700_0100)
    ntpv3_client = legacy_client_request_payload(version=3, transmit_timestamp=0xE700_0300)

    ntpv4_server = legacy_server_response_payload(
        version=4,
        stratum=2,
        reference_timestamp=0xE700_0001,
        originate_timestamp=0xE700_0100,
        receive_timestamp=0xE700_0101,
        transmit_timestamp=0xE700_0102,
    )
    ntpv3_server = legacy_server_response_payload(
        version=3,
        stratum=3,
        reference_timestamp=0xE700_0201,
        originate_timestamp=0xE700_0300,
        receive_timestamp=0xE700_0301,
        transmit_timestamp=0xE700_0302,
    )
    ntpv4_kod_rate = legacy_server_response_payload(
        version=4,
        stratum=0,
        reference_id=REFERENCE_ID_RATE,
        reference_timestamp=0xE700_0401,
        originate_timestamp=0xE700_0402,
        receive_timestamp=0xE700_0403,
        transmit_timestamp=0xE700_0404,
    )
    ntpv2_client = legacy_client_request_payload(version=2, transmit_timestamp=0xE700_0800)
    ntpv4_broadcast = legacy_server_response_payload(
        version=4,
        mode=5,
        stratum=2,
        reference_timestamp=0xE700_0901,
        originate_timestamp=0xE700_0902,
        receive_timestamp=0xE700_0903,
        transmit_timestamp=0xE700_0904,
    )
    ntp_garbage = bytes([0xFF]) + bytes(range(1, 48))

    return [
        Fixture(
            "01_ntpv4_client_request_port123.pcap",
            [client_to_server_packet(dst_port=NTP_PORT, payload=ntpv4_client, ip_id=0x4901, packet_time=legacy_time(1))],
        ),
        Fixture(
            "02_ntpv4_server_response_port123.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=ntpv4_server, ip_id=0x4902, packet_time=legacy_time(2))],
        ),
        Fixture(
            "03_ntpv3_client_request_port123.pcap",
            [client_to_server_packet(dst_port=NTP_PORT, payload=ntpv3_client, ip_id=0x4903, packet_time=legacy_time(3))],
        ),
        Fixture(
            "04_ntpv3_server_response_port123.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=ntpv3_server, ip_id=0x4904, packet_time=legacy_time(4))],
        ),
        Fixture(
            "05_ntpv4_kod_rate_response.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=ntpv4_kod_rate, ip_id=0x4905, packet_time=legacy_time(5))],
        ),
        Fixture(
            "06_ntp_garbage_port123.pcap",
            [client_to_server_packet(dst_port=NTP_PORT, payload=ntp_garbage, ip_id=0x4906, packet_time=legacy_time(6))],
        ),
        Fixture(
            "07_ntpv4_client_wrong_ports.pcap",
            [
                client_to_server_packet(
                    dst_port=NON_STANDARD_NTP_PORT,
                    payload=ntpv4_client,
                    ip_id=0x4907,
                    packet_time=legacy_time(7),
                )
            ],
        ),
        Fixture(
            "08_ntpv2_client_port123.pcap",
            [client_to_server_packet(dst_port=NTP_PORT, payload=ntpv2_client, ip_id=0x4908, packet_time=legacy_time(8))],
        ),
        Fixture(
            "09_ntpv4_broadcast_mode5.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=ntpv4_broadcast, ip_id=0x4909, packet_time=legacy_time(9))],
        ),
        Fixture(
            "10_ntpv4_truncated_47_byte_header.pcap",
            [client_to_server_packet(dst_port=NTP_PORT, payload=ntpv4_client[:47], ip_id=0x490A, packet_time=legacy_time(10))],
        ),
    ]


def structured_ntpv4_client_payload(transmit_timestamp: int) -> bytes:
    return build_structured_ntp_header(
        leap_indicator=0,
        version=4,
        mode=3,
        stratum=0,
        poll=6,
        precision=-20,
        root_delay=0,
        root_dispersion=0,
        transmit_timestamp=transmit_timestamp,
    )


def build_structured_fixtures_11_15() -> list[Fixture]:
    client_tx = ntp_timestamp_era0(utc(2026, 1, 2, 3, 4, 5), 0x40000000)
    client_v4 = structured_ntpv4_client_payload(client_tx)
    server_v4 = build_structured_ntp_header(
        leap_indicator=0,
        version=4,
        mode=4,
        stratum=2,
        poll=6,
        precision=-20,
        root_delay=fixed_16_16(1, 8, signed=True),
        root_dispersion=fixed_16_16(1, 4, signed=False),
        reference_id=REFERENCE_ID_192_0_2_1,
        reference_timestamp=ntp_timestamp_era0(utc(2026, 1, 2, 3, 0, 0), 0x80000000),
        originate_timestamp=client_tx,
        receive_timestamp=ntp_timestamp_era0(utc(2026, 1, 2, 3, 4, 5), 0x60000000),
        transmit_timestamp=ntp_timestamp_era0(utc(2026, 1, 2, 3, 4, 5), 0x80000000),
    )
    structured_v3_response = build_structured_ntp_header(
        leap_indicator=0,
        version=3,
        mode=4,
        stratum=1,
        poll=4,
        precision=-18,
        root_delay=fixed_16_16(1, 16, signed=True),
        root_dispersion=fixed_16_16(3, 16, signed=False),
        reference_id=REFERENCE_ID_GPS,
        reference_timestamp=ntp_timestamp_era0(utc(2026, 1, 3, 4, 0, 0), 0x40000000),
        originate_timestamp=ntp_timestamp_era0(utc(2026, 1, 3, 4, 0, 1), 0x60000000),
        receive_timestamp=ntp_timestamp_era0(utc(2026, 1, 3, 4, 0, 2), 0x80000000),
        transmit_timestamp=ntp_timestamp_era0(utc(2026, 1, 3, 4, 0, 3), 0x40000000),
    )
    unsynchronized_stratum16 = build_structured_ntp_header(
        leap_indicator=3,
        version=4,
        mode=4,
        stratum=16,
        poll=4,
        precision=-18,
        root_delay=fixed_16_16(1, 4, signed=True),
        root_dispersion=fixed_16_16(3, 4, signed=False),
        reference_id=b"STEP",
        reference_timestamp=ntp_timestamp_era0(utc(2026, 1, 4, 5, 0, 0)),
        transmit_timestamp=ntp_timestamp_era0(utc(2026, 1, 4, 5, 0, 1), 0x80000000),
    )
    signed_root_delay = build_structured_ntp_header(
        leap_indicator=0,
        version=4,
        mode=4,
        stratum=2,
        poll=4,
        precision=-30,
        root_delay=fixed_16_16(-1, 2, signed=True),
        root_dispersion=fixed_16_16(3, 2, signed=False),
        reference_id=REFERENCE_ID_192_0_2_1,
        reference_timestamp=ntp_timestamp_era0(utc(2026, 1, 5, 6, 0, 0), 0x80000000),
        originate_timestamp=ntp_timestamp_era0(utc(2026, 1, 5, 6, 0, 1)),
        receive_timestamp=ntp_timestamp_era0(utc(2026, 1, 5, 6, 0, 2)),
        transmit_timestamp=ntp_timestamp_era0(utc(2026, 1, 5, 6, 0, 3), 0x80000000),
    )
    era0_last_second = build_structured_ntp_header(
        leap_indicator=0,
        version=4,
        mode=4,
        stratum=2,
        poll=4,
        precision=-20,
        root_delay=0,
        root_dispersion=fixed_16_16(1, 2, signed=False),
        reference_id=REFERENCE_ID_192_0_2_1,
        transmit_timestamp=raw_ntp_timestamp(0xFFFFFFFF, 0x80000000),
    )

    return [
        Fixture(
            "11_ntpv4_structured_exchange.pcap",
            [
                client_to_server_packet(dst_port=NTP_PORT, payload=client_v4, ip_id=0x4A01, packet_time=structured_time(1)),
                server_to_client_packet(src_port=NTP_PORT, payload=server_v4, ip_id=0x4A02, packet_time=structured_time(2)),
            ],
        ),
        Fixture(
            "12_ntpv3_structured_server_response.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=structured_v3_response, ip_id=0x4A03, packet_time=structured_time(3))],
        ),
        Fixture(
            "13_ntpv4_unsynchronized_stratum16.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=unsynchronized_stratum16, ip_id=0x4A04, packet_time=structured_time(4))],
        ),
        Fixture(
            "14_ntpv4_signed_root_delay.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=signed_root_delay, ip_id=0x4A05, packet_time=structured_time(5))],
        ),
        Fixture(
            "15_ntpv4_era0_last_second.pcap",
            [server_to_client_packet(src_port=NTP_PORT, payload=era0_last_second, ip_id=0x4A06, packet_time=structured_time(6))],
        ),
    ]


def build_all_fixtures() -> list[Fixture]:
    return build_legacy_fixtures_01_10() + build_structured_fixtures_11_15()


def write_pcap(path: Path, packets: list) -> None:
    writer = PcapWriter(str(path), linktype=1, append=False, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate deterministic NTP parsing fixtures.")
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
    for fixture in build_all_fixtures():
        path = output_dir / fixture.filename
        if path.exists() and not args.force:
            raise SystemExit(f"{path} already exists; rerun with --force to overwrite.")
        write_pcap(path, fixture.packets)
        generated_paths.append(path)

    for path in generated_paths:
        print(path.as_posix())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

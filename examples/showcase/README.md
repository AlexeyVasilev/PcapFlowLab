# Pcap Flow Lab Showcase Capture

This directory contains the first materialized version of the long-lived PcapFlowLab showcase capture.

- `capture_id`: `pcap-flow-lab-showcase`
- `capture_version`: `1.0.0`
- file: [`pcap_flow_lab_showcase.pcap`](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/examples/showcase/pcap_flow_lab_showcase.pcap)
- manifest: [`manifest.json`](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/examples/showcase/manifest.json)

The primary capture is a classic Ethernet PCAP. It is intentionally versioned as a living project asset. Future revisions keep the stable filename `pcap_flow_lab_showcase.pcap` and update `capture_version` plus the manifest/README contract.

## Scope

Version `1.0.0` establishes:

- four Analysis hero flows;
- core application-protocol demonstrations;
- representative Ethernet-compatible protocol-family coverage from `tests/data/parsing`;
- identity/grouping showcase pairs for VLAN, MPLS, GTP-U, VXLAN, and Geneve;
- key Packet Details / Bytes edge cases;
- curated Unrecognized Packets coverage with distinct current reason classes;
- one shared deterministic timeline with overlapping traffic;
- stable scenario IDs for documentation and demos.

## Current Totals

Rough capture totals for `1.0.0`:

- total packets: about `1557`
- total duration: about `114.02 s`
- file size: about `729 KB`
- link type: classic Ethernet (`DLT_EN10MB`)

## Stable Scenario Identification

Use `scenario_id` from [`manifest.json`](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/examples/showcase/manifest.json) as the stable locator.

Do not rely on Flow # values in screenshots, docs, or demos:

- flow numbering can shift across versions;
- grouping settings can change visible flow indices;
- future capture revisions may insert additional scenarios.

Preferred references are:

- `scenario_id`
- endpoint pair
- service / detected protocol
- expected protocol path

## Hero Analysis Flows

The first materialized hero flows are:

- `AN-TLS-BULK-01`
  TLS bulk-transfer analysis hero with SNI `bulk-download.example.test`, strong downstream byte asymmetry, multiple rate phases, burst regions, and a clear idle period.
- `AN-TCP6-INTERACTIVE-01`
  IPv6 generic TCP/Data hero with ACK-only packets, burst/idle structure, more balanced packet counts, and byte skew.
- `AN-UDP-TELEMETRY-01`
  VLAN-tagged UDP telemetry hero with periodic traffic, a temporary higher-rate interval, and multiple packet-size buckets.
- `AN-GRE-TLS-01`
  Nested VLAN/MPLS/GRE/inner-TCP/TLS hero with SNI `gre-analysis.example.test` and a strong Protocol Path demonstration.

## Additional Scenario Families In v1

Short protocol demos:

- `APP-HTTP-01`
- `APP-HTTP-02`
- `APP-HTTP-LARGEBODY-01`
- `APP-DNS-01`
- `APP-DNS-02`
- `APP-MDNS-01`
- `APP-MDNS6-01`
- `APP-QUIC-01`
- `APP-QUIC-MULTICRYPTO-01`
- `APP-QUIC-MULTICRYPTO-02`
- `APP-QUIC-NEG-01`
- `APP-TLS-03`
- `APP-TLS-SEGMENTED-01`
- `APP-TLS-NOSNI-01`
- `APP-SSH-01`
- `APP-STUN-01`
- `APP-BITTORRENT-01`
- `APP-SMTP-01`
- `APP-POP3-01`
- `APP-IMAP-01`
- `APP-DHCP-01`
- `HINT-POSSIBLE-TLS-01`
- `HINT-POSSIBLE-QUIC-01`
- `APP-SCTP-01`
- `SEC-AH-01`
- `SEC-ESP-01`
- `TUN-IPIP-01`
- `L2-PPPOE-01`
- `L2-PBB-01`
- `L2-LLCSNAP-01`
- `TUN-EOIP-01`
- `CTRL-IGMP-01`
- `TUN-MPLS-PW-01`
- `NET-IPV4-OPTIONS-01`
- `TCP-OPTIONS-01`
- `L2-ARP-01`
- `CTRL-ICMP-01`
- `TCP-RST-01`

Identity / grouping demonstrations:

- `ID-VLAN-PAIR-01`
- `ID-MPLS-LABEL-01`
- `OVL-GTPU-TEID-01`
- `OVL-VXLAN-VNI-01`
- `OVL-GENEVE-VNI-01`

Edge cases:

- `EDGE-SNAPLEN-01`
- `EDGE-FRAG-01`
- `EDGE-UNREC-01`
- `L2-MACSEC-PACKET-01`
- `L2-PPPOE-DISCOVERY-01`
- `L2-LLCSNAP-UNREC-01`
- `TUN-MPLS-UNREC-01`

Large captured-packet size demos:

- `AN-LARGEPKT-2500-01`
- `AN-LARGEPKT-7500-01`
- `AN-LARGEPKT-60000-01`

Detailed expectations, surfaces, and notes belong in [`manifest.json`](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/examples/showcase/manifest.json).

## Coverage Policy

`tests/data/parsing` coverage in the showcase is intentionally capability-based.

A fixture directory does **not** automatically imply that the current application exposes that protocol as a recognized user-visible flow. The long-term coverage contract lives in `manifest.json` under `parsing_family_coverage`.

Each top-level family is classified as one of:

- `represented`
- `already-covered`
- `companion-capture`
- `fixture-infrastructure`
- `packet-inspection-only`

Current `1.0.0` highlights:

- `represented`
  Includes `ah`, `arp`, `dns`, `eoip`, `esp`, `geneve`, `gre`, `gtpu`, `http`, `icmp`, `igmp`, `ip_encapsulation`, `ip_options`, `llc_snap`, `mdns`, `mpls`, `mpls_pw`, `pbb`, `pppoe`, `quic`, `sctp`, `tcp_options`, `tls`, `vlan`, and `vxlan`.
- `already-covered`
  `tcp` and `udp` remain covered by existing hero/application scenarios and do not need redundant generic flows.
- `companion-capture`
  `linux_cooked` remains intentionally outside the primary showcase because `SLL` / `SLL2` require a different link type.
- `fixture-infrastructure`
  `packet_byte_views` is not treated as a protocol family; its user-visible behavior is covered by `EDGE-SNAPLEN-01` and `EDGE-UNREC-01`.
- `packet-inspection-only`
  `macsec` is listed explicitly rather than hidden. The validated checked-in fixture currently remains a no-flow / unrecognized packet in the normal CLI flow path, but selected-packet inspection support still exists, so this is not treated as a generic production gap.

This keeps packet-only/no-flow capabilities visible without overstating them as full recognized-flow showcase coverage.

## Unrecognized Packet Showcase

Version `1.0.0` intentionally includes a small curated set of packets that current import semantics do not assign to normal flows:

- `EDGE-UNREC-01`
  Truncated Ethernet record with Packet Summary fallback and Captured Packet Bytes fallback.
- `L2-MACSEC-PACKET-01`
  Packet-inspection-only MACsec example: no normal flow identity, but selected-packet Summary/Bytes still exposes `Ethernet II`, `SecTAG`, `Protected Payload`, and `ICV`.
- `L2-PPPOE-DISCOVERY-01`
  PPPoE Discovery `PADI` control packet that remains globally unrecognized rather than becoming a PPP/IP flow.
- `L2-LLCSNAP-UNREC-01`
  LLC/SNAP packet with an unknown SNAP PID.
- `TUN-MPLS-UNREC-01`
  MPLS packet whose parsed label stack never reaches bottom-of-stack.

These records are present so users can demonstrate:

- the `Unrecognized Packets` Statistics section;
- the unrecognized packet list itself;
- current reason presentation;
- Packet Details fallback versus structured selected-packet inspection;
- selected-packet `Bytes` behavior for no-flow packets;
- packet-inspection-only semantics that are not parser failures, such as current MACsec selected-packet support without normal flow identity.

The showcase does not treat all malformed or unsupported packets as generic parser failures. Many malformed packets in the repository still remain inside recognized flows; only packets that current application semantics classify as global unrecognized records belong to this showcase group.

## Large Packet Size Coverage

Three short UDP flows intentionally exercise unusually large captured packet records with maxima around `2.5 KB`, `7.5 KB`, and `60 KB`.

- These scenarios are synthetic large/offload-style captured records rather than ordinary 1500-MTU Ethernet traffic.
- They are intended to exercise Analysis min/avg/max size contrast, capture `Packet Size Distribution` large buckets, capture-wide maximum-packet behavior, and Packet Details `Summary` / `Bytes` handling for very large complete records.
- Their maximum records preserve `captured length == original length`.
- `EDGE-SNAPLEN-01` remains the separate truncated-record example where captured and original lengths intentionally differ.

## Suggested Demo Route

1. Open the capture and confirm that `Flows`, `Analysis`, and `Statistics` populate normally.
2. Find `AN-TLS-BULK-01` by service `bulk-download.example.test`.
3. In `Analysis`, inspect:
   packet-size histogram, inter-arrival histogram, rate graph, burst/idle summary, and sequence preview.
4. Open `AN-GRE-TLS-01` and verify:
   complex Protocol Path, nested TLS Packet Summary, TLS Stream rows, and Analysis view.
5. Open `Statistics` and inspect `Detected Protocol Hints`.
   This showcase now contains representative confirmed rows for `HTTP`, `TLS`, `DNS`, `QUIC`, `SSH`, `STUN`, `BitTorrent`, `Mail protocols`, `DHCP`, and `mDNS`.
6. In Qt/Tauri Settings, enable the setting that allows `Possible TLS / Possible QUIC` fallback hints, then reopen/reimport the capture and confirm:
   `HINT-POSSIBLE-TLS-01` appears as `Possible TLS`, while `HINT-POSSIBLE-QUIC-01` appears as `Possible QUIC`.
   With the default setting disabled, both scenarios stay in `Unknown`.
7. Open `APP-QUIC-01` and confirm the compact full checked-in QUIC session remains one bidirectional flow with:
   Initial `CRYPTO`, structured TLS `ClientHello`, `0-RTT`, reverse Initial `ACK`, reverse Initial `ServerHello`, and later Handshake / Protected Payload presentation.
8. Open `APP-QUIC-MULTICRYPTO-01` and `APP-QUIC-MULTICRYPTO-02` as richer QUIC Stream examples with multi-CRYPTO Initial structure, bidirectional packet exchange, and reverse ServerHello / Handshake progression.
9. Open `APP-QUIC-NEG-01` and confirm the coarse undecryptable Initial presentation remains honest and separate from the positive QUIC flows.
10. Open `APP-HTTP-02`, `APP-HTTP-LARGEBODY-01`, `APP-DNS-02`, `APP-TLS-03`, `APP-TLS-SEGMENTED-01`, `APP-SSH-01`, `APP-STUN-01`, `APP-BITTORRENT-01`, `APP-SMTP-01`, `APP-POP3-01`, `APP-IMAP-01`, and `APP-DHCP-01` as the confirmed-hint application demos.
    `APP-HTTP-LARGEBODY-01` is the dedicated large HTTP reassembly showcase: inspect several response packets in `Packet Details`, switch to `Stream`, select the reconstructed `HTTP 200 OK` item, and confirm that `Summary` remains structured while `Item Data` still reports the current HTTP authoritative-byte limitation.
11. Open `APP-TLS-SEGMENTED-01` to demonstrate the segmented TLS ClientHello case where initial import detects `TLS` while Service remains empty, then bounded selected-flow reconstruction recovers `edge.microsoft.com` because the SNI lives in the second TCP segment.
12. Open `APP-MDNS-01` for multicast DNS-SD behavior and `APP-MDNS6-01` for the compact IPv6 UDP/mDNS/DNS-SD AAAA example.
   The scenario intentionally spans two multicast source flows under one stable `scenario_id`; use the manifest's `expected_flow_count` to validate it scenario-wide.
13. Open `APP-TLS-NOSNI-01` to demonstrate `Statistics -> QUIC and TLS -> TLS` coverage where `Without SNI` is non-zero while Packet Summary still shows structured TLS `ServerHello`.
14. Open one identity pair such as `OVL-GTPU-TEID-01` or `ID-VLAN-PAIR-01` and verify that default identity keeps the same effective tuple split into separate flows.
15. Open `NET-IPV4-OPTIONS-01` and `TCP-OPTIONS-01` to confirm the current structured options presentation.
16. Open `AN-LARGEPKT-2500-01`, `AN-LARGEPKT-7500-01`, and `AN-LARGEPKT-60000-01` to compare Analysis max packet size, per-flow size contrast, and capture `Packet Size Distribution` large buckets.
17. Open `EDGE-SNAPLEN-01` and compare captured versus original length semantics.
18. Open `EDGE-UNREC-01`, `L2-MACSEC-PACKET-01`, `L2-PPPOE-DISCOVERY-01`, `L2-LLCSNAP-UNREC-01`, and `TUN-MPLS-UNREC-01` from the Unrecognized Packets list and compare:
    current reason presentation, Packet Summary fallback versus structured packet inspection, and selected-packet `Bytes` behavior.

## Deterministic Generation Policy

This capture primarily uses deterministic synthetic/documentation data:

- IPv4 addresses from documentation ranges
- IPv6 addresses from `2001:db8::/32`
- deterministic locally-administered MAC addresses
- `*.example.test` DNS/SNI names
- `.local` names for mDNS / DNS-SD

For protocol cases whose correctness depends on cryptographically protected wire bytes, selected checked-in regression fixture payloads and purpose-recorded test captures supplied specifically for showcase/regression use may be reused exactly and may retain public service names present in those bytes.

Current exception:

- `APP-QUIC-01` reuses the exact QUIC UDP payloads from all `17` packets of the checked-in `quic_example_2.pcap` fixture.
- This deliberate exception preserves genuine decryptable QUIC/TLS behavior in the normal import / CLI path, including `ClientHello`, `ServerHello`, `0-RTT`, and later Handshake / Protected Payload semantics.
- The fixture retains the public SNI/service name `www.youtube.com`, which is accepted here because the payload is a checked-in non-sensitive regression fixture rather than private user traffic.
- `APP-QUIC-MULTICRYPTO-01` and `APP-QUIC-MULTICRYPTO-02` reuse all packets from purpose-recorded local QUIC test captures that were supplied specifically for showcase/regression use.
- These two richer QUIC examples retain the public SNI/service names `web.whatsapp.com` and `ep2.adtrafficquality.google` because the captures were intentionally recorded for testing rather than taken from private production/user traffic.

The local generator used to materialize the capture is intentionally **not committed**. Only the generated showcase artifacts belong in the repository.

## Known Limitations

Version `1.0.0` does not advertise:

- retransmission classification;
- out-of-order or overlap storytelling;
- DNS transaction correlation beyond current structured presentation;
- recursive ICMP quoted-packet deep inspection;
- ICMPv6 / NDP deep inspection;
- deep SCTP Stream semantics;
- deep SVCB / HTTPS parsing.

- `macsec` is intentionally represented in the primary showcase as packet-inspection-only rather than as a normal recognized flow.
  `L2-MACSEC-PACKET-01` reuses `tests/data/parsing/macsec/01_macsec_basic_no_sci.pcap`, which currently imports as `0` flows and `1` unrecognized packet through the normal CLI flow path while still exposing selected-packet MACsec Summary/Bytes inspection.
- There is also a separate observed CLI limitation for that same unrecognized-only MACsec fixture:
  `packet-info --packet-in-file 1` currently reports the packet as out of range even though `summary` counts one unrecognized packet.
- `IGMP` / `IGMPv1` / `IGMPv2` / `IGMPv3` can appear as flow-row Detected values, but current Statistics folds them into `Unknown` rather than a dedicated Detected Protocol row.
- `Possible TLS` / `Possible QUIC` are disabled by default and currently require the frontend settings path plus capture reopen/reimport; the current CLI settings JSON intentionally does not expose that toggle.
- `SLL` / `SLL2` are intentionally excluded from the primary showcase because they require a different capture link type and belong in a separate companion showcase later.

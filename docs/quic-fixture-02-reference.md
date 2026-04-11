# QUIC Fixture 02 Reference

Fixture under test:
- [quic_example_2.pcap](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/tests/data/parsing/quic/quic_example_2.pcap)

Reference sources:
- Corrected user spreadsheet `QUIC naming 2.ods`
- The corrected spreadsheet is the primary source of truth for the expectations below.

What this fixture covers:
- one QUIC flow with 17 packets
- `ClientHello` reassembled from four `CRYPTO` fragments across three packets
- explicit `0-RTT` semantics, including a mixed `Initial + CRYPTO + 0-RTT` packet
- `Initial + ACK`, `Initial + ACK + PADDING`, and `Initial + CRYPTO + PADDING`
- mixed `Handshake + Protected payload`
- mixed `Initial + ACK + Handshake + Protected payload`

Updated naming convention:
- semantic units may be rendered in a shell-aware form such as `QUIC Initial: ACK`, `QUIC Initial: CRYPTO`, or `QUIC Initial: CRYPTO, 0-RTT`
- this makes mixed QUIC packets easier to reason about when a single UDP packet carries several semantic units
- packet-level expectations and stream-level expectations below follow that shell-aware convention

Known conservative expectations:
- standalone `PADDING` must not become a stream item
- standalone `PING` must not become a stream item
- packet-level details may describe mixed semantics by presence text rather than a nested per-frame tree
- stream-level tests should assert ownership, order, and key semantic text, not full protocol text snapshots
- server-side `ServerHello` details must not be replaced by stale `ClientHello` details

## Packet-Level Expectations

| Packet | Dir | QUIC shell | Packet objects | Shell-aware packet label | TLS semantic |
| --- | --- | --- | --- | --- | --- |
| 1 | A->B | Initial | `CRYPTO`, `CRYPTO` | `QUIC Initial: (CRYPTO, CRYPTO)` | ClientHello |
| 2 | A->B | Initial | `CRYPTO` | `QUIC Initial: CRYPTO` | ClientHello |
| 3 | A->B | Initial | `CRYPTO`, `0-RTT` | `QUIC Initial: CRYPTO, 0-RTT` | ClientHello |
| 4 | A->B | 0-RTT | `0-RTT` | `0-RTT` | none |
| 5 | A->B | 0-RTT | `0-RTT` | `0-RTT` | none |
| 6 | A->B | 0-RTT | `0-RTT` | `0-RTT` | none |
| 7 | A->B | 0-RTT | `0-RTT` | `0-RTT` | none |
| 8 | A->B | 0-RTT | `0-RTT` | `0-RTT` | none |
| 9 | B->A | Initial | `ACK` | `QUIC Initial: ACK` | none |
| 10 | B->A | Initial | `ACK` | `QUIC Initial: ACK` | none |
| 11 | B->A | Initial | `ACK`, `PADDING` | `QUIC Initial: (ACK, PADDING)` | none |
| 12 | B->A | Initial | `ACK`, `PADDING` | `QUIC Initial: (ACK, PADDING)` | none |
| 13 | B->A | Initial | `CRYPTO`, `PADDING` | `QUIC Initial: (CRYPTO, PADDING)` | ServerHello |
| 14 | B->A | Handshake + Protected payload | `Handshake`, `Protected payload` | `Handshake, Protected payload` | none |
| 15 | B->A | Protected payload | `Protected payload` | `Protected payload` | none |
| 16 | A->B | Initial + Handshake + Protected payload | `ACK`, `Handshake`, `Protected payload` | `QUIC Initial: ACK, Handshake, Protected payload` | none |
| 17 | A->B | Protected payload | `Protected payload` | `Protected payload` | none |

Packet-level details should show at least:
- packets 1 / 2: `Packet Type: Initial`, `Frame Presence: CRYPTO`, `TLS Handshake Type: ClientHello`
- packet 3: `Packet Type: Initial`, `CRYPTO`, `0-RTT`, `TLS Handshake Type: ClientHello`
- packets 4-8: `Packet Type: 0-RTT`
- packets 9 / 10: `Packet Type: Initial`, `Frame Presence: ACK`
- packets 11 / 12: `Packet Type: Initial`, `Frame Presence: ACK, PADDING`
- packet 13: `Packet Type: Initial`, `Frame Presence: CRYPTO, PADDING`, `TLS Handshake Type: ServerHello`
- packet 14: both `Handshake` and `Protected Payload`
- packet 16: `Initial`, `ACK`, `Handshake`, and `Protected Payload`

Note:
- the packet table uses semantic packet objects such as `CRYPTO`, `ACK`, `PADDING`, `0-RTT`, `Handshake`, and `Protected payload`
- in packet details, these correspond to expected packet-level frame/payload presence in the UI
- TLS semantic attachment in this fixture comes from bounded QUIC `CRYPTO` assembly, not from QUIC shell type alone

Packet-level negative expectations:
- packet 13 must not show stale `ClientHello`
- packet 13 must not show `SNI:`
- ACK-only packets must not show TLS handshake details
- pure `0-RTT`, `Handshake`, and `Protected payload` packets must not show stale TLS handshake details

## Stream-Level Expectations

Stream items here are semantic units, not packet mirrors:
- one packet may map to multiple stream items
- one packet may also contribute no standalone stream item for low-value semantics such as `PADDING` or `PING`

Expected stream sequence:

| Order | Dir | Stream label | Source packet(s) | TLS semantic |
| --- | --- | --- | --- | --- |
| 1 | A->B | `QUIC Initial: CRYPTO` | 1 | ClientHello |
| 2 | A->B | `QUIC Initial: CRYPTO` | 1 | ClientHello |
| 3 | A->B | `QUIC Initial: CRYPTO` | 2 | ClientHello |
| 4 | A->B | `QUIC Initial: CRYPTO` | 3 | ClientHello |
| 5 | A->B | `0-RTT` | 3 | none |
| 6 | A->B | `0-RTT` | 4 | none |
| 7 | A->B | `0-RTT` | 5 | none |
| 8 | A->B | `0-RTT` | 6 | none |
| 9 | A->B | `0-RTT` | 7 | none |
| 10 | A->B | `0-RTT` | 8 | none |
| 11 | B->A | `QUIC Initial: ACK` | 9 | none |
| 12 | B->A | `QUIC Initial: ACK` | 10 | none |
| 13 | B->A | `QUIC Initial: ACK` | 11 | none |
| 14 | B->A | `QUIC Initial: ACK` | 12 | none |
| 15 | B->A | `QUIC Initial: CRYPTO` | 13 | ServerHello |
| 16 | B->A | `Handshake` | 14 | none |
| 17 | B->A | `Protected payload` | 14 | none |
| 18 | B->A | `Protected payload` | 15 | none |
| 19 | A->B | `QUIC Initial: ACK` | 16 | none |
| 20 | A->B | `Handshake` | 16 | none |
| 21 | A->B | `Protected payload` | 16 | none |
| 22 | A->B | `Protected payload` | 17 | none |

Stream-level detail expectations:
- `QUIC Initial: CRYPTO` from packets 1 / 2 / 3 should attach `ClientHello`
- `0-RTT` items should remain explicit `0-RTT`, not collapse into generic UDP payloads
- `QUIC Initial: ACK` items should remain protocol-aware but must not attach TLS details
- `QUIC Initial: CRYPTO` from packet 13 should attach `ServerHello`
- `Handshake` and `Protected payload` should remain distinct when both are present in one packet

### Mixed-Semantics Rules

- `CRYPTO + CRYPTO` inside one Initial packet may emit more than one `QUIC Initial: CRYPTO` stream item
- `CRYPTO + 0-RTT` -> stream may emit both `QUIC Initial: CRYPTO` and `0-RTT`
- `ACK + PADDING` -> stream emits `QUIC Initial: ACK` only
- `CRYPTO + PADDING` -> stream emits `QUIC Initial: CRYPTO` only
- `Handshake + Protected payload` -> stream may emit both when both are semantically meaningful and reliably identifiable
- `Initial + ACK + Handshake + Protected payload` -> stream may emit all semantically meaningful units
- standalone `PADDING` and standalone `PING` must not appear as stream items

Stream-level negative expectations:
- no standalone `PADDING` item
- no standalone `PING` item
- no generic `UDP Payload` fallback where a reliable QUIC semantic item is expected
- no stale `ClientHello` details on the server-side `ServerHello` case

## Why This Fixture Matters

This fixture extends fixture 01 in several important ways:
- `ClientHello` is reassembled from four `CRYPTO` fragments rather than a simpler bounded case
- `0-RTT` is explicit and must remain visible both packet-level and stream-level
- packet 16 proves that one packet can legitimately produce `ACK`, `Handshake`, and `Protected payload` stream units together
- packets 11 / 12 / 13 prove that packet-level `PADDING` presence does not imply a standalone stream item

The exact stream sequence is intentionally useful for this fixture, but the more important long-term guarantees are semantic mapping correctness, source-packet ownership, and correct TLS attachment ownership.

This document is the human-readable reference for the paired expectation spec:
- [quic_fixture_02_expectations.json](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/tests/fixtures/quic_fixture_02_expectations.json)

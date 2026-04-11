# QUIC Fixture 01 Reference

Fixture under test:
- [quic_example_1.pcap](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/tests/data/parsing/quic/quic_example_1.pcap)

Reference sources:
- User packet/item mapping tables from `QUIC naming tables 1.odt` / `QUIC naming tables 1.pdf`
- These external authoring documents are the primary source for the expectations below.

What this fixture covers:
- one QUIC flow with 19 packets
- multi-packet TLS-over-CRYPTO attachment in both directions
- packets that map to multiple QUIC semantic units
- stream-level suppression of standalone `PADDING`
- mixed `Handshake` and `Protected payload` semantics inside the same capture segment

Updated naming convention:
- semantic units may be described in a shell-aware form such as `QUIC Initial: ACK` or `QUIC Initial: CRYPTO`
- this makes it easier to distinguish semantic units that occur inside the same QUIC shell
- fixture 01 still keeps current concrete UI labels in the paired JSON spec where tests need exact string matching

Known conservative expectations:
- `PADDING` should not become a standalone stream item
- `PING` should not become a standalone stream item
- packet-level details may describe merged frame presence rather than exposing a nested per-frame object list
- stream-level tests should assert semantic mapping, source packets, and key details text, not full protocol text snapshots
- `ServerHello` details must not be replaced by stale `ClientHello` details

## Packet-Level Expectations

| Packet | Dir | QUIC shell | Packet objects | Shell-aware packet label | TLS semantic |
| --- | --- | --- | --- | --- | --- |
| 1 | A->B | Initial | `CRYPTO`, `CRYPTO` | `QUIC Initial: (CRYPTO, CRYPTO)` | ClientHello |
| 2 | A->B | Initial | `CRYPTO` | `QUIC Initial: CRYPTO` | ClientHello |
| 3 | B->A | Initial | `ACK` | `QUIC Initial: ACK` | none |
| 4 | B->A | Initial | `ACK`, `PADDING` | `QUIC Initial: (ACK, PADDING)` | none |
| 5 | B->A | Initial | `CRYPTO`, `PADDING` | `QUIC Initial: (CRYPTO, PADDING)` | ServerHello |
| 6 | A->B | Initial | `ACK` | `QUIC Initial: ACK` | none |
| 7 | B->A | Initial | `CRYPTO`, `PADDING` | `QUIC Initial: (CRYPTO, PADDING)` | ServerHello |
| 8 | A->B | Initial | `ACK` | `QUIC Initial: ACK` | none |
| 9 | B->A | Handshake | `Handshake` | `Handshake` | none |
| 10 | B->A | Handshake | `Handshake` | `Handshake` | none |
| 11 | B->A | Handshake | `Handshake` | `Handshake` | none |
| 12 | A->B | Handshake | `Handshake` | `Handshake` | none |
| 13 | B->A | Handshake | `Handshake` | `Handshake` | none |
| 14 | B->A | Handshake | `Handshake` | `Handshake` | none |
| 15 | B->A | Handshake | `Handshake`, `Protected payload` | `Handshake, Protected payload` | none |
| 16 | A->B | Handshake | `Handshake` | `Handshake` | none |
| 17 | A->B | Handshake | `Handshake`, `Protected payload` | `Handshake, Protected payload` | none |
| 18 | A->B | Protected payload | `Protected payload` | `Protected payload` | none |
| 19 | B->A | Protected payload | `Protected payload` | `Protected payload` | none |

Packet-level details should show at least:
- packet 1 / 2: `Packet Type: Initial`, `Frame Presence: CRYPTO`, `TLS Handshake Type: ClientHello`
- packet 5 / 7: `Packet Type: Initial`, `Frame Presence: CRYPTO, PADDING`, `TLS Handshake Type: ServerHello`
- packet 3 / 4 / 6 / 8: `Packet Type: Initial` plus `Frame Presence: ACK` or `Frame Presence: ACK, PADDING`
- packet 18 / 19: `Packet Type: Protected Payload`

Note:
- the packet table uses semantic packet objects such as `CRYPTO`, `ACK`, `PADDING`, `Handshake`, and `Protected payload`
- in packet details, these correspond to expected packet-level frame/payload presence in the UI, typically expressed through `Frame Presence: ...` and the selected QUIC packet type text
- TLS semantic attachment in this fixture comes from bounded QUIC `CRYPTO` assembly, not from QUIC shell type alone

Packet-level negative expectations:
- packet 5 / 7 must not show stale `ClientHello`
- packet 5 / 7 must not show `SNI:`
- ACK-only packets must not show TLS handshake details

## Stream-Level Expectations

Stream items here are semantic units, not packet mirrors:
- one packet may map to multiple stream items
- one packet may also contribute no standalone stream item for low-value semantics such as `PADDING` or `PING`

Expected stream sequence:

| Order | Dir | Semantic label | UI label | Source packet(s) | TLS semantic |
| --- | --- | --- | --- | --- | --- |
| 1 | A->B | `QUIC Initial: CRYPTO` | `QUIC Initial: CRYPTO` | 1 | ClientHello |
| 2 | A->B | `QUIC Initial: CRYPTO` | `QUIC Initial: CRYPTO` | 1 | ClientHello |
| 3 | A->B | `QUIC Initial: CRYPTO` | `QUIC Initial: CRYPTO` | 2 | ClientHello |
| 4 | B->A | `QUIC Initial: ACK` | `QUIC Initial: ACK` | 3 | none |
| 5 | B->A | `QUIC Initial: ACK` | `QUIC Initial: ACK` | 4 | none |
| 6 | B->A | `QUIC Initial: CRYPTO` | `QUIC Initial: CRYPTO` | 5 | ServerHello |
| 7 | A->B | `QUIC Initial: ACK` | `QUIC Initial: ACK` | 6 | none |
| 8 | B->A | `QUIC Initial: CRYPTO` | `QUIC Initial: CRYPTO` | 7 | ServerHello |
| 9 | A->B | `QUIC Initial: ACK` | `QUIC Initial: ACK` | 8 | none |
| 10 | B->A | `Handshake` | `Handshake` | 9 | none |
| 11 | B->A | `Handshake` | `Handshake` | 10 | none |
| 12 | B->A | `Handshake` | `Handshake` | 11 | none |
| 13 | A->B | `Handshake` | `Handshake` | 12 | none |
| 14 | B->A | `Handshake` | `Handshake` | 13 | none |
| 15 | B->A | `Handshake` | `Handshake` | 14 | none |
| 16 | B->A | `Handshake` | `Handshake` | 15 | none |
| 17 | B->A | `Protected payload` | `Protected payload` | 15 | none |
| 18 | A->B | `Handshake` | `Handshake` | 16 | none |
| 19 | A->B | `Handshake` | `Handshake` | 17 | none |
| 20 | A->B | `Protected payload` | `Protected payload` | 17 | none |
| 21 | A->B | `Protected payload` | `Protected payload` | 18 | none |
| 22 | B->A | `Protected payload` | `Protected payload` | 19 | none |

Stream-level detail expectations:
- `QUIC Initial: CRYPTO` from packets 1 and 2 should attach `ClientHello`
- `QUIC Initial: CRYPTO` from packets 5 and 7 should attach `ServerHello`
- `QUIC Initial: ACK` items should stay protocol-aware but must not attach TLS details
- `Handshake` items should remain `Handshake`, not collapse into generic `UDP Payload`
- `Protected payload` items should remain distinct from `Handshake`

### Mixed-Semantics Rules

- `CRYPTO + PADDING` -> stream emits `QUIC Initial: CRYPTO` only
- `ACK + PADDING` -> stream emits `QUIC Initial: ACK` only
- `Handshake + Protected payload` -> stream may emit both when both are semantically meaningful and reliably identifiable
- standalone `PADDING` and standalone `PING` must not appear as stream items

Stream-level negative expectations:
- no standalone `PADDING` item
- no standalone `PING` item
- no stale `ClientHello` details on server-side `CRYPTO` items
- no generic `UDP Payload` fallback where the mapping table expects a reliable QUIC item

## Why This Fixture Matters

This fixture is intentionally stricter than the earlier narrow QUIC smoke tests:
- packet 1 maps to two QUIC `CRYPTO` semantic units
- packets 5 and 7 carry `ServerHello` semantics that must stay direction-owned
- packets 15 and 17 prove that one capture packet can map to more than one stream item

The exact stream sequence remains intentionally valuable for this fixture, but the more important long-term guarantees are semantic mapping correctness and source-packet ownership.

This document is the human-readable reference for the paired expectation spec:
- [quic_fixture_01_expectations.json](/C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/tests/fixtures/quic_fixture_01_expectations.json)

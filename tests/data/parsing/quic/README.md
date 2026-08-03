# QUIC Fixture Contracts

This directory contains the permanent QUIC packet captures used by the current
selected-flow QUIC tests.

These fixtures currently support:

- structured Packet Details Summary layers built from bounded QUIC inspection,
  not from reparsing formatted `protocol_text`;
- structured Stream Item Summary layers built from the structured QUIC and TLS
  models already retained by the selected-flow Stream path;
- selected-packet byte inspection for captured QUIC envelopes, authoritative
  Initial protected-payload ranges, decrypted Initial plaintext, plaintext
  QUIC frame ranges, and CRYPTO frame value ranges where the bounded QUIC path
  already provides authoritative provenance;
- shell-aware QUIC packet semantics;
- bounded `Initial` CRYPTO to TLS handoff for Packet Details Summary;
- bounded `Initial` CRYPTO to TLS handoff for Stream Item Summary on existing
  QUIC semantic rows;
- coalesced-packet ordering checks for `quic_example_1.pcap` and
  `quic_example_2.pcap`;
- existing stream-item contracts defined by the checked-in JSON expectation
  files.

Authoritative semantic contracts:

- [quic_fixture_01_expectations.json](../../fixtures/quic_fixture_01_expectations.json)
- [quic_fixture_02_expectations.json](../../fixtures/quic_fixture_02_expectations.json)

Repository-wide interpretation rules confirmed by these fixtures:

- shell-aware semantic labels are authoritative;
- one captured UDP packet may map to multiple QUIC semantic objects;
- one captured UDP packet may map to multiple QUIC byte-view envelope owners;
- one captured UDP packet may map to multiple selected-flow Stream items;
- decrypted Initial plaintext remains selected-packet-only, does not create
  Stream byte retention, and is not duplicated into a second complete owner
  buffer solely for byte presentation;
- `CRYPTO Data` byte views expose only CRYPTO frame value bytes; they do not
  expose the frame type or the encoded CRYPTO offset/length varints;
- packet-level `PADDING` does not require a standalone Stream item;
- packet-level QUIC frame presence and Stream item generation are different
  contracts.

## Automated Fixture Inventory

### `quic_example_1.pcap`

- Source/generation: checked-in permanent capture referenced by
  [docs/quic-fixture-01-reference.md](../../../docs/quic-fixture-01-reference.md)
  and `quic_fixture_01_expectations.json`.
- Packet count: 19.
- Packet numbers referenced by automated tests: 1, 5, 15, 17, 18, 19.
- Direction/packet classes:
  - client `Initial` with `CRYPTO`;
  - server `Initial` with `ACK`, `PADDING`, or `CRYPTO`;
  - later `Handshake`;
  - coalesced `Handshake + Protected payload`;
  - pure `Protected payload`.
- Coalesced semantics:
  - packet 15: `Handshake`, `Protected payload`;
  - packet 17: `Handshake`, `Protected payload`.
- QUIC version: QUIC v1 in current packet-details/protocol expectations.
- Initial decryption behavior:
  - client and server `Initial` packets expose bounded `CRYPTO`/TLS metadata
    where supported;
  - ACK-only `Initial` packets remain packet-local frame summaries.
- TLS semantics:
  - client `ClientHello`;
  - server `ServerHello`;
  - no stale client `SNI` on server `Initial` packets.
- Useful for:
  - Packet tests;
  - Stream tests;
  - coalesced shell-order checks.

### `quic_example_2.pcap`

- Source/generation: checked-in permanent capture referenced by
  [docs/quic-fixture-02-reference.md](../../../docs/quic-fixture-02-reference.md)
  and `quic_fixture_02_expectations.json`.
- Packet count: 17.
- Packet numbers referenced by automated tests: 1, 3, 4, 11, 13, 14, 16.
- Direction/packet classes:
  - client `Initial`;
  - explicit `0-RTT`;
  - server `Initial` with `ACK` or `CRYPTO`;
  - coalesced `Handshake + Protected payload`;
  - mixed `Initial + Handshake + Protected payload`.
- Coalesced semantics:
  - packet 3: `Initial`, `0-RTT`;
  - packet 14: `Handshake`, `Protected payload`;
  - packet 16: `Initial`, `Handshake`, `Protected payload`.
- QUIC version: QUIC v1 in current packet-details/protocol expectations.
- Initial decryption behavior:
  - bounded client `CRYPTO` reassembly exposes `ClientHello`;
  - bounded server `CRYPTO` reassembly exposes `ServerHello`;
  - selected-packet byte inspection now distinguishes:
    - early contributing client `Initial` packets that need one bounded
      cross-packet `QUIC CRYPTO Stream (Reassembled)` owner before exposing
      `TLS Handshake Message, ClientHello (Reassembled)`;
    - later/coalesced client `Initial` packet views that still expose the same
      structured `ClientHello` contract with no synthetic TLS record;
  - pure `0-RTT` packets remain opaque QUIC packet summaries without false TLS.
- TLS semantics:
  - `ClientHello` stays attached to the `Initial` shell, not to `0-RTT`;
  - server `Initial` packets expose `ServerHello` with no client `SNI`.
- Useful for:
  - Packet tests;
  - Stream tests;
  - `0-RTT` naming;
  - coalesced shell-order checks.

### `quic_initial_ch_1.pcap`

- Source/generation: permanent single-packet client `Initial` smoke fixture.
- Packet count: single-packet fixture.
- Packet numbers referenced by automated tests: 1.
- Direction/packet classes:
  - client `Initial`;
  - `CRYPTO`.
- QUIC version: current tests expect QUIC classification on UDP/443.
- Initial decryption behavior:
  - bounded `Initial` payload parsing exposes TLS over `CRYPTO`.
  - selected-packet byte inspection exposes the captured `Initial` envelope,
    the authoritative protected-payload range, one derived decrypted Initial
    owner, one plaintext `CRYPTO` frame range, and one nested `CRYPTO Data`
    range.
- TLS semantics:
  - `ClientHello`;
  - `SNI` present.
- Useful for:
  - Packet tests;
  - protocol-details tests;
  - selected-flow TLS handoff smoke coverage.

### `quic_initial_sh_2.pcap`

- Source/generation: permanent single-packet server `Initial` smoke fixture.
- Packet count: single-packet fixture.
- Packet numbers referenced by automated tests: 1.
- Direction/packet classes:
  - server `Initial`;
  - `CRYPTO`.
- Initial decryption behavior:
  - bounded `Initial` payload parsing exposes server TLS handshake metadata.
- TLS semantics:
  - `ServerHello`;
  - no client `SNI`.
- Useful for:
  - Packet tests;
  - Flow-hint QUIC recognition smoke coverage.

### `quic_handshake_3.pcap`

- Source/generation: permanent single-packet long-header `Handshake` fixture.
- Packet count: single-packet fixture.
- Packet numbers referenced by automated tests: 1.
- Direction/packet classes:
  - `Handshake`.
- Initial decryption behavior: not applicable.
- TLS semantics:
  - none;
  - packet remains opaque `Handshake`.
- Useful for:
  - Packet tests;
  - protocol-details tests;
  - Stream tests.

### `quic_protected_payload_4.pcap`

- Source/generation: permanent single-packet short-header protected-payload
  fixture.
- Packet count: single-packet fixture.
- Packet numbers referenced by automated tests: 1.
- Direction/packet classes:
  - short-header `Protected payload`.
- Initial decryption behavior: not applicable.
- TLS semantics:
  - none.
- Notes:
  - Flow-hint tests intentionally keep service detection conservative here.
  - The current selected-flow Stream contract also stays conservative here and
    keeps the row as generic `UDP Payload`, so structured `Protected payload`
    Stream Summary ownership is exercised by `quic_example_1.pcap` and
    `quic_example_2.pcap` instead of this single-packet fixture.
- Useful for:
  - Packet tests;
  - conservative Stream fallback coverage;
  - protected short-header classification coverage.

### `quic_initial_ack_decrypt_ok_1.pcap`

- Source/generation: permanent multi-packet `Initial` ACK fixture.
- Packet count: 8.
- Packet numbers referenced by automated tests: 8.
- Direction/packet classes:
  - `Initial`.
- Initial decryption behavior:
  - packet 8 exposes `ACK` only when packet-number handling is correct.
  - selected-packet byte inspection exposes the captured `Initial` envelope,
    the authoritative protected-payload range, one derived decrypted Initial
    owner, and one plaintext `ACK` frame range with no fabricated `CRYPTO`
    value view.
- TLS semantics:
  - none.
- Useful for:
  - Packet tests;
  - Stream tests;
  - conservative ACK-only `Initial` coverage.

### `quic_initial_ack_wrong_pkn_1.pcap`

- Source/generation: permanent negative packet-number fixture.
- Packet count: 8.
- Packet numbers referenced by automated tests: 8.
- Direction/packet classes:
  - `Initial`.
- Initial decryption behavior:
  - intentionally wrong packet number keeps the result conservative;
  - packet 8 must not fabricate `ACK` semantics.
  - selected-packet byte inspection must not fabricate decrypted Initial
    plaintext, plaintext QUIC frame ranges, `CRYPTO Data`, or TLS byte
    ownership.
- TLS semantics:
  - none.
- Useful for:
  - Packet tests;
  - Stream tests;
  - decryption-failure conservatism.

### `quic_constricted_1.pcap`

- Source/generation: permanent constricted-flow QUIC fixture.
- Packet count: 18.
- Packet numbers referenced by automated tests:
  - packet 1 for Packet Details Summary;
  - packet 8 in parser/stream references;
  - packets 13-18 in constricted Stream assertions.
- Direction/packet classes:
  - early `Initial` with `CRYPTO` and `ACK`;
  - later `Handshake`;
  - later `Protected payload`.
- Initial decryption behavior:
  - early `Initial` packets expose bounded `CRYPTO` semantics;
  - later packets remain selected-flow bounded and do not force full-flow
    materialization.
- TLS semantics:
  - client `ClientHello` in bounded early packets;
  - structured Stream Summary now expects the reconstructed `ClientHello` on
    every contributing early `QUIC Initial: CRYPTO` row, not only on a single
    completion row;
  - later packets remain non-TLS QUIC summaries.
- Useful for:
  - Packet tests;
  - Stream tests;
  - bounded/constricted-flow coverage.

### `ipv6_quic_constricted_1.pcap`

- Source/generation: permanent IPv6 constricted-flow QUIC fixture.
- Packet count: 16.
- Packet numbers referenced by automated tests: packet 1 and constricted Stream
  sequence coverage.
- Direction/packet classes:
  - IPv6 `Initial` with `CRYPTO`;
  - later QUIC semantic objects under the same selected-flow bounded model.
- Initial decryption behavior:
  - packet-local bounded `Initial` parsing works through the IPv6 transport
    path as well.
- TLS semantics:
  - current stream tests expect client `SNI`/QUIC flow metadata on this
    capture;
  - the early IPv6 `QUIC Initial: CRYPTO` rows provide multi-row contributing
    `ClientHello` Stream Summary coverage.
- Useful for:
  - Packet tests;
  - Stream tests;
  - IPv6 parity coverage.

## Confirmed Missing Permanent Fixture Coverage

- Retry:
  - missing permanent automated fixture coverage.
- Version Negotiation:
  - missing permanent automated fixture coverage.
- Standalone `0-RTT`:
  - partially covered by `quic_example_2.pcap` packets 4-8;
  - sufficient for packet-type naming and opaque-summary coverage;
  - still insufficient for broader IPv6 or alternate-flow standalone `0-RTT`
    scenarios.
- Coalesced datagrams:
  - covered by `quic_example_1.pcap` and `quic_example_2.pcap`.
- `CRYPTO` split across multiple `Initial` packets:
  - covered by `quic_example_2.pcap`.
- Out-of-order `CRYPTO` ranges:
  - missing permanent automated fixture coverage.
- Exact duplicate `CRYPTO` ranges:
  - missing permanent automated fixture coverage.
- Gap in `CRYPTO` ranges:
  - missing permanent automated fixture coverage.
- Identical overlap in `CRYPTO` ranges:
  - missing permanent automated fixture coverage.
- Conflicting overlap in `CRYPTO` ranges:
  - missing permanent automated fixture coverage.
- QUIC v2:
  - missing permanent automated fixture coverage.

## Not Added In This Pass

- generic QUIC `Data` summary layers;
- structured QUIC Stream Item Summary layers;
- new binary QUIC fixtures;
- Retry integrity validation;
- Version Negotiation packet-summary coverage beyond direct synthetic tests.

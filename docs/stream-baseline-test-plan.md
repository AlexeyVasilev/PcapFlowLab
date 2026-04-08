# Stream Baseline Fixture Test Plan

## Purpose

Before changing Stream materialization, we need a narrow regression baseline built around stable small captures.

This plan prefers existing repository fixtures first. New PCAP fixtures should be added only where current repository captures do not cover a required Stream behavior safely.

The baseline should focus on robust assertions:

- expected key labels
- packet count vs multi-packet behavior
- generic vs protocol-aware classification
- presence or absence of `payload_hex_text` and `protocol_text`
- details-panel fallback behavior for single-packet generic items

It should avoid brittle full-text snapshots of the entire Stream or details panes.

## Existing Fixtures That Can Be Reused

### HTTP request

Fixture:

- `tests/data/parsing/http/http_get_1.pcap`

Baseline expectations:

- one TCP flow
- one Stream item
- label is protocol-aware HTTP request
  - narrow assertion: starts with `HTTP `
  - stronger current expectation: `HTTP GET /`
- item is complete, not partial
- `packet_count == 1`
- `protocol_text` is present
- `payload_hex_text` is present
- Stream Item Details should use the item-level texts, not packet fallback

### HTTP response

Fixture:

- `tests/data/parsing/http/http_answer_2.pcap`

Baseline expectations:

- one TCP flow
- one Stream item
- label is protocol-aware HTTP response
  - narrow assertion: starts with `HTTP ` and is not `HTTP Request`
  - stronger current expectation: includes status code / reason
- item is complete, not partial
- `packet_count == 1`
- `protocol_text` is present
- `payload_hex_text` is present
- Stream Item Details should use the item-level texts

### DNS query

Fixture:

- `tests/data/parsing/dns/dns_request_1.pcap`

Recommended baseline split:

- fast mode:
  - one UDP Stream item
  - label remains generic: `UDP Payload`
  - `packet_count == 1`
  - item may rely on single-packet fallback in details
  - Protocol details fallback should follow packet-details rules for the current mode
- deep mode:
  - one UDP Stream item
  - label becomes protocol-aware DNS query
    - narrow assertion: starts with `DNS`
    - stronger current expectation: `DNS Query`
  - protocol-aware item text is acceptable if present

### DNS response

Fixture:

- `tests/data/parsing/dns/dns_response_2.pcap`

Recommended baseline split:

- fast mode:
  - generic `UDP Payload`
- deep mode:
  - protocol-aware DNS response
    - narrow assertion: starts with `DNS`
    - stronger current expectation: `DNS Response`

### TLS single-packet ClientHello

Fixture:

- `tests/data/parsing/tls/tls_client_hello_1.pcap`

Baseline expectations:

- one TCP flow
- one Stream item
- label is TLS-aware
  - narrow assertion: starts with `TLS `
  - stronger current expectation: `TLS ClientHello`
- item is complete, not partial
- `packet_count == 1`
- `protocol_text` is present
- `payload_hex_text` is present
- Stream Item Details should use item-level text, not packet fallback

### TLS single-packet ServerHello

Fixture:

- `tests/data/parsing/tls/tls_1_2_server_hello_4.pcap`
  or
- `tests/data/parsing/tls/tls_1_3_server_hello_6.pcap`

Baseline expectations:

- one TCP flow
- one Stream item
- label is TLS-aware
  - narrow assertion: starts with `TLS `
  - stronger current expectation: `TLS ServerHello`
- item is complete, not partial
- `packet_count == 1`
- `protocol_text` is present
- `payload_hex_text` is present

### QUIC flow that remains generic UDP in Stream

Fixture:

- `tests/data/parsing/quic/quic_initial_ch_1.pcap`

Baseline expectations:

- flow protocol hint may already be QUIC at flow level
- Stream still remains generic UDP for the current implementation
- one or more UDP Stream items are acceptable depending on packet count in the capture
- item labels should stay generic rather than QUIC-specific
  - narrow assertion: every Stream label in this fixture is `UDP Payload`
- no QUIC-specific Stream labels should be asserted in the baseline
- this test locks current behavior intentionally, to prevent accidental silent drift before dedicated QUIC Stream work begins

## Existing Synthetic Coverage Already Present

These tests already cover important Stream behavior, even though they are not backed by repository PCAP fixtures:

- generic TCP payload fallback
- generic UDP payload fallback
- HTTP split request reassembly
- HTTP split response reassembly
- multiple HTTP messages in one direction
- HTTP partial headers / partial payload behavior
- TLS split-record reassembly
- TLS split app-data reassembly
- TLS multi-record sequence
- TLS partial / fragmented record behavior
- selected-flow packet-prefix / `load more` behavior in UI tests

Relevant files:

- `tests/unit/StreamQueryTests.cpp`
- `tests/ui/MainControllerUiTests.cpp`

These should remain in place. The fixture-backed baseline is meant to complement them, not replace them.

## Minimal Additional PCAP Fixtures Needed

### Required: TLS multi-packet reassembly-sensitive fixture

Suggested fixture:

- `tests/data/parsing/tls/tls_split_server_hello_2pkts.pcap`

Why it is needed:

- current repository TLS fixtures are single-packet only
- we need at least one stable repository PCAP that proves Stream can materialize one TLS item from two packets
- this is the smallest fixture that protects reassembly-sensitive TLS Stream behavior without relying only on synthetic generators

Baseline expectations:

- one TCP flow
- one Stream item
- label is TLS-aware, preferably `TLS ServerHello`
- `packet_count == 2`
- item is not generic `TCP Payload`
- `protocol_text` is present
- `payload_hex_text` is present
- Stream Item Details should use item-level texts, not packet fallback

### Required: generic UDP payload fixture

Suggested fixture:

- `tests/data/parsing/udp/udp_payload_1.pcap`

Why it is needed:

- current repository fixtures do not contain a protocol-neutral UDP payload case
- DNS and QUIC are both useful, but they carry protocol meaning and should not be the only fallback references
- a tiny one-packet UDP payload fixture gives a clean baseline for generic UDP Stream fallback

Baseline expectations:

- one UDP flow
- one Stream item
- label is `UDP Payload`
- `packet_count == 1`
- item is generic, not protocol-aware
- Stream Item Details should fall back to the underlying packet for payload/protocol fields

### Optional: partial / truncated Stream fixture

Suggested fixture:

- `tests/data/parsing/http/http_partial_headers_2pkts.pcap`
  or
- `tests/data/parsing/tls/tls_partial_record_1pkt.pcap`

Why it is optional:

- partial behavior is already covered synthetically in `StreamQueryTests.cpp`
- adding one repository fixture would improve long-term readability, but it is not the first priority if we want the minimal fixture set

Recommended narrow expectation:

- one complete item followed by one partial item
- partial label is explicit
  - `HTTP Payload (partial)` or `TLS Record Fragment (partial)`
- protocol text explains incompleteness
- no brittle full-text snapshot

## Tests To Add First

### First wave: repository fixture-backed unit tests

Add small `CaptureSession::list_flow_stream_items(...)` tests first.

Recommended first set:

1. `http_get_1.pcap`
   - assert one protocol-aware HTTP request Stream item
2. `http_answer_2.pcap`
   - assert one protocol-aware HTTP response Stream item
3. `dns_request_1.pcap`
   - assert fast = generic UDP, deep = DNS Query
4. `dns_response_2.pcap`
   - assert fast = generic UDP, deep = DNS Response
5. `tls_client_hello_1.pcap`
   - assert one TLS-aware single-packet item
6. `tls_1_2_server_hello_4.pcap` or `tls_1_3_server_hello_6.pcap`
   - assert one TLS-aware single-packet item
7. `quic_initial_ch_1.pcap`
   - assert Stream remains generic UDP today

This first wave gives a stable small-capture baseline without adding any new fixture files.

### Second wave: minimal new fixture additions

After the first wave is stable, add:

1. `tls_split_server_hello_2pkts.pcap`
   - to lock reassembly-sensitive TLS Stream behavior
2. `udp_payload_1.pcap`
   - to lock pure generic UDP fallback behavior

### Third wave: optional readability fixture

Add one partial fixture only if needed for clearer long-term intent:

- `http_partial_headers_2pkts.pcap`
  or
- `tls_partial_record_1pkt.pcap`

## Suggested Assertion Style

Prefer assertions like these:

- row count is small and explicit
- labels match a narrow expected set
- `packet_count` is `1` or `2` as intended
- `protocol_text.empty()` / `payload_hex_text.empty()` presence checks
- details fallback behavior is checked by category, not full snapshots

Avoid:

- full multi-line text snapshots of protocol details
- exact byte-for-byte full payload dumps unless the case specifically needs it
- assertions that depend on incidental wording outside the core behavior

## Summary

Existing repository fixtures already cover:

- HTTP request
- HTTP response
- DNS query
- DNS response
- TLS single-packet ClientHello
- TLS single-packet ServerHello
- QUIC flow that currently remains generic UDP in Stream

Minimal new repository fixtures still needed for a stronger baseline:

- one TLS multi-packet reassembly-sensitive capture
- one protocol-neutral generic UDP payload capture

Optional later fixture:

- one partial / truncated Stream capture

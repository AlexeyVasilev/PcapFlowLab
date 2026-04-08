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

## Additional Repository Fixtures Now Available

### HTTP multi-message sequence

Fixture:

- `tests/data/parsing/http/http_multi_message_3.pcap`

Baseline expectations:

- one TCP flow
- at least three protocol-aware HTTP request items
  - narrow assertion: labels start with `HTTP GET`
- at least three protocol-aware HTTP response items
  - narrow assertion: labels start with `HTTP 200`
- at least one HTTP response item spans multiple packets
- complete large responses must stay HTTP-aware rather than collapsing into `HTTP Payload (partial)`

### HTTP redirect followed by partial response tail

Fixture:

- `tests/data/parsing/http/http_partial_response_4.pcap`

Baseline expectations:

- the capture contains two TCP flows
- one flow is a clean redirect pair
  - `HTTP GET /`
  - `HTTP 301 Moved Permanently`
- another flow contains a partial tail after a successful response
  - `HTTP GET /`
  - `HTTP 200 OK`
  - trailing `HTTP Payload (partial)`
- the partial item should explain incompleteness in `protocol_text`

### Generic UDP payload

Fixture:

- `tests/data/parsing/udp/udp_generic_payload_2.pcap`

Baseline expectations:

- one or more UDP Stream items
- every item label is `UDP Payload`
- no DNS-specific or QUIC-specific labels appear
- item-level `protocol_text` and `payload_hex_text` remain empty

### Generic TCP payload

Fixture:

- `tests/data/parsing/tcp/tcp_generic_payload_7.pcap`

Baseline expectations:

- one or more TCP Stream items
- every item label is `TCP Payload`
- no HTTP-specific or TLS-specific labels appear
- item-level `protocol_text` and `payload_hex_text` remain empty

### TLS partial tail

Fixture:

- `tests/data/parsing/tls/tls_partial_tail_5.pcap`

Baseline expectations:

- TLS-aware handshake items are still materialized before the truncated tail
- the final item is explicit partial TLS data
  - `TLS Payload (partial)` or `TLS Record Fragment (partial)`
- if the fragment label is used, `protocol_text` should explain incompleteness

### TLS retransmitted server handshake

Fixture:

- `tests/data/parsing/tls/tls_server_handshake_retransmit_6.pcap`

Baseline expectations:

- one TLS ClientHello item is present
- at least one later TLS-aware server-side item spans multiple packets
- retransmission must not degrade the whole stream to generic `TCP Payload`

## Minimal Additional PCAP Fixtures Needed

The latest fixture wave covers several previously missing baseline categories already:

- generic UDP fallback is now covered by `udp_generic_payload_2.pcap`
- generic TCP fallback is now covered by `tcp_generic_payload_7.pcap`
- repository-backed partial HTTP behavior is now covered by `http_partial_response_4.pcap`
- repository-backed multi-packet TLS behavior is now covered by `tls_server_handshake_retransmit_6.pcap`

Still useful later, if we want even smaller single-purpose captures:

- a tiny two-packet TLS ServerHello fixture with no retransmission noise
- a tiny one-message truncated HTTP or TLS fixture that isolates partial handling more narrowly than the current real captures

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

### Second wave: use the current real-fixture additions

The current repository already has good second-wave coverage in place:

1. `http_multi_message_3.pcap`
  - locks large multi-message HTTP response handling
2. `http_partial_response_4.pcap`
  - locks redirect plus partial-tail HTTP behavior
3. `udp_generic_payload_2.pcap`
  - locks pure generic UDP fallback behavior
4. `tcp_generic_payload_7.pcap`
  - locks pure generic TCP fallback behavior
5. `tls_partial_tail_5.pcap`
  - locks explicit partial TLS tail behavior
6. `tls_server_handshake_retransmit_6.pcap`
  - locks reassembly-sensitive TLS behavior under retransmission

### Third wave: optional simplification fixtures

Add smaller single-purpose captures only if the current real fixtures feel too noisy for future maintenance.

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

Additional repository fixtures now cover:

- HTTP multi-message response sequences
- HTTP redirect plus partial-tail response behavior
- generic UDP fallback
- generic TCP fallback
- partial TLS tails
- TLS retransmitted multi-packet handshake behavior

Smaller single-purpose fixtures may still be useful later, but they are no longer required to establish the current baseline.

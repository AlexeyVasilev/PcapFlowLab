# Current State

## Stream

- Fixture-backed baseline tests are in place for 7 repository PCAP cases.
- HTTP Stream reconstruction supports requests and responses, including bounded body assembly across multiple TCP segments via `Content-Length` and chunked-body traversal, with conservative fallback where needed.
- Partial HTTP and TLS cases have explicit fallback handling.
- Selected-flow-only retransmission detection is implemented.
- Retransmission indication is surfaced in the selected-flow packet list, and selected-flow Stream construction suppresses retransmitted packets in the current bounded model.
- Stream materialization now uses one bounded on-demand pipeline for both initial and extended selected-flow views.
- TLS Stream item protocol details now expose a first narrow enrichment step for `ClientHello`, `ServerHello`, and `Certificate` items.
- Packet Details now exposes the same narrow TLS enrichment for complete packet-contained `ClientHello`, `ServerHello`, and `Certificate` records.
- Selected-packet protocol details now depend on packet-bytes availability, not Deep mode alone.
- Selected-flow QUIC inspection now exposes bounded packet-aware details for `Initial`, `Handshake`, `Retry`, `Version Negotiation`, `Protected Payload`, and practical frame-level cases such as `CRYPTO`, `ACK`, and `PADDING`, with conservative fallback where confidence is limited.
- QUIC packet and Stream details now use direction-aware, ownership-aware selected-flow TLS attachment so `ClientHello` / `ServerHello` details are not reused across the wrong packet or Stream item context.
- Selected-flow QUIC packet and Stream presentation now share one bounded internal model: Packet Details stays shell-oriented but Stream labeling is more semantic when confidently isolated (`CRYPTO`, `ACK`) and suppresses standalone `PADDING` / `PING` noise.
- Bounded selected-flow QUIC TLS attachment now also surfaces handshake-aware details such as `ClientHello` and `ServerHello` when enough parseable CRYPTO bytes are available; otherwise it remains conservatively QUIC-only.

## Analysis tab

- Metadata-only Analysis blocks are implemented.
- Directional histograms are implemented.
- The Flow Rate graph is implemented as a window-based metadata view.
- Analysis does not use payload reconstruction or Stream reassembly.

## Statistics tab

- Protocol statistics and protocol-distribution reporting have been expanded.
- `Possible TLS` and `Possible QUIC` are tracked as separate weak-hint buckets.

## UI

- Navigation is menu-based.
- The selected-flow Analysis workspace is stable.
- Large-capture open progress and cooperative cancellation are implemented.

## Known gaps

- QUIC Stream handling is still bounded and incomplete; there is no full QUIC reconstruction or decryption-backed session model, and broader QUIC itemization, prioritization, and multi-packet interpretation remain future work.
- Retransmission suppression works in the current bounded selected-flow Stream model, but broader transport-complete retransmission handling is not implemented.
- TLS details are only partially exposed; richer handshake and certificate fields exist for complete packet-contained TLS records, matching Stream item types, and directly parseable QUIC CRYPTO handshake bytes.

## Next steps

- Extend retransmission handling beyond exact duplicate suppression.
- Extend TLS Stream details beyond the initial `ClientHello` / `ServerHello` / `Certificate` enrichment step.
- Extend QUIC TLS detail exposure beyond the first narrow ClientHello / ServerHello step only if bounded parseability stays explicit.
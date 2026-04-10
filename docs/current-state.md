# Current State

## Stream

- Fixture-backed baseline tests are in place for 7 repository PCAP cases.
- HTTP Stream reassembly supports `Content-Length` and chunked-body traversal for multi-message continuity.
- Partial HTTP and TLS cases have explicit fallback handling.
- Selected-flow-only retransmission detection is implemented.
- Exact duplicate TCP payload suppression is implemented for selected-flow Stream use.
- Stream materialization now uses one bounded on-demand pipeline for both initial and extended selected-flow views.
- TLS Stream item protocol details now expose a first narrow enrichment step for `ClientHello`, `ServerHello`, and `Certificate` items.
- Packet Details now exposes the same narrow TLS enrichment for complete packet-contained `ClientHello`, `ServerHello`, and `Certificate` records.
- Selected-packet protocol details now depend on packet-bytes availability, not Deep mode alone.
- Selected-flow QUIC labeling now exists in a narrow bounded form for packet-aware `Initial`, `Handshake`, `Retry`, `Version Negotiation`, and `Protected Payload` cases, with conservative fallback to `UDP Payload`.
- QUIC packet and Stream details now use direction-aware, ownership-aware selected-flow TLS attachment so `ClientHello` / `ServerHello` details are not reused across the wrong packet or Stream item context.
- Selected-flow QUIC packet and Stream presentation now share one bounded internal model: Packet Details stays shell-oriented but Stream labeling is more semantic when confidently isolated (`CRYPTO`, `ACK`) and suppresses standalone `PADDING` / `PING` noise.
- Bounded selected-flow QUIC TLS attachment now also surfaces `ServerHello` on server-side packets/items when the selected packet participates in enough same-direction CRYPTO bytes; otherwise it remains conservatively QUIC-only.

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

- QUIC Stream handling is still narrow; there is no full QUIC reconstruction or decryption-backed session model, and broader QUIC itemization, prioritization, and multi-packet interpretation remain future work.
- General retransmission handling is not implemented beyond exact duplicate suppression.
- TLS details are only partially exposed; richer handshake and certificate fields exist for complete packet-contained TLS records, matching Stream item types, and directly parseable QUIC CRYPTO handshake bytes.

## Next steps

- Extend retransmission handling beyond exact duplicate suppression.
- Extend TLS Stream details beyond the initial `ClientHello` / `ServerHello` / `Certificate` enrichment step.
- Extend QUIC TLS detail exposure beyond the first narrow ClientHello / ServerHello step only if bounded parseability stays explicit.
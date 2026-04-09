# Current State

## Stream

- Fixture-backed baseline tests are in place for 7 repository PCAP cases.
- HTTP Stream reassembly supports `Content-Length` and chunked-body traversal for multi-message continuity.
- Partial HTTP and TLS cases have explicit fallback handling.
- Selected-flow-only retransmission detection is implemented.
- Exact duplicate TCP payload suppression is implemented for selected-flow Stream use.
- Stream materialization now uses one bounded on-demand pipeline for both initial and extended selected-flow views.
- TLS Stream item protocol details now expose a first narrow enrichment step for `ClientHello`, `ServerHello`, and `Certificate` items.

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

- QUIC Stream parsing is not implemented.
- General retransmission handling is not implemented beyond exact duplicate suppression.
- TLS details are only partially exposed; richer handshake and certificate fields exist for a narrow subset of Stream item types.

## Next steps

- Extend retransmission handling beyond exact duplicate suppression.
- Extend TLS Stream details beyond the initial `ClientHello` / `ServerHello` / `Certificate` enrichment step.
- Add a narrow first step for QUIC Stream labeling.
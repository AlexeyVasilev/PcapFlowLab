# Next Steps

## Stream (short-term)

- validate and stabilize retransmission suppression for exact duplicate TCP payload segments
- ensure suppression is applied only in Stream/reassembly, not globally
- validate against existing 7 fixture-based baseline tests
- fix remaining inconsistencies in Stream item labeling (TLS / HTTP / DNS edge cases)

## Stream (model convergence)

- move to a single bounded on-demand Stream materialization path
- remove conceptual distinction between prefix/full Stream modes
- ensure `Load more` extends the same Stream build
- improve consistency between initial view and extended view
- make partial vs complete item behavior predictable

## Stream (mid-term)

- extend TLS item details beyond the first narrow step:
  - more handshake types
  - richer certificate fields when cheaply available
  - better compact summaries for incomplete TLS metadata
- improve partial handling (HTTP/TLS)
- add minimal QUIC stream labeling (bounded, selected-flow only)

## Tests

- extend HTTP edge cases:
  - HEAD / 204 / 304
  - chunked multi-response
  - request bodies (POST/PUT)
- add DNS baseline fixture (if missing)
- validate QUIC fallback behavior explicitly
- keep tests focused on behavior, not exact packet mapping

## Analysis

- keep metadata-only approach
- avoid payload/reassembly creep into Analysis tab
- optional: revisit percentiles later (not required now)

## UI

- refine Stream Item Details panel
- improve clarity of partial / reconstructed data
- validate the first TLS Protocol-tab enrichment pass against real captures
- keep selected-flow loading observable and responsive

This file reflects current working priorities and may evolve frequently.
It complements RFCs and architecture documents but does not replace them.
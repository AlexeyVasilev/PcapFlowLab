# Current State

## Stream

- Fixture-backed baseline tests are in place for 7 repository PCAP cases.
- HTTP Stream reconstruction supports requests and responses, including bounded body assembly across multiple TCP segments via `Content-Length` and chunked-body traversal, with conservative fallback where needed.
- Partial HTTP and TLS cases have explicit fallback handling.
- Retransmissions are indicated in the selected-flow packet list.
- Selected-flow Stream construction suppresses retransmitted packets in the current bounded model.
- Stream materialization now uses one bounded on-demand pipeline for both initial and extended selected-flow views.
- TLS Stream item protocol details now expose a first narrow enrichment step for `ClientHello`, `ServerHello`, and `Certificate` items.
- Packet Details now exposes the same narrow TLS enrichment for complete packet-contained `ClientHello`, `ServerHello`, and `Certificate` records.
- Selected-packet protocol details now depend on packet-bytes availability, not Deep mode alone.
- Selected-flow QUIC inspection now exposes bounded packet-aware details for `Initial`, `Handshake`, `Retry`, `Version Negotiation`, `Protected Payload`, and practical frame-level cases such as `CRYPTO`, `ACK`, and `PADDING`, with conservative fallback where confidence is limited.
- QUIC packet and Stream details now use direction-aware, ownership-aware selected-flow TLS attachment so `ClientHello` / `ServerHello` details are not reused across the wrong packet or Stream item context.
- Selected-flow QUIC packet and Stream presentation now share one bounded internal model: Packet Details stays shell-oriented but Stream labeling is more semantic when confidently isolated (`QUIC Initial: CRYPTO`, `QUIC Initial: ACK`) and suppresses standalone `PADDING` / `PING` noise.
- Bounded selected-flow QUIC TLS attachment now also surfaces handshake-aware details such as `ClientHello` and `ServerHello` when enough parseable CRYPTO bytes are available; otherwise it remains conservatively QUIC-only.

## Analysis tab

- Metadata-only Analysis blocks are implemented.
- Directional histograms are implemented.
- The Flow Rate graph is implemented as a window-based metadata view.
- Analysis does not use payload reconstruction or Stream reassembly.

## Statistics tab

- Protocol statistics and protocol-distribution reporting have been expanded.
- `Possible TLS` and `Possible QUIC` are tracked as separate weak-hint buckets.
- Qt now keeps only the overview cards plus the transport/family Protocol Summary always visible.
- Qt optional Statistics sections are now independent collapsible panels:
  - `Packet Size Distribution`
  - `Flows by Packet Count`
  - `Protocol Path Tree`
  - `Detected Protocol Hints`
  - `QUIC and TLS`
  - `Top Endpoints and Ports`
- For each capture, those optional Qt sections start collapsed, request data on first expansion only, and reuse the per-capture cached result on collapse/reopen or Statistics-tab revisit.
- `Packet Size Distribution` is a separate capture-wide contract from the selected-flow Analysis packet-size histogram:
  - it uses captured packet length, not original length
  - it counts all packet records accepted by the current importer, including unrecognized and decode-malformed packets
  - it excludes unreadable truncated tail bytes and non-packet PCAP/PCAPNG metadata
  - accumulation happens during capture import
  - index load reconstructs the same result from persisted `PacketRef::captured_length` values without rereading capture bytes
  - section expansion defers only DTO transport and rendering
  - EPBs skipped earlier by the current unsupported-interface PCAPNG path are not represented
- `Flows by Packet Count` now keeps the same packet-count buckets but exposes two presentation modes over one cached calculation:
  - `Flows`
  - `Original bytes`
- That histogram lazy pass now accumulates both flow counts and original-byte totals per bucket without issuing a second backend request when the visible mode changes.
- Opening a new capture resets the optional Qt and Tauri section expansion and visible result state.

## UI

- Navigation is menu-based.
- The selected-flow Analysis workspace is stable.
- Large-capture open progress and cooperative cancellation are implemented.
- Smart Export includes progress reporting, cooperative cancellation, and a separate per-flow output mode.
- The shared runtime settings slice now includes `Ignore VLAN and MPLS layers when grouping flows` for raw-import flow identity normalization.
- When that mode was active at raw import, Flow Path presentation and Protocol Path Statistics omit VLAN and MPLS label-stack layers while Packet Details and Bytes still show the selected packet's actual VLAN and MPLS headers.
- Opening from an existing index preserves whatever flow grouping was stored in that index; the current VLAN-and-MPLS grouping setting is not reapplied on index load.
- The same shared runtime settings slice now also includes `Ignore GTP-U TEIDs when grouping inner flows`, disabled by default and applied only during raw capture import.
- When that expert mode was active at raw import, flow identity keeps the `GTP-U` layer but strips only its TEID identifier; Flow Path presentation and Protocol Path Statistics therefore show `GTP-U` without `teid=...`, while Packet Summary and Bytes still expose each selected packet's actual TEID.
- Opening from an existing index likewise preserves the stored TEID-sensitive or TEID-agnostic grouping; the current GTP-U TEID grouping setting is not reapplied on index load.

## Known gaps

- QUIC Stream handling is still bounded and incomplete; there is no full QUIC reconstruction or decryption-backed session model, and broader QUIC itemization, prioritization, and multi-packet interpretation remain future work.
- Retransmission suppression works in the current bounded selected-flow Stream model, but broader transport-complete retransmission handling is not implemented.
- TLS details are only partially exposed; richer handshake and certificate fields exist for complete packet-contained TLS records, matching Stream item types, and directly parseable QUIC CRYPTO handshake bytes.

## Next steps

- Extend retransmission handling beyond exact duplicate suppression.
- Extend TLS Stream details beyond the initial `ClientHello` / `ServerHello` / `Certificate` enrichment step.
- Extend QUIC TLS detail exposure beyond the first narrow ClientHello / ServerHello step only if bounded parseability stays explicit.

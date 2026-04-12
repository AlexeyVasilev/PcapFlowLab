# Selected-Flow Analysis Contract

## 1. Purpose

Selected-flow analysis exists to support on-demand inspection of one chosen flow.

- It provides packet, stream, and details views for the currently selected flow.
- It is meant to improve understanding of one flow without moving expensive work into capture open or index load.
- It is a user-driven analysis surface, not a background enrichment pipeline.

## 2. Scope

Selected-flow analysis is intentionally narrow.

- It runs only after the user explicitly selects a flow.
- It is on-demand and ephemeral.
- It is not part of open-time or import-time global analysis.
- It is not stored as precomputed selected-flow state in indexes.
- It remains bounded by current controller/session limits and user actions such as `Load more`.

## 3. Inputs And Prerequisites

Selected-flow analysis depends on the following runtime inputs.

- Selected flow metadata from the current session.
- Packet rows belonging to that flow.
- Raw packet bytes when the source capture is available.
- Current session mode and current UI selection state.
- Current selected-flow packet and item budgets.

Important prerequisites and honesty rules:

- Packet-level and stream-level details depend on packet bytes being readable.
- For sessions opened from index, attached source capture is required for byte-backed selected-flow analysis.
- If bytes are unavailable, details may be unavailable, partial, or generic.
- The UI should prefer explicit unavailable or partial output over guessed semantics.

## 4. Packet-List Contract

The packet list is the packet-truth view for the selected flow.

- It shows real packets that belong to the selected flow.
- Packets remain visible even when marked as retransmissions.
- Marker columns may annotate special cases such as suspected retransmission.
- Packet Details describe the selected packet itself, not the deduplicated stream interpretation.
- Packet protocol details depend on analyzable bytes from that packet and its bounded selected-flow context where applicable.

Packet list invariants:

- A retransmitted packet must stay visible in `Packets`.
- Marker visibility must not depend on whether stream contribution is suppressed.
- Packet-level raw/protocol inspection remains available for the selected packet when bytes are available.

## 5. Stream Contract

A stream item is a semantic or presentation unit for the selected flow.

- It is not required to equal one packet.
- It may come from one packet or multiple packets.
- It may be partial.
- It may be reassembled from multiple TCP payload contributions.
- It may use a specific protocol-aware label or a conservative fallback label.

Stream behavior rules:

- Stream is built on-demand for the selected flow only.
- `Load more` expands the packet window and can extend or improve stream output.
- Stream output should be conservative and non-duplicative.
- Stream summarizes communication units; it is not a full transport-correct session reconstruction.

## 6. Source Ownership Contract

Each stream item must identify the packet ownership of its contributing bytes.

- Every stream item should expose its source packet or source packets.
- If an item is built from one packet, that packet is the owner.
- If an item is built from multiple packets, ownership must reflect the contributing packet set.
- Original contributing packets remain the owners of already-accounted bytes.
- Retransmission packets must not become false owners of already-accounted bytes.
- Source attribution should remain honest even for partial and reassembled items.
- Compact stream-item UI may show a shortened source-packet list, but details panes should preserve the fuller ownership view when needed.

This is a presentation contract, not just a convenience field. Packet ownership is part of the selected-flow truth model.

## 7. Retransmission Handling

Retransmission handling is selected-flow-only and contribution-oriented.

- Retransmitted TCP packets remain visible in the packet list.
- Retransmission markers remain visible in the packet list.
- Duplicate TCP contribution must not create duplicate stream semantics.
- Full duplicate retransmissions are suppressed from selected-flow stream contribution.
- Conservative partial-overlap suppression is supported for duplicate prefixes where sequence-space and payload agreement are reliable.
- More complex overlap, reordering, or gap geometries remain intentionally conservative unless explicitly supported.
- This suppression applies only to duplicate selected-flow semantic contribution, not to packet visibility or packet-level inspection.

Current reliability rules:

- Suppression is applied when building selected-flow semantic contribution, not when building the packet list.
- Suppression is based on TCP direction, sequence/ack context, payload-bearing packets, and payload-byte agreement.
- Weak similarity such as matching size alone must not trigger suppression.
- False negatives are acceptable; false positives are not.

## 8. Details-Pane Contract

### 8.1 Packet Details

Packet Details describe the selected packet.

- `Summary`: packet summary and packet-specific metadata.
- `Raw`: raw packet hex view.
- `TCP Payload` / `UDP Payload`: transport payload bytes for packet-level context.
- `Protocol`: protocol-specific interpretation of the selected packet bytes when analyzable.

Packet Details reflect packet truth and packet bytes.

### 8.2 Stream Item Details

Stream Item Details describe the selected stream item.

- `Summary`: compact item metadata and source ownership.
- `Item Payload`: payload/content of the semantic stream item where applicable.
- `UDP Payload`: current payload tab name for QUIC stream items, because the payload view remains transport-oriented.
- `Protocol`: richer protocol-specific interpretation of the stream item and attached semantics.

Stream Item Details reflect semantic-item truth, which may be reassembled and may not be packet-identical.

Contextual payload tab naming currently in effect:

- Packet details on TCP packets: `TCP Payload`
- Packet details on UDP packets: `UDP Payload`
- Stream item details on TLS/HTTP stream items: `Item Payload`
- Stream item details on QUIC stream items: `UDP Payload`

## 9. Protocol-Specific Selected-Flow Rules

### 9.1 TLS

TLS selected-flow presentation should prefer specific reliable labels over generic ones.

Reliable labels include:

- `TLS ClientHello`
- `TLS ServerHello`
- `TLS Certificate`
- `TLS ChangeCipherSpec`
- `TLS AppData`
- `TLS Alert`

TLS rules:

- Generic fallback such as `TLS Record` should be used only when more specific meaning is not reliably known.
- Alert records should surface alert-specific details when available.
- Protocol details for alerts should include `Alert Level` and `Alert Description` when reliably parsed.
- TLS stream items may be reassembled across multiple packets.
- Partial TLS behavior remains conservative and may fall back to partial labels.

### 9.2 HTTP

HTTP selected-flow presentation is message-oriented when reliable header structure is available.

- Requests and responses should use specific labels when reliably known.
- Multi-packet requests or responses may become one stream item when bounded reassembly has enough bytes.
- Source packet ownership must reflect the contributing packet set.
- Partial or incomplete HTTP data should fall back conservatively.
- HTTP body handling remains bounded and practical, not a general body-reconstruction subsystem.

### 9.3 QUIC

QUIC selected-flow presentation uses a bounded shell-aware model.

- Packet presentation distinguishes QUIC shell type from payload or frame semantics.
- Stream items may represent semantic units rather than whole UDP packets.
- One UDP packet may yield multiple QUIC semantic units or stream items when those units are reliably distinguished.
- Stream labels currently include cases such as:
  - `QUIC Initial: CRYPTO`
  - `QUIC Initial: ACK`
  - `0-RTT`
  - `QUIC Handshake`
  - `QUIC Protected Payload`
- Standalone `PADDING` and `PING` do not become stream items.
- QUIC stream item size should reflect semantic item size, not whole UDP packet size.
- QUIC details may include attached TLS-over-CRYPTO details when reliably derived from bounded available bytes.
- This is not full QUIC session reconstruction, decryption, or HTTP/3 parsing.

### 9.4 Generic Fallback Behavior

When stronger protocol semantics are not reliably available, selected-flow analysis must fall back honestly.

- TCP fallback label: `TCP Payload`
- UDP fallback label: `UDP Payload`
- Generic fallback is preferable to guessed protocol semantics.
- Packet truth and stream truth may differ: a packet can be protocol-rich while stream contribution remains generic or partial.

## 10. Reliability Principles

Selected-flow analysis follows reliability-first rules.

- Conservative is better than clever.
- False positives are worse than false negatives.
- Do not invent semantics from incomplete bytes.
- Do not present misleading source ownership.
- Prefer explicit unavailable or partial states over guesswork.
- Packet truth and stream truth are related, but not identical.

## 11. Known Limits / Out Of Scope

The following remain intentionally out of scope for the current contract.

- No global selected-flow precompute during capture open.
- No persistence of selected-flow analysis as a full precomputed model in indexes.
- No full QUIC session reconstruction or decryption-backed model.
- No speculative parsing beyond bounded available bytes.
- No guarantee that every packet yields protocol details.
- No guarantee that every packet yields a stream item.
- No complete handling of every TCP overlap, reordering, or gap geometry.

## 12. Regression-Sensitive Invariants

The following must remain true.

- Retransmitted packets stay visible in the packet list.
- Retransmission markers stay visible in the packet list.
- Retransmitted duplicate TCP bytes do not duplicate stream semantics.
- Stream items show honest source packet ownership.
- Original contributing packets remain the owners of already-accounted bytes.
- QUIC item size reflects semantic item size, not whole UDP packet size.
- Specific TLS labels win over generic TLS fallback when reliably known.
- TLS Alert details include alert-specific fields when reliably parsed.
- Details panes use honest context-specific payload tab naming.
- Selected-flow analysis remains on-demand only.

## See Also

- [stream_architecture.md](./stream_architecture.md)
- [quic-stream-presentation-rfc.md](./quic-stream-presentation-rfc.md)
- [quic-fixture-01-reference.md](./quic-fixture-01-reference.md)
- [quic-fixture-02-reference.md](./quic-fixture-02-reference.md)
- [current-state.md](./current-state.md)

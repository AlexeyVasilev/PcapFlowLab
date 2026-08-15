# Selected-Flow Packet Cache RFC

## 1. Status

Implemented design RFC / cache architecture reference

- Current main now has a bounded runtime-only selected-flow cache architecture for the currently selected flow only.
- It does not change the persistence model.
- It does not change open-time or index-load behavior.
- It remains the design-history record for why the cache boundary exists and which larger continuation ideas were intentionally deferred.

Implemented in current main:

- bounded runtime-only selected-flow full-packet cache
- bounded runtime-only selected-flow transport-payload cache
- per-selected-flow cache lifetime and invalidation
- direct-read fallback on cache miss or cache-limit conditions
- conservative cache clearing on session reset, capture/index open, source attach/clear, and explicit selected-flow cache clear

Partially implemented / deferred:

- broader append-style higher-level parser continuation
- making every selected-flow Stream path continue from prior cached parser state
- eviction policies beyond the current bounded stop-at-budget model
- any persistent cache or cross-flow/session cache design

## 2. Problem Statement

Selected-flow analysis is currently on-demand and byte-backed, but repeated large-flow interaction has exposed a practical weakness in the current rebuild model.

- Stream growth currently tends to rebuild from an enlarged packet prefix.
- That means already-seen packet windows may be reread from source capture and reparsed again.
- On large flows, especially TCP flows with bounded reassembly-backed analysis, this creates avoidable latency.
- The UI can feel frozen because the selected-flow path is doing too much repeated work before the user sees updated results.
- Recent attempts to improve this by patching prefix-rebuild and bounded reassembly paths directly produced regressions and brittle behavior.

The conclusion is not that on-demand selected-flow analysis is wrong. The conclusion is that the current byte-source model is too dependent on rereading the old window from disk and rebuilding ephemeral state from scratch.

## 3. Design Goals

The selected-flow packet cache should satisfy the following goals.

- Keep selected-flow analysis on-demand only.
- Reduce repeated rereads of already-loaded packet windows from source capture.
- Support future append-style selected-flow growth on `Load more`.
- Stay explicitly bounded in memory and latency.
- Preserve current persistence boundaries.
- Keep behavior honest and predictable when limits are reached.
- Create a cleaner foundation for future stream continuation work without requiring a broad redesign first.

## 4. Non-Goals

This RFC does not propose the following.

- A full stream database.
- A persistent packet-byte store.
- A session-wide or global cache across many flows.
- Full TCP-correct stream reconstruction.
- A redesign of fast open or index load.
- Unlimited selected-flow growth.
- A guarantee that all future selected-flow parsers become append-only immediately.
- A replacement for source capture as the source of truth.

## 5. High-Level Design

The currently selected flow owns a temporary in-memory byte store.

- When a flow is selected, the first selected-flow packet window is loaded from source capture into a bounded in-memory cache.
- Packet bytes for that window are copied into a temporary contiguous memory region owned by the selected-flow cache.
- A lightweight per-packet mapping records which flow-local packet number corresponds to which byte range inside that cache.
- When the user presses `Load more`, newly loaded packet bytes are appended to the same cache rather than causing the already-loaded packet window to be reread from disk.
- Selected-flow analysis paths can then read from cached bytes for the already-loaded window instead of rereading the old window from the capture file.

Important boundaries:

- Source capture remains the source of truth.
- The cache is disposable.
- Cache lifetime is tied to the current selected flow.
- Switching flows invalidates the previous selected-flow cache.
- This is a UI/performance optimization only, not a new persisted artifact.

Important semantic boundary:

- The cache is a flow-local packet-order byte store.
- Cached bytes are an input/source optimization only.
- Cached bytes do not by themselves imply transport-correct reconstruction.
- Cached bytes do not redefine stream semantics.
- Cached bytes do not replace existing parser or reassembly rules.

## 6. What Bytes Are Cached

Current main uses two related runtime-only caches:

- selected-flow full-packet cache for the currently visible/warmed packet window
- selected-flow transport-payload cache for transport-oriented selected-flow analysis

Current exact budgets:

- full-packet cache: `8 MiB`
- transport-payload cache: `16 MiB`

Current architectural interpretation:

- the full-packet cache is keyed by capture packet index and stores exact reread packet bytes for a bounded selected-flow packet window
- the transport-payload cache stores selected-flow transport payload bytes plus packet association metadata needed by bounded selected-flow analysis
- packet metadata already persisted in session state is not duplicated unnecessarily
- packet-details and other byte-backed paths may still fall back to direct packet reads when a cache does not apply or a cache miss occurs

This is intentionally not a persistent byte store and not a correctness upgrade for reassembly.

## 7. Cache Data Model

The exact code types can be chosen later, but the conceptual model should look like this.

### Cache byte buffer

- A contiguous owned byte buffer for cached selected-flow bytes.
- Append-only within the lifetime of one selected flow.

### Packet-cache entry

For each cached packet contribution:

- flow-local packet number
- original packet index in capture
- direction
- cache offset
- cache length
- optional payload length / captured length if needed by consumers
- optional flags indicating whether the cached bytes are full packet bytes or only the selected-flow-relevant payload bytes

### Window metadata

- number of cached packets
- number of cached flow-local packet numbers covered
- total cached bytes
- current cache budget
- whether cache budget is exhausted
- whether the current selected-flow packet window is fully represented in cache

This model should support cheap lookup from:

- flow-local packet number -> cached byte range
- capture packet index -> cached byte range

### Ownership And Numbering Invariants

The cache must preserve stable selected-flow identity and ownership behavior.

- Flow-local packet numbering must remain stable as the cache grows.
- Appending new packet bytes must not renumber already loaded packets.
- Source-packet ownership for already built stream items must not be silently reassigned just because `Load more` extended the window.
- The cache must not reintroduce stale enlarged-prefix rebuild behavior through a side path such as remapping or replacement of already-accounted packet ownership.

## 8. Cache Lifecycle

### Creation

- Cache is created when a flow becomes the active selected flow and byte-backed selected-flow analysis is possible.

### Initial fill

- The first selected-flow packet window is loaded from source capture.
- Newly read bytes are copied into the cache.
- Packet-cache entries are created for the packets that fit into the cache budget.

### Append on `Load more`

- `Load more` extends the selected-flow packet window.
- Only the newly added packet range should be read from source capture and appended to the cache.
- Already cached packet bytes must not be reread from disk during normal append growth.

### Invalidation

The cache is discarded when:

- selected flow changes
- source capture is detached or becomes unavailable
- session is closed or replaced
- the cached byte format is no longer valid for the current selected-flow mode

### Reset behavior

- Cache reset is explicit and honest.
- The system should not silently keep stale bytes for a different flow or session.

## 9. Memory Budget And Limits

The cache must stay bounded.

- A hard max cache size in bytes is required.
- An optional max cached packet count may also be added if it simplifies control of worst-case behavior.
- If the cache budget is reached, `Load more` must stop cleanly or the UI must report that the cache limit has been reached.
- There must be no silent truncation that pretends the cache still covers the selected-flow window fully.

Current production constants:

- selected-flow full-packet cache: `8 MiB`
- selected-flow transport-payload cache: `16 MiB`

The exact constants can still be tuned later, but current main already uses explicit bounded budgets rather than an open-ended proposal range.

## 10. Interaction With Packet List

Packet list behavior should remain aligned with the current architecture.

- Packet list metadata continues to come from existing session/query state.
- Packet list does not become a persistent byte store.
- When the selected-flow packet window is loaded, associated packet bytes may be pulled into the selected-flow cache.
- Packet numbering, retransmission markers, and packet-level truth remain packet-truth, not cache-truth.
- The cache should support packet-list-adjacent features, but it should not redefine what the packet list means.

## 11. Interaction With Stream Analysis

This is the main motivation for the RFC.

- Stream analysis should eventually operate over cached selected-flow bytes for the already-loaded packet window.
- `Load more` should append only new packet bytes to the cache.
- Future stream builders should be able to continue from prior cached state instead of rebuilding the whole old prefix from disk-backed reads.
- The selected-flow cache should make append-style growth possible even if the first implementation still rebuilds some ephemeral higher-level parser state.

Parser continuation state is a separate concern.

- The cache itself is only a bounded byte-source and packet-mapping optimization.
- Parser continuation or tail state is not the same thing as cached packet bytes.
- A future implementation may add bounded parser tail state later where it is safe and useful.
- The first cache-backed implementation does not need to promise append-only continuation for every protocol immediately.

Important honesty rule:

- this RFC enables incremental behavior
- it does not claim that the first cache implementation instantly solves every protocol case

The expected progression is:

- first remove repeated disk rereads for already-loaded packet windows
- then make more of the selected-flow stream path continue from cached state safely

## 12. Interaction With Reassembly

This RFC must stay aligned with the current bounded reassembly contract.

- The packet cache is a byte-source optimization, not a correctness upgrade by itself.
- Cached bytes remain packet-order source material, not stream-order truth.
- Current directional, bounded, heuristic reassembly rules still apply.
- Reassembly remains bounded by explicit packet and byte budgets.
- Future stream builders may use cached bytes as input, but reassembly semantics remain governed by the existing bounded rules unless changed by another RFC.

The cache should reduce repeated rereads of old packet windows. It must not be described as “solving” TCP correctness, overlaps, or reordering on its own.

## 13. UI / Product Behavior

This RFC is primarily architectural, but it has clear product-facing implications.

- Selected-flow initial analysis may become faster because already-loaded packet bytes are retained.
- `Load more` can become more predictable because only new packet bytes need to be fetched from source capture.
- Flow switches remain explicit cache boundaries.
- If the cache limit is reached, already loaded packet and stream state should remain usable.
- Further `Load more` should stop cleanly.
- UI should indicate the reason honestly.
- Partial invisible appends and ambiguous no-op behavior should be avoided.
- This remains a performance optimization, not a user-visible persistent feature.

The RFC does not define exact UI wording or layout for cache state. It only requires honest, bounded behavior.

## 14. Failure / Limit Cases

The design should handle the following cases explicitly.

- Source capture unavailable.
- Source bytes unreadable for some packets.
- Cache budget exhausted.
- A packet too large to fit into remaining cache budget.
- Selected-flow analysis still bounded by higher-level parser or reassembly logic even when cached bytes are available.

Expected behavior in such cases:

- keep the selected-flow contract honest
- do not pretend cached coverage is complete when it is not
- prefer explicit partial or unavailable states over hidden fallback behavior

## 15. Alternatives Considered

### Continue patching enlarged-prefix rebuild logic

- This was the recent direction.
- It produced regressions and brittle behavior because the current model still rereads and reparses too much old state.
- It does not create a clean ownership boundary for already-loaded selected-flow bytes.

### Build a global packet-byte cache

- Too broad for the current need.
- Pushes memory growth and lifecycle complexity into the whole session.
- Conflicts with the current “selected-flow on-demand only” architecture.

### Persist packet bytes into the index

- Breaks current persistence boundaries.
- Would increase index size and broaden product scope significantly.
- Not needed for the selected-flow performance problem we are trying to solve next.

### Move directly to a full incremental stream-state architecture

- Attractive in theory, but too large and risky as the immediate next step.
- It is easier to stabilize a bounded selected-flow byte cache first, then improve stream continuation on top of that.

Preferred next step:

- add a bounded selected-flow packet cache first
- then make stream growth depend on that cache

## 16. Recommended Implementation Staging

The staging below is now historical design context. Stage 1 and the basic byte-source/cache boundary are implemented in current main; broader parser-continuation ambitions remain deferred.

### Stage 1

Add the selected-flow cache itself.

- selected-flow-only cache object
- bounded append-only byte storage
- packet-cache entry mapping
- invalidation rules
- append on `Load more`

### Stage 2

Make selected-flow stream paths read already-loaded packet windows from cache instead of rereading old bytes from source capture.

- preserve current semantics
- improve byte-source behavior first
- packet-list byte reuse may benefit incidentally where useful
- stream growth remains the primary motivation and primary target

### Stage 3

Introduce append-oriented continuation where safe.

- keep parser/reassembly state only where bounded and understandable
- build on top of the cache boundary from Stage 1 and Stage 2, rather than conflating cache state with parser continuation state
- avoid broad “full incremental everything” claims

### Stage 4

Tune operational details.

- cache budget constants
- optional telemetry or debug visibility
- product messaging for cache-limit cases if needed

This staging intentionally separates “cache boundaries” from “incremental parser continuation.” That keeps risk lower.

## 17. Open Questions

- Future tuning question: should the current cache byte budgets change from `8 MiB` full-packet and `16 MiB` transport-payload?
- How much additional cache reuse should move from current direct-read fallbacks into cache-backed paths, if any?
- Should packet-details views reuse the cache in the first step, or stay on direct packet reads initially?
- How much parser tail state, if any, is worth carrying across `Load more` in later stages?
- Is eviction within a single selected flow worth supporting later, or is a simple “stop at budget” model preferable?

## Relationship To Existing Docs

This RFC is intended to sit alongside the current architecture and reassembly docs.

- It is consistent with [architecture.md](./architecture.md): persistent model remains packet/flow metadata, and selected-flow work remains on-demand.
- It is consistent with [stream_architecture.md](./stream_architecture.md): stream items and reassembled buffers remain ephemeral.
- It is consistent with [reassembly-rfc.md](./reassembly-rfc.md): reassembly remains bounded, heuristic, and non-persistent.
- It is consistent with [selected-flow-contract.md](./selected-flow-contract.md): the cache is an internal optimization for selected-flow analysis, not a change in packet-truth or stream-truth semantics.

Small future follow-up note:

- if this RFC is adopted, lightweight cross-links from `stream_architecture.md` and `reassembly-rfc.md` to this document would likely help future maintenance
- those updates are not part of this task

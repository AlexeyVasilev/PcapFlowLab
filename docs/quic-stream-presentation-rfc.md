# QUIC Stream Presentation RFC

## Purpose

This RFC defines a practical presentation model for QUIC in the selected-flow surfaces of Pcap Flow Lab.

The goal is to fix the conceptual model before broader QUIC logic changes continue.

This RFC covers:

- Packet Details
- Stream
- Stream Item Details

This RFC does not propose code changes by itself. It defines the intended representation rules so later implementation stays conservative, bounded, and aligned with the current architecture.

This RFC does not require packet-perfect or protocol-complete QUIC reconstruction. It defines a reliable selected-flow presentation model, not a full QUIC analyzer.

## Status

Initial selected-flow QUIC support already exists in a narrow form.

- packet-level QUIC shell labeling exists for reliable header-typed cases
- Stream can already expose narrow QUIC-oriented labels in bounded selected-flow paths
- QUIC CRYPTO bytes may already yield narrow TLS handshake enrichment when directly parseable

However, the project does not yet have a clearly fixed conceptual model for:

- QUIC packet-level presentation
- QUIC stream-level itemization
- the relation between QUIC header typing and QUIC payload or frame semantics

This RFC fixes that model.

## Architectural alignment

The RFC must remain aligned with the existing selected-flow analysis boundaries described in [docs/stream_architecture.md](docs/stream_architecture.md) and [docs/architecture.md](docs/architecture.md).

QUIC presentation work at this stage is:

- selected-flow only
- on-demand only
- ephemeral
- bounded
- non-persistent

QUIC presentation work at this stage is not:

- global parsing during capture open
- index-time enrichment
- decryption
- full QUIC session reconstruction
- full TLS-over-QUIC state reconstruction
- full HTTP/3 semantic parsing

These boundaries are intentional. The product should prefer useful bounded inspection over ambitious but unreliable reconstruction.

## Reliability-first principle

QUIC handling must be conservative.

- Prefer false negative over false positive.
- Prefer a generic QUIC label over an incorrect specific label.
- Prefer omitting TLS details over inventing them from incomplete CRYPTO bytes.
- Prefer hiding low-value noise in Stream over cluttering Stream with mechanically extracted but user-poor items.

Packet inspection and Stream summarization solve different problems. Packet Details may be richer because it explains one selected packet. Stream should stay more selective because it summarizes meaningful communication units.

## Core model

The model has two explicit layers.

### Layer A: QUIC packet shell

The packet shell is the outer QUIC packet or header identity.

Examples:

- QUIC Initial
- QUIC Handshake
- QUIC Retry
- QUIC Version Negotiation
- QUIC Protected payload (short header)

This layer answers:

"What kind of QUIC packet shell is this selected packet?"

The shell comes from header-level QUIC interpretation. It is packet-scoped.

### Layer B: QUIC payload or frame semantics

This layer describes meaningful semantics found inside the packet payload when they are reliably identifiable.

Examples:

- CRYPTO
- ACK
- STREAM
- PADDING
- PING
- other frame types only when their interpretation is already reliable enough for user-facing presentation

This layer answers:

"What meaningful QUIC payload semantics are present inside this packet or bounded packet group?"

These payload semantics are not the same thing as the shell.

## Why the layers must stay separate

The user-provided QUIC naming tables show the key distinction clearly.

- one QUIC packet can contain multiple payload or frame semantics
- packet selection and stream itemization are not the same problem
- PADDING and PING are often present but are not usually meaningful standalone Stream items
- CRYPTO may require bounded reassembly across multiple packets or fragments before TLS handshake meaning becomes visible
- TLS handshake details are layered over reassembled CRYPTO bytes when parseable; they do not replace the underlying QUIC identity

The tables should be treated as the primary conceptual source for expected behavior, not as hardcoded implementation truth for every capture.

## Definitions

### QUIC packet shell

A QUIC packet shell is the outer packet-level identity derived from the QUIC header.

It is packet-scoped and should remain stable even when payload semantics are incomplete or partially unknown.

### QUIC payload semantic unit

A QUIC payload semantic unit is a meaningful frame-level or bounded multi-frame interpretation that is useful to show to the user.

Examples include:

- ACK
- CRYPTO
- STREAM, if later promoted with enough reliability
- Protected payload (short header), when only the shell is meaningful and inner semantics are unavailable

Not every raw frame type deserves promotion to a user-facing semantic unit.

### TLS-over-QUIC detail

TLS-over-QUIC detail is additional information derived from bounded CRYPTO bytes when a TLS handshake structure is parseable.

Examples:

- TLS ClientHello details
- TLS ServerHello details
- narrow certificate information, if cheaply and reliably parseable

This is additional detail layered over QUIC presentation. It must not replace either the QUIC shell or the payload semantic summary.

## Packet Details rules

When the user selects a packet in the Packets list, Packet Details should explain that packet as a packet.

Packet presentation therefore starts from the shell and may then add payload semantics and optional TLS enrichment.

### 1. Packet shell summary

Packet Details should always show the packet shell summary when the bytes support reliable QUIC typing.

Typical fields include:

- header form: long or short
- packet type
- version, when applicable
- destination connection ID and source connection ID, when available
- connection ID lengths, when applicable
- token length or token presence, when relevant and cheaply available

The shell summary answers the packet-level question first, even if deeper payload parsing later fails.

### 2. Payload or frame summary

Packet Details should then show the meaningful payload or frame types present inside the selected packet when reliably identifiable.

Examples:

- CRYPTO
- ACK
- STREAM
- PADDING
- PING

The packet view must explicitly allow multiple payload semantics for one selected packet.

One packet may legitimately show:

- ACK + PADDING
- CRYPTO + PADDING
- CRYPTO + ACK + PADDING
- Handshake-related payload plus a short generic protected remainder, if the current parsing model can actually distinguish them

Packet view is an inspection surface. Showing low-level coexisting semantics there is acceptable and often useful.

However, a payload or frame semantic visible in Packet Details does not automatically deserve a standalone Stream item. Stream itemization is a summarization layer, not a raw frame dump.

### 3. Additional TLS details

If bounded CRYPTO assembly associated with the selected packet yields parseable TLS handshake bytes, Packet Details may append a TLS section.

Examples:

- TLS Handshake Type: ClientHello
- TLS Handshake Type: ServerHello
- SNI
- ALPN
- cipher suites or selected cipher
- supported versions
- narrow certificate summary, if already available and reliable

This TLS section is additional detail layered over the QUIC explanation.

It must not replace the shell summary.

The user should still be able to see that the packet is, for example, a QUIC Initial packet whose payload semantics include CRYPTO, even when a TLS ClientHello is also shown.

## Stream rules

Stream is not a packet list clone.

The Stream view should represent meaningful communication units for the selected flow. It should stay conservative, bounded, and useful for interactive summarization.

### Stream items are not packets

The Stream view should not assume one packet equals one Stream item.

- one packet may contribute zero, one, or multiple meaningful Stream items
- multiple packets may contribute to one Stream item when bounded assembly is required for a meaningful semantic unit
- some packet-contained elements should remain visible only in Packet Details and should not become standalone Stream items

This is the most important rule in this RFC.

Packet Details may expose a richer set of packet-contained semantics than Stream because packet inspection and Stream summarization serve different user goals.

### Elements that should appear in Stream

The following may appear as Stream items when reliably identified and when they are meaningful for user-facing flow summarization.

- QUIC ACK
- QUIC CRYPTO
- QUIC Handshake
- QUIC Protected payload
- QUIC STREAM, only when later support becomes reliable enough for stable presentation

These are examples of meaningful communication units, not a promise that every recognized frame becomes a separate item immediately.

### Elements that should not appear as standalone Stream items

The following should not become standalone Stream items in the current model.

- PADDING
- PING

They may still appear in Packet Details as part of packet inspection.

Future work could revisit PING if a strong user-facing reason appears, but the default position should remain no standalone Stream item.

### Handling mixed packets

If one packet contains multiple meaningful payload semantics, Stream itemization should summarize only the user-meaningful parts.

Expected behavior:

- ACK + PADDING: Stream may show ACK only
- CRYPTO + PADDING: Stream may show CRYPTO only
- ACK + PING + PADDING: Stream may show ACK only
- CRYPTO + ACK + PADDING: Stream may show CRYPTO and ACK if both are semantically meaningful and reliably separable in the current bounded model
- Handshake + Protected payload: Stream may show both when they are semantically distinct and reliably identified

The Stream view should suppress noise more aggressively than Packet Details.

### Near-term priority rule for mixed semantics

When mixed packet semantics could yield more than one possible near-term Stream representation, the implementation should prefer the following stable priority order.

- CRYPTO with parseable TLS semantic
- CRYPTO
- ACK
- Handshake
- Protected payload (short header)
- fallback generic QUIC or UDP representation

This priority order is intended for conservative near-term itemization, not as a claim that every packet must produce exactly one item.

The suppression rules remain explicit.

- suppress standalone PADDING
- suppress standalone PING

## Relation between packet labels and Stream labels

Packet labels and Stream labels do not need a one-to-one mapping.

They answer different user questions.

- packet shell label answers: what kind of QUIC packet is this?
- Stream item label answers: what meaningful communication unit should the user see in the selected-flow narrative?

### Approach A: shell-oriented Stream labeling

Examples:

- QUIC Initial
- QUIC Handshake
- QUIC Protected payload (short header)

Benefits:

- stable and easy to explain
- close to current packet-oriented QUIC support
- low risk of overclaiming payload semantics

Costs:

- less expressive when one packet contains mixed semantics
- can obscure the difference between shell identity and actual payload meaning

### Approach B: payload-oriented Stream labeling

Examples:

- QUIC CRYPTO
- QUIC ACK
- QUIC Protected payload (short header)

Benefits:

- closer to meaningful communication semantics
- better match for the idea that Stream is not a packet list
- aligns well with TLS detail attachment to CRYPTO-derived bytes

Costs:

- requires stronger internal modeling
- creates more risk of unstable labels when frame parsing is partial or uncertain
- can become misleading if packet-shell context is hidden entirely

### Recommended staged direction

Near term, the project should stay conservative.

- keep Stream labels stable rather than radically renaming the surface immediately
- prefer shell-oriented Stream labels in near-term UI rows when that yields more stable user-facing behavior
- allow Stream Item Details to expose payload or frame semantics and optional TLS enrichment
- allow Packet Details to remain the richest packet-inspection surface for coexisting payload semantics
- refine Stream itemization toward payload-aware semantics only when the internal model is reliable enough to do so consistently

In other words, near-term implementation should remain shell-oriented in labels more often than the eventual ideal model whenever that improves stability, while Packet Details and Stream Item Details become more explicit about payload semantics.

## Stream Item Details rules

Stream Item Details should explain why a Stream item exists and what semantic evidence supports it.

The details pane may therefore combine three layers:

- the chosen Stream item label
- the underlying packet shell context, when relevant
- payload or frame semantics, when known

For QUIC items, Stream Item Details should typically show:

- a stable item label
- contributing packet indices or packet count, when already part of the Stream model
- packet shell context, when it helps explain the origin of the item
- payload or frame summary
- optional TLS-over-QUIC detail when bounded CRYPTO assembly succeeds

This makes Stream Item Details richer than the row label without forcing the row label itself to become unstable.

## CRYPTO and TLS reassembly model

QUIC CRYPTO handling deserves an explicit model because it is the main bridge between QUIC transport presentation and TLS handshake detail.

### CRYPTO fragments may span multiple packets

CRYPTO data should be treated as potentially fragmented across packets.

- a single selected packet may contain only part of the relevant handshake bytes
- multiple CRYPTO frames may exist in one packet
- one TLS handshake message may span multiple QUIC packets or fragments

### Bounded selected-flow assembly is allowed

The product may use bounded, on-demand, selected-flow assembly of CRYPTO bytes when needed for Packet Details or Stream Item Details.

This assembly must stay:

- selected-flow only
- on-demand only
- direction-aware
- bounded by packet and byte limits
- ephemeral

This is not full QUIC session reconstruction.

### TLS semantics attach only when parseable

Assembled CRYPTO bytes may yield TLS handshake semantics when parseable.

Examples:

- ClientHello
- ServerHello
- narrow certificate information, if later exposed and reliably parseable

TLS details should be attached only when the bytes support a reliable interpretation.

If bytes are incomplete, truncated, conflicting, or directionally ambiguous, the result should stay conservative.

### Direction and ownership matter

CRYPTO interpretation must remain direction-aware.

- client-originating CRYPTO should not accidentally reuse ClientHello details for server-owned material
- server-originating CRYPTO should not be mislabeled as ClientHello simply because an earlier packet in the flow already yielded one
- attachment should reflect the actual bounded assembly result for the relevant semantic unit

### Examples of bounded CRYPTO use

Example cases that are in scope:

- TLS ClientHello reassembled from multiple CRYPTO fragments across Initial packets
- TLS ServerHello reassembled from multiple CRYPTO fragments across Initial or Handshake packets

Example cases that are out of scope at this stage:

- full connection-wide CRYPTO stream reconstruction without explicit bounds
- full TLS-over-QUIC handshake state machine modeling
- decryption-backed semantic recovery

## Recommended presentation examples

### Example 1: Initial packet with CRYPTO fragments

Packet shell:

- QUIC Initial

Payload semantics:

- CRYPTO
- CRYPTO

Packet Details should show:

- QUIC Initial shell fields
- payload summary indicating CRYPTO entries
- TLS ClientHello details if bounded CRYPTO assembly succeeds

Stream should show:

- a CRYPTO-related meaningful item, or a stable QUIC Initial item with CRYPTO semantics exposed in details
- no standalone PADDING item if padding is also present but user-irrelevant

### Example 2: Initial packet with ACK + PADDING

Packet shell:

- QUIC Initial

Payload semantics:

- ACK
- PADDING

Packet Details should show:

- QUIC Initial shell summary
- ACK in the payload summary
- PADDING in the payload summary

Stream should show:

- ACK only

Stream should not show:

- a separate PADDING item

### Example 3: Initial packet with CRYPTO + PADDING

Packet shell:

- QUIC Initial

Payload semantics:

- CRYPTO
- PADDING

Packet Details should show:

- both CRYPTO and PADDING
- TLS ServerHello details only if bounded assembly actually succeeds and the parsed handshake ownership is correct

Stream should show:

- a CRYPTO-related item

Stream should not show:

- a separate PADDING item

### Example 4: Handshake packet plus protected payload

Depending on the reliable packet structure actually observed, the selected-flow presentation may encounter semantically distinct handshake-related and protected-payload-related units.

Packet Details should show:

- the shell identity supported by the packet bytes
- the payload or frame semantics that are actually distinguishable

Stream may show:

- Handshake
- Protected payload (short header)

This is appropriate only if both are semantically distinct and reliably identifiable in the bounded model.

### Example 5: Pure Protected Payload

Packet shell:

- short-header protected payload

Packet Details should show:

- the shell summary
- any payload summary that is honestly available

Stream should show:

- Protected payload (short header)

The product should not invent TLS details or richer decrypted semantics for such a case.

## Reliability rules

The following rules are mandatory for implementation guided by this RFC.

- never invent frame types from insufficient bytes
- never invent TLS handshake details from incomplete CRYPTO bytes
- never collapse shell identity and payload semantics into one label when that would hide uncertainty
- prefer generic QUIC Protected payload (short header) over an incorrect richer interpretation
- prefer hiding PADDING and PING in Stream over cluttering Stream with low-value noise
- prefer direction-aware CRYPTO ownership over convenient reuse of previously parsed handshake details
- allow Packet Details to be richer than Stream because packet inspection and Stream summarization have different goals

If a richer interpretation is not clearly supported, the UI should fall back to a narrower but truthful QUIC representation.

## Out of scope

The following remain out of scope for this stage.

- full QUIC session reconstruction
- packet number space tracking beyond cheap local usage
- ACK range analytics
- general QUIC decryption
- connection-wide CRYPTO stream reconstruction without explicit bounds
- full HTTP/3 semantic parsing
- global open-time QUIC parsing
- persistence of QUIC Stream artifacts into index or session state

These items may become future work, but they must not leak into the current selected-flow presentation model by accident.

## Internal model recommendation

To support the presentation rules above, the next implementation stages should move toward a narrow internal QUIC presentation model.

That model should be presentation-oriented rather than protocol-complete.

Useful fields may include:

- packet shell type
- shell metadata fields used in Packet Details
- payload or frame semantic list for the relevant packet or bounded item
- references to CRYPTO fragments contributing to a bounded semantic unit
- optional assembled TLS semantic summary
- confidence or fallback state sufficient to keep the UI conservative

This model does not need to become a global connection object. It only needs to support selected-flow presentation correctly.

## Recommended implementation plan

### Stage 1

Fix correctness of current QUIC TLS attachment.

- do not reuse ClientHello details for packets or items that should show ServerHello
- ensure bounded CRYPTO assembly is direction-aware and ownership-aware
- keep fallback behavior conservative when assembly is incomplete or ambiguous

### Stage 2

Introduce an internal QUIC presentation model.

- packet shell type
- payload or frame list
- CRYPTO fragment references
- optional assembled TLS semantic

This stage should improve correctness first, not UI ambition.

### Stage 3

Improve Packet Details presentation.

- show packet shell summary clearly
- show payload or frame summary clearly
- attach TLS details only when bounded assembly succeeds reliably

### Stage 4

Improve Stream itemization conservatively.

- suppress PADDING and PING as standalone Stream items
- keep ACK, CRYPTO, Handshake, and Protected payload semantics when reliably meaningful
- refine labels only when the internal model is stable enough to support them consistently

### Stage 5

Optional future enrichment.

- QUIC certificate details
- minimal HTTP/3-aware handling
- clearer payload-oriented Stream labels if reliability remains high

## Relationship to current planning docs

This RFC complements the current Stream and planning documents rather than replacing them.

- [docs/stream_architecture.md](docs/stream_architecture.md) defines the selected-flow Stream boundaries
- [docs/current-state.md](docs/current-state.md) records the current narrow QUIC support level
- [docs/next-steps.md](docs/next-steps.md) tracks short-term implementation priorities

The practical effect of this RFC is to define the conceptual model that later QUIC work should follow.
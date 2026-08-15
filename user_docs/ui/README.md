# Desktop interface

Pcap Flow Lab is a flow-first desktop application for working with packet
captures and reusable indexes.

A useful mental model is:

`capture -> canonical flows -> packets / stream inspection -> per-flow Analysis -> whole-capture Statistics`

Qt remains the primary desktop UI. Most screenshots on this page use the Tauri
UI because its compact layout shows more of the workflow in a single frame.

If you want the detailed control-by-control guides after this overview, jump to
the navigation table at the end of the page.

## From capture to flow

Opening a raw `PCAP` or `PCAPNG`, or reopening a saved index, gives you the
canonical flow inventory that the rest of the desktop UI uses.

![Flows overview](images/flows/flows-tauri-overview.png)

From there, the normal workflow is straightforward:

1. select a canonical flow in `Flows`;
2. inspect its packets;
3. read structured `Packet Details` in `Summary`;
4. switch to `Bytes` when you need authoritative packet or protocol-unit byte
   views.

This is the core shape of the application: capture-wide navigation on top,
packet and stream inspection underneath, and a selected-item inspector on the
right.

Use [Flows workspace](flows.md) for the detailed guide.

## Inspect protocol streams

`Stream` is derived from the selected canonical flow.

![TLS stream inspection](images/overview/overview-tls-stream.png)

Instead of forcing you to stay at the packet list, the Stream view can expose
protocol-aware reconstructed items such as `TLS ClientHello`,
`TLS ServerHello`, and `TLS AppData`.

This is useful when the meaningful unit is not a single packet:

- a stream item can represent a reconstructed semantic unit;
- that unit may be backed by one packet or by multiple packets together;
- `Stream Item Details` can show `Summary` and `Item Data` when authoritative
  bytes are available.

Treat the visible TLS example as a strong illustration of the UI concept, not
as a claim that every TLS flow produces the same shape.

The full stream-inspection behavior is covered in [Flows workspace](flows.md).

## Analyze one flow

`Analysis` is the selected-flow quantitative workspace.

![Analysis overview and metrics](images/analysis/analysis-overview-metrics.png)

Use it when one canonical flow is interesting enough to explain as a whole:

- overall packet and byte totals;
- protocol-specific metadata where available;
- derived metrics;
- burst and idle summaries;
- first/last timing context.

![Analysis graphs and distributions](images/analysis/analysis-rate-direction-histogram.png)

The deeper visual side of `Analysis` adds:

- directionality;
- rate graphs;
- packet-size distribution;
- timing and burst/idle behavior;
- sequence preview for packet order.

This workspace stays focused on one canonical flow at a time, which makes it a
natural next step after you narrow the capture down in `Flows`.

Use [Analysis workspace](analysis.md) for the full guide.

## Understand the whole capture

`Statistics` is the whole-capture or whole-index view.

![Statistics overview](images/statistics/statistics-overview.png)

Where `Analysis` explains one canonical flow, `Statistics` answers broader
questions about the active session:

- how many packets and recognized flows were surfaced;
- how much captured and original byte volume is present;
- how traffic is split across transport and IP-family summaries;
- how much data remains outside recognized canonical flows.

It also expands into deeper whole-session views such as protocol hints,
QUIC/TLS summaries, top endpoints and ports, and packet/flow size
distributions.

Use [Statistics workspace](statistics.md) for the full guide.

## Follow protocol paths

Protocol Path is one of the most useful ways to understand why two packets do
or do not belong to the same canonical flow.

![Protocol Path identity tree](images/statistics/statistics-protocol-path-identity.png)

A flow is not always just an effective inner 5-tuple. Encapsulation and path
context can matter to identity. The Protocol Path views can preserve ordered
structure such as:

- VLAN identity;
- MPLS labels;
- nested tunnel layers;
- the outer-to-inner protocol path used for grouped flow identity.

This makes it easier to see when traffic is separated or merged because of path
context rather than only inner transport fields. The Statistics workspace can
also aggregate by protocol path and send matching results back into `Flows`.

Use [Statistics workspace](statistics.md) for the detailed Protocol Path guide.

## Work with captures and indexes

Raw captures can be opened directly, and indexes can be reopened later to reuse
materialized flow inventory and stored metadata.

That is useful when you want fast re-entry into an already interpreted session
without treating every reopen as a fresh raw import. Byte-backed inspection and
export can still depend on source capture availability, and the source capture
can be reattached if needed.

Use [Captures and indexes](capture-and-index.md) for the full lifecycle.

## Export what you need

Once you have narrowed the session down to the flows you care about, the
desktop UI can export:

- the current flow;
- selected flows;
- unselected flows;
- bounded packet-retention variants through `Smart Export`;
- combined or per-flow capture output;
- flow information CSV.

Use [Flow actions and export](flow-actions.md) for the export workflows.

## Configure interpretation and presentation

`Settings` is split between two ideas:

- `View & Inspection` behavior that mainly changes current presentation or
  selected-item inspection;
- `Capture Processing` rules that affect how raw captures are interpreted when
  they are imported or reopened.

That distinction matters because grouping-related settings do not silently
regroup an already opened raw session.

Use [Settings](settings.md) for the practical guide.

## Detailed UI guides

| Guide | Use it for |
| --- | --- |
| [Main window](main-window.md) | Overall window layout, top-level navigation, menus, and workspace placement |
| [Flows workspace](flows.md) | Canonical flow navigation, packet inspection, stream inspection, Packet Details, and Bytes |
| [Analysis workspace](analysis.md) | Selected-flow metrics, rates, timing, size distributions, and sequence preview |
| [Statistics workspace](statistics.md) | Whole-capture summaries, protocol-path aggregation, and capture-wide quantitative views |
| [Captures and indexes](capture-and-index.md) | Raw capture import, index reuse, source-capture attachment, and session lifecycle |
| [Flow actions and export](flow-actions.md) | Desktop export actions, Smart Export, and flow-info CSV workflows |
| [Settings](settings.md) | Immediate view behavior, capture-processing rules, and raw-capture reopen semantics |

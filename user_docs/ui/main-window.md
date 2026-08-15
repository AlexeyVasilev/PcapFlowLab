# Main window

This page explains the current desktop main window from an end-user point of
view. It is written against the Qt desktop application first, because that is
the most complete and stable UI surface today.

If you also use the CLI, see [CLI overview](../cli/README.md). For raw-capture
settings that can also be supplied through `settings.json`, see
[capture processing settings](../reference/settings.md).

## What the main window is for

The main window combines three different workspaces:

- `Flows` for flow selection, packet inspection, and stream inspection;
- `Analysis` for selected-flow quantitative analysis;
- `Statistics` for whole-capture or whole-index summaries.

At the top of the window, `Active session` shows what is currently open:

- a raw capture such as PCAP or PCAPNG; or
- an index created earlier from a capture.

When an index depends on original packet bytes, the UI can also show a
`Source PCAP` path. This matters for packet bytes, stream reconstruction, and
other byte-backed inspection features.

For the dedicated end-user guide to opening raw captures, opening/saving
indexes, source-capture reattachment, and open-progress behavior, see
[Captures and indexes](capture-and-index.md).

## Main areas

The Qt main window uses four top-level menu groups:

- `File`
- `Flow`
- `View`
- `Help`

The most common actions are:

- `Open Capture`
- `Open Index`
- `Save Index`
- `Settings`
- `Supported Protocols`
- `Protocol Path Legend`
- `About`

The `Flow` menu contains export actions for the current flow set, including
selected-flow export, unselected-flow export, CSV export of all flow info, and
Smart Export.

## Flows workspace

`Flows` is the primary inspection workspace. It has three coordinated parts:

- the flow table at the top;
- the packet or stream list at bottom-left;
- `Packet Details` or `Stream Item Details` at bottom-right.

For the detailed end-user guide to this workspace, see
[Flows workspace](flows.md).

### Flow table

The flow table is where you usually start.

It supports:

- filtering by protocol, hint, service, address, or port;
- selecting one flow for packet and stream inspection;
- selecting multiple flows for export actions;
- optional visibility of the `Protocol Path` column;
- optional visibility of the fragmented-packet-count column;
- copying a Wireshark display filter for the currently selected flow.

When one or more flows are checked, Qt also shows a small selection status bar
below the flow table.

The table can also expose a special `Unrecognized packets list (...)` row. That
row is not a normal flow. It is a shortcut into packets that were imported but
could not be assigned to a canonical flow.

### Packets tab

The lower-left area defaults to `Packets`.

This list follows the currently selected flow. If no flow is selected, the
normal empty state is:

`Select a flow to inspect packets`

When the unrecognized-packets row is selected, the packet list changes scope
and shows those packets instead.

Depending on the current windowed loading state, the footer can report:

- `Showing all ... packets`
- `Showing ... of ... packets`
- `Load more`

### Stream tab

The lower-left `Stream` tab is a semantic reconstruction of the selected flow,
not just a packet list in another format.

Current Stream behavior:

- Stream is available only for a selected normal flow.
- Stream is disabled for the unrecognized-packets list.
- Stream items are directional semantic items such as protocol-aware payload
  units or reconstructed application-level items.
- Stream can be partial when only part of the packet window is currently loaded.

Important availability limitation:

- Stream reconstruction requires original source bytes.

If source bytes are not currently available, the stream area explains that the
original source capture must be reattached. In that state, packet lists can
still be usable while stream reconstruction is unavailable.

Typical Stream status messages include:

- `Building stream view...`
- `Showing all ... stream items`
- `Showing first ... stream items`
- `Load more packets to extend the stream view.`

## Packet Details and Stream Item Details

The lower-right inspector changes with the current selection.

### Packet Details

When a packet is selected, the inspector title is `Packet Details`.

Current Packet Details tabs are:

- `Summary`
- `Bytes`

There is no `Protocol` tab. There are no separate `Raw`, `TCP Payload`, or
`UDP Payload` tabs.

#### Summary

`Summary` is the structured packet-inspection surface.

It can show:

- nested protocol layers;
- important fields inside those layers;
- warnings or validation notes when the current packet supports them;
- plain-text fallback content when structured layers are not available.

This is the main place to understand what the packet contains.

#### Bytes

`Bytes` exposes protocol-unit and derived byte views for the selected packet.

Examples of byte views can include:

- the whole captured packet or frame;
- a recognized outer protocol unit such as Ethernet II, IPv4, TCP, or UDP;
- transport payload views;
- protocol-specific derived views when available.

The byte-view selector can contain more than one entry. The selected entry
controls:

- the status line;
- the rendered byte text;
- the `Export Bytes...` action.

Some byte views can be unavailable even when packet summary data is available.
For example, the UI may know that a protocol unit exists while still lacking
the exact source bytes required to materialize it.

### Stream Item Details

When a stream item is selected, the inspector title becomes
`Stream Item Details`.

Current Stream Item Details tabs are:

- `Summary`
- `Item Data`

#### Summary

`Summary` is the structured semantic view of the selected stream item. It uses
the same general presentation style as packet summary, but the content is about
the stream item rather than a single packet.

#### Item Data

`Item Data` is the byte/text materialization surface for the selected stream
item.

Current behavior:

- if authoritative item-owned bytes exist, the pane shows them and enables
  `Export Bytes...`;
- if the item does not currently retain one authoritative byte sequence, the
  pane stays unavailable and explains that item data is unavailable.

This distinction is important: some stream items are protocol-aware and useful
in `Summary` even when `Item Data` is not currently materialized.

## Analysis workspace

`Analysis` is a selected-flow quantitative workspace. It is not a whole-capture
dashboard.

The left side lists analysis flows. The right side shows the analysis for the
currently selected flow.

Current Analysis surfaces include:

- overview and identity information for the selected flow;
- packet and byte totals;
- packet direction and data direction summaries;
- packet ratio and byte ratio summaries;
- timing fields such as first packet, last packet, duration, and largest gap;
- protocol/service-specific summary panels when available;
- derived metrics;
- burst / idle summary;
- packet-size histogram;
- inter-arrival histogram;
- sequence preview with CSV export;
- rate graph controls and plotted directional series.

Use `Open in Flows` when you want to move from analysis back to detailed packet
and stream inspection for the same flow.

For the detailed end-user guide to this workspace, see
[Analysis workspace](analysis.md).

## Statistics workspace

`Statistics` is the whole-capture or whole-index summary workspace.

It includes always-visible overview content plus several independently
collapsible sections.

### Always-visible summary

At the top of `Statistics`, the UI shows high-level totals such as:

- packets
- flows
- original bytes
- captured bytes

It also shows protocol summary tables, including:

- transport summary
- IP family summary

If the capture contains packets that were imported but not assigned to a flow,
the UI also shows `Unrecognized Packets`.

### Optional statistics sections

The current optional/collapsible statistics sections are:

1. `Packet Size Distribution`
2. `Flows by Packet Count`
3. `Protocol Path Tree`
4. `Detected Protocol Hints`
5. `QUIC and TLS`
6. `Top Endpoints and Ports`

These sections load lazily. In practice, that means the application can defer
some heavier calculations until you actually open the section.

For the detailed end-user guide to this workspace, see
[Statistics workspace](statistics.md).

### Protocol Path Tree

`Protocol Path Tree` is especially important because it connects protocol-path
aggregation to flow inspection.

Current controls include:

- `Show flows`
- mode switching
- `Expand all`
- `Collapse all`
- `Export`

Use `Show flows` to pivot from an aggregate protocol-path row back to the
matching flow set.

## Settings

Open `View -> Settings` to change current GUI behavior and capture-processing
preferences.

Use the dedicated [Settings](settings.md) guide for the practical lifecycle of
immediate view options, next-import processing options, and raw-capture reopen
behavior.

Current settings are split into two groups:

- `View & Inspection`
- `Capture Processing`

Examples of immediate GUI-facing settings:

- `Use possible TLS/QUIC`
- `Show Wireshark filter for selected flow`
- `Show Protocol Path column in the flow table`
- `Show fragmented packet count column in the flow table`
- `Validate IPv4/TCP/UDP checksums for selected packet`

Examples of next-open capture-processing settings:

- `HTTP: use request path as service hint when Host is missing`
- `Ignore VLAN and MPLS layers when grouping flows`
- `Ignore GTP-U TEIDs when grouping inner flows`

Important distinction:

- the GUI settings dialog changes application behavior inside the desktop app;
- `settings.json` is a CLI input file used by CLI commands for raw-capture
  processing;
- index files keep the grouping decisions that were already stored into them.

That means reopening a previously created index does not re-import its flow
inventory with new grouping settings.

## Raw captures, indexes, and source capture

The UI works with both directly opened captures and previously saved indexes.

### Raw capture

When you open a raw capture:

- flow inventory is built from the capture;
- packet bytes are available directly from the source file;
- stream reconstruction can use the source capture immediately.

### Index

When you open an index:

- you get the previously materialized flow inventory quickly;
- whole-capture summaries can still be available;
- byte-backed details can depend on whether the original source capture is also
  available.

If the index was opened without usable source bytes, the UI can still show
high-level data while disabling or constraining:

- packet byte materialization;
- stream reconstruction;
- checksum validation that requires source bytes.

When needed, the UI can surface the expected source-capture path so you can
reattach the original PCAP.

## Empty, loading, and disabled states

The main window intentionally uses explicit guidance text when a selection or
source file is missing.

Common examples:

- `Select a flow to inspect packets`
- `Select a packet or stream item to inspect details`
- `Loading selected flow...`
- `Applying new session...`
- source-capture-unavailable messaging for stream reconstruction

These states are part of the normal workflow. They are not necessarily errors.

## Qt and Tauri

This page is Qt-first, but the Tauri UI currently follows the same high-level
model:

- the same top-level `Flows`, `Analysis`, and `Statistics` workspaces;
- `Packet Details` with `Summary` and `Bytes`;
- `Stream Item Details` with `Summary` and `Item Data`;
- settings, supported protocols, protocol-path legend, and about surfaces;
- protocol-path export and analysis-flow navigation.

Current user-relevant differences:

- Qt is the primary and more complete desktop implementation.
- Tauri is a spike/prototype UI that already mirrors most major workflows.
- Some wording and persistence notes can differ slightly between Qt and Tauri,
  especially in settings-related helper text.
- When release notes or screenshots disagree, prefer current Qt behavior for
  end-user expectations unless the documentation explicitly says otherwise.

## Suggested reading order

If you are learning the application for the first time, this sequence usually
works well:

1. Open a capture or index.
2. Start in `Flows`.
3. Select a flow and inspect packets.
4. Use `Packet Details -> Summary` first, then `Bytes` when you need source
   materialization.
5. Open `Stream` for protocol-aware item reconstruction when source bytes are
   available.
6. Use `Analysis` for timing, ratios, histograms, and directional behavior.
7. Use `Statistics` for whole-capture summaries and protocol-path aggregation.

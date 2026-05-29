# Frontend DTO Mapping Audit

## Purpose

This document maps the shared presentation contract in [presentation_contract.md](C:/My2/Projects/C++/PcapFlowLab/PcapFlowLab_1/PcapFlowLab/docs/ui/presentation_contract.md) to the current implementation.

The goal is to show:

- which fields and semantics are already available today;
- which ones already look frontend-neutral;
- which ones still live mostly in Qt-specific models/view-models;
- which ones are currently duplicated or drifting between Qt and Tauri;
- which gaps should be handled first in later code changes.

This document is an audit only. It does not introduce a new contract and does not require immediate implementation changes.

## Summary

### What is already close to frontend-neutral

- Session-level shell facts in `CaptureSession`:
  - open source kind;
  - source availability;
  - expected source path;
  - partial-open state;
  - summary/protocol/recognition counters.
- Session row/query shapes in `FlowRows.h`:
  - `FlowRow`;
  - `PacketRow`;
  - `StreamItemRow`;
  - protocol/statistics summary structs.
- The `FrontendSessionAdapter` layer already exposes a useful read-side API for:
  - overview;
  - flows;
  - selected-flow packets;
  - selected-flow stream;
  - selected-flow packet details.

### What is mostly Qt-specific today

- Flow filtering, sorting, and checked-flow batch-selection semantics.
- Packet inspector structure and most packet-details presentation composition.
- Stream-item details presentation in the right-hand inspector.
- Large parts of Statistics grouping/presentation.
- Most of Analysis presentation.

### What is currently duplicated or drifting between Qt and Tauri

- Open shell state semantics:
  - Tauri has explicit `idle/opening/opened/error`;
  - Qt exposes similar meaning through several controller properties but not the same shape.
- Flow filtering/search:
  - Qt filters over richer flow-model semantics;
  - Tauri filters only over currently loaded client-side DTO fields.
- Wireshark filter generation:
  - Qt uses `selected_flow_wireshark_filter(...)`;
  - Tauri now consumes a shared adapter-provided filter string, but parity still depends on matching helper semantics.
- Packet inspector:
  - Qt is text-first via `PacketDetailsViewModel`;
  - Tauri is partially structured in UI but still backed by text-oriented adapter fields.
- Source availability:
  - frontend-neutral grouping has started through a shared `SourceAvailability` shape in open/details/stream results;
  - Qt still consumes equivalent facts mostly through controller/view-model properties and placeholder builders.
- Stream:
  - Qt supports selected stream item and stream-item details;
  - Tauri currently shows stream rows only and does not yet model selected stream item.

### What should be handled first in future DTO cleanup

- Flow DTO alignment.
- Packet Row DTO alignment.
- SourceAvailabilityState alignment.
- PacketInspector DTO refinement.
- Stream DTO refinement.

## Mapping Table: Global Shell / Session State

| Contract item | Current Qt source | Current frontend-neutral DTO/API | Current Tauri source | Gap / mismatch | Proposed owner | Priority |
|---|---|---|---|---|---|---|
| active session path | `MainController.currentInputPath`, `Main.qml` active session frame | `FrontendOpenResult.input_path`; `CaptureSession::capture_path()` | `OpenCaptureResultDto.input_path`; held in `main.js` only via status/open result, not normalized as long-lived shell DTO | Tauri does not keep a richer shell session object; no explicit active-session DTO | app/session + frontend-neutral shell DTO | High |
| open source kind: capture/index | `MainController.openedFromIndex`, `Main.qml` displays `PCAP:` or `Index:` | `FrontendOpenResult.opened_from_index`; `CaptureSession::opened_from_index()` | `OpenCaptureResultDto.opened_from_index`; Tauri uses it indirectly, not as dedicated shell display model | semantics available, but shell shape not standardized | app/session + frontend-neutral shell DTO | High |
| open mode | `MainController.captureOpenMode`, `Main.qml` combo box | `FrontendOpenMode`; adapter `open_capture(path, mode)` | `open_mode` string in Tauri command, local select value in `main.js` | currently request-only in adapter; no persistent shell DTO field | app/session + frontend controller | Medium |
| open state | Qt splits this across `isOpening`, `openErrorText`, `statusText`, success state by loaded session | no explicit frontend-neutral open-state enum | Tauri `main.js` explicit `idle/opening/opened/error` | mismatch in shape; Tauri has cleaner explicit state | frontend-neutral shell DTO candidate | High |
| source availability | `MainController.hasSourceCapture`, source warnings, unavailable placeholders | `FrontendSourceAvailabilityDto` nested in open/details/stream results; `CaptureSession::has_source_capture()`, `source_capture_accessible()` | Tauri now consumes grouped `source_availability` in shell warning text and unavailable fallbacks | grouped facts exist, but Qt still does not consume one shared DTO shape | app/session + frontend-neutral SourceAvailabilityState | Improved |
| expected source path | `MainController.expectedSourceCapturePath`, `Main.qml` warning block | `FrontendSourceAvailabilityDto.expected_source_capture_path`; legacy scalar field still present on `FrontendOpenResult` | Tauri now uses grouped state in shell/unavailable fallbacks | legacy scalars still coexist during migration | app/session + frontend-neutral SourceAvailabilityState | Improved |
| partial-open warning/state | `MainController.partialOpen`, `partialOpenWarningText`, `Main.qml` warning panel | `FrontendSourceAvailabilityDto.partial_open`; legacy scalar field still present on `FrontendOpenResult` | Tauri now uses grouped state for compact shell warning note | warning wording remains frontend-specific | app/session for fact, frontend rendering for wording | Improved |
| selected flow | `MainController.selectedFlowIndex` | `FrontendSessionAdapter::selected_flow_index()` only internally; `select_flow(flow_index)` mutation API | `state.selectedFlowIndex` in `main.js`; set by flow row click | no read DTO for selected-flow shell state; mutation-only | frontend controller/model with stable `flow_index` | High |
| selected packet | `MainController.selectedPacketIndex` | no adapter-level explicit selected-packet query; packet details API takes `packet_index` | `state.selectedPacketIndex` and `state.selectedPacketRow` in `main.js` | selection state is frontend-local today | frontend controller/model with stable `packet_index` | Medium |
| selected stream item | `MainController.selectedStreamItemIndex` | no frontend-neutral API for selecting/querying stream item details | none in current Tauri shell | Tauri gap; no shared frontend-neutral stream-item selection path yet | deferred frontend-neutral DTO / controller work | Medium |
| status/error text | `MainController.statusText`, `statusIsError`, `openErrorText` | `FrontendOpenResult.error_text`; packet/stream/detail result error/unavailable text fields | `state.statusText`, `statusKind`, plus per-panel error text in `main.js` | no common shell/status DTO; mixed global and local message ownership | app/session facts + frontend rendering wording | Medium |

## Mapping Table: Flows View

| Contract item | Current Qt source | Current frontend-neutral DTO/API | Current Tauri source | Gap / mismatch | Proposed owner | Priority |
|---|---|---|---|---|---|---|
| `flow_index` | `FlowRow.index`; `FlowListModel.FlowIndexRole`; selected flow uses stable index | `FrontendFlowDto.flow_index` | `FlowDto.flow_index`; used in `main.js` | aligned | frontend-neutral DTO | High |
| `flow_display_number` if present | Qt displays 1-based number from `flow_index + 1` in `FlowTable.qml` | none explicit | Tauri now derives and renders a 1-based display number locally while keeping stable `flow_index` for selection and backend calls | no backend gap; frontend-derived display numbering is aligned | frontend rendering over stable `flow_index` | Resolved |
| address family | `FlowRow.family`; `FlowListModel.FamilyRole` formatted to `IPv4`/`IPv6` | `FrontendFlowDto.family` enum | `FlowDto.family` string `"ipv4"/"ipv6"`; now shown in Tauri flow table | aligned | frontend-neutral DTO | Resolved |
| protocol | `FlowRow.protocol_text`; `FlowListModel.ProtocolRole` | `FrontendFlowDto.protocol_text` | `FlowDto.protocol_text`; shown in Tauri table | aligned | frontend-neutral DTO | High |
| protocol hint | `FlowRow.protocol_hint`; `FlowListModel.ProtocolHintRole` formats display text | `FrontendFlowDto.protocol_hint` plus `protocol_hint_display` | `FlowDto.protocol_hint_display` now used by Tauri table/filter display | shared display-oriented hint field added without changing core semantics | frontend-neutral DTO | Resolved |
| service | `FlowRow.service_hint`; `FlowListModel.ServiceHintRole` | `FrontendFlowDto.service_hint` | `FlowDto.service_hint`; shown in Tauri table/filter | aligned enough | frontend-neutral DTO | High |
| address A | `FlowRow.address_a`; `FlowListModel.AddressARole` | `FrontendFlowDto.address_a` | `FlowDto.address_a`; used for filter and Wireshark generation | aligned | frontend-neutral DTO | High |
| port A | `FlowRow.port_a`; `FlowListModel.PortARole` | `FrontendFlowDto.port_a` | `FlowDto.port_a`; used for display/filter/Wireshark generation | aligned | frontend-neutral DTO | High |
| address B | `FlowRow.address_b`; `FlowListModel.AddressBRole` | `FrontendFlowDto.address_b` | `FlowDto.address_b`; used for filter and Wireshark generation | aligned | frontend-neutral DTO | High |
| port B | `FlowRow.port_b`; `FlowListModel.PortBRole` | `FrontendFlowDto.port_b` | `FlowDto.port_b`; used for display/filter/Wireshark generation | aligned | frontend-neutral DTO | High |
| combined endpoint text | `FlowRow.endpoint_a`, `endpoint_b`; `FlowListModel` filter uses them | `FrontendFlowDto.endpoint_a`, `endpoint_b` | `FlowDto.endpoint_a`, `endpoint_b`; used in Tauri filter but not shown in table | aligned at data level, not in visible columns | frontend-neutral DTO | Medium |
| fragmentation indicator/count | `has_fragmented_packets`, `fragmented_packet_count`; `Frag` column in Qt | `FrontendFlowDto.has_fragmented_packets`, `fragmented_packet_count` | `FlowDto.has_fragmented_packets`, `fragmented_packet_count`; now surfaced as compact `Frag` marker text in Tauri | aligned enough for compact table | frontend-neutral DTO | Resolved |
| packet count | `FlowRow.packet_count`; `FlowListModel.PacketsRole` | `FrontendFlowDto.packet_count` | `FlowDto.packet_count`; shown and filterable in Tauri | aligned | frontend-neutral DTO | High |
| byte count | `FlowRow.total_bytes`; `FlowListModel.BytesRole` | `FrontendFlowDto.total_bytes` | `FlowDto.total_bytes`; shown and filterable in Tauri | aligned | frontend-neutral DTO | High |
| selected/checked state | `FlowListModel.CheckedRole`, `setFlowChecked()`, checked count/export selection | none in frontend-neutral adapter DTO | Tauri has selected row only, no checked batch-selection state | major Qt-only gap | deferred frontend-neutral DTO or frontend-only if batch selection stays UI-specific | Medium |
| filter/search fields | Qt `FlowListModel.setFilterText()` matches family, protocol, hint, service, addresses, endpoints, ports, fragmentation | no dedicated query API; relies on already-structured flow fields | Tauri `main.js` filters over `protocol_text`, `protocol_hint`, `service_hint`, endpoints, addresses, ports, packets, bytes | same idea, but field set differs and logic is duplicated | frontend controller/model over shared flow DTO fields | High |
| sort fields | Qt `FlowListModel.SortKey`, `MainController.sortFlows()` | no frontend-neutral sort API | Tauri currently does not sort flows | Tauri gap; sort is frontend-only by design for now | frontend controller/model | Low |
| Wireshark display filter | Qt `MainController.selectedFlowWiresharkFilter()` via shared helper over flow model | `FrontendFlowDto.wireshark_display_filter` now carries a conservative generated string through the adapter | Tauri now consumes `FlowDto.wireshark_display_filter` instead of rebuilding locally | generation is now shared at adapter layer, but semantics still need periodic parity review with Qt helper | frontend-neutral DTO | Improved |

## Mapping Table: Selected-Flow Packets

| Contract item | Current Qt source | Current frontend-neutral DTO/API | Current Tauri source | Gap / mismatch | Proposed owner | Priority |
|---|---|---|---|---|---|---|
| `flow_packet_row` / row number within selected flow | `PacketRow.row_number`; `PacketListModel.RowNumberRole` | `FrontendPacketDto.row_number` | `PacketDto.row_number`; shown in Tauri table | aligned | frontend-neutral DTO | High |
| `packet_index` | `PacketRow.packet_index`; `PacketListModel.PacketIndexRole`; `MainController.selectedPacketIndex` | `FrontendPacketDto.packet_index`; packet details API keyed by `packet_index` | `PacketDto.packet_index`; selected packet state uses it | aligned | frontend-neutral DTO | High |
| direction | `PacketRow.direction_text`; `PacketListModel.DirectionTextRole`; Qt adds badge styling | `FrontendPacketDto.direction_text` | `PacketDto.direction_text`; shown directly | aligned at data level | frontend-neutral DTO | High |
| timestamp | `PacketRow.timestamp_text`; `PacketListModel.TimestampRole` | `FrontendPacketDto.timestamp_text` | `PacketDto.timestamp_text` | aligned | frontend-neutral DTO | High |
| captured length | `PacketRow.captured_length`; `CapturedLengthRole` | `FrontendPacketDto.captured_length` | `PacketDto.captured_length` | aligned | frontend-neutral DTO | High |
| original length | `PacketRow.original_length`; `OriginalLengthRole` | `FrontendPacketDto.original_length` | `PacketDto.original_length` | aligned | frontend-neutral DTO | High |
| transport payload length | `PacketRow.payload_length`; `PayloadLengthRole`; Qt enriches rows with original transport payload lengths | `FrontendPacketDto.payload_length`; adapter applies `apply_original_transport_payload_lengths()` | `PacketDto.payload_length` | aligned, but semantics depend on adapter enrichment | app/session + frontend-neutral row DTO | High |
| TCP flags | `PacketRow.tcp_flags_text`; `TcpFlagsTextRole` | `FrontendPacketDto.tcp_flags_text` | `PacketDto.tcp_flags_text` | aligned | frontend-neutral DTO | High |
| IP fragmentation marker | `PacketRow.is_ip_fragmented`; `IsIpFragmentedRole` | `FrontendPacketDto.is_ip_fragmented` | `PacketDto.is_ip_fragmented`; now shown in a compact Tauri marker column | aligned enough for current scope | frontend-neutral DTO | Resolved |
| suspected retransmission marker | `PacketRow.suspected_tcp_retransmission`; `SuspectedTcpRetransmissionRole`; `hasVisibleMarkers` in Qt model | `FrontendPacketDto.suspected_tcp_retransmission`; adapter derives via `suspected_tcp_retransmission_packet_indices(...)` | `PacketDto.suspected_tcp_retransmission`; now shown in a compact Tauri marker column | aligned enough for current scope | frontend-neutral DTO already sufficient | Resolved |
| packet pagination / offset / limit / total | Qt controller exposes `loadedPacketRowCount`, `totalPacketRowCount`, `canLoadMorePackets`; load-more semantics | `FrontendSelectedFlowPacketsResult.offset`, `limit`, `total_count`; adapter uses offset/limit query | Tauri `SelectedFlowPacketsDto` and `main.js` page state with `packetOffset`, fixed page size, prev/next | semantic mismatch: Qt load-more vs Tauri page stepping | app/session facts + frontend controller/model | High |
| packet loading state | `MainController.packetsLoading` | none explicit in result DTO | Tauri `packetState = idle/loading/loaded/error` | shell/controller-state mismatch, not DTO gap | frontend controller/model | Medium |
| packet error state | Qt largely controller-driven; packet list can be cleared/reset | result DTO has no packet-list `error_text` field | Tauri uses invoke exception path and local `packetErrorText` | no explicit packet-list error DTO | frontend controller/model or future list-state DTO | Low |
| packet unavailable state | Qt uses source-availability and selected-flow state | no explicit packet-list unavailable text field | Tauri currently infers from shell/open/selection state | acceptable for now | app/session facts + frontend controller/model | Low |

## Mapping Table: Packet Inspector

| Contract item | Current Qt source | Current frontend-neutral DTO/API | Current Tauri source | Gap / mismatch | Proposed owner | Priority |
|---|---|---|---|---|---|---|
| details title / header fields | `PacketDetailsViewModel.detailsTitle`, `headerPrimaryText`, `headerSecondaryText`, `badgeText` | none in `FrontendPacketDetailsDto` | Tauri hardcodes panel title and summary labels in `main.js` | strongly Qt-specific today | deferred PacketInspector DTO refinement | Medium |
| summary text | `PacketDetailsViewModel.summaryText`; built in `MainController::buildPacketSummary(...)` | no summary text field | Tauri reconstructs compact summary UI from packet row + details fields | text-first in Qt, structured-ish in Tauri | candidate structured summary DTO | High |
| structured summary fields | Qt mostly does not expose them as DTO roles; summary is text-first | `FrontendPacketDetailsDto` exposes `timestamp_text`, lengths, flags, `link/network/transport_summary_text` | Tauri uses these fields in summary grid | partially aligned, but still hybrid | frontend-neutral DTO | High |
| raw preview text | `PacketDetailsViewModel.hexText` | `FrontendPacketDetailsDto.raw_preview_text` | `PacketDetailsDto.raw_preview_text` | aligned | frontend-neutral DTO | High |
| raw preview truncated metadata | Qt text and UI state imply it, but not clearly as a standalone property | `FrontendPacketDetailsDto.raw_preview_truncated`, `raw_preview_available`, `raw_preview_unavailable_text` | Tauri uses them explicitly | Tauri/frontend-neutral shape is cleaner than Qt VM surface here | frontend-neutral DTO | High |
| payload preview text | `PacketDetailsViewModel.payloadText` | `FrontendPacketDetailsDto.payload_preview_text` | `PacketDetailsDto.payload_preview_text` | aligned | frontend-neutral DTO | High |
| payload tab title | `PacketDetailsViewModel.payloadTabTitle` | none in frontend-neutral DTO | Tauri currently hardcodes `Payload` tab | contract drift; Qt supports protocol-specific payload labels, adapter/Tauri do not | candidate PacketInspector DTO field | Medium |
| payload no-payload/truncated/unavailable metadata | Qt currently encodes much of this through text content and tab title | `FrontendPacketDetailsDto.payload_preview_available`, `payload_preview_truncated`, `payload_preview_unavailable_text`, `unavailable_text` | Tauri uses explicit state texts | adapter/Tauri shape is more explicit than Qt surface | frontend-neutral DTO | High |
| protocol details text | `PacketDetailsViewModel.protocolText` | `FrontendPacketDetailsDto.protocol_details_text` | `PacketDetailsDto.protocol_details_text` | aligned | frontend-neutral DTO | High |
| packet details loading state | Qt controller `reloadSelectedPacketDetails()` path, not DTO-owned | no explicit loading field | Tauri `packetDetailsState = loading/...` | frontend/controller-only by design | frontend controller/model | Low |
| packet details error state | Qt clears or shows placeholders; not formalized as separate DTO | `FrontendPacketDetailsDto.error_text`, `details_available`, `packet_found` | Tauri uses explicit `error` state and text | partial alignment | frontend-neutral DTO + frontend controller | Medium |
| packet details unavailable state | Qt has placeholder builders for source-unavailable packet details | `FrontendPacketDetailsDto.unavailable_text`, source-access flags, preview unavailable texts | Tauri uses explicit `unavailable` state | frontend-neutral shape exists, Qt still text-first | frontend-neutral DTO | High |

## Mapping Table: Selected-Flow Stream

| Contract item | Current Qt source | Current frontend-neutral DTO/API | Current Tauri source | Gap / mismatch | Proposed owner | Priority |
|---|---|---|---|---|---|---|
| stream item index | `StreamItemRow.stream_item_index`; `StreamListModel.StreamItemIndexRole` | `FrontendStreamItemDto.stream_item_index` | `StreamItemDto.stream_item_index` | aligned | frontend-neutral DTO | High |
| stream item display number | Qt uses item index visually in stream list; no separate display-number field | none explicit | Tauri shows `stream_item_index` directly | no explicit distinction yet | frontend rendering over stable `stream_item_index` | Low |
| direction | `StreamItemRow.direction_text`; `DirectionTextRole` | `FrontendStreamItemDto.direction_text` | `StreamItemDto.direction_text` | aligned | frontend-neutral DTO | High |
| label / type / kind | `StreamItemRow.label`; `LabelRole` | `FrontendStreamItemDto.label` | `StreamItemDto.label` | aligned | frontend-neutral DTO | High |
| byte length | `StreamItemRow.byte_count`; `ByteCountRole` | `FrontendStreamItemDto.byte_count` | `StreamItemDto.byte_count` | aligned | frontend-neutral DTO | High |
| contributing packet count | `StreamItemRow.packet_count`; `PacketCountRole` | `FrontendStreamItemDto.packet_count` | `StreamItemDto.packet_count` | aligned | frontend-neutral DTO | High |
| source packet references | `StreamItemRow.packet_indices` in session row, `StreamListModel` turns this into text | adapter receives raw `packet_indices` but only exports formatted `source_packets_text` | Tauri only sees `source_packets_text` | structured refs lost at frontend-neutral boundary | candidate Stream DTO refinement | High |
| source packet display text | `StreamListModel.SourcePacketsTextRole`; `StreamView.qml` further compacts for UI | `FrontendStreamItemDto.source_packets_text` | `StreamItemDto.source_packets_text` | aligned as text-only | frontend-neutral DTO may keep shared text, plus structured refs later | Medium |
| constricted / quality flags | `StreamItemRow.has_constricted_contribution`; notes exist in session row but not Qt model roles beyond bool | `FrontendStreamItemDto.has_constricted_contribution` only | `StreamItemDto.has_constricted_contribution`; shown as `Constricted` note | notes/truncation semantics not carried across adapter | candidate Stream DTO refinement | Medium |
| bounded packet window metadata | Qt controller exposes `streamPacketWindowCount`, `streamPacketWindowPartial` | `FrontendSelectedFlowStreamResult.packet_window_count`, `total_flow_packet_count`, `packet_window_partial` | Tauri `SelectedFlowStreamDto` and local state use them | aligned | frontend-neutral DTO | High |
| `can_load_more` / load-more state | Qt `canLoadMoreStreamItems`, `streamPartiallyLoaded`, `loadedStreamItemCount`, `totalStreamItemCount` | `FrontendSelectedFlowStreamResult.can_load_more`, `stream_partially_loaded`, `loaded_item_count`, `total_item_count` | Tauri uses same fields | aligned | frontend-neutral DTO | High |
| stream loading state | Qt `MainController.streamLoading` and tab-activation logic | no explicit loading field in result DTO | Tauri `streamState = idle/loading/loaded/error/unavailable` | frontend/controller-owned | frontend controller/model | Low |
| stream error state | Qt state via controller reset/unavailable text | `FrontendSelectedFlowStreamResult.error_text` | Tauri uses explicit error state | aligned enough | frontend-neutral DTO + frontend controller | Medium |
| stream unavailable state | Qt `sourceCaptureAvailable` + stream empty-state text + placeholders | `FrontendSelectedFlowStreamResult.source_capture_accessible`, `stream_available`, `unavailable_text` | Tauri uses explicit unavailable state | aligned enough | frontend-neutral DTO | High |
| stream item selection | Qt `selectedStreamItemIndex` and stream-item details path exist | no frontend-neutral API for stream item selection/details | Tauri does not select stream items today | major gap | deferred stream-item DTO/controller work | Medium |

## Mapping Table: Statistics / Overview

| Contract item | Current Qt source | Current frontend-neutral DTO/API | Current Tauri source | Gap / mismatch | Proposed owner | Priority |
|---|---|---|---|---|---|---|
| packet count | `SummaryBar`, `MainController.packetCount` | `FrontendOverviewDto.summary.packet_count` | `OverviewDto.summary.packet_count` | aligned | frontend-neutral DTO | High |
| flow count | `SummaryBar`, `MainController.flowCount` | `FrontendOverviewDto.summary.flow_count` | `OverviewDto.summary.flow_count` | aligned | frontend-neutral DTO | High |
| original bytes | Qt `SummaryBar` shows original bytes | adapter overview exposes only `summary.total_bytes`, plus protocol stats with `original_bytes` by bucket | Tauri statistics tab shows `total_bytes`, not separate original vs captured bytes | mismatch; current adapter overview is not Qt-equivalent | candidate DTO refinement | High |
| captured bytes | Qt `SummaryBar` shows captured bytes | adapter overview does not expose top-level captured bytes directly | Tauri statistics tab does not show captured bytes | mismatch | candidate DTO refinement | High |
| TCP/UDP/Other counters | `ProtocolStatsPane` transport section | `FrontendOverviewDto.protocol_summary.tcp/udp/other` with flow/packet/captured/original | Tauri uses only TCP and UDP flow counts from overview | partial alignment; Tauri drops packets/original/captured/other | frontend-neutral DTO already richer than Tauri UI | Medium |
| IPv4/IPv6 counters | `ProtocolStatsPane` family section | `FrontendOverviewDto.protocol_summary.ipv4/ipv6` | currently unused in Tauri | Tauri gap only | frontend-neutral DTO | Medium |
| protocol hint groups | Qt derives grouped table from `protocolHintDistribution` in `MainController` | no frontend-neutral adapter field for protocol hint distribution | not present in current Tauri adapter/UI | Qt-only today | deferred DTO refinement | Medium |
| QUIC summary | Qt protocol stats pane; `MainController.quic*` properties | `FrontendOverviewDto.quic_recognition` | Tauri uses only `quic_recognition.total_flows` | partial alignment | frontend-neutral DTO already sufficient for more UI later | Medium |
| TLS summary | Qt protocol stats pane; `MainController.tls*` properties | `FrontendOverviewDto.tls_recognition` | not surfaced in current Tauri UI | Tauri gap only | frontend-neutral DTO | Medium |
| top endpoints | `TopTalkersPane`, `topEndpointsModel`, drill-down action | no frontend-neutral adapter field | not present in Tauri | Qt-only today | deferred statistics DTO refinement | Low |
| top ports | `TopTalkersPane`, `topPortsModel`, drill-down action | no frontend-neutral adapter field | not present in Tauri | Qt-only today | deferred statistics DTO refinement | Low |
| statistics drill-down actions | Qt `drillDownToEndpoint`, `drillDownToPort` | no frontend-neutral action/query contract | not present in Tauri | UI-specific today | frontend controller/model + later contract decision | Low |

## Mapping Table: Analysis

Analysis remains reference/deferred. The mapping below records what is statically visible today.

| Contract item | Current Qt source | Current frontend-neutral DTO/API | Current Tauri source | Gap / mismatch | Proposed owner | Priority |
|---|---|---|---|---|---|---|
| selected-flow analysis trigger | `sendSelectedFlowToAnalysis()`, `currentTabIndex`, `analysis_tab_active_` | direct session API exists: `CaptureSession::get_flow_analysis(flow_index)` | Tauri `Analysis` tab is placeholder only | Tauri gap; no frontend-neutral app adapter API | deferred | Medium |
| analysis flow list | `AnalysisWorkspacePane` left list from `flowModel` | none separate; Qt reuses flow model | none | frontend-only today | deferred | Low |
| duration/timeline metrics | `MainController.analysisDurationText`, timeline properties | session returns `FlowAnalysisResult`; not wrapped by frontend adapter | none | no frontend-neutral adapter surface | deferred | Medium |
| endpoint summary | `analysisEndpointSummaryText` | session analysis result exists | none | no frontend-neutral adapter surface | deferred | Medium |
| packet/byte/rate metrics | multiple `analysis*Text` properties in `MainController` | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Medium |
| direction split metrics | `analysisPacketsAToBText`, `analysisBytesAToBText`, etc. | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Medium |
| packet size metrics | `analysisAveragePacketSizeText`, min/max size texts | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Medium |
| inter-arrival metrics | `analysisAverageInterArrivalText`, histograms | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Medium |
| protocol hint/service/version text | `analysisProtocolHint`, `analysisServiceHint`, `analysisProtocolVersionText` | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Medium |
| TCP control counts | `analysisHasTcpControlCounts`, SYN/FIN/RST props | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Medium |
| burst/idle-gap metrics | `analysisBurstCountText`, `analysisLargestIdleGapText` | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Medium |
| rate graph status/window | `analysisRateGraphAvailable`, status/window text, series props | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Low |
| histograms | packet size and inter-arrival histogram properties | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Low |
| sequence preview | `analysisSequencePreview` | session analysis result exists | none | Qt-only app/controller formatting today | deferred | Low |
| analysis export action | `browseExportSelectedFlowSequenceCsv()` and availability props | no frontend-neutral adapter API | none | Qt-only today | deferred | Low |

## Gap Classification

### Already aligned

- Stable flow fields in `FlowRow` -> `FrontendFlowDto` -> Tauri `FlowDto`
- Stable packet-row fields in `PacketRow` -> `FrontendPacketDto` -> Tauri `PacketDto`
- Basic selected-flow stream row fields in `StreamItemRow` -> `FrontendStreamItemDto` -> Tauri `StreamItemDto`
- Basic overview counters and recognition stats in `FrontendOverviewDto`
- Grouped source-availability facts in `CaptureSession` -> frontend-neutral `SourceAvailability` -> Tauri open/details/stream DTOs

### Naming mismatch only

- `flow_index` vs visible 1-based Qt display number
- `row_number` vs `flow packet row` terminology
- `stream_item_index` vs possible display number naming
- `total_bytes` in adapter overview vs Qt summary using separate captured/original byte labels

### Available in Qt but not frontend-neutral

- checked/selected-for-batch-export flow state
- protocol-hint distribution table
- top endpoints / top ports data
- stream-item details path in the right-hand inspector
- analysis workspace shape
- Qt source-unavailable placeholders still live in controller/view-model logic rather than consuming one grouped source-availability DTO directly

### Available in Tauri but not contract-aligned

- explicit shell `openState` enum in `main.js`
- explicit packet details state machine in `main.js`
- explicit stream state machine in `main.js`

These are useful implementation patterns, but they are local Tauri state, not yet shared contract fields.

### Missing structured fields

- explicit shell/session-state DTO
- explicit selected-stream-item frontend-neutral path
- structured source packet references for stream items
- structured packet inspector summary fields
- top-talker statistics DTO

### Text-only today, candidate for structured DTO

- packet summary text in Qt
- stream-item summary/details text in Qt
- source-unavailable placeholder texts
- Wireshark filter string
- protocol-hint grouping labels

### Frontend-only by design

- filtering widget state
- sorting widget state
- tab activation
- row highlighting
- compact vs comfortable density
- local prev/next vs load-more UX

### Needs design decision

- final owner of Wireshark filter generation
- whether packet inspector should be mostly structured or text-first
- whether stream item details join the same shared inspector contract as packet details
- how far statistics beyond basic counters should be standardized for CLI
- when Analysis should get any frontend-neutral adapter surface

## Recommended Follow-Up Order

### 1. Flow DTO alignment

Why first:

- already mostly aligned across session, adapter, Qt, and Tauri;
- lowest-risk cleanup;
- helps both Tauri and future CLI quickly.

Expected risk:

- low.

Affected layers:

- backend/session naming surface;
- frontend-neutral DTO layer;
- Qt/Tauri small field-alignment work;
- future CLI.

### 2. Packet Row DTO alignment

Why second:

- selected-flow packets are already close to shared shape;
- packet rows feed both packet table and packet inspector entry point.

Expected risk:

- low to medium.

Affected layers:

- app/session row semantics;
- frontend-neutral DTO layer;
- Qt/Tauri packet-table alignment;
- future CLI.

### 3. SourceAvailabilityState alignment

Why third:

- source-unavailable semantics affect shell, packets, stream, details, and exports;
- this is a cross-cutting source of duplicated wording and local branching.

Expected risk:

- medium.

Affected layers:

- app/session;
- frontend-neutral DTO layer;
- Qt/Tauri shell and unavailable-state rendering;
- future CLI messaging.

### 4. PacketInspector DTO refinement

Why fourth:

- packet inspector is where Qt and Tauri currently diverge the most in shape;
- stabilizing it reduces future repeated adapter logic.

Expected risk:

- medium.

Affected layers:

- frontend-neutral DTO layer;
- Qt packet-details composition;
- Tauri packet inspector;
- future CLI inspect commands.

### 5. Stream DTO refinement

Why fifth:

- stream already has good bounded/on-demand session behavior;
- main remaining gaps are DTO shape and stream-item references/details.

Expected risk:

- medium.

Affected layers:

- app/session adapter layer;
- Qt stream/details path;
- Tauri stream tab;
- future CLI stream queries.

### 6. Tauri UI alignment with stabilized DTOs

Why sixth:

- Tauri already consumes the adapter and will benefit immediately once DTOs settle;
- better to align after DTO shape is less fluid.

Expected risk:

- low to medium.

Affected layers:

- Tauri Rust DTOs/FFI;
- Tauri web UI;
- no required core behavior change.

### 7. CLI design based on stabilized DTOs

Why seventh:

- CLI should consume a shared contract, not invent a third shape in parallel;
- easier once flows/packets/details/stream semantics are settled.

Expected risk:

- medium.

Affected layers:

- CLI only at first;
- shared DTO naming/serialization choices.

### 8. Statistics / Analysis revisit later

Why later:

- statistics and especially analysis are still the richest and least-stable surfaces;
- they should follow after lower-risk DTO alignment work.

Expected risk:

- medium to high.

Affected layers:

- app/session;
- Qt-rich presentation paths;
- Tauri future parity work;
- future CLI reporting surfaces.

## Open Questions

### Identifiers / display numbering

- Should we explicitly carry both stable identifiers and display numbers in shared DTOs?
- Should `flow_display_number` be standardized or remain frontend-derived?
- Should stream rows expose both stable index and display number?

### Field naming

- Should `total_bytes` in current overview become explicit `captured_bytes` and `original_bytes` at top level?
- Should `service_hint` and `protocol_hint` keep current names or move to more generic display-neutral naming later?

### DTO ownership

- Should Wireshark filter generation become shared adapter output, or remain frontend assembly from flow DTO fields?
- Should checked-flow batch-selection state ever become frontend-neutral, or remain UI-local?

### Text vs structured fields

- Should packet summary remain text-first, structured-first, or hybrid?
- Should stream source-packet references carry both structured refs and display text?
- Which statistics grouping labels are shared semantics versus UI wording?

### Source-unavailable states

- Should there be one common `SourceAvailabilityState` across shell, packet details, stream, and exports?
- How much unavailable wording belongs in DTOs versus frontends?

### Packet inspector

- Should the future PacketInspector DTO include explicit title/header fields, or only content fields?
- Should payload tab title become shared DTO data?

### Stream

- Should stream-item details get a frontend-neutral API before CLI work starts?
- How should stream-item selection and stream-to-packet navigation be represented?

### Statistics

- Which Qt statistics sections are required for future CLI output?
- Should top-talker drill-down semantics become part of the shared contract or remain frontend-only?

### Analysis

- Which parts of Qt Analysis are stable enough to map into a frontend-neutral adapter?
- Should Analysis remain reference-only until flows/packets/details/stream DTOs are stable?

### CLI

- Should CLI prefer structured JSON first and add display text as optional fields?
- Which fields should be considered contractually stable before any CLI surface is introduced?

## Non-Goals

- No code changes in this audit.
- No DTO changes in this audit.
- No behavior changes.
- No final CLI design.
- No final Analysis DTO design.

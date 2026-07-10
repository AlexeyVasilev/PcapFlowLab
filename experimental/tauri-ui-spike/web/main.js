(function () {
  const invoke = (...args) => {
    const tauriInvoke = window.__TAURI__?.core?.invoke;
    if (typeof tauriInvoke !== "function") {
      throw new Error("Tauri API is unavailable in this frontend.");
    }

    return tauriInvoke(...args);
  };
  const packetPageSize = 30;
  const initialStreamItems = 15;
  const streamItemBatchSize = 15;
  const initialStreamPacketBudget = 30;
  const streamPacketBatchSize = 30;
  const flowVirtualRowHeight = 32;
  const analysisFlowVirtualRowHeight = 44;
  const protocolPathStatsVirtualRowHeight = 32;
  const flowVirtualOverscanRows = 12;
  const analysisFlowVirtualOverscanRows = 10;
  const protocolPathStatsVirtualOverscanRows = 12;

  const state = {
    memoryDiagnosticsEnabled: false,
    openMenu: null,
    aboutDialogVisible: false,
    settingsDialogVisible: false,
    protocolPathLegendDialogVisible: false,
    protocolPathLegendLoading: false,
    protocolPathLegendEntries: [],
    protocolPathPresentationsById: new Map(),
    protocolPathLegendStatusText: "",
    protocolPathLegendStatusKind: "neutral",
    settingsDialogLoading: false,
    settingsSaveInProgress: false,
    settingsStatusText: "",
    settingsStatusKind: "neutral",
    showProtocolPathColumn: true,
    settings: {
      http_use_path_as_service_hint: false,
      use_possible_tls_quic: false,
      show_wireshark_filter_for_selected_flow: true,
      validate_selected_packet_checksums: false,
    },
    smartExportDialogVisible: false,
    activeTab: "flows",
    flowViewTab: "packets",
    splitterDrag: null,
    openState: "idle",
    currentSessionPath: "",
    currentSessionOpenedFromIndex: false,
    openRequestToken: 0,
    openProgress: {
      in_progress: false,
      cancel_requested: false,
      opening_as_index: false,
      packets_processed: 0,
      bytes_processed: 0,
      total_bytes: 0,
      percent: 0,
      input_path: "",
    },
    attachSourceInProgress: false,
    saveIndexInProgress: false,
    exportCurrentFlowInProgress: false,
    exportSelectedFlowsInProgress: false,
    exportUnselectedFlowsInProgress: false,
    smartExportInProgress: false,
    smartExportStatusText: "",
    smartExportStatusKind: "neutral",
    statusKind: "neutral",
    statusText: "",
    partialOpenWarningText: "",
    sourceAvailability: null,
    overview: null,
    flows: [],
    flowFilterText: "",
    activeProtocolPathFilter: null,
    flowSortKey: "index",
    flowSortDirection: "asc",
    flowVirtualWindowStart: 0,
    flowVirtualWindowEnd: 0,
    flowVirtualizationActive: false,
    checkedFlowIndices: new Set(),
    selectedFlowIndex: null,
    unrecognizedPacketsSelected: false,
    packets: [],
    packetsTotalCount: 0,
    packetOffset: 0,
    packetCanLoadMore: false,
    packetLoadingMore: false,
    selectedPacketIndex: null,
    selectedPacketRow: null,
    packetDetails: null,
    flowState: "idle",
    packetState: "idle",
    packetErrorText: "",
    streamItems: [],
    streamState: "idle",
    streamErrorText: "",
    streamUnavailableText: "",
    streamLoadedItemCount: 0,
    streamTotalItemCount: 0,
    streamPacketWindowCount: 0,
    streamCanLoadMore: false,
    streamPartiallyLoaded: false,
    streamPacketWindowPartial: false,
    streamRequestedItemLimit: initialStreamItems,
    streamRequestedPacketBudget: initialStreamPacketBudget,
    streamLoadedForFlowIndex: null,
    selectedStreamItemIndex: null,
    selectedStreamItem: null,
    selectedStreamItemDetails: null,
    streamDetailsState: "idle",
    streamDetailsErrorText: "",
    streamDetailsTab: "summary",
    analysis: null,
    analysisState: "idle",
    analysisErrorText: "",
    analysisUnavailableText: "",
    analysisLoadedForFlowIndex: null,
    analysisFlowVirtualWindowStart: 0,
    analysisFlowVirtualWindowEnd: 0,
    analysisFlowVirtualizationActive: false,
    protocolPathStatsMode: 0,
    protocolPathStatsVisibleRows: [],
    selectedProtocolPathNode: null,
    protocolPathExpandedNodeIds: new Set(),
    analysisSequenceExportInProgress: false,
    analysisSequenceExportStatusText: "",
    analysisSequenceExportStatusKind: "neutral",
    analysisRateMetricMode: "data",
    analysisRateDirectionMode: "both",
    analysisPacketSizeHistogramMode: "all",
    analysisInterArrivalHistogramMode: "all",
    packetDetailsState: "idle",
    packetDetailsErrorText: "",
    packetDetailsTab: "summary",
    packetSummaryExpansionProfiles: new Map(),
    wiresharkFilterStatusText: "",
    wiresharkFilterStatusKind: "neutral",
    flowSelectionRequestToken: 0,
    protocolPathFilterRequestToken: 0,
    packetRequestToken: 0,
    streamRequestToken: 0,
    streamDetailsRequestToken: 0,
    analysisRequestToken: 0,
    diagnosticsPacketRequestOffset: 0,
    diagnosticsPacketRequestLimit: packetPageSize,
    diagnosticsPacketReturnedRowCount: 0,
    diagnosticsPacketReturnedTotalCount: 0,
    flowsTopSizePx: null,
    flowsBottomLeftSizePx: null,
    analysisLeftSizePx: null,
  };

  const elements = {
    menuButtons: Array.from(document.querySelectorAll("[data-menu-button]")),
    menuPanels: Array.from(document.querySelectorAll("[data-menu-panel]")),
    menuItems: Array.from(document.querySelectorAll("[data-menu-action]")),
    menuSaveIndex: document.getElementById("menuSaveIndex"),
    aboutDialog: document.getElementById("aboutDialog"),
    aboutDialogCloseButton: document.getElementById("aboutDialogCloseButton"),
    settingsDialog: document.getElementById("settingsDialog"),
    protocolPathLegendDialog: document.getElementById("protocolPathLegendDialog"),
    protocolPathLegendCloseButton: document.getElementById("protocolPathLegendCloseButton"),
    protocolPathLegendGrid: document.getElementById("protocolPathLegendGrid"),
    protocolPathLegendStatusText: document.getElementById("protocolPathLegendStatusText"),
    settingsHttpUsePathAsServiceHint: document.getElementById("settingsHttpUsePathAsServiceHint"),
    settingsUsePossibleTlsQuic: document.getElementById("settingsUsePossibleTlsQuic"),
    settingsShowWiresharkFilterForSelectedFlow: document.getElementById("settingsShowWiresharkFilterForSelectedFlow"),
    settingsShowProtocolPathColumn: document.getElementById("settingsShowProtocolPathColumn"),
    settingsValidateSelectedPacketChecksums: document.getElementById("settingsValidateSelectedPacketChecksums"),
    settingsStatusText: document.getElementById("settingsStatusText"),
    settingsCancelButton: document.getElementById("settingsCancelButton"),
    settingsSaveButton: document.getElementById("settingsSaveButton"),
    smartExportDialog: document.getElementById("smartExportDialog"),
    smartExportCloseButton: document.getElementById("smartExportCloseButton"),
    smartExportCancelButton: document.getElementById("smartExportCancelButton"),
    smartExportRunButton: document.getElementById("smartExportRunButton"),
    smartExportStatusText: document.getElementById("smartExportStatusText"),
    smartExportScopeCurrent: document.getElementById("smartExportScopeCurrent"),
    smartExportScopeMatchingFilter: document.getElementById("smartExportScopeMatchingFilter"),
    smartExportScopeSelected: document.getElementById("smartExportScopeSelected"),
    smartExportScopeNotMatchingFilter: document.getElementById("smartExportScopeNotMatchingFilter"),
    smartExportScopeUnselected: document.getElementById("smartExportScopeUnselected"),
    smartExportScopeUnrecognized: document.getElementById("smartExportScopeUnrecognized"),
    smartExportScopeAll: document.getElementById("smartExportScopeAll"),
    smartExportBaseAllPackets: document.getElementById("smartExportBaseAllPackets"),
    smartExportBaseFirstNPackets: document.getElementById("smartExportBaseFirstNPackets"),
    smartExportBaseFirstMOriginalBytes: document.getElementById("smartExportBaseFirstMOriginalBytes"),
    smartExportFirstNPackets: document.getElementById("smartExportFirstNPackets"),
    smartExportFirstMOriginalBytes: document.getElementById("smartExportFirstMOriginalBytes"),
    smartExportIncludeLastPacket: document.getElementById("smartExportIncludeLastPacket"),
    smartExportIncludeEveryKthPacket: document.getElementById("smartExportIncludeEveryKthPacket"),
    smartExportEveryKthPacket: document.getElementById("smartExportEveryKthPacket"),
    smartExportExtrasHint: document.getElementById("smartExportExtrasHint"),
    smartExportOutputSingleFile: document.getElementById("smartExportOutputSingleFile"),
    smartExportOutputSeparateFiles: document.getElementById("smartExportOutputSeparateFiles"),
    smartExportDestinationFolderRow: document.getElementById("smartExportDestinationFolderRow"),
    smartExportDestinationFolder: document.getElementById("smartExportDestinationFolder"),
    smartExportBrowseFolderButton: document.getElementById("smartExportBrowseFolderButton"),
    smartExportFolderHelp: document.getElementById("smartExportFolderHelp"),
    smartExportBufferBudgetRow: document.getElementById("smartExportBufferBudgetRow"),
    smartExportBufferBudget: document.getElementById("smartExportBufferBudget"),
    smartExportBufferHelp: document.getElementById("smartExportBufferHelp"),
    capturePath: document.getElementById("capturePath"),
    openMode: document.getElementById("openMode"),
    openFileButton: document.getElementById("openFileButton"),
    activeSessionPanel: document.getElementById("activeSessionPanel"),
    activeSessionText: document.getElementById("activeSessionText"),
    activeSourceSessionRow: document.getElementById("activeSourceSessionRow"),
    activeSourceSessionText: document.getElementById("activeSourceSessionText"),
    openProgressPanel: document.getElementById("openProgressPanel"),
    openProgressTitle: document.getElementById("openProgressTitle"),
    openProgressProcessed: document.getElementById("openProgressProcessed"),
    openProgressTrack: document.getElementById("openProgressTrack"),
    openProgressFill: document.getElementById("openProgressFill"),
    openCancelButton: document.getElementById("openCancelButton"),
    attachSourceButton: document.getElementById("attachSourceButton"),
    partialOpenWarningBanner: document.getElementById("partialOpenWarningBanner"),
    partialOpenWarningText: document.getElementById("partialOpenWarningText"),
    sourceWarningBanner: document.getElementById("sourceWarningBanner"),
    sourceWarningText: document.getElementById("sourceWarningText"),
    sourceWarningExpectedPath: document.getElementById("sourceWarningExpectedPath"),
    statusText: document.getElementById("statusText"),
    tabButtons: Array.from(document.querySelectorAll(".tab-button")),
    tabPanels: Array.from(document.querySelectorAll(".tab-panel")),
    flowsLayout: document.getElementById("flowsLayout"),
    flowsBottom: document.querySelector(".flows-bottom"),
    analysisLayout: document.querySelector(".analysis-layout"),
    flowsVerticalSplitter: document.getElementById("flowsVerticalSplitter"),
    flowsHorizontalSplitter: document.getElementById("flowsHorizontalSplitter"),
    analysisHorizontalSplitter: document.getElementById("analysisHorizontalSplitter"),
    flowViewTabButtons: Array.from(document.querySelectorAll(".subtab-button")),
    flowViewPanels: Array.from(document.querySelectorAll(".flow-view-panel")),
    flowViewTabStreamButton: document.querySelector('[data-flow-view-tab="stream"]'),
    overviewMeta: document.getElementById("overviewMeta"),
    flowMeta: document.getElementById("flowMeta"),
    flowFilterInput: document.getElementById("flowFilterInput"),
    clearFlowFilterButton: document.getElementById("clearFlowFilterButton"),
    protocolPathFlowFilterRow: document.getElementById("protocolPathFlowFilterRow"),
    protocolPathFlowFilterText: document.getElementById("protocolPathFlowFilterText"),
    clearProtocolPathFlowFilterButton: document.getElementById("clearProtocolPathFlowFilterButton"),
    flowSortHeaders: Array.from(document.querySelectorAll("[data-flow-sort-key]")),
    flowPathHeader: document.getElementById("flowPathHeader"),
    flowTableBody: document.getElementById("flowTableBody"),
    flowTableViewport: document.getElementById("flowTableViewport"),
    flowRenderCapBar: document.getElementById("flowRenderCapBar"),
    flowRenderCapText: document.getElementById("flowRenderCapText"),
    checkedFlowsStatusBar: document.getElementById("checkedFlowsStatusBar"),
    checkedFlowsStatusText: document.getElementById("checkedFlowsStatusText"),
    unrecognizedPacketsButton: document.getElementById("unrecognizedPacketsButton"),
    unrecognizedPacketsMeta: document.getElementById("unrecognizedPacketsMeta"),
    wiresharkFilterRow: document.getElementById("wiresharkFilterRow"),
    wiresharkFilterText: document.getElementById("wiresharkFilterText"),
    wiresharkFilterStatusText: document.getElementById("wiresharkFilterStatusText"),
    copyWiresharkFilterButton: document.getElementById("copyWiresharkFilterButton"),
    packetMeta: document.getElementById("packetMeta"),
    packetTableBody: document.getElementById("packetTableBody"),
    packetDirectionHeader: document.getElementById("packetDirectionHeader"),
    packetPayloadHeader: document.getElementById("packetPayloadHeader"),
    packetFlagsHeader: document.getElementById("packetFlagsHeader"),
    packetMarkerHeader: document.getElementById("packetMarkerHeader"),
    packetLoadMoreButton: document.getElementById("packetLoadMoreButton"),
    streamLoadMoreButton: document.getElementById("streamLoadMoreButton"),
    streamTableBody: document.getElementById("streamTableBody"),
    packetDetailsTitle: document.getElementById("packetDetailsTitle"),
    packetDetailsMeta: document.getElementById("packetDetailsMeta"),
    packetInspectorView: document.getElementById("packetInspectorView"),
    streamInspectorView: document.getElementById("streamInspectorView"),
    packetDetailsTabButtons: Array.from(document.querySelectorAll("[data-packet-details-tab]")),
    packetDetailsTabPanels: Array.from(document.querySelectorAll(".packet-details-tab-panel")),
    packetDetailsPayloadTabButton: document.getElementById("packetDetailsPayloadTabButton"),
    packetDetailsStateText: document.getElementById("packetDetailsStateText"),
    packetDetailsSummary: document.getElementById("packetDetailsSummary"),
    packetDetailsRawStateText: document.getElementById("packetDetailsRawStateText"),
    packetDetailsRawText: document.getElementById("packetDetailsRawText"),
    packetDetailsPayloadStateText: document.getElementById("packetDetailsPayloadStateText"),
    packetDetailsProtocolText: document.getElementById("packetDetailsProtocolText"),
    packetDetailsProtocolStateText: document.getElementById("packetDetailsProtocolStateText"),
    packetDetailsPayloadText: document.getElementById("packetDetailsPayloadText"),
    streamDetailsStateText: document.getElementById("streamDetailsStateText"),
    streamDetailsHeaderCard: document.getElementById("streamDetailsHeaderCard"),
    streamDetailsHeaderPrimary: document.getElementById("streamDetailsHeaderPrimary"),
    streamDetailsHeaderSecondary: document.getElementById("streamDetailsHeaderSecondary"),
    streamDetailsHeaderBadge: document.getElementById("streamDetailsHeaderBadge"),
    streamDetailsTabButtons: Array.from(document.querySelectorAll("[data-stream-details-tab]")),
    streamDetailsTabPanels: Array.from(document.querySelectorAll("[data-stream-details-panel]")),
    streamDetailsPayloadTabButton: document.getElementById("streamDetailsPayloadTabButton"),
    streamDetailsSummaryText: document.getElementById("streamDetailsSummaryText"),
    streamDetailsPayloadStateText: document.getElementById("streamDetailsPayloadStateText"),
    streamDetailsPayloadText: document.getElementById("streamDetailsPayloadText"),
    streamDetailsProtocolStateText: document.getElementById("streamDetailsProtocolStateText"),
    streamDetailsProtocolText: document.getElementById("streamDetailsProtocolText"),
    analysisFlowMeta: document.getElementById("analysisFlowMeta"),
    analysisFlowTableBody: document.getElementById("analysisFlowTableBody"),
    analysisFlowTableViewport: document.getElementById("analysisFlowTableViewport"),
    analysisFlowRenderCapBar: document.getElementById("analysisFlowRenderCapBar"),
    analysisFlowRenderCapText: document.getElementById("analysisFlowRenderCapText"),
    analysisMeta: document.getElementById("analysisMeta"),
    analysisStateText: document.getElementById("analysisStateText"),
    analysisContent: document.getElementById("analysisContent"),
    analysisFlowSummary: document.getElementById("analysisFlowSummary"),
    analysisProtocolPanelSection: document.getElementById("analysisProtocolPanelSection"),
    analysisProtocolPanel: document.getElementById("analysisProtocolPanel"),
    analysisTrafficTotalsSection: document.getElementById("analysisTrafficTotalsSection"),
    analysisTrafficTotals: document.getElementById("analysisTrafficTotals"),
    analysisDirectionSplit: document.getElementById("analysisDirectionSplit"),
    analysisDerivedMetricsSection: document.getElementById("analysisDerivedMetricsSection"),
    analysisDerivedMetrics: document.getElementById("analysisDerivedMetrics"),
    analysisTimingSizeSection: document.getElementById("analysisTimingSizeSection"),
    analysisTimingSize: document.getElementById("analysisTimingSize"),
    analysisBurstIdleSection: document.getElementById("analysisBurstIdleSection"),
    analysisBurstIdleSummary: document.getElementById("analysisBurstIdleSummary"),
    analysisRateGraphSection: document.getElementById("analysisRateGraphSection"),
    analysisRateGraphHeaderText: document.getElementById("analysisRateGraphHeaderText"),
    analysisRateGraphContextText: document.getElementById("analysisRateGraphContextText"),
    analysisRateGraphLegend: document.getElementById("analysisRateGraphLegend"),
    analysisRateGraphStatusText: document.getElementById("analysisRateGraphStatusText"),
    analysisRateGraphSurface: document.getElementById("analysisRateGraphSurface"),
    analysisRateGraphSvg: document.getElementById("analysisRateGraphSvg"),
    analysisRateMetricModeData: document.getElementById("analysisRateMetricModeData"),
    analysisRateMetricModePackets: document.getElementById("analysisRateMetricModePackets"),
    analysisRateDirectionModeAToB: document.getElementById("analysisRateDirectionModeAToB"),
    analysisRateDirectionModeBToA: document.getElementById("analysisRateDirectionModeBToA"),
    analysisRateDirectionModeBoth: document.getElementById("analysisRateDirectionModeBoth"),
    analysisPacketSizeHistogramSection: document.getElementById("analysisPacketSizeHistogramSection"),
    analysisPacketSizeHistogramRows: document.getElementById("analysisPacketSizeHistogramRows"),
    analysisPacketSizeHistogramMax: document.getElementById("analysisPacketSizeHistogramMax"),
    analysisPacketSizeHistogramModeAll: document.getElementById("analysisPacketSizeHistogramModeAll"),
    analysisPacketSizeHistogramModeAToB: document.getElementById("analysisPacketSizeHistogramModeAToB"),
    analysisPacketSizeHistogramModeBToA: document.getElementById("analysisPacketSizeHistogramModeBToA"),
    analysisInterArrivalHistogramSection: document.getElementById("analysisInterArrivalHistogramSection"),
    analysisInterArrivalHistogramRows: document.getElementById("analysisInterArrivalHistogramRows"),
    analysisInterArrivalHistogramMax: document.getElementById("analysisInterArrivalHistogramMax"),
    analysisInterArrivalHistogramModeAll: document.getElementById("analysisInterArrivalHistogramModeAll"),
    analysisInterArrivalHistogramModeAToB: document.getElementById("analysisInterArrivalHistogramModeAToB"),
    analysisInterArrivalHistogramModeBToA: document.getElementById("analysisInterArrivalHistogramModeBToA"),
    analysisSequencePreviewSection: document.getElementById("analysisSequencePreviewSection"),
    analysisSequencePreviewBody: document.getElementById("analysisSequencePreviewBody"),
    analysisExportSequenceCsvButton: document.getElementById("analysisExportSequenceCsvButton"),
    analysisExportSequenceCsvStatusText: document.getElementById("analysisExportSequenceCsvStatusText"),
    analysisOpenInFlowsButton: document.getElementById("analysisOpenInFlowsButton"),
    metricPackets: document.getElementById("metricPackets"),
    metricFlows: document.getElementById("metricFlows"),
    metricCapturedBytes: document.getElementById("metricCapturedBytes"),
    metricOriginalBytes: document.getElementById("metricOriginalBytes"),
    transportStatsBody: document.getElementById("transportStatsBody"),
    familyStatsBody: document.getElementById("familyStatsBody"),
    protocolHintStatsBody: document.getElementById("protocolHintStatsBody"),
    protocolPathStatsModeKindOverview: document.getElementById("protocolPathStatsModeKindOverview"),
    protocolPathStatsModeIdentityTree: document.getElementById("protocolPathStatsModeIdentityTree"),
    protocolPathStatsModeTerminalPaths: document.getElementById("protocolPathStatsModeTerminalPaths"),
    protocolPathShowFlowsButton: document.getElementById("protocolPathShowFlowsButton"),
    protocolPathExpandAllButton: document.getElementById("protocolPathExpandAllButton"),
    protocolPathCollapseAllButton: document.getElementById("protocolPathCollapseAllButton"),
    protocolPathStatsPrimaryHeader: document.getElementById("protocolPathStatsPrimaryHeader"),
    protocolPathStatsViewport: document.getElementById("protocolPathStatsViewport"),
    protocolPathStatsBody: document.getElementById("protocolPathStatsBody"),
    quicStatsBody: document.getElementById("quicStatsBody"),
    tlsStatsBody: document.getElementById("tlsStatsBody"),
    topEndpointsBody: document.getElementById("topEndpointsBody"),
    topPortsBody: document.getElementById("topPortsBody"),
  };

  function formatNumber(value) {
    return Number(value ?? 0).toLocaleString("en-US");
  }

  function formatPlainInteger(value) {
    const number = Number(value ?? 0);
    if (!Number.isFinite(number)) {
      return "0";
    }
    return String(Math.trunc(number));
  }

  function formatAnalysisProtocolLine(analysis) {
    const protocol = String(analysis?.protocol_text || "").trim();
    const hint = String(analysis?.protocol_hint_display || "").trim();
    if (!protocol && !hint) {
      return "-";
    }
    if (!hint || hint === protocol) {
      return protocol || hint;
    }
    return `${protocol} (${hint})`;
  }

  function trimTrailingZeros(text) {
    return String(text).replace(/(?:\.0+|(\.\d*?[1-9])0+)$/, "$1");
  }

  function ratePointValue(point, metricMode) {
    return metricMode === "packets"
      ? Number(point?.packets_per_second ?? 0)
      : Number(point?.data_per_second ?? 0);
  }

  function trimRateGraphSeries(seriesA, seriesB) {
    const safeA = Array.isArray(seriesA) ? seriesA : [];
    const safeB = Array.isArray(seriesB) ? seriesB : [];
    let lastIndex = Math.max(safeA.length, safeB.length) - 1;
    while (lastIndex >= 0) {
      const pointA = lastIndex < safeA.length ? safeA[lastIndex] : null;
      const pointB = lastIndex < safeB.length ? safeB[lastIndex] : null;
      const zeroA = !pointA || (Number(pointA.data_per_second ?? 0) === 0 && Number(pointA.packets_per_second ?? 0) === 0);
      const zeroB = !pointB || (Number(pointB.data_per_second ?? 0) === 0 && Number(pointB.packets_per_second ?? 0) === 0);
      if (!zeroA || !zeroB) {
        break;
      }
      lastIndex -= 1;
    }
    const count = Math.max(0, lastIndex + 1);
    return {
      seriesA: safeA.slice(0, count),
      seriesB: safeB.slice(0, count),
      sampleCount: count,
    };
  }

  function rateUnitForValue(metricMode, peakValue) {
    if (metricMode === "packets") {
      return "pkt/s";
    }
    if (peakValue >= 1024 * 1024) {
      return "MB/s";
    }
    if (peakValue >= 1024) {
      return "KB/s";
    }
    return "B/s";
  }

  function scaleRateValue(value, unit) {
    if (unit === "MB/s") {
      return value / (1024 * 1024);
    }
    if (unit === "KB/s") {
      return value / 1024;
    }
    return value;
  }

  function formatRatePeakValue(value, unit) {
    const scaled = scaleRateValue(value, unit);
    const decimals = unit === "B/s" || unit === "pkt/s" ? 0 : 2;
    return `${trimTrailingZeros(scaled.toFixed(decimals))} ${unit}`;
  }

  function formatRateGraphWindowContext(windowText) {
    const normalized = String(windowText || "").trim();
    if (normalized.length === 0 || normalized === "-") {
      return "Window: -";
    }

    const match = /^([0-9]+(?:\.[0-9]+)?)\s*(ms|s)\s*\(auto\)$/i.exec(normalized);
    if (!match) {
      return `Window: ${normalized}`;
    }

    const value = Number(match[1]);
    const unit = String(match[2] || "").toLowerCase();
    if (!Number.isFinite(value) || value <= 0) {
      return "Window: -";
    }

    const windowMs = unit === "s" ? value * 1000 : value;
    if (windowMs < 1000) {
      return `Window: ${Math.max(1, Math.round(windowMs))} ms (auto)`;
    }

    return `Window: ${(windowMs / 1000).toFixed(1)} s (auto)`;
  }

  function buildSvgPolylinePoints(series, maxX, maxY) {
    const width = 1000;
    const height = 180;
    const padLeft = 14;
    const padRight = 14;
    const padTop = 10;
    const padBottom = 10;
    const graphWidth = width - padLeft - padRight;
    const graphHeight = height - padTop - padBottom;
    return series.map((point) => {
      const x = padLeft + ((Number(point.relative_time_us ?? 0) / maxX) * graphWidth);
      const y = padTop + (1 - (ratePointValue(point, state.analysisRateMetricMode) / maxY)) * graphHeight;
      return `${x},${y}`;
    }).join(" ");
  }

  function renderAnalysisRateGraph(analysis) {
    const section = elements.analysisRateGraphSection;
    const header = elements.analysisRateGraphHeaderText;
    const context = elements.analysisRateGraphContextText;
    const legend = elements.analysisRateGraphLegend;
    const status = elements.analysisRateGraphStatusText;
    const surface = elements.analysisRateGraphSurface;
    const svg = elements.analysisRateGraphSvg;

    section.style.display = "";
    header.textContent = "";
    context.textContent = "";
    status.textContent = "";
    status.className = "compact-status-text";
    legend.style.display = "none";
    surface.classList.remove("is-visible");
    svg.innerHTML = "";

    const rateAvailable = Boolean(analysis?.rate_graph_available);
    const rawSeriesA = analysis?.rate_graph_points_a_to_b || [];
    const rawSeriesB = analysis?.rate_graph_points_b_to_a || [];
    const trimmed = trimRateGraphSeries(rawSeriesA, rawSeriesB);
    const showA = state.analysisRateDirectionMode === "a_to_b" || state.analysisRateDirectionMode === "both";
    const showB = state.analysisRateDirectionMode === "b_to_a" || state.analysisRateDirectionMode === "both";
    const seriesA = showA ? trimmed.seriesA : [];
    const seriesB = showB ? trimmed.seriesB : [];
    const visibleSeries = [...seriesA, ...seriesB];

    if (!rateAvailable || visibleSeries.length === 0) {
      status.textContent = analysis?.rate_graph_status_text || "Rate graph is unavailable for this flow.";
      return;
    }

    const peakValue = visibleSeries.reduce(
      (maxValue, point) => Math.max(maxValue, ratePointValue(point, state.analysisRateMetricMode)),
      0
    );
    const unit = rateUnitForValue(state.analysisRateMetricMode, peakValue);
    const metricLabel = state.analysisRateMetricMode === "packets"
      ? "Packets rate (pkt/s)"
      : `Data rate (${unit})`;
    header.textContent = `${metricLabel} • Peak: ${formatRatePeakValue(peakValue, unit)}`;
    context.textContent = `Duration: ${analysis?.duration_text || "-"} • ${formatRateGraphWindowContext(analysis?.rate_graph_window_text)} • Samples: ${trimmed.sampleCount}`;
    legend.style.display = state.analysisRateDirectionMode === "both" ? "" : "none";

    const maxX = Math.max(
      Number(seriesA.length > 0 ? seriesA[seriesA.length - 1].relative_time_us : 0),
      Number(seriesB.length > 0 ? seriesB[seriesB.length - 1].relative_time_us : 0),
      1
    );
    const maxY = Math.max(peakValue, 1);
    const polylines = [];
    if (seriesA.length > 0) {
      polylines.push(`<polyline fill="none" stroke="#22c55e" stroke-width="2" points="${buildSvgPolylinePoints(seriesA, maxX, maxY)}"></polyline>`);
    }
    if (seriesB.length > 0) {
      polylines.push(`<polyline fill="none" stroke="#3b82f6" stroke-width="2" points="${buildSvgPolylinePoints(seriesB, maxX, maxY)}"></polyline>`);
    }
    svg.innerHTML = polylines.join("");
    surface.classList.add("is-visible");
  }

  function fileNameFromPath(path) {
    const normalized = String(path || "").trim();
    if (normalized.length === 0) {
      return "";
    }

    const parts = normalized.replaceAll("\\", "/").split("/");
    return parts.length > 0 ? parts[parts.length - 1] : normalized;
  }

  function formatByteSize(bytes) {
    const value = Math.max(0, Number(bytes || 0));
    const units = ["B", "KB", "MB", "GB", "TB"];
    let unitIndex = 0;
    let size = value;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex += 1;
    }

    const digits = size >= 100 || unitIndex === 0 ? 0 : 1;
    return `${size.toFixed(digits)} ${units[unitIndex]}`;
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function renderStatsStateRow(colspan, text, kind = "neutral") {
    const className = kind === "error" ? "table-state-row is-error" : "table-state-row";
    return `<tr class="${className}"><td colspan="${colspan}">${escapeHtml(text)}</td></tr>`;
  }

  function packetMarkerText(packet) {
    if (packet?.suspected_tcp_retransmission) {
      return "Suspected retransmission";
    }

    if (packet?.is_ip_fragmented) {
      return "Fragmented";
    }

    return "";
  }

  function isPacketCaptureTruncated(packet) {
    return Number(packet?.captured_length || 0) < Number(packet?.original_length || 0);
  }

  function loadedPacketsHaveMarkers() {
    if (state.unrecognizedPacketsSelected) {
      return false;
    }
    return state.packets.some((packet) => packetMarkerText(packet).length > 0);
  }

  function formatEndpoint(address, port) {
    const trimmedAddress = String(address || "").trim();
    const numericPort = Number(port);
    const hasPort = Number.isFinite(numericPort) && numericPort > 0;

    if (!trimmedAddress) {
      return "";
    }

    const displayAddress = hasPort && trimmedAddress.includes(":")
      ? `[${trimmedAddress}]`
      : trimmedAddress;

    return hasPort
      ? `${displayAddress} : ${numericPort}`
      : displayAddress;
  }

  function formatEndpointParts(address, port) {
    const trimmedAddress = String(address || "").trim();
    const numericPort = Number(port);
    const hasPort = Number.isFinite(numericPort) && numericPort > 0;

    if (!trimmedAddress) {
      return {
        address: "",
        hasPort: false,
        port: "",
      };
    }

    const displayAddress = hasPort && trimmedAddress.includes(":")
      ? `[${trimmedAddress}]`
      : trimmedAddress;

    return {
      address: displayAddress,
      hasPort,
      port: hasPort ? String(numericPort) : "",
    };
  }

  function renderEndpointCell(address, port) {
    const parts = formatEndpointParts(address, port);
    return `
      <span class="endpoint-cell-inner">
        <span class="endpoint-address" title="${escapeHtml(parts.address)}">${escapeHtml(parts.address)}</span>
        <span class="endpoint-separator${parts.hasPort ? "" : " is-hidden"}">:</span>
        <span class="endpoint-port${parts.hasPort ? "" : " is-hidden"}">${escapeHtml(parts.port)}</span>
      </span>
    `;
  }

  function renderProtocolPathCell(flow) {
    const protocolPathId = Number(flow?.protocol_path_id || 0);
    const presentation = protocolPathId > 0
      ? state.protocolPathPresentationsById?.get(protocolPathId) || null
      : null;
    const fullText = String(presentation?.path_text || "").trim();
    const compactText = String(presentation?.compact_text || "").trim();
    const badges = Array.isArray(presentation?.badges) ? presentation.badges : [];

    if (badges.length > 0) {
      const chips = badges.map((badge) => {
        const shortLabel = String(badge?.short_label || "").trim();
        const tooltip = String(badge?.tooltip || "").trim();
        const backgroundColor = String(badge?.background_color || "").trim() || "#e2e8f0";
        const borderColor = String(badge?.border_color || "").trim() || "#cbd5e1";
        const textColor = String(badge?.text_color || "").trim() || "#334155";
        const colorKey = String(badge?.color_key || "").trim();
        const className = colorKey ? `flow-path-badge flow-path-badge-${escapeHtml(colorKey)}` : "flow-path-badge";

        return `
          <span
            class="${className}"
            style="background:${escapeHtml(backgroundColor)};border-color:${escapeHtml(borderColor)};color:${escapeHtml(textColor)}"
            title="${escapeHtml(tooltip || fullText || shortLabel)}"
          >${escapeHtml(shortLabel)}</span>
        `;
      }).join("");

      return `<span class="flow-path-cell-inner" title="${escapeHtml(fullText || compactText)}">${chips}</span>`;
    }

    if (!compactText) {
      return "";
    }

    return `<span class="flow-path-compact-text" title="${escapeHtml(fullText || compactText)}">${escapeHtml(compactText)}</span>`;
  }

  function unrecognizedPacketCount() {
    return Number(state.overview?.unrecognized_packet_count || 0);
  }

  function currentProtocolPathMode() {
    return Number(state.protocolPathStatsMode ?? state.overview?.protocol_path_statistics_default_mode ?? 0);
  }

  function currentProtocolPathStatsRows() {
    const overview = state.overview;
    const protocolPathMode = currentProtocolPathMode();
    if (protocolPathMode === 1) {
      return Array.isArray(overview?.protocol_path_statistics_identity_tree) ? overview.protocol_path_statistics_identity_tree : [];
    }
    if (protocolPathMode === 2) {
      return Array.isArray(overview?.protocol_path_statistics_terminal_paths) ? overview.protocol_path_statistics_terminal_paths : [];
    }
    return Array.isArray(overview?.protocol_path_statistics) ? overview.protocol_path_statistics : [];
  }

  function protocolPathModeLabel(mode) {
    const normalizedMode = Number(mode);
    if (normalizedMode === 1) {
      return "Identity tree";
    }
    if (normalizedMode === 2) {
      return "Terminal paths";
    }
    return "Kind overview";
  }

  function protocolPathRowFilterLabel(row, mode) {
    const pathText = String(row?.path_text || "").trim();
    const layerText = String(row?.layer_text || "").trim();
    const suffix = pathText.length > 0 ? pathText : layerText;
    return suffix.length > 0
      ? `${protocolPathModeLabel(mode)} / ${suffix}`
      : protocolPathModeLabel(mode);
  }

  function syncSelectedProtocolPathNode(rows = currentProtocolPathStatsRows(), mode = currentProtocolPathMode()) {
    const currentSelection = state.selectedProtocolPathNode;
    if (!currentSelection || Number(currentSelection.mode) !== Number(mode)) {
      state.selectedProtocolPathNode = null;
      return null;
    }

    const matchingRow = rows.find((row) => Number(row?.node_id) === Number(currentSelection.nodeId)) || null;
    if (!matchingRow) {
      state.selectedProtocolPathNode = null;
      return null;
    }

    state.selectedProtocolPathNode = {
      mode: Number(mode),
      nodeId: Number(matchingRow.node_id),
      label: protocolPathRowFilterLabel(matchingRow, mode),
      flowCount: Number(matchingRow.flow_count ?? 0),
    };
    return state.selectedProtocolPathNode;
  }

  function hasActiveProtocolPathFilter() {
    return state.activeProtocolPathFilter != null && state.activeProtocolPathFilter.flowIndexSet instanceof Set;
  }

  function hasActiveFlowFilters() {
    return state.flowFilterText.trim().length > 0 || hasActiveProtocolPathFilter();
  }

  function clearSelectedFlowArtifacts() {
    state.selectedFlowIndex = null;
    clearPackets();
    clearStream();
    clearAnalysis();
  }

  function ensureSelectedFlowVisible(reasonText = "") {
    if (state.selectedFlowIndex == null) {
      return;
    }

    const selectedFlowVisible = filteredFlows().some((flow) => flow.flow_index === state.selectedFlowIndex);
    if (!selectedFlowVisible) {
      clearSelectedFlowArtifacts();
      if (reasonText.length > 0) {
        setStatus(reasonText, "neutral");
      }
    }
  }

  function formatPercent(part, total) {
    const safePart = Number(part ?? 0);
    const safeTotal = Number(total ?? 0);
    if (safeTotal <= 0 || safePart <= 0) {
      return "0%";
    }

    const value = (safePart * 100) / safeTotal;
    if (value < 0.01) {
      return "<0.01%";
    }
    if (value < 1) {
      return `${value.toFixed(2)}%`;
    }
    return `${Math.round(value)}%`;
  }

  function formatFlowPercentAndCount(part, total) {
    return `${formatPercent(part, total)} (${formatNumber(part)} flows)`;
  }

  function protocolHintFilterValue(protocolLabel) {
    const normalized = String(protocolLabel || "").trim().toLowerCase();
    const mapping = {
      "http": "http",
      "tls": "tls",
      "possible tls": "possible tls",
      "dns": "dns",
      "quic": "quic",
      "possible quic": "possible quic",
      "ssh": "ssh",
      "stun": "stun",
      "bittorrent": "bittorrent",
      "mail protocols": "mail_protocols",
      "dhcp": "dhcp",
      "mdns": "mdns",
      "unknown": "unknown",
    };

    return mapping[normalized] || "";
  }

  function setStatus(text, kind = "neutral") {
    state.statusText = text || "";
    state.statusKind = kind;
  }

  function shortenPathForMemoryLog(path) {
    const normalizedPath = String(path || "").trim();
    if (normalizedPath.length === 0) {
      return "";
    }

    const pathParts = normalizedPath.split(/[\\/]+/).filter((part) => part.length > 0);
    return pathParts.length > 0 ? pathParts[pathParts.length - 1] : normalizedPath;
  }

  function currentOpenPathForDiagnostics(pathOverride = null) {
    return String(pathOverride ?? elements.capturePath?.value ?? "").trim();
  }

  function waitForNextPaint() {
    return new Promise((resolve) => {
      window.requestAnimationFrame(() => resolve());
    });
  }

  function resetFlowVirtualizationState(resetScroll = true) {
    state.flowVirtualWindowStart = 0;
    state.flowVirtualWindowEnd = 0;
    state.flowVirtualizationActive = false;
    if (resetScroll && elements.flowTableViewport) {
      elements.flowTableViewport.scrollTop = 0;
    }
  }

  function resetAnalysisFlowVirtualizationState(resetScroll = true) {
    state.analysisFlowVirtualWindowStart = 0;
    state.analysisFlowVirtualWindowEnd = 0;
    state.analysisFlowVirtualizationActive = false;
    if (resetScroll && elements.analysisFlowTableViewport) {
      elements.analysisFlowTableViewport.scrollTop = 0;
    }
  }

  function setWorkspaceCssVariable(name, value) {
    document.documentElement.style.setProperty(name, value);
  }

  function applyWorkspaceSplitSizes() {
    setWorkspaceCssVariable("--flows-top-size", state.flowsTopSizePx != null ? `${state.flowsTopSizePx}px` : "52%");
    setWorkspaceCssVariable(
      "--flows-bottom-left-size",
      state.flowsBottomLeftSizePx != null ? `${state.flowsBottomLeftSizePx}px` : "minmax(420px, 1.12fr)"
    );
    setWorkspaceCssVariable(
      "--analysis-left-size",
      state.analysisLeftSizePx != null ? `${state.analysisLeftSizePx}px` : "minmax(300px, 0.85fr)"
    );
  }

  function isCompactWorkspaceMode() {
    return window.matchMedia("(max-width: 1180px)").matches;
  }

  function beginSplitterDrag(config, event) {
    if (isCompactWorkspaceMode()) {
      return;
    }

    event.preventDefault();
    state.splitterDrag = config;
    config.splitter.classList.add("is-active");
    document.body.classList.add("is-resizing");
    if (config.axis === "x") {
      document.body.classList.add("is-resizing-vertical");
    }
  }

  function updateSplitterDrag(event) {
    const drag = state.splitterDrag;
    if (!drag || isCompactWorkspaceMode()) {
      return;
    }

    const bounds = drag.container.getBoundingClientRect();
    if (drag.axis === "y") {
      const rawSize = event.clientY - bounds.top;
      drag.onChange(Math.min(Math.max(rawSize, drag.min), bounds.height - drag.maxTrailing));
      scheduleFlowViewportRender();
    } else {
      const rawSize = event.clientX - bounds.left;
      drag.onChange(Math.min(Math.max(rawSize, drag.min), bounds.width - drag.maxTrailing));
      if (drag.rerenderAnalysis) {
        scheduleAnalysisFlowViewportRender();
      }
    }
  }

  function endSplitterDrag() {
    if (!state.splitterDrag) {
      return;
    }

    state.splitterDrag.splitter.classList.remove("is-active");
    state.splitterDrag = null;
    document.body.classList.remove("is-resizing", "is-resizing-vertical");
  }

  function initializeWorkspaceSplitters() {
    applyWorkspaceSplitSizes();
    const keyboardStep = 24;

    const bindKeyboardResize = (splitter, axis, adjust) => {
      splitter?.addEventListener("keydown", (event) => {
        if (isCompactWorkspaceMode()) {
          return;
        }

        const isDecrease = (axis === "y" && event.key === "ArrowUp") || (axis === "x" && event.key === "ArrowLeft");
        const isIncrease = (axis === "y" && event.key === "ArrowDown") || (axis === "x" && event.key === "ArrowRight");
        if (!isDecrease && !isIncrease) {
          return;
        }

        event.preventDefault();
        adjust(isIncrease ? keyboardStep : -keyboardStep);
      });
    };

    elements.flowsVerticalSplitter?.addEventListener("pointerdown", (event) => {
      if (!elements.flowsLayout) {
        return;
      }
      beginSplitterDrag({
        axis: "y",
        splitter: elements.flowsVerticalSplitter,
        container: elements.flowsLayout,
        min: 260,
        maxTrailing: 180 + 10,
        onChange: (sizePx) => {
          state.flowsTopSizePx = sizePx;
          applyWorkspaceSplitSizes();
        },
      }, event);
    });
    bindKeyboardResize(elements.flowsVerticalSplitter, "y", (delta) => {
      const bounds = elements.flowsLayout?.getBoundingClientRect();
      if (!bounds) {
        return;
      }
      const next = Math.min(Math.max((state.flowsTopSizePx ?? (bounds.height * 0.52)) + delta, 260), bounds.height - 190);
      state.flowsTopSizePx = next;
      applyWorkspaceSplitSizes();
      scheduleFlowViewportRender();
    });

    elements.flowsHorizontalSplitter?.addEventListener("pointerdown", (event) => {
      if (!elements.flowsBottom) {
        return;
      }
      beginSplitterDrag({
        axis: "x",
        splitter: elements.flowsHorizontalSplitter,
        container: elements.flowsBottom,
        min: 380,
        maxTrailing: 440 + 10,
        onChange: (sizePx) => {
          state.flowsBottomLeftSizePx = sizePx;
          applyWorkspaceSplitSizes();
        },
      }, event);
    });
    bindKeyboardResize(elements.flowsHorizontalSplitter, "x", (delta) => {
      const bounds = elements.flowsBottom?.getBoundingClientRect();
      if (!bounds) {
        return;
      }
      const next = Math.min(Math.max((state.flowsBottomLeftSizePx ?? (bounds.width * 0.48)) + delta, 380), bounds.width - 450);
      state.flowsBottomLeftSizePx = next;
      applyWorkspaceSplitSizes();
    });

    elements.analysisHorizontalSplitter?.addEventListener("pointerdown", (event) => {
      if (!elements.analysisLayout) {
        return;
      }
      beginSplitterDrag({
        axis: "x",
        splitter: elements.analysisHorizontalSplitter,
        container: elements.analysisLayout,
        min: 300,
        maxTrailing: 520 + 10,
        rerenderAnalysis: true,
        onChange: (sizePx) => {
          state.analysisLeftSizePx = sizePx;
          applyWorkspaceSplitSizes();
        },
      }, event);
    });
    bindKeyboardResize(elements.analysisHorizontalSplitter, "x", (delta) => {
      const bounds = elements.analysisLayout?.getBoundingClientRect();
      if (!bounds) {
        return;
      }
      const next = Math.min(Math.max((state.analysisLeftSizePx ?? (bounds.width * 0.36)) + delta, 300), bounds.width - 530);
      state.analysisLeftSizePx = next;
      applyWorkspaceSplitSizes();
      scheduleAnalysisFlowViewportRender();
    });

    window.addEventListener("pointermove", updateSplitterDrag);
    window.addEventListener("pointerup", endSplitterDrag);
    window.addEventListener("pointercancel", endSplitterDrag);
    window.addEventListener("resize", () => {
      applyWorkspaceSplitSizes();
      scheduleFlowViewportRender();
      scheduleAnalysisFlowViewportRender();
    });
  }

  function clearRenderedTablesAndPanels() {
    const clearHtml = (element) => {
      if (element) {
        element.innerHTML = "";
      }
    };
    const clearText = (element) => {
      if (element) {
        element.textContent = "";
      }
    };

    clearHtml(elements.flowTableBody);
    clearHtml(elements.packetTableBody);
    clearHtml(elements.streamTableBody);
    clearHtml(elements.analysisFlowTableBody);
    clearHtml(elements.analysisSequencePreviewBody);
    clearHtml(elements.transportStatsBody);
    clearHtml(elements.familyStatsBody);
    clearHtml(elements.protocolHintStatsBody);
    clearHtml(elements.protocolPathStatsBody);
    clearHtml(elements.quicStatsBody);
    clearHtml(elements.tlsStatsBody);
    clearHtml(elements.topEndpointsBody);
    clearHtml(elements.topPortsBody);
    clearHtml(elements.packetDetailsSummary);
    clearHtml(elements.streamDetailsSummary);
    clearHtml(elements.analysisFlowSummary);
    clearHtml(elements.analysisProtocolPanel);
    clearHtml(elements.analysisTrafficTotals);
    clearHtml(elements.analysisDirectionSplit);
    clearHtml(elements.analysisDerivedMetrics);
    clearHtml(elements.analysisTimingSize);
    clearHtml(elements.analysisBurstIdleSummary);
    clearHtml(elements.analysisPacketSizeHistogramRows);
    clearHtml(elements.analysisInterArrivalHistogramRows);
    clearText(elements.packetDetailsRawText);
    clearText(elements.packetDetailsPayloadText);
    clearText(elements.packetDetailsProtocolText);
    clearText(elements.packetDetailsRawStateText);
    clearText(elements.packetDetailsPayloadStateText);
    clearText(elements.packetDetailsProtocolStateText);
    clearText(elements.packetDetailsStateText);
    clearText(elements.streamDetailsStateText);
    clearText(elements.streamDetailsSourcePacketsText);
    clearText(elements.streamDetailsSourcePacketIndicesText);
    clearText(elements.streamDetailsConstrictedNotesText);
    clearText(elements.analysisPacketSizeHistogramMax);
    clearText(elements.analysisInterArrivalHistogramMax);
    clearText(elements.flowRenderCapText);
    clearText(elements.analysisFlowRenderCapText);
    elements.flowRenderCapBar?.classList.remove("is-visible");
    elements.analysisFlowRenderCapBar?.classList.remove("is-visible");
  }

  function collectMemorySnapshot(phase, pathOverride = null) {
    const openPath = currentOpenPathForDiagnostics(pathOverride);
    const filteredFlowCount = filteredFlows().length;
    const totalAnalysisFlowCount = state.flows.length;
    const analysisSequenceRows = Array.isArray(state.analysis?.sequence_preview_rows)
      ? state.analysis.sequence_preview_rows.length
      : 0;
    const packetSizeHistogramRows = Array.isArray(state.analysis?.packet_size_histogram_rows)
      ? state.analysis.packet_size_histogram_rows.length
      : 0;
    const interArrivalHistogramRows = Array.isArray(state.analysis?.inter_arrival_histogram_rows)
      ? state.analysis.inter_arrival_histogram_rows.length
      : 0;

    return {
      phase,
      open_path: openPath,
      open_path_short: shortenPathForMemoryLog(openPath),
      open_state: state.openState,
      active_tab: state.activeTab,
      flow_view_tab: state.flowViewTab,
      flow_count: state.flows.length,
      visible_flow_count: filteredFlowCount,
      total_analysis_flow_count: totalAnalysisFlowCount,
      checked_flow_count: checkedFlowCount(),
      packet_count: state.packets.length,
      stream_item_count: state.streamItems.length,
      analysis_sequence_row_count: analysisSequenceRows,
      packet_size_histogram_row_count: packetSizeHistogramRows,
      inter_arrival_histogram_row_count: interArrivalHistogramRows,
      rendered_flow_dom_row_count: elements.flowTableBody?.querySelectorAll("tr.flow-row").length ?? 0,
      rendered_packet_dom_row_count: elements.packetTableBody?.children.length ?? 0,
      rendered_stream_dom_row_count: elements.streamTableBody?.children.length ?? 0,
      rendered_analysis_flow_dom_row_count: elements.analysisFlowTableBody?.querySelectorAll("tr.analysis-flow-row").length ?? 0,
      rendered_analysis_sequence_dom_row_count: elements.analysisSequencePreviewBody?.children.length ?? 0,
      rendered_transport_dom_row_count: elements.transportStatsBody?.children.length ?? 0,
      rendered_protocol_hint_dom_row_count: elements.protocolHintStatsBody?.children.length ?? 0,
      rendered_top_endpoints_dom_row_count: elements.topEndpointsBody?.children.length ?? 0,
      rendered_top_ports_dom_row_count: elements.topPortsBody?.children.length ?? 0,
      flow_virtual_window_start: state.flowVirtualWindowStart,
      flow_virtual_window_end: state.flowVirtualWindowEnd,
      analysis_flow_virtual_window_start: state.analysisFlowVirtualWindowStart,
      analysis_flow_virtual_window_end: state.analysisFlowVirtualWindowEnd,
      flow_virtualization_active: state.flowVirtualizationActive,
      analysis_flow_virtualization_active: state.analysisFlowVirtualizationActive,
      packet_request_offset: state.diagnosticsPacketRequestOffset,
      packet_request_limit: state.diagnosticsPacketRequestLimit,
      packet_request_row_count: state.diagnosticsPacketReturnedRowCount,
      packet_request_total_count: state.diagnosticsPacketReturnedTotalCount,
      overview_loaded: state.overview != null,
      packet_details_loaded: state.packetDetails != null,
      analysis_loaded: state.analysis != null,
      selected_flow_index: state.selectedFlowIndex ?? -1,
      selected_packet_index: state.selectedPacketIndex ?? -1,
    };
  }

  async function logMemoryPhase(phase, pathOverride = null) {
    if (!state.memoryDiagnosticsEnabled || typeof invoke !== "function") {
      return;
    }

    try {
      await invoke("memory_diagnostics_log", collectMemorySnapshot(phase, pathOverride));
    } catch (error) {
      console.warn(`Failed to write memory diagnostics for phase '${phase}'.`, error);
    }
  }

  async function initializeMemoryDiagnostics() {
    if (typeof invoke !== "function") {
      return;
    }

    try {
      state.memoryDiagnosticsEnabled = Boolean(await invoke("memory_diagnostics_enabled"));
      if (state.memoryDiagnosticsEnabled) {
        await logMemoryPhase("app_started");
      }
    } catch (error) {
      state.memoryDiagnosticsEnabled = false;
      console.warn("Failed to initialize Tauri memory diagnostics.", error);
    }
  }

  function clearSettingsStatus() {
    state.settingsStatusText = "";
    state.settingsStatusKind = "neutral";
  }

  function clearProtocolPathLegendStatus() {
    state.protocolPathLegendStatusText = "";
    state.protocolPathLegendStatusKind = "neutral";
  }

  function flowTableColumnCount() {
    return state.showProtocolPathColumn ? 12 : 11;
  }

  function sourceAvailabilityOrDefault(sourceAvailability) {
    return {
      has_source_capture: Boolean(sourceAvailability?.has_source_capture),
      source_capture_accessible: Boolean(sourceAvailability?.source_capture_accessible),
      opened_from_index: Boolean(sourceAvailability?.opened_from_index),
      partial_open: Boolean(sourceAvailability?.partial_open),
      byte_backed_inspection_available: Boolean(sourceAvailability?.byte_backed_inspection_available),
      active_source_capture_path: String(sourceAvailability?.active_source_capture_path || ""),
      expected_source_capture_path: String(sourceAvailability?.expected_source_capture_path || ""),
    };
  }

  function currentSourceAvailability() {
    return sourceAvailabilityOrDefault(state.sourceAvailability);
  }

  function canAttachSourceCapture() {
    return state.openState === "opened" && !currentSourceAvailability().byte_backed_inspection_available;
  }

  function canSaveIndex() {
    const availability = currentSourceAvailability();
    return state.openState === "opened"
      && !state.saveIndexInProgress
      && !state.exportCurrentFlowInProgress
      && !state.exportSelectedFlowsInProgress
      && !state.exportUnselectedFlowsInProgress
      && !state.smartExportInProgress
      && !availability.partial_open
      && availability.byte_backed_inspection_available;
  }

  function canExportCurrentFlow() {
    const availability = currentSourceAvailability();
    return state.openState === "opened"
      && state.selectedFlowIndex != null
      && availability.byte_backed_inspection_available
      && !state.attachSourceInProgress
      && !state.saveIndexInProgress
      && !state.exportCurrentFlowInProgress
      && !state.exportSelectedFlowsInProgress
      && !state.exportUnselectedFlowsInProgress
      && !state.smartExportInProgress;
  }

  function canExportSelectedFlows() {
    const availability = currentSourceAvailability();
    return state.openState === "opened"
      && checkedFlowCount() > 0
      && availability.byte_backed_inspection_available
      && !state.attachSourceInProgress
      && !state.saveIndexInProgress
      && !state.exportCurrentFlowInProgress
      && !state.exportSelectedFlowsInProgress
      && !state.exportUnselectedFlowsInProgress
      && !state.smartExportInProgress;
  }

  function canExportUnselectedFlows() {
    const availability = currentSourceAvailability();
    return state.openState === "opened"
      && uncheckedFlowCount() > 0
      && availability.byte_backed_inspection_available
      && !state.attachSourceInProgress
      && !state.saveIndexInProgress
      && !state.exportCurrentFlowInProgress
      && !state.exportSelectedFlowsInProgress
      && !state.exportUnselectedFlowsInProgress
      && !state.smartExportInProgress;
  }

  function canSmartExport() {
    const availability = currentSourceAvailability();
    return state.openState === "opened"
      && availability.byte_backed_inspection_available
      && !state.attachSourceInProgress
      && !state.saveIndexInProgress
      && !state.exportCurrentFlowInProgress
      && !state.exportSelectedFlowsInProgress
      && !state.exportUnselectedFlowsInProgress
      && !state.smartExportInProgress;
  }

  function packetDetailsSourceAvailability(details) {
    return sourceAvailabilityOrDefault(details?.source_availability || state.sourceAvailability);
  }

  function streamSourceAvailability(streamResult) {
    return sourceAvailabilityOrDefault(streamResult?.source_availability || state.sourceAvailability);
  }

  function sourceWarningBannerText() {
    return "Original source capture unavailable. Metadata views remain available, but raw packet bytes, stream reconstruction, and flow export require the original capture file.";
  }

  function flowDisplayNumber(flow) {
    return Number(flow?.flow_index ?? 0) + 1;
  }

  function formatProtocolHint(flow) {
    return String(flow?.protocol_hint_display || flow?.protocol_hint || "");
  }

  function formatFlowFamily(flow) {
    return flow?.family === "ipv6" ? "IPv6" : "IPv4";
  }

  function isDescendingDefaultSortKey(sortKey) {
    return sortKey === "packets" || sortKey === "bytes" || sortKey === "frag";
  }

  function normalizeSortText(value) {
    return String(value || "").trim().toLowerCase();
  }

  function compareFlowValues(leftValue, rightValue, direction) {
    const multiplier = direction === "desc" ? -1 : 1;

    if (typeof leftValue === "number" && typeof rightValue === "number") {
      return (leftValue - rightValue) * multiplier;
    }

    return normalizeSortText(leftValue).localeCompare(normalizeSortText(rightValue)) * multiplier;
  }

  function getFlowSortValue(flow, sortKey) {
    switch (sortKey) {
      case "index":
        return Number(flow?.flow_index ?? 0);
      case "family":
        return formatFlowFamily(flow);
      case "protocol":
        return String(flow?.protocol_text || "");
      case "hint":
        return formatProtocolHint(flow);
      case "service":
        return String(flow?.service_hint || "");
      case "frag":
        return Number(flow?.fragmented_packet_count ?? 0);
      case "endpoint_a":
        return formatEndpoint(flow?.address_a, flow?.port_a) || String(flow?.endpoint_a || "");
      case "endpoint_b":
        return formatEndpoint(flow?.address_b, flow?.port_b) || String(flow?.endpoint_b || "");
      case "packets":
        return Number(flow?.packet_count ?? 0);
      case "bytes":
        return Number(flow?.total_bytes ?? 0);
      default:
        return Number(flow?.flow_index ?? 0);
    }
  }

  function formatFlowFragmentMarker(flow) {
    if (!flow?.has_fragmented_packets) {
      return "";
    }

    return flow.fragmented_packet_count > 0
      ? `Frag (${formatNumber(flow.fragmented_packet_count)})`
      : "Frag";
  }

  function packetDirectionClassSuffix(directionText) {
    if (directionText === "A→B") {
      return "is-a-to-b";
    }
    if (directionText === "B→A") {
      return "is-b-to-a";
    }
    return "";
  }

  function renderPacketDirectionChip(directionText) {
    const text = String(directionText || "").trim();
    if (text.length === 0) {
      return "";
    }

    const suffix = packetDirectionClassSuffix(text);
    const className = suffix.length > 0 ? `packet-direction-chip ${suffix}` : "packet-direction-chip";
    return `<span class="${className}">${escapeHtml(text)}</span>`;
  }

  function packetFlagsTone(flagsText) {
    const text = String(flagsText || "").trim().toUpperCase();
    if (text.length === 0) {
      return "";
    }
    if (text.includes("RST") || text === "R") {
      return "is-rst";
    }
    if (text.includes("SYN") || text === "S" || text === "SA") {
      return "is-syn";
    }
    if (text.includes("FIN") || text === "F") {
      return "is-fin";
    }
    return "";
  }

  function renderPacketFlagsChip(flagsText) {
    const text = String(flagsText || "").trim();
    if (text.length === 0) {
      return "";
    }

    const tone = packetFlagsTone(text);
    const className = tone.length > 0 ? `packet-flags-chip ${tone}` : "packet-flags-chip";
    return `<span class="${className}">${escapeHtml(text)}</span>`;
  }

  function formatStreamSourcePacketRefs(item) {
    const packetIndices = Array.isArray(item?.source_packet_indices) ? item.source_packet_indices : [];
    if (packetIndices.length === 0) {
      return "";
    }

    return packetIndices.map((packetIndex) => `#${packetIndex}`).join(", ");
  }

  function compactStreamSourcePacketsText(sourcePacketsText) {
    const text = String(sourcePacketsText || "").trim();
    if (!text.startsWith("packets ")) {
      return text;
    }

    const packetRefs = text.slice(8).split(",");
    if (packetRefs.length <= 3 && text.length <= 26) {
      return text;
    }

    return `packets ${packetRefs.slice(0, 3).join(",")}…`;
  }

  function formatStreamConstrictedNotes(item) {
    const contributionNotes = Array.isArray(item?.constricted_contribution_notes)
      ? item.constricted_contribution_notes.filter((note) => String(note || "").trim().length > 0)
      : [];
    const packetNotes = Array.isArray(item?.constricted_packet_notes)
      ? item.constricted_packet_notes.filter((note) => String(note || "").trim().length > 0)
      : [];

    return [...contributionNotes, ...packetNotes];
  }

  function setWiresharkFilterStatus(text, kind = "neutral") {
    state.wiresharkFilterStatusText = text || "";
    state.wiresharkFilterStatusKind = kind;
  }

  function checkedFlowCount() {
    return state.checkedFlowIndices.size;
  }

  function uncheckedFlowCount() {
    return Math.max(0, state.flows.length - checkedFlowCount());
  }

  function getUncheckedFlowIndices() {
    return state.flows
      .filter((flow) => !state.checkedFlowIndices.has(flow.flow_index))
      .map((flow) => flow.flow_index)
      .sort((left, right) => left - right);
  }

  function getAllFlowIndices() {
    return state.flows
      .map((flow) => flow.flow_index)
      .sort((left, right) => left - right);
  }

  function setSmartExportStatus(text, kind = "neutral") {
    state.smartExportStatusText = text || "";
    state.smartExportStatusKind = kind;
  }

  function clearSmartExportStatus() {
    setSmartExportStatus("", "neutral");
  }

  function selectedSmartExportFlowScope() {
    if (elements.smartExportScopeMatchingFilter?.checked) {
      return "matching_filter";
    }
    if (elements.smartExportScopeSelected?.checked) {
      return "selected";
    }
    if (elements.smartExportScopeNotMatchingFilter?.checked) {
      return "not_matching_filter";
    }
    if (elements.smartExportScopeUnselected?.checked) {
      return "unselected";
    }
    if (elements.smartExportScopeUnrecognized?.checked) {
      return "unrecognized";
    }
    if (elements.smartExportScopeAll?.checked) {
      return "all";
    }
    return "current";
  }

  function smartExportFilterTargetEnabled() {
    return state.flowFilterText.trim().length > 0;
  }

  function smartExportUnrecognizedTargetEnabled() {
    return unrecognizedPacketCount() > 0;
  }

  function selectedSmartExportBaseMode() {
    if (elements.smartExportBaseFirstNPackets?.checked) {
      return "first_n_packets";
    }
    if (elements.smartExportBaseFirstMOriginalBytes?.checked) {
      return "first_m_original_bytes";
    }
    return "all_packets";
  }

  function selectedSmartExportOutputMode() {
    return elements.smartExportOutputSeparateFiles?.checked ? "separate_files" : "single_file";
  }

  function smartExportExtrasEnabled() {
    return selectedSmartExportBaseMode() !== "all_packets";
  }

  function parsePositiveIntegerText(text) {
    const trimmed = String(text || "").trim();
    if (!/^\d+$/.test(trimmed)) {
      return null;
    }

    const value = Number(trimmed);
    if (!Number.isSafeInteger(value) || value <= 0) {
      return null;
    }

    return value;
  }

  function getSmartExportFlowIndices(scope) {
    switch (scope) {
      case "current":
        return state.selectedFlowIndex != null ? [state.selectedFlowIndex] : [];
      case "matching_filter":
        return getVisibleFlows().map((flow) => flow.flow_index);
      case "selected":
        return Array.from(state.checkedFlowIndices).sort((left, right) => left - right);
      case "not_matching_filter": {
        const matchingFlowIndexSet = new Set(filteredFlows().map((flow) => flow.flow_index));
        return getSortedFlows(state.flows.filter((flow) => !matchingFlowIndexSet.has(flow.flow_index)))
          .map((flow) => flow.flow_index);
      }
      case "unselected":
        return getUncheckedFlowIndices();
      case "all":
        return getAllFlowIndices();
      default:
        return [];
    }
  }

  function clearCurrentFlowExportStatusIfPresent() {
    if (
      state.statusText === "Flow exported successfully."
      || state.statusText === "Failed to export selected flow."
      || state.statusText.startsWith("Failed to export selected flow:")
    ) {
      setStatus("", "neutral");
    }
  }

  function clearSmartExportMainStatusIfPresent() {
    if (
      state.statusText === "Smart export completed successfully."
      || state.statusText === "Failed to smart-export flows."
      || state.statusText === "Failed to smart-export unrecognized packets."
      || state.statusText.startsWith("Failed to smart-export flows:")
      || state.statusText.startsWith("Failed to smart-export unrecognized packets:")
    ) {
      setStatus("", "neutral");
    }
  }

  function applyFlowFilterState(filterText) {
    const nextFilterText = String(filterText || "");
    const filterChanged = state.flowFilterText !== nextFilterText;
    state.flowFilterText = nextFilterText;
    if (filterChanged) {
      resetFlowVirtualizationState();
      resetAnalysisFlowVirtualizationState();
    }
    setWiresharkFilterStatus("", "neutral");
    ensureSelectedFlowVisible("Selected flow was cleared because it no longer matches the current filter.");
  }

  function applyFlowFilterFromStatistics(filterText, sourceLabel) {
    state.activeTab = "flows";
    applyFlowFilterState(filterText);
    setStatus(`Filtered flows by ${sourceLabel}.`, "success");
    render();
  }

  function clearProtocolPathFlowFilter(statusText = "Cleared protocol path filter.") {
    if (!hasActiveProtocolPathFilter()) {
      return;
    }

    state.protocolPathFilterRequestToken += 1;
    state.activeProtocolPathFilter = null;
    ensureSelectedFlowVisible("Selected flow was cleared because it no longer matches the current filter.");
    setStatus(statusText, "neutral");
  }

  async function showSelectedProtocolPathFlows() {
    const selection = syncSelectedProtocolPathNode();
    if (!selection || Number(selection.flowCount) <= 0) {
      return;
    }

    const requestToken = ++state.protocolPathFilterRequestToken;
    try {
      const flowIndices = await invoke("get_protocol_path_summary_flow_indices", {
        mode: Number(selection.mode),
        node_id: Number(selection.nodeId),
      });

      if (requestToken !== state.protocolPathFilterRequestToken) {
        return;
      }

      const normalizedFlowIndices = Array.isArray(flowIndices)
        ? flowIndices
          .map((value) => Number(value))
          .filter((value) => Number.isInteger(value) && value >= 0)
        : [];

      state.activeProtocolPathFilter = {
        mode: Number(selection.mode),
        nodeId: Number(selection.nodeId),
        label: String(selection.label || "").trim(),
        flowIndices: normalizedFlowIndices,
        flowIndexSet: new Set(normalizedFlowIndices),
      };
      state.activeTab = "flows";
      ensureSelectedFlowVisible("Selected flow was cleared because it no longer matches the current filter.");
      setStatus(`Applied protocol path filter: ${selection.label}.`, "success");
      render();
    } catch (error) {
      if (requestToken !== state.protocolPathFilterRequestToken) {
        return;
      }
      setStatus(`Failed to filter flows by protocol path: ${String(error)}`, "error");
      render();
    }
  }

  function clearOverview() {
    state.overview = null;
    state.protocolPathStatsVisibleRows = [];
    state.selectedProtocolPathNode = null;
    state.activeProtocolPathFilter = null;
    state.protocolPathFilterRequestToken += 1;
    state.protocolPathExpandedNodeIds.clear();
  }

  function isProtocolPathTreeMode(mode) {
    return Number(mode) !== 2;
  }

  function pruneProtocolPathExpandedNodeIds(rows, mode) {
    if (!isProtocolPathTreeMode(mode)) {
      state.protocolPathExpandedNodeIds.clear();
      return;
    }

    const validExpandableIds = new Set();
    for (const row of rows) {
      if (row?.has_children) {
        validExpandableIds.add(Number(row.node_id));
      }
    }

    for (const nodeId of Array.from(state.protocolPathExpandedNodeIds)) {
      if (!validExpandableIds.has(Number(nodeId))) {
        state.protocolPathExpandedNodeIds.delete(nodeId);
      }
    }
  }

  function buildVisibleProtocolPathRows(rows, mode) {
    if (!isProtocolPathTreeMode(mode)) {
      return rows;
    }

    const visibleRows = [];
    const visibleByNodeId = new Map();
    for (const row of rows) {
      const nodeId = Number(row?.node_id);
      const parentNodeId = Number(row?.parent_node_id);
      const visible = !Number.isFinite(parentNodeId)
        || parentNodeId === 0
        ? true
        : Boolean(visibleByNodeId.get(parentNodeId)) && state.protocolPathExpandedNodeIds.has(parentNodeId);

      visibleByNodeId.set(nodeId, visible);
      if (visible) {
        visibleRows.push(row);
      }
    }

    return visibleRows;
  }

  function setProtocolPathStatsMode(mode) {
    const normalizedMode = Number(mode) === 1 ? 1 : (Number(mode) === 2 ? 2 : 0);
    if (state.protocolPathStatsMode === normalizedMode) {
      return;
    }

    state.protocolPathStatsMode = normalizedMode;
    state.protocolPathExpandedNodeIds.clear();
    if (elements.protocolPathStatsViewport) {
      elements.protocolPathStatsViewport.scrollTop = 0;
    }
    renderProtocolPathStatsSection();
  }

  function toggleProtocolPathNode(nodeId) {
    const normalizedNodeId = Number(nodeId);
    if (!Number.isFinite(normalizedNodeId) || normalizedNodeId <= 0) {
      return;
    }

    if (state.protocolPathExpandedNodeIds.has(normalizedNodeId)) {
      state.protocolPathExpandedNodeIds.delete(normalizedNodeId);
    } else {
      state.protocolPathExpandedNodeIds.add(normalizedNodeId);
    }

    renderProtocolPathStatsSection();
  }

  function renderProtocolPathStatsRow(row, protocolPathMode, selectedProtocolPathNode) {
    const depth = Number(row?.depth ?? 0);
    const nodeId = Number(row?.node_id ?? 0);
    const hasChildren = Boolean(row?.has_children);
    const expanded = hasChildren && state.protocolPathExpandedNodeIds.has(nodeId);
    const layerText = String(row?.layer_text || "").trim();
    const fullText = String(row?.path_text || "").trim();
    const displayText = layerText.length > 0 ? layerText : fullText;
    const selected = selectedProtocolPathNode
      && Number(selectedProtocolPathNode.mode) === Number(protocolPathMode)
      && Number(selectedProtocolPathNode.nodeId) === Number(nodeId);

    return `
      <tr class="protocol-path-stats-row${selected ? " is-selected" : ""}" data-protocol-path-row-node-id="${nodeId}" title="${escapeHtml(fullText)}">
        <td>
          <div class="protocol-path-cell" style="padding-left:${Math.max(0, depth) * 18}px;">
            ${hasChildren
              ? `<button type="button" class="protocol-path-expander" data-protocol-path-node-id="${nodeId}" aria-label="${expanded ? "Collapse" : "Expand"} protocol path row">${expanded ? "&#9660;" : "&#9654;"}</button>`
              : `<span class="protocol-path-expander-spacer" aria-hidden="true"></span>`}
            <span class="protocol-path-label">${escapeHtml(displayText)}</span>
          </div>
        </td>
        <td>${escapeHtml(String(row?.flow_count_text || formatNumber(row?.flow_count)))}</td>
        <td>${escapeHtml(String(row?.packet_count_text || formatNumber(row?.packet_count)))}</td>
        <td>${escapeHtml(String(row?.original_byte_count_text || formatNumber(row?.original_byte_count)))}</td>
      </tr>
    `;
  }

  function renderProtocolPathStatsSection() {
    const overview = state.overview;
    const protocolPathMode = currentProtocolPathMode();
    const protocolPathRows = currentProtocolPathStatsRows();

    pruneProtocolPathExpandedNodeIds(protocolPathRows, protocolPathMode);
    const selectedProtocolPathNode = syncSelectedProtocolPathNode(protocolPathRows, protocolPathMode);
    const visibleProtocolPathRows = buildVisibleProtocolPathRows(protocolPathRows, protocolPathMode);
    state.protocolPathStatsVisibleRows = visibleProtocolPathRows;

    elements.protocolPathStatsModeKindOverview?.classList.toggle("is-active", protocolPathMode === 0);
    elements.protocolPathStatsModeIdentityTree?.classList.toggle("is-active", protocolPathMode === 1);
    elements.protocolPathStatsModeTerminalPaths?.classList.toggle("is-active", protocolPathMode === 2);
    elements.protocolPathStatsModeKindOverview?.setAttribute("aria-pressed", protocolPathMode === 0 ? "true" : "false");
    elements.protocolPathStatsModeIdentityTree?.setAttribute("aria-pressed", protocolPathMode === 1 ? "true" : "false");
    elements.protocolPathStatsModeTerminalPaths?.setAttribute("aria-pressed", protocolPathMode === 2 ? "true" : "false");

    if (elements.protocolPathShowFlowsButton) {
      elements.protocolPathShowFlowsButton.disabled = !selectedProtocolPathNode || Number(selectedProtocolPathNode.flowCount) <= 0;
    }
    if (elements.protocolPathExpandAllButton) {
      elements.protocolPathExpandAllButton.disabled = !isProtocolPathTreeMode(protocolPathMode) || protocolPathRows.length === 0;
      elements.protocolPathExpandAllButton.hidden = !isProtocolPathTreeMode(protocolPathMode);
    }
    if (elements.protocolPathCollapseAllButton) {
      elements.protocolPathCollapseAllButton.disabled = !isProtocolPathTreeMode(protocolPathMode) || protocolPathRows.length === 0;
      elements.protocolPathCollapseAllButton.hidden = !isProtocolPathTreeMode(protocolPathMode);
    }
    if (elements.protocolPathStatsPrimaryHeader) {
      elements.protocolPathStatsPrimaryHeader.textContent = protocolPathMode === 2 ? "Path" : "Layer";
    }

    if (state.openState === "opening") {
      elements.protocolPathStatsBody.innerHTML = renderStatsStateRow(4, "Loading protocol-path statistics...");
      return;
    }

    if (state.openState === "error") {
      elements.protocolPathStatsBody.innerHTML = renderStatsStateRow(4, "Open failed. No protocol-path statistics were loaded.", "error");
      return;
    }

    if (state.openState !== "opened" || !overview) {
      elements.protocolPathStatsBody.innerHTML = renderStatsStateRow(4, "Open a capture or index to load protocol-path statistics.");
      return;
    }

    if (visibleProtocolPathRows.length === 0) {
      elements.protocolPathStatsBody.innerHTML = renderStatsStateRow(4, "No protocol-path statistics are available.");
      if (elements.protocolPathStatsViewport) {
        elements.protocolPathStatsViewport.scrollTop = 0;
      }
      return;
    }

    const viewportElement = elements.protocolPathStatsViewport;
    if (viewportElement) {
      const viewportHeight = Math.max(0, Number(viewportElement.clientHeight || 0));
      const totalHeight = visibleProtocolPathRows.length * protocolPathStatsVirtualRowHeight;
      const maxScrollTop = Math.max(0, totalHeight - viewportHeight);
      if (viewportElement.scrollTop > maxScrollTop) {
        viewportElement.scrollTop = maxScrollTop;
      }
    }

    renderVirtualizedTableBody({
      tableBody: elements.protocolPathStatsBody,
      rows: visibleProtocolPathRows,
      rowHeight: protocolPathStatsVirtualRowHeight,
      viewportElement: elements.protocolPathStatsViewport,
      overscanRows: protocolPathStatsVirtualOverscanRows,
      colspan: 4,
      renderRow: (row) => renderProtocolPathStatsRow(row, protocolPathMode, selectedProtocolPathNode),
    });
  }

  function applyUpdatedFlowRow(updatedFlow) {
    if (updatedFlow == null || typeof updatedFlow.flow_index !== "number") {
      return;
    }

    const flowIndex = Number(updatedFlow.flow_index);
    const existingIndex = state.flows.findIndex((flow) => Number(flow?.flow_index) === flowIndex);
    if (existingIndex < 0) {
      return;
    }

    state.flows[existingIndex] = {
      ...state.flows[existingIndex],
      ...updatedFlow,
    };
  }

  function clearPacketDetails() {
    state.selectedPacketIndex = null;
    state.selectedPacketRow = null;
    state.packetDetails = null;
    state.packetDetailsState = "idle";
    state.packetDetailsErrorText = "";
  }

  function clearStream() {
    state.streamItems = [];
    state.streamState = "idle";
    state.streamErrorText = "";
    state.streamUnavailableText = "";
    state.streamLoadedItemCount = 0;
    state.streamTotalItemCount = 0;
    state.streamPacketWindowCount = 0;
    state.streamCanLoadMore = false;
    state.streamPartiallyLoaded = false;
    state.streamPacketWindowPartial = false;
    state.streamRequestedItemLimit = initialStreamItems;
    state.streamRequestedPacketBudget = initialStreamPacketBudget;
    state.streamLoadedForFlowIndex = null;
    state.selectedStreamItemIndex = null;
    state.selectedStreamItem = null;
    state.selectedStreamItemDetails = null;
    state.streamDetailsState = "idle";
    state.streamDetailsErrorText = "";
  }

  function clearAnalysis(resetFlowListState = true) {
    state.analysis = null;
    state.analysisState = "idle";
    state.analysisErrorText = "";
    state.analysisUnavailableText = "";
    state.analysisLoadedForFlowIndex = null;
    if (resetFlowListState) {
      resetAnalysisFlowVirtualizationState();
    }
    state.analysisSequenceExportInProgress = false;
    state.analysisSequenceExportStatusText = "";
    state.analysisSequenceExportStatusKind = "neutral";
    state.analysisRateMetricMode = "data";
    state.analysisRateDirectionMode = "both";
    state.analysisPacketSizeHistogramMode = "all";
    state.analysisInterArrivalHistogramMode = "all";
  }

  function canExportAnalysisSequenceCsv() {
    return state.openState === "opened"
      && state.selectedFlowIndex != null
      && state.analysisState === "loaded"
      && Array.isArray(state.analysis?.sequence_preview_rows)
      && state.analysis.sequence_preview_rows.length > 0
      && !state.analysisSequenceExportInProgress;
  }

  function clearFlows() {
    state.flows = [];
    state.flowFilterText = "";
    resetFlowVirtualizationState();
    resetAnalysisFlowVirtualizationState();
    state.checkedFlowIndices.clear();
    state.selectedFlowIndex = null;
    state.unrecognizedPacketsSelected = false;
    state.flowState = "idle";
    clearAnalysis(false);
    setWiresharkFilterStatus("", "neutral");
  }

  function clearPackets() {
    state.packets = [];
    state.packetsTotalCount = 0;
    state.packetOffset = 0;
    state.packetCanLoadMore = false;
    state.packetLoadingMore = false;
    state.packetState = "idle";
    state.packetErrorText = "";
    state.diagnosticsPacketRequestOffset = 0;
    state.diagnosticsPacketRequestLimit = packetPageSize;
    state.diagnosticsPacketReturnedRowCount = 0;
    state.diagnosticsPacketReturnedTotalCount = 0;
    clearPacketDetails();
  }

  function resetForNewOpen() {
    state.flowSelectionRequestToken += 1;
    state.packetRequestToken += 1;
    state.streamRequestToken += 1;
    state.analysisRequestToken += 1;
    clearRenderedTablesAndPanels();
    clearOverview();
    clearFlows();
    clearPackets();
    clearStream();
    clearAnalysis();
    state.attachSourceInProgress = false;
    state.saveIndexInProgress = false;
    state.exportCurrentFlowInProgress = false;
    state.exportSelectedFlowsInProgress = false;
    state.exportUnselectedFlowsInProgress = false;
    state.smartExportInProgress = false;
    clearSmartExportStatus();
    state.openMenu = null;
    state.aboutDialogVisible = false;
    state.settingsDialogVisible = false;
    state.settingsDialogLoading = false;
    state.settingsSaveInProgress = false;
    clearSettingsStatus();
    state.smartExportDialogVisible = false;
    state.sourceAvailability = null;
    state.partialOpenWarningText = "";
    state.currentSessionPath = "";
    state.currentSessionOpenedFromIndex = false;
    state.openProgress = {
      in_progress: false,
      cancel_requested: false,
      opening_as_index: false,
      packets_processed: 0,
      bytes_processed: 0,
      total_bytes: 0,
      percent: 0,
      input_path: "",
    };
    setStatus("", "neutral");
  }

  function setOpenControlsDisabled(disabled) {
    elements.capturePath.disabled = disabled;
    elements.openMode.disabled = disabled;
    elements.openFileButton.disabled = disabled;
    elements.openCancelButton.disabled = !disabled || state.openState !== "opening";
    elements.attachSourceButton.disabled = disabled || state.attachSourceInProgress || !canAttachSourceCapture();
  }

  function renderStatus() {
    elements.statusText.textContent = state.statusText;
    elements.statusText.className = "status-text topbar-status-text";
    if (state.statusKind === "error") {
      elements.statusText.classList.add("is-error");
    } else if (state.statusKind === "success") {
      elements.statusText.classList.add("is-success");
    }
    elements.statusText.classList.toggle("is-visible", state.statusText.trim().length > 0);
  }

  function closeMenus() {
    state.openMenu = null;
  }

  function renderMenuState() {
    try {
      for (const button of elements.menuButtons || []) {
        button.classList.toggle("is-open", button.dataset.menuButton === state.openMenu);
      }

      for (const panel of elements.menuPanels || []) {
        panel.classList.toggle("is-open", panel.dataset.menuPanel === state.openMenu);
      }

      for (const item of elements.menuItems || []) {
        const action = item.dataset.menuAction || "";
        if (action === "save-index") {
          item.disabled = !canSaveIndex();
          item.textContent = state.saveIndexInProgress ? "Saving Index..." : "Save Index";
        } else if (action === "export-current-flow") {
          item.disabled = !canExportCurrentFlow();
          item.textContent = state.exportCurrentFlowInProgress ? "Exporting Current Flow..." : "Export Current Flow";
        } else if (action === "export-selected-flows") {
          item.disabled = !canExportSelectedFlows();
          item.textContent = state.exportSelectedFlowsInProgress ? "Exporting Selected Flows..." : "Export Selected Flows";
        } else if (action === "export-unselected-flows") {
          item.disabled = !canExportUnselectedFlows();
          item.textContent = state.exportUnselectedFlowsInProgress ? "Exporting Unselected Flows..." : "Export Unselected Flows";
        } else if (action === "smart-export") {
          item.disabled = !canSmartExport();
          item.textContent = state.smartExportInProgress ? "Smart Exporting..." : "Smart Export...";
        } else if (
          action === "open-capture-fast"
          || action === "open-capture-deep"
          || action === "open-index"
        ) {
          item.disabled = state.openState === "opening"
            || state.attachSourceInProgress
            || state.saveIndexInProgress
            || state.exportCurrentFlowInProgress
            || state.exportSelectedFlowsInProgress
            || state.exportUnselectedFlowsInProgress
            || state.smartExportInProgress;
        } else if (action === "settings") {
          item.disabled = state.settingsDialogLoading || state.settingsSaveInProgress;
        } else if (action === "protocol-path-legend") {
          item.disabled = state.protocolPathLegendLoading;
        }
      }

      if (elements.aboutDialog) {
        elements.aboutDialog.classList.toggle("is-visible", state.aboutDialogVisible);
        elements.aboutDialog.setAttribute("aria-hidden", state.aboutDialogVisible ? "false" : "true");
      }
      if (elements.settingsDialog) {
        elements.settingsDialog.classList.toggle("is-visible", state.settingsDialogVisible);
        elements.settingsDialog.setAttribute("aria-hidden", state.settingsDialogVisible ? "false" : "true");
      }
      if (elements.protocolPathLegendDialog) {
        elements.protocolPathLegendDialog.classList.toggle("is-visible", state.protocolPathLegendDialogVisible);
        elements.protocolPathLegendDialog.setAttribute("aria-hidden", state.protocolPathLegendDialogVisible ? "false" : "true");
      }
      if (elements.smartExportDialog) {
        elements.smartExportDialog.classList.toggle("is-visible", state.smartExportDialogVisible);
        elements.smartExportDialog.setAttribute("aria-hidden", state.smartExportDialogVisible ? "false" : "true");
      }
    } catch (error) {
      console.error("Failed to render menu state.", error);
    }
  }

  function renderSettingsDialog() {
    const dialogDisabled = state.settingsDialogLoading || state.settingsSaveInProgress;

    if (elements.settingsHttpUsePathAsServiceHint) {
      elements.settingsHttpUsePathAsServiceHint.checked = Boolean(state.settings.http_use_path_as_service_hint);
      elements.settingsHttpUsePathAsServiceHint.disabled = dialogDisabled;
    }
    if (elements.settingsUsePossibleTlsQuic) {
      elements.settingsUsePossibleTlsQuic.checked = Boolean(state.settings.use_possible_tls_quic);
      elements.settingsUsePossibleTlsQuic.disabled = dialogDisabled;
    }
    if (elements.settingsShowWiresharkFilterForSelectedFlow) {
      elements.settingsShowWiresharkFilterForSelectedFlow.checked = Boolean(state.settings.show_wireshark_filter_for_selected_flow);
      elements.settingsShowWiresharkFilterForSelectedFlow.disabled = dialogDisabled;
    }
    if (elements.settingsShowProtocolPathColumn) {
      elements.settingsShowProtocolPathColumn.checked = Boolean(state.showProtocolPathColumn);
      elements.settingsShowProtocolPathColumn.disabled = dialogDisabled;
    }
    if (elements.settingsValidateSelectedPacketChecksums) {
      elements.settingsValidateSelectedPacketChecksums.checked = Boolean(state.settings.validate_selected_packet_checksums);
      elements.settingsValidateSelectedPacketChecksums.disabled = dialogDisabled;
    }
    if (elements.settingsCancelButton) {
      elements.settingsCancelButton.disabled = dialogDisabled;
    }
    if (elements.settingsSaveButton) {
      elements.settingsSaveButton.disabled = dialogDisabled;
      elements.settingsSaveButton.textContent = state.settingsSaveInProgress ? "Saving..." : "OK";
    }
    if (elements.settingsStatusText) {
      elements.settingsStatusText.textContent = state.settingsStatusText;
      elements.settingsStatusText.className = "status-text";
      if (state.settingsStatusKind === "error") {
        elements.settingsStatusText.classList.add("is-error");
      } else if (state.settingsStatusKind === "success") {
        elements.settingsStatusText.classList.add("is-success");
      }
    }
  }

  function renderProtocolPathLegendDialog() {
    if (elements.protocolPathLegendCloseButton) {
      elements.protocolPathLegendCloseButton.disabled = state.protocolPathLegendLoading;
    }

    if (elements.protocolPathLegendStatusText) {
      elements.protocolPathLegendStatusText.textContent = state.protocolPathLegendStatusText;
      elements.protocolPathLegendStatusText.className = "status-text";
      if (state.protocolPathLegendStatusKind === "error") {
        elements.protocolPathLegendStatusText.classList.add("is-error");
      } else if (state.protocolPathLegendStatusKind === "success") {
        elements.protocolPathLegendStatusText.classList.add("is-success");
      }
    }

    if (!elements.protocolPathLegendGrid) {
      return;
    }

    if (state.protocolPathLegendLoading) {
      elements.protocolPathLegendGrid.innerHTML = '<div class="settings-disabled-row">Loading protocol path legend...</div>';
      return;
    }

    if (!Array.isArray(state.protocolPathLegendEntries) || state.protocolPathLegendEntries.length === 0) {
      elements.protocolPathLegendGrid.innerHTML = '<div class="settings-disabled-row">Protocol path legend is unavailable.</div>';
      return;
    }

    elements.protocolPathLegendGrid.innerHTML = state.protocolPathLegendEntries.map((entry) => {
      const shortLabel = String(entry?.short_label || "").trim();
      const fullName = String(entry?.full_name || "").trim();
      const tooltip = String(entry?.tooltip || fullName || shortLabel).trim();
      const colorKey = String(entry?.color_key || "").trim();
      const backgroundColor = String(entry?.background_color || "").trim() || "#e2e8f0";
      const borderColor = String(entry?.border_color || "").trim() || "#cbd5e1";
      const textColor = String(entry?.text_color || "").trim() || "#334155";

      return `
        <div class="protocol-path-legend-item" title="${escapeHtml(tooltip)}">
          <span
            class="flow-path-badge${colorKey ? ` flow-path-badge-${escapeHtml(colorKey)}` : ""}"
            style="background:${escapeHtml(backgroundColor)};border-color:${escapeHtml(borderColor)};color:${escapeHtml(textColor)}"
          >${escapeHtml(shortLabel)}</span>
          <div class="protocol-path-legend-copy">
            <span class="protocol-path-legend-title">${escapeHtml(fullName)}</span>
            <span class="protocol-path-legend-meta">${escapeHtml(colorKey || "protocol")}</span>
          </div>
        </div>
      `;
    }).join("");
  }

  function renderSmartExportDialog() {
    const extrasEnabled = smartExportExtrasEnabled();
    const dialogDisabled = state.smartExportInProgress;
    const filterTargetEnabled = smartExportFilterTargetEnabled();
    const unrecognizedTargetEnabled = smartExportUnrecognizedTargetEnabled();

    if (elements.smartExportScopeUnrecognized) {
      elements.smartExportScopeUnrecognized.disabled = dialogDisabled || !unrecognizedTargetEnabled;
    }

    if (elements.smartExportScopeMatchingFilter) {
      elements.smartExportScopeMatchingFilter.disabled = dialogDisabled || !filterTargetEnabled;
    }
    if (elements.smartExportScopeNotMatchingFilter) {
      elements.smartExportScopeNotMatchingFilter.disabled = dialogDisabled || !filterTargetEnabled;
    }
    if (
      !filterTargetEnabled
      && (elements.smartExportScopeMatchingFilter?.checked || elements.smartExportScopeNotMatchingFilter?.checked)
    ) {
      if (state.selectedFlowIndex != null && !dialogDisabled) {
        elements.smartExportScopeCurrent.checked = true;
      } else if (!dialogDisabled) {
        elements.smartExportScopeAll.checked = true;
      }
    }
    if (
      !unrecognizedTargetEnabled
      && elements.smartExportScopeUnrecognized?.checked
    ) {
      if (state.selectedFlowIndex != null && !dialogDisabled) {
        elements.smartExportScopeCurrent.checked = true;
      } else if (!dialogDisabled) {
        elements.smartExportScopeAll.checked = true;
      }
    }

    if (
      elements.smartExportScopeUnrecognized?.checked
      && elements.smartExportOutputSeparateFiles?.checked
      && !dialogDisabled
    ) {
      elements.smartExportOutputSingleFile.checked = true;
    }

    const perFlowMode = selectedSmartExportOutputMode() === "separate_files";
    if (elements.smartExportOutputSeparateFiles) {
      elements.smartExportOutputSeparateFiles.disabled = dialogDisabled || elements.smartExportScopeUnrecognized?.checked;
    }
    if (elements.smartExportOutputSingleFile) {
      elements.smartExportOutputSingleFile.disabled = dialogDisabled;
    }

    if (!extrasEnabled) {
      elements.smartExportIncludeLastPacket.checked = false;
      elements.smartExportIncludeEveryKthPacket.checked = false;
    }

    elements.smartExportFirstNPackets.disabled = dialogDisabled || !elements.smartExportBaseFirstNPackets.checked;
    elements.smartExportFirstMOriginalBytes.disabled = dialogDisabled || !elements.smartExportBaseFirstMOriginalBytes.checked;
    elements.smartExportIncludeLastPacket.disabled = dialogDisabled || !extrasEnabled;
    elements.smartExportIncludeEveryKthPacket.disabled = dialogDisabled || !extrasEnabled;
    elements.smartExportEveryKthPacket.disabled = dialogDisabled || !extrasEnabled || !elements.smartExportIncludeEveryKthPacket.checked;
    elements.smartExportDestinationFolderRow.style.display = perFlowMode ? "flex" : "none";
    elements.smartExportFolderHelp.style.display = perFlowMode ? "block" : "none";
    elements.smartExportBufferBudgetRow.style.display = perFlowMode ? "flex" : "none";
    elements.smartExportBufferHelp.style.display = perFlowMode ? "block" : "none";
    elements.smartExportDestinationFolder.disabled = dialogDisabled || !perFlowMode;
    elements.smartExportBrowseFolderButton.disabled = dialogDisabled || !perFlowMode;
    elements.smartExportBufferBudget.disabled = dialogDisabled || !perFlowMode;
    if (elements.smartExportCloseButton) {
      elements.smartExportCloseButton.disabled = dialogDisabled;
    }
    elements.smartExportCancelButton.disabled = dialogDisabled;
    elements.smartExportRunButton.disabled = dialogDisabled;
    elements.smartExportRunButton.textContent = state.smartExportInProgress ? "Exporting..." : "OK";
    elements.smartExportExtrasHint.textContent = "Packets are exported when they match the base rule or one of the enabled extras.";

    elements.smartExportStatusText.textContent = state.smartExportStatusText;
    elements.smartExportStatusText.className = "status-text";
    if (state.smartExportStatusKind === "error") {
      elements.smartExportStatusText.classList.add("is-error");
    } else if (state.smartExportStatusKind === "success") {
      elements.smartExportStatusText.classList.add("is-success");
    }
  }

  function filteredFlows() {
    const filterText = state.flowFilterText.trim().toLowerCase();
    const protocolPathFilter = hasActiveProtocolPathFilter() ? state.activeProtocolPathFilter : null;

    return state.flows.filter((flow) => {
      if (protocolPathFilter && !protocolPathFilter.flowIndexSet.has(Number(flow.flow_index))) {
        return false;
      }

      if (filterText.length === 0) {
        return true;
      }

      const haystack = [
        formatFlowFamily(flow),
        flow.protocol_text,
        flow.protocol_hint,
        flow.protocol_hint_display,
        flow.service_hint,
        flow.endpoint_a,
        flow.endpoint_b,
        flow.address_a,
        flow.address_b,
        String(flow.port_a ?? ""),
        String(flow.port_b ?? ""),
        String(flow.fragmented_packet_count ?? ""),
        flow.has_fragmented_packets ? "frag fragmented" : "",
        String(flow.packet_count ?? ""),
        String(flow.total_bytes ?? ""),
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(filterText);
    });
  }

  function getVisibleFlows() {
    return [...filteredFlows()].sort((left, right) => {
      const result = compareFlowValues(
        getFlowSortValue(left, state.flowSortKey),
        getFlowSortValue(right, state.flowSortKey),
        state.flowSortDirection
      );

      if (result !== 0) {
        return result;
      }

      return Number(left?.flow_index ?? 0) - Number(right?.flow_index ?? 0);
    });
  }

  function getSortedFlows(flowList) {
    return [...(flowList || [])].sort((left, right) => {
      const result = compareFlowValues(
        getFlowSortValue(left, state.flowSortKey),
        getFlowSortValue(right, state.flowSortKey),
        state.flowSortDirection
      );

      if (result !== 0) {
        return result;
      }

      return Number(left?.flow_index ?? 0) - Number(right?.flow_index ?? 0);
    });
  }

  function getSelectedFlow() {
    return state.flows.find((flow) => flow.flow_index === state.selectedFlowIndex) || null;
  }

  function isUnknownAnalysisValue(value) {
    return String(value || "").trim().toLowerCase() === "unknown";
  }

  function analysisSelectedFlowServiceHint(analysis) {
    const selectedFlowServiceHint = String(getSelectedFlow()?.service_hint || "").trim();
    const analysisServiceHint = String(analysis?.service_hint_text || "").trim();
    const protocolPanelService = String(analysis?.protocol_service_text || "").trim();
    const protocolHint = String(analysis?.protocol_hint_display || analysis?.protocol_hint || "").trim().toUpperCase();
    const prefersSelectedFlowHint = protocolHint === "QUIC" || protocolHint === "TLS";

    if (analysisServiceHint && (!prefersSelectedFlowHint || !isUnknownAnalysisValue(analysisServiceHint))) {
      return analysisServiceHint;
    }

    if (protocolPanelService && (!prefersSelectedFlowHint || !isUnknownAnalysisValue(protocolPanelService))) {
      return protocolPanelService;
    }

    return selectedFlowServiceHint;
  }

  function analysisProtocolServiceValue(analysis) {
    const protocolPanelService = String(analysis?.protocol_service_text || "").trim();
    const protocolHint = String(analysis?.protocol_hint_display || analysis?.protocol_hint || "").trim().toUpperCase();
    const prefersSelectedFlowHint = protocolHint === "QUIC" || protocolHint === "TLS";

    if (protocolPanelService && (!prefersSelectedFlowHint || !isUnknownAnalysisValue(protocolPanelService))) {
      return protocolPanelService;
    }

    const selectedFlowServiceHint = String(getSelectedFlow()?.service_hint || "").trim();
    if (selectedFlowServiceHint) {
      return selectedFlowServiceHint;
    }

    return "";
  }

  function ensureFlowVisibleInViewport(rows, viewportElement, rowHeight) {
    if (state.selectedFlowIndex == null || !Array.isArray(rows) || !viewportElement) {
      return;
    }

    const selectedRowIndex = rows.findIndex((flow) => Number(flow?.flow_index) === Number(state.selectedFlowIndex));
    if (selectedRowIndex < 0) {
      return;
    }

    const viewportHeight = Math.max(0, Number(viewportElement.clientHeight || 0));
    if (viewportHeight <= 0) {
      return;
    }

    const rowTop = selectedRowIndex * rowHeight;
    const totalHeight = rows.length * rowHeight;
    const centeredScrollTop = rowTop - ((viewportHeight - rowHeight) / 2);
    const maxScrollTop = Math.max(0, totalHeight - viewportHeight);
    viewportElement.scrollTop = Math.min(Math.max(0, centeredScrollTop), maxScrollTop);
  }

  function ensureSelectedFlowVisibleForTab(tabName) {
    if (tabName === "flows") {
      ensureFlowVisibleInViewport(getVisibleFlows(), elements.flowTableViewport, flowVirtualRowHeight);
      return;
    }

    if (tabName === "analysis") {
      ensureFlowVisibleInViewport(getSortedFlows(state.flows), elements.analysisFlowTableViewport, analysisFlowVirtualRowHeight);
    }
  }

  function getVirtualizedWindow(totalCount, viewportElement, rowHeight, overscanRows) {
    const safeTotalCount = Math.max(0, Number(totalCount || 0));
    if (safeTotalCount === 0) {
      return {
        startIndex: 0,
        endIndex: 0,
        viewportHeight: 0,
        virtualizationActive: false,
      };
    }

    const scrollTop = Math.max(0, Number(viewportElement?.scrollTop || 0));
    const viewportHeight = Math.max(
      Number(viewportElement?.clientHeight || 0),
      rowHeight * 8
    );
    const visibleRowCount = Math.max(1, Math.ceil(viewportHeight / rowHeight));
    const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - overscanRows);
    const endIndex = Math.min(
      safeTotalCount,
      startIndex + visibleRowCount + (overscanRows * 2)
    );

    return {
      startIndex,
      endIndex,
      viewportHeight,
      virtualizationActive: safeTotalCount > visibleRowCount,
    };
  }

  function renderVirtualizedTableBody({
    tableBody,
    rows,
    rowHeight,
    viewportElement,
    overscanRows,
    colspan,
    renderRow,
  }) {
    const safeRows = Array.isArray(rows) ? rows : [];
    const { startIndex, endIndex, virtualizationActive } = getVirtualizedWindow(
      safeRows.length,
      viewportElement,
      rowHeight,
      overscanRows
    );
    const windowRows = safeRows.slice(startIndex, endIndex);
    const topSpacerHeight = startIndex * rowHeight;
    const bottomSpacerHeight = Math.max(0, safeRows.length - endIndex) * rowHeight;
    const topSpacerRow = topSpacerHeight > 0
      ? `<tr class="virtual-spacer-row" aria-hidden="true"><td colspan="${colspan}" style="height: ${topSpacerHeight}px;"></td></tr>`
      : "";
    const bottomSpacerRow = bottomSpacerHeight > 0
      ? `<tr class="virtual-spacer-row" aria-hidden="true"><td colspan="${colspan}" style="height: ${bottomSpacerHeight}px;"></td></tr>`
      : "";

    tableBody.innerHTML = `${topSpacerRow}${windowRows.map(renderRow).join("")}${bottomSpacerRow}`;

    return {
      startIndex,
      endIndex,
      virtualizationActive,
      windowRows,
    };
  }

  function clearFlowTableDom() {
    if (elements.flowTableBody) {
      elements.flowTableBody.innerHTML = "";
    }
    if (elements.flowRenderCapText) {
      elements.flowRenderCapText.textContent = "";
    }
    elements.flowRenderCapBar?.classList.remove("is-visible");
    state.flowVirtualWindowStart = 0;
    state.flowVirtualWindowEnd = 0;
    state.flowVirtualizationActive = false;
  }

  function clearPacketTableDom() {
    if (elements.packetTableBody) {
      elements.packetTableBody.innerHTML = "";
    }
  }

  function clearStreamTableDom() {
    if (elements.streamTableBody) {
      elements.streamTableBody.innerHTML = "";
    }
  }

  function clearPacketDetailsDom() {
    elements.packetDetailsSummary && (elements.packetDetailsSummary.innerHTML = "");
    elements.packetDetailsRawText && (elements.packetDetailsRawText.textContent = "");
    elements.packetDetailsPayloadText && (elements.packetDetailsPayloadText.textContent = "");
    elements.packetDetailsProtocolText && (elements.packetDetailsProtocolText.textContent = "");
    elements.packetDetailsRawStateText && (elements.packetDetailsRawStateText.textContent = "");
    elements.packetDetailsPayloadStateText && (elements.packetDetailsPayloadStateText.textContent = "");
    elements.packetDetailsProtocolStateText && (elements.packetDetailsProtocolStateText.textContent = "");
    elements.packetDetailsStateText && (elements.packetDetailsStateText.textContent = "");
  }

  function clearStreamDetailsDom() {
    elements.streamDetailsSummary && (elements.streamDetailsSummary.innerHTML = "");
    elements.streamDetailsStateText && (elements.streamDetailsStateText.textContent = "");
    elements.streamDetailsSourcePacketsText && (elements.streamDetailsSourcePacketsText.textContent = "");
    elements.streamDetailsSourcePacketIndicesText && (elements.streamDetailsSourcePacketIndicesText.textContent = "");
    elements.streamDetailsConstrictedNotesText && (elements.streamDetailsConstrictedNotesText.textContent = "");
  }

  function clearStatisticsDom() {
    elements.transportStatsBody && (elements.transportStatsBody.innerHTML = "");
    elements.familyStatsBody && (elements.familyStatsBody.innerHTML = "");
    elements.protocolHintStatsBody && (elements.protocolHintStatsBody.innerHTML = "");
    elements.protocolPathStatsBody && (elements.protocolPathStatsBody.innerHTML = "");
    state.protocolPathStatsVisibleRows = [];
    elements.quicStatsBody && (elements.quicStatsBody.innerHTML = "");
    elements.tlsStatsBody && (elements.tlsStatsBody.innerHTML = "");
    elements.topEndpointsBody && (elements.topEndpointsBody.innerHTML = "");
    elements.topPortsBody && (elements.topPortsBody.innerHTML = "");
  }

  function clearAnalysisDom() {
    elements.analysisFlowTableBody && (elements.analysisFlowTableBody.innerHTML = "");
    elements.analysisFlowRenderCapText && (elements.analysisFlowRenderCapText.textContent = "");
    elements.analysisFlowRenderCapBar?.classList.remove("is-visible");
    state.analysisFlowVirtualWindowStart = 0;
    state.analysisFlowVirtualWindowEnd = 0;
    state.analysisFlowVirtualizationActive = false;
    elements.analysisFlowSummary && (elements.analysisFlowSummary.innerHTML = "");
    elements.analysisProtocolPanel && (elements.analysisProtocolPanel.innerHTML = "");
    elements.analysisTrafficTotals && (elements.analysisTrafficTotals.innerHTML = "");
    elements.analysisDirectionSplit && (elements.analysisDirectionSplit.innerHTML = "");
    elements.analysisDerivedMetrics && (elements.analysisDerivedMetrics.innerHTML = "");
    elements.analysisTimingSize && (elements.analysisTimingSize.innerHTML = "");
    elements.analysisBurstIdleSummary && (elements.analysisBurstIdleSummary.innerHTML = "");
    elements.analysisPacketSizeHistogramRows && (elements.analysisPacketSizeHistogramRows.innerHTML = "");
    elements.analysisPacketSizeHistogramMax && (elements.analysisPacketSizeHistogramMax.textContent = "");
    elements.analysisInterArrivalHistogramRows && (elements.analysisInterArrivalHistogramRows.innerHTML = "");
    elements.analysisInterArrivalHistogramMax && (elements.analysisInterArrivalHistogramMax.textContent = "");
    elements.analysisSequencePreviewBody && (elements.analysisSequencePreviewBody.innerHTML = "");
  }

  function renderTabs() {
    for (const button of elements.tabButtons) {
      button.classList.toggle("active", button.dataset.tab === state.activeTab);
    }

    for (const panel of elements.tabPanels) {
      panel.classList.toggle("active", panel.dataset.tabPanel === state.activeTab);
    }
  }

  function renderFlowSortHeaders() {
    for (const header of elements.flowSortHeaders) {
      const sortKey = header.dataset.flowSortKey || "";
      const label = header.dataset.flowSortLabel || header.textContent.replace(/\s[↑↓]$/, "");
      header.dataset.flowSortLabel = label;

      const isActive = sortKey === state.flowSortKey;
      const arrow = !isActive ? "" : (state.flowSortDirection === "desc" ? " ↓" : " ↑");
      header.textContent = `${label}${arrow}`;
      header.classList.toggle("is-active", isActive);
      header.title = isActive
        ? `Sorted ${state.flowSortDirection === "desc" ? "descending" : "ascending"}`
        : "Click to sort";
    }
  }

  function renderFlowViewTabs() {
    for (const button of elements.flowViewTabButtons) {
      button.classList.toggle("active", button.dataset.flowViewTab === state.flowViewTab);
    }

    for (const panel of elements.flowViewPanels) {
      panel.classList.toggle("active", panel.dataset.flowViewPanel === state.flowViewTab);
    }

    const showingPackets = state.flowViewTab === "packets";
    if (elements.flowViewTabStreamButton) {
      elements.flowViewTabStreamButton.disabled = state.unrecognizedPacketsSelected;
    }
    elements.packetLoadMoreButton.style.display = showingPackets ? "" : "none";
    elements.streamLoadMoreButton.style.display = showingPackets || state.unrecognizedPacketsSelected ? "none" : "";
  }

  function renderInspectorMode() {
    const showingPacketInspector = state.flowViewTab !== "stream";
    elements.packetInspectorView.classList.toggle("active", showingPacketInspector);
    elements.streamInspectorView.classList.toggle("active", !showingPacketInspector);
  }

  function renderUnrecognizedPacketsPanel() {
    if (!elements.unrecognizedPacketsButton || !elements.unrecognizedPacketsMeta) {
      return;
    }

    const count = unrecognizedPacketCount();
    const visible = state.openState === "opened" && count > 0;
    elements.unrecognizedPacketsButton.classList.toggle("is-hidden", !visible);
    elements.unrecognizedPacketsButton.classList.toggle("is-selected", visible && state.unrecognizedPacketsSelected);
    elements.unrecognizedPacketsButton.disabled = !visible || state.openState === "opening";
    elements.unrecognizedPacketsMeta.textContent = visible
      ? `${formatPlainInteger(count)} packets could not be assigned to a recognized flow`
      : "";
  }

  function renderPacketDetailsTabs() {
    for (const button of elements.packetDetailsTabButtons) {
      button.classList.toggle("active", button.dataset.packetDetailsTab === state.packetDetailsTab);
    }

    for (const panel of elements.packetDetailsTabPanels) {
      panel.classList.toggle("active", panel.dataset.packetDetailsPanel === state.packetDetailsTab);
    }
  }

  function activeSourceSessionDisplayText() {
    const availability = currentSourceAvailability();
    const activeSourcePath = String(availability.active_source_capture_path || "").trim();
    const expectedSourcePath = String(availability.expected_source_capture_path || "").trim();

    if (!state.currentSessionOpenedFromIndex) {
      return {
        visible: false,
        text: "",
      };
    }

    if (activeSourcePath.length > 0) {
      return {
        visible: true,
        text: activeSourcePath,
      };
    }

    if (expectedSourcePath.length > 0) {
      return {
        visible: true,
        text: availability.source_capture_accessible ? expectedSourcePath : `${expectedSourcePath} (unavailable)`,
      };
    }

    return {
      visible: true,
      text: "not attached",
    };
  }

  function renderOpenState() {
    const activeSessionText = state.currentSessionPath
      ? `${state.currentSessionOpenedFromIndex ? "Index" : "PCAP"}: ${state.currentSessionPath}`
      : "No active session";
    const activeSourceDisplay = activeSourceSessionDisplayText();

    elements.activeSessionText.textContent = activeSessionText;
    if (elements.activeSourceSessionRow && elements.activeSourceSessionText) {
      elements.activeSourceSessionRow.classList.toggle("is-hidden", !activeSourceDisplay.visible);
      elements.activeSourceSessionText.textContent = activeSourceDisplay.text;
    }
    elements.activeSessionPanel.title = activeSourceDisplay.visible
      ? `Active session: ${activeSessionText}\nSource PCAP: ${activeSourceDisplay.text}`
      : `Active session: ${activeSessionText}`;
    elements.attachSourceButton.textContent = state.attachSourceInProgress ? "Attaching..." : "Locate Source...";
    setOpenControlsDisabled(
      state.openState === "opening"
      || state.attachSourceInProgress
      || state.saveIndexInProgress
      || state.exportCurrentFlowInProgress
      || state.exportSelectedFlowsInProgress
      || state.exportUnselectedFlowsInProgress
      || state.smartExportInProgress
    );

    const progress = state.openProgress || {};
    const progressVisible = state.openState === "opening";
    elements.openProgressPanel.classList.toggle("is-visible", progressVisible);
    if (!progressVisible) {
      elements.openProgressTitle.textContent = "";
      elements.openProgressProcessed.textContent = "";
      elements.openProgressTrack.classList.remove("is-indeterminate");
      elements.openProgressFill.style.width = "0%";
      elements.openCancelButton.disabled = true;
      return;
    }

    const openingFileName = fileNameFromPath(progress.input_path) || fileNameFromPath(elements.capturePath.value) || "selected file";
    elements.openProgressTitle.textContent = `${progress.opening_as_index ? "Opening index" : "Opening capture"}: ${openingFileName}`;
    if (Number(progress.total_bytes || 0) > 0) {
      const percentText = `${Math.max(0, Math.min(100, Number(progress.percent || 0) * 100)).toFixed(1).replace(/\\.0$/, "")}%`;
      elements.openProgressProcessed.textContent = `Processed: ${formatByteSize(progress.bytes_processed)} / ${formatByteSize(progress.total_bytes)} (${percentText})`;
      elements.openProgressTrack.classList.remove("is-indeterminate");
      elements.openProgressFill.style.width = `${Math.max(0, Math.min(100, Number(progress.percent || 0) * 100))}%`;
    } else {
      elements.openProgressProcessed.textContent = `Processed: ${formatByteSize(progress.bytes_processed)}`;
      elements.openProgressTrack.classList.add("is-indeterminate");
      elements.openProgressFill.style.width = "32%";
    }
    elements.openCancelButton.disabled = Boolean(progress.cancel_requested);
    elements.openCancelButton.textContent = progress.cancel_requested ? "Cancelling..." : "Cancel";
  }

  function renderSourceWarningBanner() {
    const availability = currentSourceAvailability();
    const showBanner = state.openState === "opened" && !availability.byte_backed_inspection_available;

    elements.sourceWarningBanner.classList.toggle("is-visible", showBanner);
    if (!showBanner) {
      elements.sourceWarningText.textContent = "";
      elements.sourceWarningExpectedPath.textContent = "";
      return;
    }

    elements.sourceWarningText.textContent = sourceWarningBannerText();
    elements.sourceWarningExpectedPath.textContent = availability.expected_source_capture_path
      ? `Expected source path: ${availability.expected_source_capture_path}`
      : "";
  }

  function renderPartialOpenWarningBanner() {
    const warningText = String(state.partialOpenWarningText || "").trim();
    const showBanner = state.openState === "opened" && warningText.length > 0;

    elements.partialOpenWarningBanner.classList.toggle("is-visible", showBanner);
    elements.partialOpenWarningText.textContent = showBanner ? warningText : "";
  }

  function renderOverview() {
    const overview = state.overview;
    const transportRows = overview ? [
      ["TCP", overview.protocol_summary?.tcp],
      ["UDP", overview.protocol_summary?.udp],
      ["SCTP", overview.protocol_summary?.sctp],
      ["Other", overview.protocol_summary?.other],
    ] : [];
    const familyRows = overview ? [
      ["IPv4", overview.protocol_summary?.ipv4],
      ["IPv6", overview.protocol_summary?.ipv6],
    ] : [];
    const protocolHintRows = Array.isArray(overview?.protocol_hints) ? overview.protocol_hints : [];
    const topEndpoints = Array.isArray(overview?.top_endpoints) ? overview.top_endpoints : [];
    const topPorts = Array.isArray(overview?.top_ports) ? overview.top_ports : [];
    const topTalkersVisible = Number(overview?.summary?.flow_count ?? 0) > 30;
    const quicRecognition = overview?.quic_recognition || null;
    const tlsRecognition = overview?.tls_recognition || null;

    elements.metricPackets.textContent = overview ? formatNumber(overview.summary?.packet_count) : "-";
    elements.metricFlows.textContent = overview ? formatNumber(overview.summary?.flow_count) : "-";
    elements.metricCapturedBytes.textContent = overview ? formatNumber(overview.summary?.captured_bytes) : "-";
    elements.metricOriginalBytes.textContent = overview ? formatNumber(overview.summary?.original_bytes) : "-";

    if (state.openState === "opening") {
      elements.overviewMeta.textContent = "Loading overview...";
      elements.transportStatsBody.innerHTML = renderStatsStateRow(5, "Loading transport statistics...");
      elements.familyStatsBody.innerHTML = renderStatsStateRow(5, "Loading IP family statistics...");
      elements.protocolHintStatsBody.innerHTML = renderStatsStateRow(6, "Loading protocol-hint statistics...");
      elements.topEndpointsBody.innerHTML = renderStatsStateRow(3, "Loading top endpoints...");
      elements.topPortsBody.innerHTML = renderStatsStateRow(3, "Loading top ports...");
      elements.quicStatsBody.innerHTML = renderStatsStateRow(2, "Loading QUIC recognition...");
      elements.tlsStatsBody.innerHTML = renderStatsStateRow(2, "Loading TLS recognition...");
    } else if (state.openState === "opened" && overview) {
      elements.overviewMeta.textContent = "Overview, transport, family, protocol-path, protocol-hint, QUIC/TLS, and top-talker summaries loaded from the active capture or index.";
      elements.transportStatsBody.innerHTML = transportRows
        .map(([label, stats]) => `
          <tr>
            <td>${escapeHtml(label)}</td>
            <td>${formatNumber(stats?.flow_count)}</td>
            <td>${formatNumber(stats?.packet_count)}</td>
            <td>${formatNumber(stats?.captured_bytes)}</td>
            <td>${formatNumber(stats?.original_bytes)}</td>
          </tr>
        `)
        .join("");
      elements.familyStatsBody.innerHTML = familyRows
        .map(([label, stats]) => `
          <tr>
            <td>${escapeHtml(label)}</td>
            <td>${formatNumber(stats?.flow_count)}</td>
            <td>${formatNumber(stats?.packet_count)}</td>
            <td>${formatNumber(stats?.captured_bytes)}</td>
            <td>${formatNumber(stats?.original_bytes)}</td>
            </tr>
          `)
          .join("");
      elements.protocolHintStatsBody.innerHTML = protocolHintRows.length > 0
        ? protocolHintRows
          .map((row) => `
            <tr class="${protocolHintFilterValue(row.protocol_label) ? "stats-drilldown-row" : ""}" data-protocol-filter="${escapeHtml(protocolHintFilterValue(row.protocol_label))}" title="${protocolHintFilterValue(row.protocol_label) ? "Filter flows by this protocol hint" : ""}">
              <td>${escapeHtml(row.group)}</td>
              <td>${escapeHtml(row.protocol_label)}</td>
              <td>${formatNumber(row.flow_count)}</td>
              <td>${formatNumber(row.packet_count)}</td>
              <td>${formatNumber(row.captured_bytes)}</td>
              <td>${formatNumber(row.original_bytes)}</td>
            </tr>
          `)
          .join("")
        : renderStatsStateRow(6, "No protocol-hint statistics are available.");
      elements.quicStatsBody.innerHTML = [
        ["Flows", formatNumber(quicRecognition?.total_flows)],
        ["Recognised Initial", formatFlowPercentAndCount(quicRecognition?.with_sni, quicRecognition?.total_flows)],
        ["Unrecognised", formatFlowPercentAndCount(quicRecognition?.without_sni, quicRecognition?.total_flows)],
        ["v1", formatNumber(quicRecognition?.version_v1)],
        ["draft-29", formatNumber(quicRecognition?.version_draft29)],
        ["v2", formatNumber(quicRecognition?.version_v2)],
        ["Version unavailable", formatNumber(quicRecognition?.version_unknown)],
      ]
        .map(([label, value]) => `
          <tr>
            <td>${escapeHtml(label)}</td>
            <td>${escapeHtml(value)}</td>
          </tr>
        `)
        .join("");
      elements.tlsStatsBody.innerHTML = [
        ["Flows", formatNumber(tlsRecognition?.total_flows)],
        ["With SNI", formatFlowPercentAndCount(tlsRecognition?.with_sni, tlsRecognition?.total_flows)],
        ["Without SNI", formatFlowPercentAndCount(tlsRecognition?.without_sni, tlsRecognition?.total_flows)],
        ["TLS 1.2", formatNumber(tlsRecognition?.version_tls12)],
        ["TLS 1.3", formatNumber(tlsRecognition?.version_tls13)],
        ["Version unavailable", formatNumber(tlsRecognition?.version_unknown)],
      ]
        .map(([label, value]) => `
          <tr>
            <td>${escapeHtml(label)}</td>
            <td>${escapeHtml(value)}</td>
          </tr>
        `)
        .join("");
      elements.topEndpointsBody.innerHTML = topEndpoints.length > 0
        && topTalkersVisible
        ? topEndpoints
          .map((row) => `
            <tr class="stats-drilldown-row" data-endpoint-filter="${escapeHtml(row.endpoint_label)}" title="Filter flows by this endpoint">
              <td>${escapeHtml(row.endpoint_label)}</td>
              <td>${formatNumber(row.packet_count)}</td>
              <td>${formatNumber(row.total_bytes)}</td>
            </tr>
          `)
          .join("")
        : renderStatsStateRow(
          3,
          topTalkersVisible
            ? "No top-endpoint summary is available for this capture."
            : "Top-endpoint summary appears once more than 30 flows are present."
        );
      elements.topPortsBody.innerHTML = topPorts.length > 0
        && topTalkersVisible
        ? topPorts
          .map((row) => `
            <tr class="stats-drilldown-row" data-port-filter="${row.port}" title="Filter flows by this port">
              <td>${formatNumber(row.port)}</td>
              <td>${formatNumber(row.packet_count)}</td>
              <td>${formatNumber(row.total_bytes)}</td>
            </tr>
          `)
          .join("")
        : renderStatsStateRow(
          3,
          topTalkersVisible
            ? "No top-port summary is available for this capture."
            : "Top-port summary appears once more than 30 flows are present."
        );

      for (const row of elements.protocolHintStatsBody.querySelectorAll(".stats-drilldown-row")) {
        row.addEventListener("click", () => {
          const filterText = String(row.dataset.protocolFilter || "").trim();
          if (!filterText) {
            return;
          }

          applyFlowFilterFromStatistics(filterText, `protocol hint "${filterText}"`);
        });
      }

      for (const row of elements.topEndpointsBody.querySelectorAll(".stats-drilldown-row")) {
        row.addEventListener("click", () => {
          const filterText = String(row.dataset.endpointFilter || "").trim();
          if (!filterText) {
            return;
          }

          applyFlowFilterFromStatistics(filterText, `endpoint "${filterText}"`);
        });
      }

      for (const row of elements.topPortsBody.querySelectorAll(".stats-drilldown-row")) {
        row.addEventListener("click", () => {
          const filterText = String(row.dataset.portFilter || "").trim();
          if (!filterText) {
            return;
          }

          applyFlowFilterFromStatistics(filterText, `port ${filterText}`);
        });
      }
    } else if (state.openState === "error") {
      elements.overviewMeta.textContent = "No overview or protocol-path statistics available after open failure.";
      elements.transportStatsBody.innerHTML = renderStatsStateRow(5, "Open failed. No transport statistics were loaded.", "error");
      elements.familyStatsBody.innerHTML = renderStatsStateRow(5, "Open failed. No IP family statistics were loaded.", "error");
      elements.protocolHintStatsBody.innerHTML = renderStatsStateRow(6, "Open failed. No protocol-hint statistics were loaded.", "error");
      elements.topEndpointsBody.innerHTML = renderStatsStateRow(3, "Open failed. No top-endpoint summary was loaded.", "error");
      elements.topPortsBody.innerHTML = renderStatsStateRow(3, "Open failed. No top-port summary was loaded.", "error");
      elements.quicStatsBody.innerHTML = renderStatsStateRow(2, "Open failed. No QUIC recognition was loaded.", "error");
      elements.tlsStatsBody.innerHTML = renderStatsStateRow(2, "Open failed. No TLS recognition was loaded.", "error");
    } else {
      elements.overviewMeta.textContent = "No capture loaded.";
      elements.transportStatsBody.innerHTML = renderStatsStateRow(5, "Open a capture or index to load transport statistics.");
      elements.familyStatsBody.innerHTML = renderStatsStateRow(5, "Open a capture or index to load IP family statistics.");
      elements.protocolHintStatsBody.innerHTML = renderStatsStateRow(6, "Open a capture or index to load protocol-hint statistics.");
      elements.topEndpointsBody.innerHTML = renderStatsStateRow(3, "Open a capture or index to load top endpoints.");
      elements.topPortsBody.innerHTML = renderStatsStateRow(3, "Open a capture or index to load top ports.");
      elements.quicStatsBody.innerHTML = renderStatsStateRow(2, "Open a capture or index to load QUIC recognition.");
      elements.tlsStatsBody.innerHTML = renderStatsStateRow(2, "Open a capture or index to load TLS recognition.");
    }

    renderProtocolPathStatsSection();
  }

  function renderFlows() {
    const flows = state.flows;
    const visibleFlows = getVisibleFlows();
    const checkedCount = checkedFlowCount();
    const columnCount = flowTableColumnCount();
    const hasProtocolPathFilter = hasActiveProtocolPathFilter();
    const protocolPathFilterLabel = hasProtocolPathFilter
      ? String(state.activeProtocolPathFilter?.label || "").trim()
      : "";

    elements.flowFilterInput.value = state.flowFilterText;
    elements.clearFlowFilterButton.disabled = state.flowFilterText.trim().length === 0;
    if (elements.protocolPathFlowFilterRow) {
      elements.protocolPathFlowFilterRow.style.display = hasProtocolPathFilter ? "grid" : "none";
    }
    if (elements.protocolPathFlowFilterText) {
      elements.protocolPathFlowFilterText.textContent = hasProtocolPathFilter
        ? protocolPathFilterLabel
        : "No protocol path filter.";
      elements.protocolPathFlowFilterText.title = hasProtocolPathFilter ? protocolPathFilterLabel : "";
    }
    if (elements.clearProtocolPathFlowFilterButton) {
      elements.clearProtocolPathFlowFilterButton.disabled = !hasProtocolPathFilter;
    }
    elements.checkedFlowsStatusBar.classList.toggle("is-visible", checkedCount > 0);
    elements.checkedFlowsStatusText.textContent = checkedCount === 1 ? "1 flow selected" : `${formatNumber(checkedCount)} flows selected`;
    if (elements.flowPathHeader) {
      elements.flowPathHeader.style.display = state.showProtocolPathColumn ? "" : "none";
    }
    renderUnrecognizedPacketsPanel();

    if (state.openState === "opening" || state.flowState === "loading") {
      elements.flowMeta.textContent = "Loading flows...";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${columnCount}">Loading flows...</td></tr>`;
      return;
    }

    if (state.openState === "error") {
      elements.flowMeta.textContent = "No flows available after open failure.";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="${columnCount}">Open failed. No flows were loaded.</td></tr>`;
      return;
    }

    if (state.openState !== "opened") {
      elements.flowMeta.textContent = "No capture loaded.";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${columnCount}">Open a capture or index to load flows.</td></tr>`;
      return;
    }

    if (flows.length === 0) {
      elements.flowMeta.textContent = "No flows were found in the opened capture.";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${columnCount}">No flows available.</td></tr>`;
      return;
    }

    if (visibleFlows.length === 0) {
      elements.flowMeta.textContent = hasActiveFlowFilters()
        ? `Filtered to 0 of ${formatNumber(flows.length)} flows.`
        : "";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${columnCount}">No flows match the current filter.</td></tr>`;
      return;
    }

    const virtualWindow = renderVirtualizedTableBody({
      tableBody: elements.flowTableBody,
      rows: visibleFlows,
      rowHeight: flowVirtualRowHeight,
      viewportElement: elements.flowTableViewport,
      overscanRows: flowVirtualOverscanRows,
      colspan: columnCount,
      renderRow: (flow) => {
        const selected = state.selectedFlowIndex === flow.flow_index ? " selected" : "";
        const checked = state.checkedFlowIndices.has(flow.flow_index) ? " checked" : "";
        const protocolPathCell = state.showProtocolPathColumn
          ? `<td class="flow-path-cell">${renderProtocolPathCell(flow)}</td>`
          : "";
        return `
          <tr class="flow-row${selected}${checked}" data-flow-index="${flow.flow_index}">
            <td class="flow-check-cell"><input type="checkbox" class="flow-check-input" data-flow-check-index="${flow.flow_index}" ${state.checkedFlowIndices.has(flow.flow_index) ? "checked" : ""} aria-label="Select flow ${flowDisplayNumber(flow)} for batch actions" /></td>
            <td>${flowDisplayNumber(flow)}</td>
            <td>${escapeHtml(formatFlowFamily(flow))}</td>
            <td>${escapeHtml(flow.protocol_text)}</td>
            <td>${escapeHtml(formatProtocolHint(flow))}</td>
            <td>${escapeHtml(flow.service_hint)}</td>
            <td title="${escapeHtml(formatFlowFragmentMarker(flow))}">${escapeHtml(formatFlowFragmentMarker(flow))}</td>
            <td class="flow-endpoint-cell">${renderEndpointCell(flow.address_a, flow.port_a)}</td>
            <td class="flow-endpoint-cell">${renderEndpointCell(flow.address_b, flow.port_b)}</td>
            ${protocolPathCell}
            <td>${formatPlainInteger(flow.packet_count)}</td>
            <td>${formatPlainInteger(flow.total_bytes)}</td>
          </tr>
        `;
      },
    });
    const renderedFlows = virtualWindow.windowRows;
    const selectedFlowVisible = visibleFlows.some((flow) => flow.flow_index === state.selectedFlowIndex);
    const selectedFlowRendered = renderedFlows.some((flow) => flow.flow_index === state.selectedFlowIndex);
    const selectedFlowOutsideRenderedSlice = selectedFlowVisible && !selectedFlowRendered;
    state.flowVirtualWindowStart = virtualWindow.startIndex;
    state.flowVirtualWindowEnd = virtualWindow.endIndex;
    state.flowVirtualizationActive = virtualWindow.virtualizationActive;

    elements.flowMeta.textContent = hasActiveFlowFilters()
      ? `Filtered to ${formatNumber(visibleFlows.length)} of ${formatNumber(flows.length)} flows.`
      : "";
    elements.flowRenderCapBar.classList.remove("is-visible");
    elements.flowRenderCapText.textContent = "";

    for (const row of elements.flowTableBody.querySelectorAll(".flow-row")) {
      row.addEventListener("click", async () => {
        const flowIndex = Number(row.dataset.flowIndex);
        await selectFlow(flowIndex);
      });
    }

    for (const checkbox of elements.flowTableBody.querySelectorAll(".flow-check-input")) {
      checkbox.addEventListener("click", (event) => {
        event.stopPropagation();
      });
      checkbox.addEventListener("change", () => {
        const flowIndex = Number(checkbox.dataset.flowCheckIndex);
        if (checkbox.checked) {
          state.checkedFlowIndices.add(flowIndex);
        } else {
          state.checkedFlowIndices.delete(flowIndex);
        }
        render();
      });
    }
  }

  function renderWiresharkFilter() {
    const showWiresharkFilter = state.settings.show_wireshark_filter_for_selected_flow !== false;
    if (elements.wiresharkFilterRow) {
      elements.wiresharkFilterRow.style.display = showWiresharkFilter ? "grid" : "none";
    }
    if (elements.wiresharkFilterStatusText) {
      elements.wiresharkFilterStatusText.style.display = showWiresharkFilter ? "block" : "none";
    }

    if (!showWiresharkFilter) {
      return;
    }

    const selectedFlow = state.flows.find((flow) => flow.flow_index === state.selectedFlowIndex) || null;
    const filterText = String(selectedFlow?.wireshark_display_filter || "");

    elements.wiresharkFilterStatusText.textContent = state.wiresharkFilterStatusText;
    elements.wiresharkFilterStatusText.className = "status-text";
    if (state.wiresharkFilterStatusKind === "error") {
      elements.wiresharkFilterStatusText.classList.add("is-error");
    } else if (state.wiresharkFilterStatusKind === "success") {
      elements.wiresharkFilterStatusText.classList.add("is-success");
    }

    if (selectedFlow == null) {
      elements.wiresharkFilterText.textContent = "No flow selected.";
      elements.copyWiresharkFilterButton.disabled = true;
      return;
    }

    elements.wiresharkFilterText.textContent = filterText || "No conservative display filter is available for this flow.";
    elements.copyWiresharkFilterButton.disabled = filterText.length === 0;
  }

  function renderPackets() {
    if (state.flowViewTab !== "packets") {
      return;
    }

    const unrecognizedMode = state.unrecognizedPacketsSelected;
    const showMarkerColumn = loadedPacketsHaveMarkers();
    const packetTableColspan = unrecognizedMode ? 5 : (showMarkerColumn ? 7 : 6);
    if (elements.packetDirectionHeader) {
      elements.packetDirectionHeader.style.display = unrecognizedMode ? "none" : "";
    }
    if (elements.packetPayloadHeader) {
      elements.packetPayloadHeader.textContent = unrecognizedMode ? "Original" : "Payload";
    }
    if (elements.packetFlagsHeader) {
      elements.packetFlagsHeader.textContent = unrecognizedMode ? "Parsed up to / Reason" : "Flags";
    }
    if (elements.packetMarkerHeader) {
      elements.packetMarkerHeader.style.display = !unrecognizedMode && showMarkerColumn ? "" : "none";
    }

    if (state.packetState === "loading" && !state.packetLoadingMore) {
      elements.packetMeta.textContent = unrecognizedMode ? "Loading unrecognized packets..." : "Loading packets...";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${packetTableColspan}">Loading packets...</td></tr>`;
      elements.packetLoadMoreButton.disabled = true;
      elements.packetLoadMoreButton.hidden = false;
      return;
    }

    if (state.packetState === "error") {
      elements.packetMeta.textContent = state.packetErrorText || "Failed to load packets.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="${packetTableColspan}">${escapeHtml(state.packetErrorText || "Failed to load packets.")}</td></tr>`;
      elements.packetLoadMoreButton.disabled = true;
      elements.packetLoadMoreButton.hidden = true;
      return;
    }

    if (!unrecognizedMode && state.selectedFlowIndex == null) {
      elements.packetMeta.textContent = "Select a flow to load packets.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${packetTableColspan}">No selected flow.</td></tr>`;
      elements.packetLoadMoreButton.disabled = true;
      elements.packetLoadMoreButton.hidden = true;
      return;
    }

    if (unrecognizedMode && state.openState !== "opened") {
      elements.packetMeta.textContent = "Open a capture or index to inspect unrecognized packets.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${packetTableColspan}">No capture loaded.</td></tr>`;
      elements.packetLoadMoreButton.disabled = true;
      elements.packetLoadMoreButton.hidden = true;
      return;
    }

    if (unrecognizedMode && unrecognizedPacketCount() === 0) {
      elements.packetMeta.textContent = "No unrecognized packets were collected.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${packetTableColspan}">No unrecognized packets.</td></tr>`;
      elements.packetLoadMoreButton.disabled = true;
      elements.packetLoadMoreButton.hidden = true;
      return;
    }

    if (state.packetsTotalCount === 0) {
      elements.packetMeta.textContent = unrecognizedMode ? "Showing 0 of 0 unrecognized packets" : "Showing 0 of 0 packets";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="${packetTableColspan}">${unrecognizedMode ? "No unrecognized packets available." : "No packets available for the selected flow."}</td></tr>`;
      elements.packetLoadMoreButton.disabled = true;
      elements.packetLoadMoreButton.hidden = true;
      return;
    }

    const loadedCount = state.packets.length;
    const totalCount = state.packetsTotalCount;
    elements.packetMeta.textContent = state.packetLoadingMore
      ? `Showing ${loadedCount} of ${totalCount} ${unrecognizedMode ? "unrecognized packets" : "packets"}. Loading more...`
      : `Showing ${loadedCount} of ${totalCount} ${unrecognizedMode ? "unrecognized packets" : "packets"}`;

    elements.packetTableBody.innerHTML = state.packets
      .map((packet) => {
        const selected = state.selectedPacketIndex === packet.packet_index ? " selected" : "";
        const warning = isPacketCaptureTruncated(packet) ? " is-warning" : "";
        const markerText = packetMarkerText(packet);
        const markerBadgeClass = packet.suspected_tcp_retransmission
          ? "packet-marker-badge is-retransmission"
          : "packet-marker-badge";
        const markerContent = markerText
          ? `<span class="${markerBadgeClass}" title="${escapeHtml(markerText)}">${escapeHtml(markerText)}</span>`
          : "";
        if (unrecognizedMode) {
          return `
            <tr class="packet-row${selected}${warning}" data-packet-index="${packet.packet_index}">
              <td>${packet.row_number}</td>
              <td>${escapeHtml(packet.timestamp_text)}</td>
              <td>${packet.captured_length}</td>
              <td>${packet.original_length}</td>
              <td class="packet-reason-cell" title="${escapeHtml(packet.reason_text || "")}">${escapeHtml(packet.reason_text || "")}</td>
            </tr>
          `;
        }

        return `
          <tr class="packet-row${selected}${warning}" data-packet-index="${packet.packet_index}">
            <td>${packet.row_number}</td>
            <td class="packet-direction-cell">${renderPacketDirectionChip(packet.direction_text)}</td>
            <td>${escapeHtml(packet.timestamp_text)}</td>
            <td>${packet.captured_length}</td>
            <td>${packet.payload_length}</td>
            <td class="packet-flags-cell">${renderPacketFlagsChip(packet.tcp_flags_text)}</td>
            ${showMarkerColumn ? `<td class="packet-marker-cell">${markerContent}</td>` : ""}
          </tr>
        `;
      })
      .join("");

    for (const row of elements.packetTableBody.querySelectorAll(".packet-row")) {
      row.addEventListener("click", async () => {
        const packetIndex = Number(row.dataset.packetIndex);
        await selectPacket(packetIndex);
      });
    }

    elements.packetLoadMoreButton.disabled = state.packetState === "loading" || !state.packetCanLoadMore;
    elements.packetLoadMoreButton.textContent = state.packetLoadingMore ? "Loading..." : "Load More";
    elements.packetLoadMoreButton.hidden = !state.packetCanLoadMore;
  }

  function renderStream() {
    if (state.flowViewTab !== "stream") {
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.unrecognizedPacketsSelected) {
      elements.packetMeta.textContent = "Stream view is unavailable for unrecognized packets.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state">Stream reconstruction is unavailable for unrecognized packets.</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.openState === "opening" || state.streamState === "loading") {
      elements.packetMeta.textContent = "Loading stream items...";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state">Loading stream items...</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.openState === "error") {
      elements.packetMeta.textContent = "No stream view is available after open failure.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state is-error">Open failed. Stream items were cleared.</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.openState !== "opened") {
      elements.packetMeta.textContent = "Open a capture or index to inspect stream items.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state">Open a capture or index to load stream items.</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.selectedFlowIndex == null) {
      elements.packetMeta.textContent = "Select a flow to inspect stream items.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state">No selected flow.</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamState === "error") {
      elements.packetMeta.textContent = state.streamErrorText || "Failed to load stream items.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state is-error">${escapeHtml(state.streamErrorText || "Failed to load stream items.")}</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamState === "unavailable") {
      elements.packetMeta.textContent = state.streamUnavailableText || "Stream view is unavailable for this flow.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state is-error">${escapeHtml(state.streamUnavailableText || "Stream view is unavailable for this flow.")}</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamState === "idle") {
      elements.packetMeta.textContent = "Stream items load on demand for the selected flow.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state">Stream items have not been loaded for this flow yet.</div>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamItems.length === 0) {
      elements.packetMeta.textContent = "No stream items are available for the selected flow.";
      elements.streamTableBody.innerHTML = `<div class="stream-list-state">No stream items available for this flow.</div>`;
      elements.streamLoadMoreButton.disabled = !state.streamCanLoadMore;
      return;
    }

    if (state.streamPartiallyLoaded) {
      elements.packetMeta.textContent = state.streamTotalItemCount > 0
        ? `Showing ${formatNumber(state.streamLoadedItemCount)} of ${formatNumber(state.streamTotalItemCount)} stream items.`
        : `Showing first ${formatNumber(state.streamLoadedItemCount)} stream items.`;
    } else {
      elements.packetMeta.textContent = `Showing all ${formatNumber(state.streamTotalItemCount || state.streamLoadedItemCount)} stream items.`;
    }

    if (state.streamPacketWindowPartial) {
      elements.packetMeta.textContent += ` Built from the first ${formatNumber(state.streamPacketWindowCount)} packets.`;
    }

    elements.streamTableBody.innerHTML = state.streamItems
      .map((item) => {
        const sourcePacketRefs = formatStreamSourcePacketRefs(item);
        const constrictedNotes = formatStreamConstrictedNotes(item);
        const sourcePacketSummary = item.source_packets_text || (item.packet_count > 1 ? `${formatNumber(item.packet_count)} packets` : "1 packet");
        const compactSourcePacketSummary = compactStreamSourcePacketsText(sourcePacketSummary);
        const sourcePacketsTitle = sourcePacketRefs.length > 0
          ? `Source packet indices: ${sourcePacketRefs}`
          : sourcePacketSummary;
        const constrictedTitle = constrictedNotes.length > 0
          ? constrictedNotes.join("\n")
          : (item.has_constricted_contribution ? "Constricted contribution." : "");
        const selected = state.selectedStreamItemIndex === item.stream_item_index ? " selected" : "";
        const directionClass = item.direction_text === "B→A" ? " is-b-to-a" : " is-a-to-b";
        const summaryText = `${formatNumber(item.byte_count)} bytes | ${compactSourcePacketSummary}`;
        const fullSummaryText = `${formatNumber(item.byte_count)} bytes | ${sourcePacketSummary}`;
        const headerMetaText = `#${item.stream_item_index} · ${item.direction_text}`;

        return `
        <div class="stream-card-row${directionClass}">
          <article
            class="stream-card stream-row${selected ? " is-selected" : ""}"
            data-stream-item-index="${item.stream_item_index}"
            title="${escapeHtml([item.label, fullSummaryText, sourcePacketsTitle, constrictedTitle].filter((part) => String(part || "").trim().length > 0).join("\n"))}"
          >
            <div class="stream-card-header">
              <p class="stream-card-title">${escapeHtml(item.label)}</p>
              <span class="stream-card-header-meta">${escapeHtml(headerMetaText)}</span>
            </div>
            <div class="stream-card-summary-row">
              <p class="stream-card-summary">${escapeHtml(summaryText)}</p>
              ${item.has_constricted_contribution ? '<span class="stream-card-badge is-warning">Constricted</span>' : ""}
            </div>
          </article>
        </div>
      `;
      })
      .join("");

    for (const row of elements.streamTableBody.querySelectorAll(".stream-row")) {
      row.addEventListener("click", () => {
        const streamItemIndex = Number(row.dataset.streamItemIndex);
        selectStreamItem(streamItemIndex);
      });
    }

    elements.streamLoadMoreButton.disabled = !state.streamCanLoadMore || state.streamState === "loading";
  }

  function renderStreamDetails() {
    elements.streamDetailsStateText.className = "status-text";
    elements.streamDetailsStateText.classList.add("is-hidden");
    elements.streamDetailsPayloadStateText.className = "status-text compact-status-text";
    elements.streamDetailsProtocolStateText.className = "status-text compact-status-text";
    elements.streamDetailsHeaderPrimary.textContent = "Select a stream item to inspect details.";
    elements.streamDetailsHeaderSecondary.textContent = "";
    elements.streamDetailsHeaderBadge.textContent = "";
    elements.streamDetailsHeaderBadge.classList.add("is-hidden");
    elements.streamDetailsSummaryText.textContent = "Select a stream item to inspect details.";
    elements.streamDetailsPayloadStateText.textContent = "";
    elements.streamDetailsProtocolStateText.textContent = "";
    elements.streamDetailsPayloadText.textContent = "Select a stream item to inspect details.";
    elements.streamDetailsProtocolText.textContent = "Select a stream item to inspect details.";
    elements.streamDetailsPayloadText.classList.remove("is-muted");
    elements.streamDetailsProtocolText.classList.remove("is-muted");

    for (const button of elements.streamDetailsTabButtons) {
      const active = button.dataset.streamDetailsTab === state.streamDetailsTab;
      button.classList.toggle("active", active);
    }
    for (const panel of elements.streamDetailsTabPanels) {
      panel.classList.toggle("active", panel.dataset.streamDetailsPanel === state.streamDetailsTab);
    }

    if (state.flowViewTab !== "stream") {
      return;
    }

    if (state.streamState === "loading") {
      elements.packetDetailsTitle.textContent = "Stream Item Details";
      elements.packetDetailsMeta.textContent = "";
      elements.streamDetailsStateText.classList.remove("is-hidden");
      elements.streamDetailsStateText.textContent = "Loading stream items...";
      elements.streamDetailsSummaryText.textContent = "Loading stream items...";
      elements.streamDetailsPayloadText.textContent = "Loading stream items...";
      elements.streamDetailsProtocolText.textContent = "Loading stream items...";
      return;
    }

    if (state.streamState === "error") {
      elements.packetDetailsTitle.textContent = "Stream Item Details";
      elements.packetDetailsMeta.textContent = "";
      elements.streamDetailsStateText.classList.remove("is-hidden");
      elements.streamDetailsStateText.textContent = state.streamErrorText || "Failed to load stream items.";
      elements.streamDetailsStateText.classList.add("is-error");
      elements.streamDetailsSummaryText.textContent = "Stream item details are unavailable because the stream request failed.";
      elements.streamDetailsPayloadStateText.textContent = "Payload preview unavailable.";
      elements.streamDetailsProtocolStateText.textContent = "Protocol details unavailable.";
      elements.streamDetailsPayloadStateText.classList.add("is-error");
      elements.streamDetailsProtocolStateText.classList.add("is-error");
      elements.streamDetailsPayloadText.textContent = "Stream payload is unavailable because the stream request failed.";
      elements.streamDetailsProtocolText.textContent = "Stream protocol details are unavailable because the stream request failed.";
      elements.streamDetailsPayloadText.classList.add("is-muted");
      elements.streamDetailsProtocolText.classList.add("is-muted");
      return;
    }

    if (state.streamState === "unavailable") {
      elements.packetDetailsTitle.textContent = "Stream Item Details";
      elements.packetDetailsMeta.textContent = "";
      elements.streamDetailsStateText.classList.remove("is-hidden");
      elements.streamDetailsStateText.textContent = state.streamUnavailableText || "Stream item details are unavailable.";
      elements.streamDetailsStateText.classList.add("is-error");
      elements.streamDetailsSummaryText.textContent = state.streamUnavailableText || "Stream item details are unavailable.";
      elements.streamDetailsPayloadStateText.textContent = state.streamUnavailableText || "Stream payload is unavailable.";
      elements.streamDetailsProtocolStateText.textContent = state.streamUnavailableText || "Stream protocol details are unavailable.";
      elements.streamDetailsPayloadStateText.classList.add("is-error");
      elements.streamDetailsProtocolStateText.classList.add("is-error");
      elements.streamDetailsPayloadText.textContent = state.streamUnavailableText || "Stream payload is unavailable.";
      elements.streamDetailsProtocolText.textContent = state.streamUnavailableText || "Stream protocol details are unavailable.";
      elements.streamDetailsPayloadText.classList.add("is-muted");
      elements.streamDetailsProtocolText.classList.add("is-muted");
      return;
    }

    if (state.selectedStreamItem == null) {
      elements.packetDetailsTitle.textContent = "Stream Item Details";
      elements.packetDetailsMeta.textContent = "";
      elements.streamDetailsStateText.textContent = "";
      elements.streamDetailsPayloadText.textContent = "Select a stream item to inspect details.";
      elements.streamDetailsProtocolText.textContent = "Select a stream item to inspect details.";
      elements.streamDetailsPayloadText.classList.add("is-muted");
      elements.streamDetailsProtocolText.classList.add("is-muted");
      return;
    }

    const item = state.selectedStreamItemDetails || state.selectedStreamItem;
    elements.packetDetailsTitle.textContent = "Stream Item Details";
    elements.packetDetailsMeta.textContent = "";
    elements.streamDetailsStateText.textContent = "";
    elements.streamDetailsHeaderPrimary.textContent = item.label || "Stream item";
    elements.streamDetailsHeaderSecondary.textContent = item.header_secondary_text || `${formatNumber(item.byte_count)} bytes`;
    elements.streamDetailsHeaderBadge.textContent = item.badge_text || "";
    elements.streamDetailsHeaderBadge.classList.toggle("is-hidden", String(item.badge_text || "").trim().length === 0);
    elements.streamDetailsHeaderBadge.classList.toggle("is-warning", String(item.badge_text || "").trim() === "Constricted");
    elements.streamDetailsPayloadTabButton.textContent = item.payload_tab_title || "Payload";
    elements.streamDetailsSummaryText.textContent = item.summary_text || "No summary details are available for this stream item.";

    if (state.streamDetailsState === "loading") {
      elements.streamDetailsPayloadStateText.textContent = "Loading payload details...";
      elements.streamDetailsProtocolStateText.textContent = "Loading protocol details...";
      elements.streamDetailsPayloadText.textContent = "Loading payload details...";
      elements.streamDetailsProtocolText.textContent = "Loading protocol details...";
      elements.streamDetailsPayloadText.classList.add("is-muted");
      elements.streamDetailsProtocolText.classList.add("is-muted");
      return;
    }

    if (state.streamDetailsState === "error" && state.streamDetailsErrorText) {
      elements.streamDetailsStateText.classList.remove("is-hidden");
      elements.streamDetailsStateText.classList.add("is-error");
      elements.streamDetailsStateText.textContent = state.streamDetailsErrorText;
    }

    if (item.payload_preview_text) {
      elements.streamDetailsPayloadText.textContent = item.payload_preview_text;
    } else {
      elements.streamDetailsPayloadStateText.textContent = item.payload_preview_unavailable_text || "Payload is not available for this stream item.";
      elements.streamDetailsPayloadStateText.classList.add("is-error");
      elements.streamDetailsPayloadText.textContent = item.payload_preview_unavailable_text || "Payload is not available for this stream item.";
      elements.streamDetailsPayloadText.classList.add("is-muted");
    }

    if (item.protocol_details_text) {
      elements.streamDetailsProtocolText.textContent = item.protocol_details_text;
    } else {
      elements.streamDetailsProtocolStateText.textContent = "Protocol details are not available for this stream item.";
      elements.streamDetailsProtocolStateText.classList.add("is-error");
      elements.streamDetailsProtocolText.textContent = "Protocol details are not available for this stream item.";
      elements.streamDetailsProtocolText.classList.add("is-muted");
    }
  }

  function fallbackPacketSummaryText(selectedPacket, details, sourceAvailability) {
    const lines = [
      "Packet",
      `  Packet index in file: ${selectedPacket.packet_index}`,
      `  Time: ${details?.timestamp_text || selectedPacket.timestamp_text || "-"}`,
      `  Captured Length: ${details?.captured_length ?? selectedPacket.captured_length}`,
      `  Original Length: ${details?.original_length ?? selectedPacket.original_length}`,
    ];

    const warnings = [];
    if (selectedPacket?.is_ip_fragmented) {
      warnings.push("Packet is IP-fragmented");
    }
    if ((details?.captured_length ?? selectedPacket.captured_length) !== (details?.original_length ?? selectedPacket.original_length)) {
      warnings.push("Packet is truncated in capture");
    }
    if (details?.checksum_validation_enabled && Array.isArray(details?.checksum_warning_lines)) {
      warnings.push(...details.checksum_warning_lines);
    }
    if (!details?.source_capture_accessible && sourceAvailability?.expected_source_capture_path) {
      warnings.push(`Byte-backed packet details are unavailable until the source capture is attached/readable: ${sourceAvailability.expected_source_capture_path}`);
    }

    if (warnings.length > 0) {
      lines.push("", "Warnings");
      for (const warning of warnings) {
        lines.push(`  ${warning}`);
      }
    }

    return lines.join("\n");
  }

  function buildSummaryLayerOccurrences(layers) {
    const occurrences = new Map();

    function visit(layerList) {
      for (const layer of layerList) {
        const layerId = String(layer?.id || "").trim();
        if (!layerId) {
          continue;
        }

        const nextIndex = occurrences.get(layerId) || 0;
        occurrences.set(layerId, nextIndex + 1);

        const children = Array.isArray(layer?.children) ? layer.children : [];
        if (children.length > 0) {
          visit(children);
        }
      }
    }

    visit(Array.isArray(layers) ? layers : []);
    return occurrences;
  }

  function buildSummaryLayerIdentity(layer, index, totalCount) {
    const layerId = String(layer?.id || "").trim() || "layer";
    if (layerId === "warnings") {
      return "warnings";
    }
    if (layerId !== "vlan" && totalCount <= 1) {
      return layerId;
    }
    return `${layerId}#${index}`;
  }

  function buildSummaryLayerSignature(layers) {
    const occurrences = buildSummaryLayerOccurrences(layers);
    const nextIndexes = new Map();
    const signatureKeys = [];

    function visit(layerList) {
      for (const layer of layerList) {
        const layerId = String(layer?.id || "").trim();
        if (!layerId) {
          continue;
        }

        const index = nextIndexes.get(layerId) || 0;
        nextIndexes.set(layerId, index + 1);
        const identity = buildSummaryLayerIdentity(layer, index, occurrences.get(layerId) || 1);
        if (identity !== "warnings") {
          signatureKeys.push(identity);
        }

        const children = Array.isArray(layer?.children) ? layer.children : [];
        if (children.length > 0) {
          visit(children);
        }
      }
    }

    visit(Array.isArray(layers) ? layers : []);
    return signatureKeys.join("|");
  }

  function getPacketSummaryExpansionProfile(signature) {
    return state.packetSummaryExpansionProfiles.get(signature) || null;
  }

  function collectExpandedPacketSummaryLayerKeys(layers) {
    const expandedLayerKeys = new Set();

    function visit(layerList) {
      for (const layer of layerList) {
        const layerKey = String(layer?.expansion_key || "");
        if (layerKey && layerKey !== "warnings" && layer?.expanded_by_default !== false) {
          expandedLayerKeys.add(layerKey);
        }

        const children = Array.isArray(layer?.children) ? layer.children : [];
        if (children.length > 0) {
          visit(children);
        }
      }
    }

    visit(Array.isArray(layers) ? layers : []);
    return expandedLayerKeys;
  }

  function rememberPacketSummaryExpansion(signature, layerKey, expanded, isWarning, currentLayers = []) {
    if (!signature) {
      return;
    }

    let profile = state.packetSummaryExpansionProfiles.get(signature);
    if (!profile) {
      profile = {
        expandedLayerKeys: new Set(),
        hasExpandedLayerProfile: false,
        warningExpanded: undefined,
      };
      state.packetSummaryExpansionProfiles.set(signature, profile);
    }

    if (isWarning) {
      profile.warningExpanded = expanded;
      return;
    }

    if (!profile.hasExpandedLayerProfile) {
      profile.expandedLayerKeys = collectExpandedPacketSummaryLayerKeys(currentLayers);
    }

    profile.hasExpandedLayerProfile = true;
    if (expanded) {
      profile.expandedLayerKeys.add(layerKey);
    } else {
      profile.expandedLayerKeys.delete(layerKey);
    }
  }

  function applyPacketSummaryExpansionProfile(layers, signature) {
    const occurrences = buildSummaryLayerOccurrences(layers);
    const nextIndexes = new Map();
    const profile = getPacketSummaryExpansionProfile(signature);

    function decorate(layerList) {
      return layerList.map((layer) => {
        const layerId = String(layer?.id || "").trim();
        const index = nextIndexes.get(layerId) || 0;
        nextIndexes.set(layerId, index + 1);
        const layerKey = buildSummaryLayerIdentity(layer, index, occurrences.get(layerId) || 1);
        const children = Array.isArray(layer?.children) ? decorate(layer.children) : [];

        let expandedByDefault = layer?.expanded_by_default !== false;
        if (profile) {
          if (layerKey === "warnings") {
            expandedByDefault = profile.warningExpanded !== undefined
              ? Boolean(profile.warningExpanded)
              : expandedByDefault;
          } else if (profile.hasExpandedLayerProfile) {
            expandedByDefault = profile.expandedLayerKeys.has(layerKey);
          }
        }

        return {
          ...layer,
          children,
          expanded_by_default: expandedByDefault,
          expansion_key: layerKey,
        };
      });
    }

    return decorate(Array.isArray(layers) ? layers : []);
  }

  function renderPacketSummaryField(field) {
    const label = String(field?.label || "").trim();
    const value = String(field?.value || "");
    if (!label) {
      return `
        <div class="packet-summary-field packet-summary-field-full">
          <span class="packet-summary-field-value">${escapeHtml(value)}</span>
        </div>
      `;
    }

    return `
      <div class="packet-summary-field">
        <span class="packet-summary-field-label">${escapeHtml(label)}</span>
        <span class="packet-summary-field-value">${escapeHtml(value)}</span>
      </div>
    `;
  }

  function renderPacketSummaryLayer(layer) {
    const fields = Array.isArray(layer?.fields) ? layer.fields : [];
    const children = Array.isArray(layer?.children) ? layer.children : [];
    const markerText = String(layer?.marker_text || "").trim();
    const expansionKey = String(layer?.expansion_key || "");
    const childHtml = children.length > 0
      ? `
        <div class="packet-summary-children">
          ${children.map((child) => renderPacketSummaryLayer(child)).join("")}
        </div>
      `
      : "";

    return `
      <details class="packet-summary-layer${layer?.warning ? " is-warning" : ""}" data-expansion-key="${escapeHtml(expansionKey)}"${layer?.expanded_by_default === false ? "" : " open"}>
        <summary class="packet-summary-layer-header">
          <span class="packet-summary-layer-title">${escapeHtml(String(layer?.title || ""))}</span>
          ${markerText ? `<span class="packet-summary-layer-marker${layer?.warning ? " is-warning" : ""}">${escapeHtml(markerText)}</span>` : ""}
        </summary>
        <div class="packet-summary-layer-body">
          <div class="packet-summary-fields">
            ${fields.map((field) => renderPacketSummaryField(field)).join("")}
          </div>
          ${childHtml}
        </div>
      </details>
    `;
  }

  function renderPacketSummary(container, details, selectedPacket, sourceAvailability) {
    const layers = Array.isArray(details?.summary_layers) ? details.summary_layers : [];
    if (layers.length > 0) {
      const signature = buildSummaryLayerSignature(layers);
      const decoratedLayers = applyPacketSummaryExpansionProfile(layers, signature);
      container.innerHTML = `<div class="packet-summary-layers" data-summary-signature="${escapeHtml(signature)}">${decoratedLayers.map((layer) => renderPacketSummaryLayer(layer)).join("")}</div>`;
      for (const detailsElement of container.querySelectorAll(".packet-summary-layer")) {
        detailsElement.addEventListener("toggle", () => {
          rememberPacketSummaryExpansion(
            signature,
            String(detailsElement.dataset.expansionKey || ""),
            detailsElement.open,
            detailsElement.classList.contains("is-warning"),
            decoratedLayers
          );
        });
      }
      return;
    }

    const summaryText = String(details?.summary_text || "").trim() || fallbackPacketSummaryText(selectedPacket, details, sourceAvailability);
    container.innerHTML = `<pre class="details-pre packet-summary-pre">${escapeHtml(summaryText)}</pre>`;
  }

  function renderPacketDetails() {
    const details = state.packetDetails;
    const packetDetailsTitle = String(details?.details_title || "Selected Packet Details");
    const payloadTabTitle = String(details?.payload_tab_title || "Payload");

    elements.packetDetailsTitle.textContent = packetDetailsTitle;
    elements.packetDetailsPayloadTabButton.textContent = payloadTabTitle;
    elements.packetDetailsStateText.className = "status-text";
    elements.packetDetailsRawStateText.className = "status-text compact-status-text";
    elements.packetDetailsPayloadStateText.className = "status-text compact-status-text";
    elements.packetDetailsProtocolStateText.className = "status-text compact-status-text";
    elements.packetDetailsSummary.innerHTML = "";
    elements.packetDetailsRawStateText.textContent = "";
    elements.packetDetailsPayloadStateText.textContent = "";
    elements.packetDetailsProtocolStateText.textContent = "";
    elements.packetDetailsRawText.classList.remove("is-muted");
    elements.packetDetailsPayloadText.classList.remove("is-muted");
    elements.packetDetailsProtocolText.classList.remove("is-muted");

    if (state.packetDetailsState === "loading") {
      elements.packetDetailsMeta.textContent = state.selectedPacketIndex == null
        ? "Loading packet details..."
        : `Loading details for packet ${state.selectedPacketIndex}...`;
      elements.packetDetailsStateText.textContent = "Loading packet details...";
      elements.packetDetailsRawStateText.textContent = "Loading raw bytes...";
      elements.packetDetailsPayloadStateText.textContent = "Loading payload bytes...";
      elements.packetDetailsProtocolStateText.textContent = "Loading protocol details...";
      elements.packetDetailsRawText.textContent = "Loading packet details...";
      elements.packetDetailsProtocolText.textContent = "Loading packet details...";
      elements.packetDetailsPayloadText.textContent = "Loading packet details...";
      return;
    }

    if (state.selectedPacketRow == null) {
      elements.packetDetailsMeta.textContent = "Select a packet to inspect details.";
      elements.packetDetailsStateText.textContent = "";
      elements.packetDetailsRawText.textContent = "No packet selected.";
      elements.packetDetailsProtocolText.textContent = "No packet selected.";
      elements.packetDetailsPayloadText.textContent = "No packet selected.";
      elements.packetDetailsRawText.classList.add("is-muted");
      elements.packetDetailsProtocolText.classList.add("is-muted");
      elements.packetDetailsPayloadText.classList.add("is-muted");
      return;
    }

    const selectedPacket = state.selectedPacketRow;
    const sourceAvailability = packetDetailsSourceAvailability(details);
    renderPacketSummary(elements.packetDetailsSummary, details, selectedPacket, sourceAvailability);

    if (state.packetDetailsState === "error") {
      elements.packetDetailsMeta.textContent = `Packet ${selectedPacket.packet_index} details failed to load.`;
      elements.packetDetailsStateText.textContent = state.packetDetailsErrorText || "Failed to load packet details.";
      elements.packetDetailsStateText.classList.add("is-error");
      elements.packetDetailsRawStateText.textContent = "Raw bytes unavailable.";
      elements.packetDetailsPayloadStateText.textContent = "Payload bytes unavailable.";
      elements.packetDetailsProtocolStateText.textContent = "Protocol details unavailable.";
      elements.packetDetailsRawStateText.classList.add("is-error");
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsProtocolStateText.classList.add("is-error");
      elements.packetDetailsRawText.textContent = "Raw packet bytes are unavailable because the backend request failed.";
      elements.packetDetailsProtocolText.textContent = "Packet details are unavailable because the backend request failed.";
      elements.packetDetailsPayloadText.textContent = "Packet payload bytes are unavailable because the backend request failed.";
      elements.packetDetailsRawText.classList.add("is-muted");
      elements.packetDetailsProtocolText.classList.add("is-muted");
      elements.packetDetailsPayloadText.classList.add("is-muted");
      return;
    }

    const explicitProtocolText = String(details?.protocol_details_text || "").trim();
    const protocolSections = explicitProtocolText
      ? [explicitProtocolText]
      : [
          details?.link_summary_text,
          details?.network_summary_text,
          details?.transport_summary_text,
        ].filter((value) => value && value.trim().length > 0);
    const protocolText = protocolSections.length > 0
      ? protocolSections.join("\n\n")
      : "No additional protocol details are available for this packet.";

    if (state.packetDetailsState === "unavailable") {
      const unavailableText = details?.unavailable_text
        || (sourceAvailability.expected_source_capture_path
          ? `Byte-backed packet details are unavailable until the source capture is attached/readable: ${sourceAvailability.expected_source_capture_path}`
          : "Packet details are unavailable for this session.");
      elements.packetDetailsMeta.textContent = `Packet ${selectedPacket.packet_index} metadata loaded, byte-backed details unavailable.`;
      elements.packetDetailsStateText.textContent = unavailableText;
      elements.packetDetailsStateText.classList.add("is-error");
      elements.packetDetailsRawStateText.textContent = details?.raw_preview_unavailable_text || unavailableText;
      elements.packetDetailsPayloadStateText.textContent = details?.payload_preview_unavailable_text || unavailableText;
      elements.packetDetailsProtocolStateText.textContent = unavailableText;
      elements.packetDetailsRawStateText.classList.add("is-error");
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsProtocolStateText.classList.add("is-error");
      elements.packetDetailsRawText.textContent = details?.raw_preview_unavailable_text || unavailableText;
      elements.packetDetailsProtocolText.textContent = details?.protocol_details_text || "Byte-backed protocol details are unavailable.";
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_unavailable_text || "Packet payload bytes are unavailable.";
      elements.packetDetailsRawText.classList.add("is-muted");
      if (!details?.protocol_details_text) {
        elements.packetDetailsProtocolText.classList.add("is-muted");
      }
      elements.packetDetailsPayloadText.classList.add("is-muted");
      return;
    }

    const rawLoaded = Boolean(details?.raw_preview_available);
    const payloadLoaded = Boolean(details?.payload_preview_available);
    elements.packetDetailsMeta.textContent = `Packet ${selectedPacket.packet_index} details loaded.`;
    elements.packetDetailsStateText.textContent = "";
    elements.packetDetailsProtocolStateText.textContent = protocolSections.length > 0
      ? "Protocol details loaded."
      : "No additional protocol details are available.";
    elements.packetDetailsProtocolText.textContent = protocolText;
    if (protocolSections.length === 0) {
      elements.packetDetailsProtocolText.classList.add("is-muted");
    }

    if (rawLoaded) {
      elements.packetDetailsRawStateText.textContent = "Raw bytes loaded.";
      elements.packetDetailsRawText.textContent = details?.raw_preview_text || "";
    } else {
      elements.packetDetailsRawStateText.textContent = details?.raw_preview_unavailable_text || "Raw bytes are unavailable.";
      elements.packetDetailsRawStateText.classList.add("is-error");
      elements.packetDetailsRawText.textContent = details?.raw_preview_unavailable_text || "Raw bytes are unavailable.";
      elements.packetDetailsRawText.classList.add("is-muted");
    }

    if (payloadLoaded) {
      elements.packetDetailsPayloadStateText.textContent = "Payload bytes loaded.";
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_text || "";
    } else if (details?.payload_preview_no_payload) {
      elements.packetDetailsPayloadStateText.textContent = "No payload is available for this packet.";
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_unavailable_text || "No transport payload is available for this packet.";
      elements.packetDetailsPayloadText.classList.add("is-muted");
    } else {
      elements.packetDetailsPayloadStateText.textContent = details?.payload_preview_unavailable_text || "No payload bytes are available.";
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_unavailable_text || "No payload bytes are available.";
      elements.packetDetailsPayloadText.classList.add("is-muted");
    }
  }

  function renderSummaryRows(container, items) {
    container.innerHTML = items
      .map(([label, value]) => `
        <div class="summary-row">
          <span class="summary-label">${escapeHtml(label)}</span>
          <span class="summary-value">${escapeHtml(value)}</span>
        </div>
      `)
      .join("");
  }

  function renderAnalysisMetricMatrix(container, rows) {
    container.innerHTML = `
      <table class="data-table compact-stats-table analysis-matrix-table">
        <thead>
          <tr>
            <th>Metric</th>
            <th>All</th>
            <th>A-&gt;B</th>
            <th>B-&gt;A</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(([label, allValue, aToBValue, bToAValue]) => `
            <tr>
              <td>${escapeHtml(label)}</td>
              <td>${escapeHtml(allValue || "-")}</td>
              <td>${escapeHtml(aToBValue || "-")}</td>
              <td>${escapeHtml(bToAValue || "-")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  function renderAnalysisOverview(container, analysis) {
    const serviceHint = analysisSelectedFlowServiceHint(analysis);
    const leftRows = [
      ["Total Packets", analysis.total_packets_text || formatNumber(analysis.total_packets)],
      ["Original Bytes", analysis.total_bytes_text || formatNumber(analysis.total_bytes)],
      ["Captured Bytes", analysis.captured_bytes_text || formatNumber(analysis.captured_bytes)],
      ["Protocol Hint", analysis.protocol_hint_display || "-"],
      ["Service Hint", serviceHint || "-"],
    ];
    const rightRows = [
      ["First Packet", analysis.first_packet_time_text || "-"],
      ["Last Packet", analysis.last_packet_time_text || "-"],
      ["Duration", analysis.duration_text || "-"],
      ["Largest Gap", analysis.largest_gap_text || "-"],
      ["Packets Considered", analysis.packets_considered_text || "-"],
    ];

    container.innerHTML = `
      <p class="analysis-overview-primary">${escapeHtml(analysis.endpoint_summary_text || "-")}</p>
      <p class="analysis-overview-secondary">Protocol: ${escapeHtml(formatAnalysisProtocolLine(analysis))}</p>
      <div class="analysis-overview-grid">
        <div class="analysis-overview-column">
          ${leftRows.map(([label, value]) => `
            <div class="summary-row">
              <span class="summary-label">${escapeHtml(label)}</span>
              <span class="summary-value">${escapeHtml(value)}</span>
            </div>
          `).join("")}
        </div>
        <div class="analysis-overview-column">
          ${rightRows.map(([label, value]) => `
            <div class="summary-row">
              <span class="summary-label">${escapeHtml(label)}</span>
              <span class="summary-value">${escapeHtml(value)}</span>
            </div>
          `).join("")}
        </div>
      </div>
    `;
  }

  function renderAnalysisDirectional(container, analysis) {
    container.innerHTML = `
      <div class="analysis-directional-group analysis-directional-counts-group">
        <p class="analysis-directional-group-title">Counts</p>
        <table class="analysis-directional-counts-table">
          <thead>
            <tr>
              <th></th>
              <th>A-&gt;B</th>
              <th>B-&gt;A</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Packets</td>
              <td>${escapeHtml(analysis.packets_a_to_b_text || formatNumber(analysis.packets_a_to_b))}</td>
              <td>${escapeHtml(analysis.packets_b_to_a_text || formatNumber(analysis.packets_b_to_a))}</td>
            </tr>
            <tr>
              <td>Bytes</td>
              <td>${escapeHtml(analysis.bytes_a_to_b_text || formatNumber(analysis.bytes_a_to_b))}</td>
              <td>${escapeHtml(analysis.bytes_b_to_a_text || formatNumber(analysis.bytes_b_to_a))}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="analysis-directional-group">
        <p class="analysis-directional-group-title">Ratios</p>
        <div class="analysis-directional-rows">
          <div class="analysis-directional-row">
            <span class="analysis-directional-label">Packet Ratio</span>
            <span class="analysis-directional-value">${escapeHtml(analysis.packet_ratio_text || "-")}</span>
          </div>
          <div class="analysis-directional-row">
            <span class="analysis-directional-label">Byte Ratio</span>
            <span class="analysis-directional-value">${escapeHtml(analysis.byte_ratio_text || "-")}</span>
          </div>
        </div>
      </div>
      <div class="analysis-directional-group">
        <p class="analysis-directional-group-title">Dominance</p>
        <div class="analysis-directional-rows">
          <div class="analysis-directional-row">
            <span class="analysis-directional-label">Packet Direction</span>
            <span class="analysis-directional-value">${escapeHtml(analysis.packet_direction_text || "-")}</span>
          </div>
          <div class="analysis-directional-row">
            <span class="analysis-directional-label">Data Direction</span>
            <span class="analysis-directional-value">${escapeHtml(analysis.data_direction_text || "-")}</span>
          </div>
        </div>
      </div>
    `;
  }

  function renderAnalysisProtocolPanel(container, analysis) {
    const hint = String(analysis?.protocol_hint_display || "").trim().toUpperCase();
    const version = String(analysis?.protocol_version_text || "").trim();
    const service = analysisProtocolServiceValue(analysis);
    const fallback = String(analysis?.protocol_fallback_text || "").trim();
    const hasTcpCounts = Boolean(analysis?.has_tcp_control_counts);
    const isQuic = hint === "QUIC";
    const isTls = hint === "TLS" || version.toUpperCase().includes("TLS");

    if (isQuic) {
      renderSummaryRows(container, [
        ["QUIC Version", version || "-"],
        ["SNI / Service", service || "-"],
      ]);
      return;
    }

    if (isTls || hasTcpCounts) {
      const rows = [];
      if (version) {
        rows.push(["TLS Version", version]);
      }
      if (service) {
        rows.push(["SNI / Service", service]);
      }
      if (hasTcpCounts) {
        rows.push(["SYN Packets", analysis.tcp_syn_packets_text || formatNumber(analysis.tcp_syn_packets)]);
        rows.push(["FIN Packets", analysis.tcp_fin_packets_text || formatNumber(analysis.tcp_fin_packets)]);
        rows.push(["RST Packets", analysis.tcp_rst_packets_text || formatNumber(analysis.tcp_rst_packets)]);
      }
      renderSummaryRows(container, rows);
      return;
    }

    const rows = [];
    if (version) {
      rows.push(["Version", version]);
    }
    if (service) {
      rows.push(["SNI / Service", service]);
    }
    if (fallback) {
      rows.push(["Notes", fallback]);
    }
    renderSummaryRows(container, rows);
  }

  function histogramCountForMode(row, mode) {
    if (mode === "a_to_b") {
      return Number(row?.count_a_to_b ?? 0);
    }
    if (mode === "b_to_a") {
      return Number(row?.count_b_to_a ?? 0);
    }
    return Number(row?.count_all ?? 0);
  }

  function renderAnalysisHistogram(section, rowsContainer, maxLabel, rows, mode, fillClassName = "") {
    if (!rows || rows.length === 0) {
      section.style.display = "";
      maxLabel.textContent = "";
      rowsContainer.innerHTML = `<div class="analysis-histogram-empty">No histogram rows are available.</div>`;
      return;
    }

    const counts = rows.map((row) => histogramCountForMode(row, mode));
    const maxCount = counts.reduce((currentMax, value) => Math.max(currentMax, value), 0);
    section.style.display = "";
    maxLabel.textContent = `max: ${formatNumber(maxCount)}`;
    rowsContainer.innerHTML = rows
      .map((row) => {
        const count = histogramCountForMode(row, mode);
        const percent = maxCount > 0 ? Math.max((count / maxCount) * 100, count > 0 ? 0.5 : 0) : 0;
        return `
          <div class="analysis-histogram-row">
            <span class="analysis-histogram-label">${escapeHtml(row.bucket_label || "-")}</span>
            <div class="analysis-histogram-track">
              <div class="analysis-histogram-fill${fillClassName ? ` ${fillClassName}` : ""}" style="width: ${percent}%;"></div>
            </div>
            <span class="analysis-histogram-count">${formatNumber(count)}</span>
          </div>
        `;
      })
      .join("");
  }

  function renderAnalysisHistogramModeButtons(prefix, activeMode) {
    const buttonMap = {
      all: elements[`${prefix}ModeAll`],
      a_to_b: elements[`${prefix}ModeAToB`],
      b_to_a: elements[`${prefix}ModeBToA`],
    };

    for (const [mode, button] of Object.entries(buttonMap)) {
      button.classList.toggle("is-active", mode === activeMode);
    }
  }

  function renderAnalysisFlowList() {
    const flows = getSortedFlows(state.flows);

    if (state.openState === "opening" || state.flowState === "loading") {
      elements.analysisFlowMeta.textContent = "Loading flows for analysis...";
      elements.analysisFlowRenderCapBar.classList.remove("is-visible");
      state.analysisFlowVirtualWindowStart = 0;
      state.analysisFlowVirtualWindowEnd = 0;
      state.analysisFlowVirtualizationActive = false;
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="5">Loading analysis flows...</td></tr>`;
      return;
    }

    if (state.openState === "error") {
      elements.analysisFlowMeta.textContent = "No analysis flows available after open failure.";
      elements.analysisFlowRenderCapBar.classList.remove("is-visible");
      state.analysisFlowVirtualWindowStart = 0;
      state.analysisFlowVirtualWindowEnd = 0;
      state.analysisFlowVirtualizationActive = false;
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="5">Open failed. Analysis flows were cleared.</td></tr>`;
      return;
    }

    if (state.openState !== "opened") {
      elements.analysisFlowMeta.textContent = "No capture loaded.";
      elements.analysisFlowRenderCapBar.classList.remove("is-visible");
      state.analysisFlowVirtualWindowStart = 0;
      state.analysisFlowVirtualWindowEnd = 0;
      state.analysisFlowVirtualizationActive = false;
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="5">Open a capture or index to inspect analysis flows.</td></tr>`;
      return;
    }

    if (flows.length === 0) {
      elements.analysisFlowMeta.textContent = "No flows are available for analysis.";
      elements.analysisFlowRenderCapBar.classList.remove("is-visible");
      state.analysisFlowVirtualWindowStart = 0;
      state.analysisFlowVirtualWindowEnd = 0;
      state.analysisFlowVirtualizationActive = false;
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="5">No flows available.</td></tr>`;
      return;
    }

    const virtualWindow = renderVirtualizedTableBody({
      tableBody: elements.analysisFlowTableBody,
      rows: flows,
      rowHeight: analysisFlowVirtualRowHeight,
      viewportElement: elements.analysisFlowTableViewport,
      overscanRows: analysisFlowVirtualOverscanRows,
      colspan: 5,
      renderRow: (flow) => {
        const selected = state.selectedFlowIndex === flow.flow_index ? " selected" : "";
        const hintOrProtocol = formatProtocolHint(flow) || flow.protocol_text || "-";
        const endpointSummary = `${formatEndpoint(flow.address_a, flow.port_a)} <-> ${formatEndpoint(flow.address_b, flow.port_b)}`;
        const titleText = flow.service_hint
          ? `${flow.service_hint}\n${endpointSummary}`
          : endpointSummary;
        return `
          <tr class="flow-row${selected} analysis-flow-row" data-analysis-flow-index="${flow.flow_index}" title="${escapeHtml(titleText)}">
            <td>${flowDisplayNumber(flow)}</td>
            <td>${escapeHtml(hintOrProtocol)}</td>
            <td class="analysis-flow-service-cell" title="${escapeHtml(titleText)}">
              <span class="analysis-flow-primary">${escapeHtml(flow.service_hint || "-")}</span>
              <span class="analysis-flow-secondary">${escapeHtml(endpointSummary)}</span>
            </td>
            <td>${formatPlainInteger(flow.packet_count)}</td>
            <td>${formatPlainInteger(flow.total_bytes)}</td>
          </tr>
        `;
      },
    });
    const renderedFlows = virtualWindow.windowRows;
    const selectedFlowVisible = flows.some((flow) => flow.flow_index === state.selectedFlowIndex);
    const selectedFlowRendered = renderedFlows.some((flow) => flow.flow_index === state.selectedFlowIndex);
    const selectedFlowOutsideRenderedSlice = selectedFlowVisible && !selectedFlowRendered;
    state.analysisFlowVirtualWindowStart = virtualWindow.startIndex;
    state.analysisFlowVirtualWindowEnd = virtualWindow.endIndex;
    state.analysisFlowVirtualizationActive = virtualWindow.virtualizationActive;

    elements.analysisFlowMeta.textContent = state.selectedFlowIndex == null
      ? `Showing ${formatNumber(flows.length)} analysis flows. Select one to load analysis.`
      : `Showing ${formatNumber(flows.length)} analysis flows. Flow ${formatNumber(state.selectedFlowIndex + 1)} is active.`;
    elements.analysisFlowRenderCapBar.classList.remove("is-visible");
    elements.analysisFlowRenderCapText.textContent = "";

    for (const row of elements.analysisFlowTableBody.querySelectorAll(".analysis-flow-row")) {
      row.addEventListener("click", async () => {
        const flowIndex = Number(row.dataset.analysisFlowIndex);
        applyFlowFilterState("");
        await selectFlow(flowIndex);
      });
    }
  }

  function renderAnalysis() {
    renderAnalysisFlowList();
    elements.analysisStateText.className = "status-text";
    elements.analysisFlowSummary.innerHTML = "";
    elements.analysisProtocolPanel.innerHTML = "";
    elements.analysisTrafficTotals.innerHTML = "";
    elements.analysisDirectionSplit.innerHTML = "";
    elements.analysisDerivedMetrics.innerHTML = "";
    elements.analysisTimingSize.innerHTML = "";
    elements.analysisBurstIdleSummary.innerHTML = "";
    elements.analysisRateGraphHeaderText.textContent = "";
    elements.analysisRateGraphContextText.textContent = "";
    elements.analysisRateGraphStatusText.textContent = "";
    elements.analysisRateGraphStatusText.className = "compact-status-text";
    elements.analysisRateGraphSvg.innerHTML = "";
    elements.analysisRateGraphSurface.classList.remove("is-visible");
    elements.analysisRateGraphLegend.style.display = "none";
    elements.analysisPacketSizeHistogramRows.innerHTML = "";
    elements.analysisPacketSizeHistogramMax.textContent = "";
    elements.analysisInterArrivalHistogramRows.innerHTML = "";
    elements.analysisInterArrivalHistogramMax.textContent = "";
    elements.analysisSequencePreviewBody.innerHTML = "";
    elements.analysisExportSequenceCsvStatusText.textContent = state.analysisSequenceExportStatusText;
    elements.analysisExportSequenceCsvStatusText.className = "compact-status-text";
    if (state.analysisSequenceExportStatusKind === "error") {
      elements.analysisExportSequenceCsvStatusText.classList.add("is-error");
    } else if (state.analysisSequenceExportStatusKind === "success") {
      elements.analysisExportSequenceCsvStatusText.classList.add("is-success");
    }
    elements.analysisExportSequenceCsvButton.disabled = !canExportAnalysisSequenceCsv();
    elements.analysisExportSequenceCsvButton.textContent = state.analysisSequenceExportInProgress
      ? "Exporting..."
      : "Export sequence CSV";
    elements.analysisProtocolPanelSection.style.display = "none";
    elements.analysisDerivedMetricsSection.style.display = "none";
    elements.analysisBurstIdleSection.style.display = "none";
    elements.analysisRateGraphSection.style.display = "none";
    elements.analysisTrafficTotalsSection.style.display = "none";
    elements.analysisTimingSizeSection.style.display = "none";
    elements.analysisPacketSizeHistogramSection.style.display = "none";
    elements.analysisInterArrivalHistogramSection.style.display = "none";
    elements.analysisSequencePreviewSection.style.display = "none";
    elements.analysisContent.classList.remove("is-hidden");
    elements.analysisOpenInFlowsButton.disabled = state.selectedFlowIndex == null;
    renderAnalysisRateGraphModeButtons();

    if (state.openState === "opening") {
      elements.analysisMeta.textContent = "Opening capture before selected-flow analysis can run.";
      elements.analysisStateText.textContent = "Opening capture...";
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    if (state.openState === "error") {
      elements.analysisMeta.textContent = "No analysis available after open failure.";
      elements.analysisStateText.textContent = "Open failed. Selected-flow analysis was cleared.";
      elements.analysisStateText.classList.add("is-error");
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    if (state.openState !== "opened") {
      elements.analysisMeta.textContent = "No capture loaded.";
      elements.analysisStateText.textContent = "Open a capture or index to inspect selected-flow analysis.";
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    if (state.flowState === "loaded" && state.flows.length === 0) {
      elements.analysisMeta.textContent = "No flows available.";
      elements.analysisStateText.textContent = "No flows are available for selected-flow analysis.";
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    if (state.selectedFlowIndex == null) {
      elements.analysisMeta.textContent = "No selected flow.";
      elements.analysisStateText.textContent = "Select a flow to inspect analysis.";
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    if (state.analysisState === "loading") {
      elements.analysisMeta.textContent = `Loading analysis for flow ${formatNumber(state.selectedFlowIndex + 1)}...`;
      elements.analysisStateText.textContent = "Loading selected-flow analysis...";
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    if (state.analysisState === "error") {
      elements.analysisMeta.textContent = `Analysis failed for flow ${formatNumber(state.selectedFlowIndex + 1)}.`;
      elements.analysisStateText.textContent = state.analysisErrorText || "Failed to load selected-flow analysis.";
      elements.analysisStateText.classList.add("is-error");
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    if (state.analysisState === "unavailable") {
      elements.analysisMeta.textContent = `Analysis is unavailable for flow ${formatNumber(state.selectedFlowIndex + 1)}.`;
      elements.analysisStateText.textContent = state.analysisUnavailableText || "Analysis is unavailable for the selected flow.";
      elements.analysisStateText.classList.add("is-error");
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    const analysis = state.analysis;
    if (analysis == null || state.analysisState !== "loaded") {
      elements.analysisMeta.textContent = "Selected-flow analysis loads on demand.";
      elements.analysisStateText.textContent = "Open the Analysis tab with a selected flow to load analysis.";
      elements.analysisContent.classList.add("is-hidden");
      return;
    }

    elements.analysisMeta.textContent = `Selected-flow analysis loaded for flow ${formatNumber((analysis.flow_index ?? state.selectedFlowIndex) + 1)}.`;
    elements.analysisStateText.textContent = "";

    renderAnalysisOverview(elements.analysisFlowSummary, analysis);

    const hasProtocolPanel =
      Boolean(analysis.protocol_version_text)
      || Boolean(analysis.protocol_service_text)
      || Boolean(analysis.protocol_fallback_text)
      || Boolean(analysis.has_tcp_control_counts);
    if (hasProtocolPanel) {
      elements.analysisProtocolPanelSection.style.display = "";
      renderAnalysisProtocolPanel(elements.analysisProtocolPanel, analysis);
    }

    const derivedMetricRows = [
      [
        "Packets / sec",
        analysis.packets_per_second_text || "-",
        analysis.packets_per_second_a_to_b_text || "-",
        analysis.packets_per_second_b_to_a_text || "-",
      ],
      [
        "Data Rate",
        analysis.bytes_per_second_text || "-",
        analysis.bytes_per_second_a_to_b_text || "-",
        analysis.bytes_per_second_b_to_a_text || "-",
      ],
      [
        "Avg Packet Size",
        analysis.average_packet_size_text || "-",
        analysis.average_packet_size_a_to_b_text || "-",
        analysis.average_packet_size_b_to_a_text || "-",
      ],
      [
        "Avg Inter-arrival",
        analysis.average_inter_arrival_text || "-",
        "",
        "",
      ],
      [
        "Min Packet Size",
        analysis.min_packet_size_text || "-",
        analysis.min_packet_size_a_to_b_text || "-",
        analysis.min_packet_size_b_to_a_text || "-",
      ],
      [
        "Max Packet Size",
        analysis.max_packet_size_text || "-",
        analysis.max_packet_size_a_to_b_text || "-",
        analysis.max_packet_size_b_to_a_text || "-",
      ],
    ];
    elements.analysisDerivedMetricsSection.style.display = "";
    renderAnalysisMetricMatrix(elements.analysisDerivedMetrics, derivedMetricRows);

    const burstIdleRows = [
      ["Burst Count", analysis.burst_count_text || "-"],
      ["Longest Burst", analysis.longest_burst_packet_count_text || "-"],
      ["Largest Burst Bytes", analysis.largest_burst_bytes_text || "-"],
      ["Idle Gap Count", analysis.idle_gap_count_text || "-"],
      ["Largest Idle Gap", analysis.largest_idle_gap_text || "-"],
    ];
    elements.analysisBurstIdleSection.style.display = "";
    renderSummaryRows(elements.analysisBurstIdleSummary, burstIdleRows);

    renderAnalysisRateGraph(analysis);

    renderAnalysisDirectional(elements.analysisDirectionSplit, analysis);

    renderAnalysisHistogramModeButtons("analysisPacketSizeHistogram", state.analysisPacketSizeHistogramMode);
    renderAnalysisHistogram(
      elements.analysisPacketSizeHistogramSection,
      elements.analysisPacketSizeHistogramRows,
      elements.analysisPacketSizeHistogramMax,
      analysis.packet_size_histogram_rows || [],
      state.analysisPacketSizeHistogramMode,
      "is-packet-size"
    );

    renderAnalysisHistogramModeButtons("analysisInterArrivalHistogram", state.analysisInterArrivalHistogramMode);
    renderAnalysisHistogram(
      elements.analysisInterArrivalHistogramSection,
      elements.analysisInterArrivalHistogramRows,
      elements.analysisInterArrivalHistogramMax,
      analysis.inter_arrival_histogram_rows || [],
      state.analysisInterArrivalHistogramMode
    );

    elements.analysisSequencePreviewSection.style.display = "";
    const sequencePreviewRows = analysis.sequence_preview_rows || [];
    if (sequencePreviewRows.length === 0) {
      elements.analysisSequencePreviewBody.innerHTML = renderStatsStateRow(7, "No sequence preview rows are available.");
    } else {
      elements.analysisSequencePreviewBody.innerHTML = sequencePreviewRows
        .map((row) => `
          <tr>
            <td>${formatNumber(row.flow_packet_number)}</td>
            <td>${escapeHtml(row.direction_text || "-")}</td>
            <td>${escapeHtml(row.delta_time_text || "-")}</td>
            <td>${formatNumber(row.captured_length)}</td>
            <td>${formatNumber(row.original_length)}</td>
            <td>${formatNumber(row.payload_length)}</td>
            <td>${escapeHtml(row.timestamp_text || "-")}</td>
          </tr>
        `)
        .join("");
    }
  }

  function render() {
    const renderSteps = [
      ["menu", renderMenuState],
      ["settings dialog", renderSettingsDialog],
      ["protocol path legend dialog", renderProtocolPathLegendDialog],
      ["smart export dialog", renderSmartExportDialog],
      ["tabs", renderTabs],
      ["flow view tabs", renderFlowViewTabs],
      ["inspector mode", renderInspectorMode],
      ["packet detail tabs", renderPacketDetailsTabs],
      ["flow sort headers", renderFlowSortHeaders],
      ["open state", renderOpenState],
      ["partial-open warning banner", renderPartialOpenWarningBanner],
      ["source warning banner", renderSourceWarningBanner],
      ["status", renderStatus],
    ];

    if (state.activeTab === "flows") {
      clearStatisticsDom();
      clearAnalysisDom();
      renderSteps.push(["flows", renderFlows]);
      renderSteps.push(["Wireshark filter", renderWiresharkFilter]);
      if (state.flowViewTab === "packets") {
        clearStreamTableDom();
        clearStreamDetailsDom();
        renderSteps.push(["packets", renderPackets]);
        renderSteps.push(["packet details", renderPacketDetails]);
      } else {
        clearPacketTableDom();
        clearPacketDetailsDom();
        renderSteps.push(["stream", renderStream]);
        renderSteps.push(["stream details", renderStreamDetails]);
      }
    } else if (state.activeTab === "statistics") {
      clearFlowTableDom();
      clearPacketTableDom();
      clearStreamTableDom();
      clearPacketDetailsDom();
      clearStreamDetailsDom();
      clearAnalysisDom();
      renderSteps.push(["overview", renderOverview]);
    } else if (state.activeTab === "analysis") {
      clearFlowTableDom();
      clearPacketTableDom();
      clearStreamTableDom();
      clearPacketDetailsDom();
      clearStreamDetailsDom();
      clearStatisticsDom();
      renderSteps.push(["analysis", renderAnalysis]);
    }

    for (const [name, renderStep] of renderSteps) {
      try {
        renderStep();
      } catch (error) {
        console.error(`Failed to render ${name}.`, error);
      }
    }
  }

  let flowViewportRenderScheduled = false;
  let analysisViewportRenderScheduled = false;
  let protocolPathStatsViewportRenderScheduled = false;

  function scheduleFlowViewportRender() {
    if (flowViewportRenderScheduled) {
      return;
    }

    flowViewportRenderScheduled = true;
    window.requestAnimationFrame(() => {
      flowViewportRenderScheduled = false;
      if (state.activeTab === "flows") {
        renderFlows();
      }
    });
  }

  function scheduleAnalysisFlowViewportRender() {
    if (analysisViewportRenderScheduled) {
      return;
    }

    analysisViewportRenderScheduled = true;
    window.requestAnimationFrame(() => {
      analysisViewportRenderScheduled = false;
      if (state.activeTab === "analysis") {
        renderAnalysisFlowList();
      }
    });
  }

  function scheduleProtocolPathStatsViewportRender() {
    if (protocolPathStatsViewportRenderScheduled) {
      return;
    }

    protocolPathStatsViewportRenderScheduled = true;
    window.requestAnimationFrame(() => {
      protocolPathStatsViewportRenderScheduled = false;
      if (state.activeTab === "statistics") {
        renderProtocolPathStatsSection();
      }
    });
  }

  async function loadOverviewAndFlows() {
    state.flowState = "loading";
    render();

    const [overview, flows] = await Promise.all([
      invoke("get_overview"),
      invoke("get_flows"),
    ]);

    state.overview = overview;
    state.protocolPathPresentationsById = new Map(
      (Array.isArray(overview?.protocol_path_presentations) ? overview.protocol_path_presentations : [])
        .map((presentation) => [Number(presentation?.protocol_path_id || 0), presentation])
        .filter(([protocolPathId]) => protocolPathId > 0)
    );
    await logMemoryPhase("after_get_overview");
    state.flows = flows || [];
    state.flowState = "loaded";
    await logMemoryPhase("after_get_flows");
  }

  async function loadSelectedFlowPackets(selectionToken = state.flowSelectionRequestToken, options = {}) {
    if (state.unrecognizedPacketsSelected) {
      await loadUnrecognizedPackets(selectionToken, options);
      return;
    }

    if (state.selectedFlowIndex == null) {
      clearPackets();
      render();
      return;
    }

    const append = options.append === true;
    const requestedFlowIndex = state.selectedFlowIndex;
    const requestedOffset = append ? state.packets.length : 0;
    const requestedLimit = packetPageSize;
    const requestToken = ++state.packetRequestToken;
    if (!append) {
      clearPacketDetails();
    }
    state.packetState = "loading";
    state.packetLoadingMore = append && state.packets.length > 0;
    state.packetErrorText = "";
    state.packetOffset = requestedOffset;
    state.diagnosticsPacketRequestOffset = requestedOffset;
    state.diagnosticsPacketRequestLimit = requestedLimit;
    state.diagnosticsPacketReturnedRowCount = 0;
    state.diagnosticsPacketReturnedTotalCount = 0;
    render();
    await logMemoryPhase("packets_request_started");

    try {
      const packetResult = await invoke("get_selected_flow_packets", {
        offset: requestedOffset,
        limit: requestedLimit,
      });

      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.packetRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
        || state.packetOffset !== requestedOffset
      ) {
        return;
      }

      const receivedPackets = packetResult?.packets || [];
      if (append) {
        const existingPacketIndices = new Set(state.packets.map((packet) => packet.packet_index));
        state.packets = state.packets.concat(receivedPackets.filter((packet) => !existingPacketIndices.has(packet.packet_index)));
      } else {
        state.packets = receivedPackets;
      }
      state.packetsTotalCount = packetResult?.total_count || 0;
      state.packetOffset = packetResult?.offset ?? requestedOffset;
      state.packetCanLoadMore = state.packets.length < state.packetsTotalCount;
      state.packetLoadingMore = false;
      state.packetState = "loaded";
      state.diagnosticsPacketReturnedRowCount = receivedPackets.length;
      state.diagnosticsPacketReturnedTotalCount = state.packetsTotalCount;
      await logMemoryPhase("packets_request_finished");
    } catch (error) {
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.packetRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
      ) {
        return;
      }

      state.packets = [];
      state.packetsTotalCount = 0;
      state.packetCanLoadMore = false;
      state.packetLoadingMore = false;
      state.packetState = "error";
      state.packetErrorText = `Failed to load packets: ${String(error)}`;
      setStatus(state.packetErrorText, "error");
      state.diagnosticsPacketReturnedRowCount = 0;
      state.diagnosticsPacketReturnedTotalCount = 0;
      await logMemoryPhase("packets_request_finished");
    }

    render();
    await waitForNextPaint();
    await logMemoryPhase("packets_render_finished");
  }

  async function loadUnrecognizedPackets(selectionToken = state.flowSelectionRequestToken, options = {}) {
    if (!state.unrecognizedPacketsSelected) {
      clearPackets();
      render();
      return;
    }

    const append = options.append === true;
    const requestedOffset = append ? state.packets.length : 0;
    const requestedLimit = packetPageSize;
    const requestToken = ++state.packetRequestToken;
    if (!append) {
      clearPacketDetails();
    }
    state.packetState = "loading";
    state.packetLoadingMore = append && state.packets.length > 0;
    state.packetErrorText = "";
    state.packetOffset = requestedOffset;
    state.diagnosticsPacketRequestOffset = requestedOffset;
    state.diagnosticsPacketRequestLimit = requestedLimit;
    state.diagnosticsPacketReturnedRowCount = 0;
    state.diagnosticsPacketReturnedTotalCount = 0;
    render();

    try {
      const packetResult = await invoke("get_unrecognized_packets", {
        offset: requestedOffset,
        limit: requestedLimit,
      });

      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.packetRequestToken
        || !state.unrecognizedPacketsSelected
        || state.packetOffset !== requestedOffset
      ) {
        return;
      }

      const receivedPackets = packetResult?.packets || [];
      if (append) {
        const existingPacketIndices = new Set(state.packets.map((packet) => packet.packet_index));
        state.packets = state.packets.concat(receivedPackets.filter((packet) => !existingPacketIndices.has(packet.packet_index)));
      } else {
        state.packets = receivedPackets;
      }
      state.packetsTotalCount = packetResult?.total_count || 0;
      state.packetOffset = packetResult?.offset ?? requestedOffset;
      state.packetCanLoadMore = state.packets.length < state.packetsTotalCount;
      state.packetLoadingMore = false;
      state.packetState = "loaded";
      state.diagnosticsPacketReturnedRowCount = receivedPackets.length;
      state.diagnosticsPacketReturnedTotalCount = state.packetsTotalCount;
    } catch (error) {
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.packetRequestToken
        || !state.unrecognizedPacketsSelected
      ) {
        return;
      }

      state.packets = [];
      state.packetsTotalCount = 0;
      state.packetCanLoadMore = false;
      state.packetLoadingMore = false;
      state.packetState = "error";
      state.packetErrorText = `Failed to load unrecognized packets: ${String(error)}`;
      state.diagnosticsPacketReturnedRowCount = 0;
      state.diagnosticsPacketReturnedTotalCount = 0;
      setStatus(state.packetErrorText, "error");
    }

    render();
  }

  async function loadSelectedFlowStream(selectionToken = state.flowSelectionRequestToken) {
    if (state.selectedFlowIndex == null) {
      clearStream();
      render();
      return;
    }

    const requestedFlowIndex = state.selectedFlowIndex;
    const requestToken = ++state.streamRequestToken;
    state.streamState = "loading";
    state.streamErrorText = "";
    state.streamUnavailableText = "";
    render();
    await logMemoryPhase("stream_request_started");

    try {
      const streamResult = await invoke("get_selected_flow_stream", {
        max_packets_to_scan: state.streamRequestedPacketBudget,
        limit: state.streamRequestedItemLimit,
      });
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.streamRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
      ) {
        return;
      }
      const sourceAvailability = streamSourceAvailability(streamResult);
      state.sourceAvailability = sourceAvailability;

      state.streamItems = streamResult?.items || [];
      state.streamLoadedItemCount = streamResult?.loaded_item_count || state.streamItems.length;
      state.streamTotalItemCount = streamResult?.total_item_count || 0;
      state.streamPacketWindowCount = streamResult?.packet_window_count || 0;
      state.streamCanLoadMore = Boolean(streamResult?.can_load_more);
      state.streamPartiallyLoaded = Boolean(streamResult?.stream_partially_loaded);
      state.streamPacketWindowPartial = Boolean(streamResult?.packet_window_partial);
      state.streamLoadedForFlowIndex = state.selectedFlowIndex;
      const previousSelectedStreamItemIndex = state.selectedStreamItemIndex;

      if (streamResult?.error_text) {
        state.streamState = "error";
        state.streamErrorText = streamResult.error_text;
        setStatus(streamResult.error_text, "error");
      } else if (streamResult?.unavailable_text && !streamResult?.stream_available) {
        state.streamState = "unavailable";
        state.streamUnavailableText = streamResult.unavailable_text;
      } else if (!sourceAvailability.byte_backed_inspection_available && !streamResult?.stream_available) {
        state.streamState = "unavailable";
        state.streamUnavailableText = sourceAvailability.expected_source_capture_path
          ? `Stream reconstruction requires the original source capture to be attached and readable: ${sourceAvailability.expected_source_capture_path}`
          : "Stream reconstruction requires the original source capture to be attached and readable.";
      } else {
        state.streamState = "loaded";
        state.streamUnavailableText = streamResult?.unavailable_text || "";
      }

      if (previousSelectedStreamItemIndex != null) {
        const selectedItem = state.streamItems.find((item) => item.stream_item_index === previousSelectedStreamItemIndex) || null;
        state.selectedStreamItemIndex = selectedItem?.stream_item_index ?? null;
        state.selectedStreamItem = selectedItem;
        state.selectedStreamItemDetails = selectedItem;
        state.streamDetailsState = selectedItem ? "loading" : "idle";
        state.streamDetailsErrorText = "";
        if (selectedItem) {
          void loadSelectedStreamItemDetails(selectedItem.stream_item_index, selectionToken);
        }
      } else {
        state.selectedStreamItemIndex = null;
        state.selectedStreamItem = null;
        state.selectedStreamItemDetails = null;
        state.streamDetailsState = "idle";
        state.streamDetailsErrorText = "";
      }
    } catch (error) {
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.streamRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
      ) {
        return;
      }

      state.streamItems = [];
      state.streamState = "error";
      state.streamErrorText = `Failed to load stream items: ${String(error)}`;
      state.streamLoadedForFlowIndex = null;
      state.selectedStreamItemIndex = null;
      state.selectedStreamItem = null;
      state.selectedStreamItemDetails = null;
      state.streamDetailsState = "error";
      state.streamDetailsErrorText = state.streamErrorText;
      setStatus(state.streamErrorText, "error");
    }

    render();
    await logMemoryPhase("stream_request_finished");
    await logMemoryPhase("after_stream_loaded");
  }

  async function loadSelectedFlowAnalysis(selectionToken = state.flowSelectionRequestToken) {
    if (state.selectedFlowIndex == null) {
      clearAnalysis();
      render();
      return;
    }

    const requestedFlowIndex = state.selectedFlowIndex;
    const requestToken = ++state.analysisRequestToken;
    state.analysisState = "loading";
    state.analysisErrorText = "";
    state.analysisUnavailableText = "";
    state.analysis = null;
    render();
    await logMemoryPhase("analysis_request_started");

    try {
      const analysis = await invoke("get_selected_flow_analysis");
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.analysisRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
      ) {
        return;
      }

      state.analysis = analysis;
      state.analysisLoadedForFlowIndex = requestedFlowIndex;

      if (analysis?.error_text) {
        state.analysisState = "error";
        state.analysisErrorText = analysis.error_text;
        setStatus(analysis.error_text, "error");
      } else if (analysis?.unavailable_text || !analysis?.analysis_available) {
        state.analysisState = "unavailable";
        state.analysisUnavailableText = analysis?.unavailable_text || "Analysis is unavailable for the selected flow.";
      } else {
        state.analysisState = "loaded";
      }
    } catch (error) {
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.analysisRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
      ) {
        return;
      }

      state.analysis = null;
      state.analysisLoadedForFlowIndex = null;
      state.analysisState = "error";
      state.analysisErrorText = `Failed to load selected-flow analysis: ${String(error)}`;
      setStatus(state.analysisErrorText, "error");
    }

    render();
    await logMemoryPhase("analysis_request_finished");
    await logMemoryPhase("after_analysis_loaded");
  }

  async function loadSelectedPacketDetails() {
    if (state.selectedPacketIndex == null) {
      clearPacketDetails();
      render();
      return;
    }

    state.packetDetailsState = "loading";
    state.packetDetailsErrorText = "";
    state.packetDetails = null;
    render();

    try {
      const details = state.unrecognizedPacketsSelected
        ? await invoke("get_unrecognized_packet_details", {
          packet_index: state.selectedPacketIndex,
        })
        : await invoke("get_selected_flow_packet_details", {
          packet_index: state.selectedPacketIndex,
          flow_packet_index: Number(state.selectedPacketRow?.row_number || 0),
        });
      const sourceAvailability = packetDetailsSourceAvailability(details);
      state.sourceAvailability = sourceAvailability;

      state.packetDetails = details;
      if (details?.error_text) {
        state.packetDetailsState = "error";
        state.packetDetailsErrorText = details.error_text;
        setStatus(details.error_text, "error");
      } else if (details?.unavailable_text && !details?.details_available) {
        state.packetDetailsState = "unavailable";
      } else if (!sourceAvailability.byte_backed_inspection_available && !details?.details_available) {
        state.packetDetailsState = "unavailable";
      } else if (details?.unavailable_text && !details?.payload_preview_available) {
        state.packetDetailsState = "loaded";
      } else {
        state.packetDetailsState = "loaded";
      }
    } catch (error) {
      state.packetDetails = null;
      state.packetDetailsState = "error";
      state.packetDetailsErrorText = `Failed to load packet details: ${String(error)}`;
      setStatus(state.packetDetailsErrorText, "error");
    }

    render();
  }

  async function selectFlow(flowIndex) {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    const selectionToken = ++state.flowSelectionRequestToken;
    state.selectedFlowIndex = flowIndex;
    state.unrecognizedPacketsSelected = false;
    clearCurrentFlowExportStatusIfPresent();
    clearSmartExportMainStatusIfPresent();
    state.packetOffset = 0;
    clearPackets();
    clearStream();
    clearAnalysis(false);
    setWiresharkFilterStatus("", "neutral");
    state.packetState = state.activeTab === "flows" && state.flowViewTab === "packets" ? "loading" : "idle";
    if (state.activeTab === "flows" && state.flowViewTab === "stream") {
      state.streamState = "loading";
      state.streamErrorText = "";
      state.streamUnavailableText = "";
    }
    if (state.activeTab === "analysis") {
      state.analysisState = "loading";
      state.analysisErrorText = "";
      state.analysisUnavailableText = "";
    }
    render();
    await logMemoryPhase("flow_select_started");
    await waitForNextPaint();

    try {
      const selection = await invoke("select_flow", { flow_index: flowIndex });
      if (selectionToken !== state.flowSelectionRequestToken || state.selectedFlowIndex !== flowIndex) {
        return;
      }

      if (!selection?.selected) {
        state.selectedFlowIndex = null;
        clearPackets();
        clearStream();
        clearAnalysis(false);
        setStatus(`Failed to select flow ${flowIndex}.`, "error");
        render();
        return;
      }

      if (selection?.updated_flow) {
        applyUpdatedFlowRow(selection.updated_flow);
      }

      if (state.activeTab === "flows" && state.flowViewTab === "packets") {
        await loadSelectedFlowPackets(selectionToken, { append: false });
      } else if (state.activeTab === "flows" && state.flowViewTab === "stream") {
        await loadSelectedFlowStream(selectionToken);
      }
      if (state.activeTab === "analysis") {
        await loadSelectedFlowAnalysis(selectionToken);
      }
    } catch (error) {
      if (selectionToken !== state.flowSelectionRequestToken || state.selectedFlowIndex !== flowIndex) {
        return;
      }

      state.selectedFlowIndex = null;
      clearPackets();
      clearStream();
      clearAnalysis(false);
      state.packetState = "error";
      state.packetErrorText = `Failed to select flow ${flowIndex}: ${String(error)}`;
      setStatus(state.packetErrorText, "error");
      render();
    }
  }

  async function selectUnrecognizedPackets() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    if (unrecognizedPacketCount() === 0 || state.unrecognizedPacketsSelected) {
      return;
    }

    const selectionToken = ++state.flowSelectionRequestToken;
    state.selectedFlowIndex = null;
    state.unrecognizedPacketsSelected = true;
    state.flowViewTab = "packets";
    clearCurrentFlowExportStatusIfPresent();
    clearSmartExportMainStatusIfPresent();
    state.packetOffset = 0;
    clearPackets();
    clearStream();
    clearAnalysis(false);
    setWiresharkFilterStatus("", "neutral");
    state.packetState = state.activeTab === "flows" ? "loading" : "idle";
    render();

    await loadUnrecognizedPackets(selectionToken, { append: false });
  }

  async function selectPacket(packetIndex) {
    const packet = state.packets.find((candidate) => candidate.packet_index === packetIndex) || null;
    if (packet == null) {
      clearPacketDetails();
      setStatus("The selected packet is not available on the current page.", "error");
      render();
      return;
    }

    state.selectedPacketIndex = packetIndex;
    state.selectedPacketRow = packet;
    state.packetDetails = null;
    state.packetDetailsState = "loading";
    state.packetDetailsErrorText = "";
    render();
    await loadSelectedPacketDetails();
  }

  function selectStreamItem(streamItemIndex) {
    const item = state.streamItems.find((candidate) => candidate.stream_item_index === streamItemIndex) || null;
    if (item == null) {
      state.selectedStreamItemIndex = null;
      state.selectedStreamItem = null;
      state.selectedStreamItemDetails = null;
      state.streamDetailsState = "idle";
      state.streamDetailsErrorText = "";
      setStatus("The selected stream item is not available in the current stream window.", "error");
      render();
      return;
    }

    state.selectedStreamItemIndex = streamItemIndex;
    state.selectedStreamItem = item;
    state.selectedStreamItemDetails = item;
    state.streamDetailsState = "loading";
    state.streamDetailsErrorText = "";
    render();
    void loadSelectedStreamItemDetails(streamItemIndex);
  }

  async function loadSelectedStreamItemDetails(streamItemIndex, selectionToken = state.flowSelectionRequestToken) {
    if (state.selectedFlowIndex == null) {
      state.selectedStreamItemDetails = null;
      state.streamDetailsState = "idle";
      state.streamDetailsErrorText = "";
      render();
      return;
    }

    const requestedFlowIndex = state.selectedFlowIndex;
    const requestToken = ++state.streamDetailsRequestToken;

    try {
      const details = await invoke("get_selected_flow_stream_item_details", {
        max_packets_to_scan: state.streamRequestedPacketBudget,
        limit: state.streamRequestedItemLimit,
        stream_item_index: streamItemIndex,
      });
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.streamDetailsRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
        || state.selectedStreamItemIndex !== streamItemIndex
      ) {
        return;
      }

      state.selectedStreamItemDetails = {
        ...(state.selectedStreamItem || {}),
        ...(details || {}),
      };
      state.streamDetailsState = "loaded";
      state.streamDetailsErrorText = "";
    } catch (error) {
      if (
        selectionToken !== state.flowSelectionRequestToken
        || requestToken !== state.streamDetailsRequestToken
        || state.selectedFlowIndex !== requestedFlowIndex
        || state.selectedStreamItemIndex !== streamItemIndex
      ) {
        return;
      }

      state.selectedStreamItemDetails = state.selectedStreamItem;
      state.streamDetailsState = "error";
      state.streamDetailsErrorText = `Failed to load stream item details: ${String(error)}`;
    }

    render();
  }

  function renderAnalysisRateGraphModeButtons() {
    elements.analysisRateMetricModeData.classList.toggle("is-active", state.analysisRateMetricMode === "data");
    elements.analysisRateMetricModePackets.classList.toggle("is-active", state.analysisRateMetricMode === "packets");
    elements.analysisRateDirectionModeAToB.classList.toggle("is-active", state.analysisRateDirectionMode === "a_to_b");
    elements.analysisRateDirectionModeBToA.classList.toggle("is-active", state.analysisRateDirectionMode === "b_to_a");
    elements.analysisRateDirectionModeBoth.classList.toggle("is-active", state.analysisRateDirectionMode === "both");
  }

  function waitForDelay(delayMs) {
    return new Promise((resolve) => window.setTimeout(resolve, delayMs));
  }

  async function pollOpenCaptureUntilComplete(openRequestToken, path, hadLoadedSession) {
    while (openRequestToken === state.openRequestToken) {
      const poll = await invoke("poll_open_capture");
      if (openRequestToken !== state.openRequestToken) {
        return;
      }

      state.openProgress = poll?.progress || {
        in_progress: true,
        cancel_requested: false,
        opening_as_index: false,
        packets_processed: 0,
        bytes_processed: 0,
        total_bytes: 0,
        percent: 0,
        input_path: path,
      };
      render();

      if (poll?.ready) {
        const result = poll?.result || null;
        if (result?.cancelled) {
          resetForNewOpen();
          state.openState = "idle";
          setStatus("Open cancelled.", "neutral");
          render();
          if (hadLoadedSession) {
            await logMemoryPhase("after_next_open", path);
          }
          return;
        }

        if (!result?.opened) {
          resetForNewOpen();
          state.openState = "error";
          setStatus(result?.error_text || "Open failed.", "error");
          render();
          if (hadLoadedSession) {
            await logMemoryPhase("after_next_open", path);
          }
          return;
        }

        state.sourceAvailability = sourceAvailabilityOrDefault(result?.source_availability);
        state.partialOpenWarningText = String(result?.partial_open_warning_text || "");
        state.currentSessionPath = String(result?.input_path || path);
        state.currentSessionOpenedFromIndex = Boolean(result?.opened_from_index);
        await loadOverviewAndFlows();
        state.openState = "opened";
        setStatus("", "neutral");
        render();
        await logMemoryPhase("after_render_flows", path);
        await logMemoryPhase("after_statistics_loaded", path);
        if (hadLoadedSession) {
          await logMemoryPhase("after_next_open", path);
        }
        return;
      }

      await waitForDelay(120);
    }
  }

  async function openCapture(pathOverride = null, modeOverride = null) {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    const path = String(pathOverride ?? elements.capturePath.value).trim();
    const openMode = String(modeOverride ?? elements.openMode.value ?? "fast");
    const hadLoadedSession = state.openState === "opened" || state.overview != null || state.flows.length > 0;

    if (hadLoadedSession) {
      await logMemoryPhase("before_next_open", path);
    }

    await logMemoryPhase("before_open_cleanup", path);
    resetForNewOpen();
    await logMemoryPhase("after_open_cleanup", path);
    const openRequestToken = state.openRequestToken + 1;
    state.openRequestToken = openRequestToken;
    state.openState = "opening";
    state.flowState = "loading";
    state.openProgress = {
      in_progress: true,
      cancel_requested: false,
      opening_as_index: /\.idx$|\.pflidx$/i.test(path),
      packets_processed: 0,
      bytes_processed: 0,
      total_bytes: 0,
      percent: 0,
      input_path: path,
    };
    setStatus("", "neutral");
    render();

    try {
      await logMemoryPhase("before_open_capture", path);
      const startResult = await invoke("start_open_capture", {
        path,
        open_mode: openMode,
      });
      await logMemoryPhase("after_open_capture", path);

      if (!startResult?.started) {
        resetForNewOpen();
        state.openState = "error";
        setStatus(startResult?.error_text || "Open failed.", "error");
        render();
        if (hadLoadedSession) {
          await logMemoryPhase("after_next_open", path);
        }
        return;
      }

      await pollOpenCaptureUntilComplete(openRequestToken, path, hadLoadedSession);
    } catch (error) {
      resetForNewOpen();
      state.openState = "error";
      setStatus(`Open failed: ${String(error)}`, "error");
      render();
      if (hadLoadedSession) {
        await logMemoryPhase("after_next_open", path);
      }
    }
  }

  async function openCaptureFromDialog() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    try {
      const selectedPath = await invoke("pick_open_capture_path");
      if (!selectedPath) {
        return;
      }

      elements.capturePath.value = selectedPath;
      await openCapture(selectedPath);
    } catch (error) {
      setStatus(`Failed to open the native file dialog: ${String(error)}`, "error");
      render();
    }
  }

  async function openCaptureFromMenu(mode) {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    try {
      const selectedPath = await invoke("pick_open_capture_path");
      if (!selectedPath) {
        return;
      }

      elements.capturePath.value = selectedPath;
      elements.openMode.value = mode;
      await openCapture(selectedPath, mode);
    } catch (error) {
      setStatus(`Failed to open the native file dialog: ${String(error)}`, "error");
      render();
    }
  }

  async function openIndexFromMenu() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    try {
      const selectedPath = await invoke("pick_open_index_path");
      if (!selectedPath) {
        return;
      }

      elements.capturePath.value = selectedPath;
      await openCapture(selectedPath);
    } catch (error) {
      setStatus(`Failed to open the native index dialog: ${String(error)}`, "error");
      render();
    }
  }

  async function attachSourceCaptureFromDialog() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    if (!canAttachSourceCapture()) {
      return;
    }

    try {
      const selectedPath = await invoke("pick_source_capture_path");
      if (!selectedPath) {
        return;
      }

      state.attachSourceInProgress = true;
      setStatus("Attaching source capture...", "neutral");
      render();

      const result = await invoke("attach_source_capture", { path: selectedPath });
      if (!result?.attached) {
        state.attachSourceInProgress = false;
        setStatus(result?.error_text || "Failed to attach source capture.", "error");
        render();
        return;
      }

      state.sourceAvailability = sourceAvailabilityOrDefault(result?.source_availability);
      clearPacketDetails();
      clearStream();
      state.attachSourceInProgress = false;
      setStatus(`Attached source capture: ${selectedPath}`, "success");
      render();
    } catch (error) {
      state.attachSourceInProgress = false;
      setStatus(`Failed to attach source capture: ${String(error)}`, "error");
      render();
    }
  }

  async function saveIndexFromMenu() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    if (!canSaveIndex()) {
      return;
    }

    try {
      const selectedPath = await invoke("pick_save_index_path");
      if (!selectedPath) {
        return;
      }

      state.saveIndexInProgress = true;
      setStatus("Saving analysis index...", "neutral");
      render();

      const result = await invoke("save_index", { path: selectedPath });
      if (result?.saved) {
        setStatus("Analysis index saved successfully.", "success");
      } else {
        setStatus(result?.error_text || "Failed to save analysis index.", "error");
      }
    } catch (error) {
      setStatus(`Failed to save analysis index: ${String(error)}`, "error");
    } finally {
      state.saveIndexInProgress = false;
      render();
    }
  }

  async function exportCurrentFlowFromMenu() {
    if (!canExportCurrentFlow()) {
      return;
    }

    try {
      const selectedPath = await invoke("pick_save_flow_export_path");
      if (!selectedPath) {
        return;
      }

      state.exportCurrentFlowInProgress = true;
      setStatus("Exporting selected flow...", "neutral");
      render();

      const result = await invoke("export_current_flow", { path: selectedPath });
      if (result?.exported) {
        setStatus("Flow exported successfully.", "success");
      } else {
        setStatus(result?.error_text || "Failed to export selected flow.", "error");
      }
    } catch (error) {
      setStatus(`Failed to export selected flow: ${String(error)}`, "error");
    } finally {
      state.exportCurrentFlowInProgress = false;
      render();
    }
  }

  async function exportSelectedFlowsFromMenu() {
    if (!canExportSelectedFlows()) {
      return;
    }

    try {
      const selectedPath = await invoke("pick_save_flow_export_path");
      if (!selectedPath) {
        return;
      }

      state.exportSelectedFlowsInProgress = true;
      setStatus("Exporting selected flows...", "neutral");
      render();

      const flowIndices = Array.from(state.checkedFlowIndices).sort((left, right) => left - right);
      const result = await invoke("export_selected_flows", { path: selectedPath, flow_indices: flowIndices });
      if (result?.exported) {
        setStatus("Selected flows exported successfully.", "success");
      } else {
        setStatus(result?.error_text || "Failed to export selected flows.", "error");
      }
    } catch (error) {
      setStatus(`Failed to export selected flows: ${String(error)}`, "error");
    } finally {
      state.exportSelectedFlowsInProgress = false;
      render();
    }
  }

  async function exportUnselectedFlowsFromMenu() {
    if (!canExportUnselectedFlows()) {
      return;
    }

    try {
      const flowIndices = getUncheckedFlowIndices();
      if (flowIndices.length === 0) {
        setStatus("No unselected flows for export.", "neutral");
        render();
        return;
      }

      const selectedPath = await invoke("pick_save_flow_export_path");
      if (!selectedPath) {
        return;
      }

      state.exportUnselectedFlowsInProgress = true;
      setStatus("Exporting unselected flows...", "neutral");
      render();

      const result = await invoke("export_selected_flows", { path: selectedPath, flow_indices: flowIndices });
      if (result?.exported) {
        setStatus("Unselected flows exported successfully.", "success");
      } else {
        setStatus(result?.error_text || "Failed to export unselected flows.", "error");
      }
    } catch (error) {
      setStatus(`Failed to export unselected flows: ${String(error)}`, "error");
    } finally {
      state.exportUnselectedFlowsInProgress = false;
      render();
    }
  }

  async function openSettingsDialogFromMenu() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    clearSettingsStatus();
    state.settingsDialogVisible = true;
    state.settingsDialogLoading = true;
    render();

    try {
      const settings = await invoke("get_settings");
      state.settings = {
        http_use_path_as_service_hint: Boolean(settings?.http_use_path_as_service_hint),
        use_possible_tls_quic: Boolean(settings?.use_possible_tls_quic),
        show_wireshark_filter_for_selected_flow: settings?.show_wireshark_filter_for_selected_flow !== false,
        validate_selected_packet_checksums: Boolean(settings?.validate_selected_packet_checksums),
      };
    } catch (error) {
      state.settingsStatusText = `Failed to load settings: ${String(error)}`;
      state.settingsStatusKind = "error";
    } finally {
      state.settingsDialogLoading = false;
      render();
    }
  }

  async function openProtocolPathLegendDialogFromMenu() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    clearProtocolPathLegendStatus();
    state.protocolPathLegendDialogVisible = true;
    state.protocolPathLegendLoading = true;
    render();

    try {
      const legend = await invoke("get_protocol_path_legend");
      state.protocolPathLegendEntries = Array.isArray(legend) ? legend : [];
      if (state.protocolPathLegendEntries.length === 0) {
        state.protocolPathLegendStatusText = "Protocol path legend is unavailable.";
        state.protocolPathLegendStatusKind = "error";
      }
    } catch (error) {
      state.protocolPathLegendEntries = [];
      state.protocolPathLegendStatusText = `Failed to load protocol path legend: ${String(error)}`;
      state.protocolPathLegendStatusKind = "error";
    } finally {
      state.protocolPathLegendLoading = false;
      render();
    }
  }

  function closeSettingsDialog() {
    if (state.settingsDialogLoading || state.settingsSaveInProgress) {
      return;
    }

    state.settingsDialogVisible = false;
    clearSettingsStatus();
    render();
  }

  function closeProtocolPathLegendDialog() {
    if (state.protocolPathLegendLoading) {
      return;
    }

    state.protocolPathLegendDialogVisible = false;
    clearProtocolPathLegendStatus();
    render();
  }

  async function saveSettingsFromDialog() {
    if (typeof invoke !== "function") {
      state.settingsStatusText = "Tauri API is unavailable in this frontend.";
      state.settingsStatusKind = "error";
      render();
      return;
    }

    const httpUsePathAsServiceHint = Boolean(elements.settingsHttpUsePathAsServiceHint?.checked);
    const usePossibleTlsQuic = Boolean(elements.settingsUsePossibleTlsQuic?.checked);
    const showWiresharkFilterForSelectedFlow = Boolean(elements.settingsShowWiresharkFilterForSelectedFlow?.checked);
    const showProtocolPathColumn = Boolean(elements.settingsShowProtocolPathColumn?.checked);
    const validateSelectedPacketChecksums = Boolean(elements.settingsValidateSelectedPacketChecksums?.checked);

    state.settingsSaveInProgress = true;
    clearSettingsStatus();
    render();

    try {
      const settings = await invoke("update_settings", {
        http_use_path_as_service_hint: httpUsePathAsServiceHint,
        use_possible_tls_quic: usePossibleTlsQuic,
        show_wireshark_filter_for_selected_flow: showWiresharkFilterForSelectedFlow,
        validate_selected_packet_checksums: validateSelectedPacketChecksums,
      });

      state.settings = {
        http_use_path_as_service_hint: Boolean(settings?.http_use_path_as_service_hint),
        use_possible_tls_quic: Boolean(settings?.use_possible_tls_quic),
        show_wireshark_filter_for_selected_flow: settings?.show_wireshark_filter_for_selected_flow !== false,
        validate_selected_packet_checksums: Boolean(settings?.validate_selected_packet_checksums),
      };
      state.showProtocolPathColumn = showProtocolPathColumn;

      if (state.openState === "opened") {
        await loadOverviewAndFlows();
        if (state.analysisState !== "idle" && state.selectedFlowIndex != null) {
          await loadSelectedFlowAnalysis();
        }
      }
      if (state.selectedPacketIndex != null && state.selectedFlowIndex != null && state.packetDetailsState !== "idle") {
        await loadSelectedPacketDetails();
      }

      setStatus("Settings updated.", "success");
      state.settingsDialogVisible = false;
      clearSettingsStatus();
    } catch (error) {
      state.settingsStatusText = `Failed to save settings: ${String(error)}`;
      state.settingsStatusKind = "error";
    } finally {
      state.settingsSaveInProgress = false;
      render();
    }
  }

  function openSmartExportDialogFromMenu() {
    if (!canSmartExport()) {
      return;
    }

    clearSmartExportStatus();
    state.smartExportDialogVisible = true;
    render();
  }

  function closeSmartExportDialog() {
    if (state.smartExportInProgress) {
      return;
    }

    state.smartExportDialogVisible = false;
    clearSmartExportStatus();
    render();
  }

  async function browseSmartExportDestinationFolder() {
    if (typeof invoke !== "function") {
      setSmartExportStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    if (selectedSmartExportOutputMode() !== "separate_files" || state.smartExportInProgress) {
      return;
    }

    try {
      const selectedPath = await invoke("pick_smart_export_destination_folder");
      if (!selectedPath) {
        return;
      }

      elements.smartExportDestinationFolder.value = selectedPath;
      clearSmartExportStatus();
      render();
    } catch (error) {
      setSmartExportStatus(`Failed to open the destination folder dialog: ${String(error)}`, "error");
      render();
    }
  }

  async function runSmartExportFromDialog() {
    if (typeof invoke !== "function") {
      setSmartExportStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    if (!canSmartExport()) {
      return;
    }

    const flowScope = selectedSmartExportFlowScope();
    const isUnrecognizedScope = flowScope === "unrecognized";
    const flowIndices = isUnrecognizedScope ? [] : getSmartExportFlowIndices(flowScope);
    if (!isUnrecognizedScope && flowIndices.length === 0) {
      const emptySelectionMessage = flowScope === "current"
        ? "No current flow selected for smart export."
        : (flowScope === "matching_filter"
          ? "No flows match the current filter for smart export."
          : (flowScope === "selected"
            ? "No selected flows for smart export."
            : (flowScope === "not_matching_filter"
              ? "No flows remain outside the current filter for smart export."
              : (flowScope === "unselected"
                ? "No unselected flows for smart export."
                : "No flows available for smart export."))));
      setSmartExportStatus(emptySelectionMessage, "error");
      render();
      return;
    }
    if (isUnrecognizedScope && !smartExportUnrecognizedTargetEnabled()) {
      setSmartExportStatus("No unrecognized packets available for smart export.", "error");
      render();
      return;
    }

    const baseMode = selectedSmartExportBaseMode();
    const outputMode = selectedSmartExportOutputMode();
    const extrasEnabled = smartExportExtrasEnabled();
    const firstNPackets = baseMode === "first_n_packets"
      ? parsePositiveIntegerText(elements.smartExportFirstNPackets.value)
      : 0;
    const firstMOriginalBytes = baseMode === "first_m_original_bytes"
      ? parsePositiveIntegerText(elements.smartExportFirstMOriginalBytes.value)
      : 0;
    const everyKthPacket = extrasEnabled && elements.smartExportIncludeEveryKthPacket.checked
      ? parsePositiveIntegerText(elements.smartExportEveryKthPacket.value)
      : 0;

    if (baseMode === "first_n_packets" && !firstNPackets) {
      setSmartExportStatus("Enter a positive packet count for smart export.", "error");
      render();
      return;
    }
    if (baseMode === "first_m_original_bytes" && !firstMOriginalBytes) {
      setSmartExportStatus("Enter a positive original-byte limit for smart export.", "error");
      render();
      return;
    }
    if (extrasEnabled && elements.smartExportIncludeEveryKthPacket.checked && !everyKthPacket) {
      setSmartExportStatus("Enter a positive K value for sparse smart export retention.", "error");
      render();
      return;
    }

    const perFlowBufferBudgetMb = outputMode === "separate_files"
      ? parsePositiveIntegerText(elements.smartExportBufferBudget.value)
      : 0;
    if (outputMode === "separate_files" && !perFlowBufferBudgetMb) {
      setSmartExportStatus("Select a valid buffer memory budget preset for per-flow smart export.", "error");
      render();
      return;
    }

    let outputPath = "";
    if (isUnrecognizedScope && outputMode !== "single_file") {
      setSmartExportStatus("Unrecognized packets can only be smart-exported to a single output file.", "error");
      render();
      return;
    }
    if (!isUnrecognizedScope && outputMode === "separate_files") {
      outputPath = String(elements.smartExportDestinationFolder.value || "").trim();
      if (!outputPath) {
        setSmartExportStatus("No destination folder selected for smart export.", "error");
        render();
        return;
      }
    }

    clearSmartExportStatus();
    state.smartExportDialogVisible = false;
    render();

    try {
      if (outputMode === "single_file") {
        const selectedPath = await invoke("pick_save_flow_export_path");
        if (!selectedPath) {
          return;
        }
        outputPath = selectedPath;
      }

      state.smartExportInProgress = true;
      setStatus("Smart export in progress...", "neutral");
      render();

      const result = isUnrecognizedScope
        ? await invoke("export_smart_unrecognized_packets", {
          path: outputPath,
          base_mode: baseMode === "first_n_packets" ? 1 : (baseMode === "first_m_original_bytes" ? 2 : 0),
          first_n_packets: firstNPackets || 0,
          first_m_original_bytes: firstMOriginalBytes || 0,
          include_last_packet: extrasEnabled && elements.smartExportIncludeLastPacket.checked,
          include_every_kth_packet_after_base: extrasEnabled && elements.smartExportIncludeEveryKthPacket.checked,
          every_kth_packet: everyKthPacket || 0,
        })
        : await invoke("export_smart_flows", {
          path: outputPath,
          flow_indices: flowIndices,
          output_mode: outputMode === "separate_files" ? 1 : 0,
          base_mode: baseMode === "first_n_packets" ? 1 : (baseMode === "first_m_original_bytes" ? 2 : 0),
          first_n_packets: firstNPackets || 0,
          first_m_original_bytes: firstMOriginalBytes || 0,
          include_last_packet: extrasEnabled && elements.smartExportIncludeLastPacket.checked,
          include_every_kth_packet_after_base: extrasEnabled && elements.smartExportIncludeEveryKthPacket.checked,
          every_kth_packet: everyKthPacket || 0,
          per_flow_buffer_budget_bytes: (perFlowBufferBudgetMb || 0) * 1024 * 1024,
        });

      if (result?.exported) {
        setStatus("Smart export completed successfully.", "success");
      } else {
        const errorText = result?.error_text || (isUnrecognizedScope
          ? "Failed to smart-export unrecognized packets."
          : "Failed to smart-export flows.");
        setStatus(errorText, "error");
      }
    } catch (error) {
      setStatus(
        isUnrecognizedScope
          ? `Failed to smart-export unrecognized packets: ${String(error)}`
          : `Failed to smart-export flows: ${String(error)}`,
        "error"
      );
    } finally {
      state.smartExportInProgress = false;
      render();
    }
  }

  async function exitAppFromMenu() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    try {
      await invoke("exit_app");
    } catch (error) {
      setStatus(`Failed to exit the application: ${String(error)}`, "error");
      render();
    }
  }

  async function handleMenuAction(action) {
    closeMenus();
    render();

    switch (action) {
      case "open-capture-fast":
        await openCaptureFromMenu("fast");
        return;
      case "open-capture-deep":
        await openCaptureFromMenu("deep");
        return;
      case "open-index":
        await openIndexFromMenu();
        return;
      case "save-index":
        await saveIndexFromMenu();
        return;
      case "exit-app":
        await exitAppFromMenu();
        return;
      case "about":
        state.aboutDialogVisible = true;
        render();
        return;
      case "protocol-path-legend":
        await openProtocolPathLegendDialogFromMenu();
        return;
      case "export-current-flow":
        await exportCurrentFlowFromMenu();
        return;
      case "export-selected-flows":
        await exportSelectedFlowsFromMenu();
        return;
      case "export-unselected-flows":
        await exportUnselectedFlowsFromMenu();
        return;
      case "settings":
        await openSettingsDialogFromMenu();
        return;
      case "smart-export":
        openSmartExportDialogFromMenu();
        return;
      default:
        return;
    }
  }

  async function exportAnalysisSequenceCsv() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    if (!canExportAnalysisSequenceCsv()) {
      return;
    }

    try {
      const selectedPath = await invoke("pick_save_analysis_sequence_csv_path");
      if (!selectedPath) {
        return;
      }

      state.analysisSequenceExportInProgress = true;
      state.analysisSequenceExportStatusText = "";
      state.analysisSequenceExportStatusKind = "neutral";
      state.exportCurrentFlowInProgress = false;
      render();

      const result = await invoke("export_selected_flow_analysis_sequence_csv", {
        path: selectedPath,
      });

      if (result?.exported) {
        state.analysisSequenceExportStatusText = `Sequence CSV exported: ${result.output_path || selectedPath}`;
        state.analysisSequenceExportStatusKind = "success";
        setStatus("Selected-flow sequence CSV exported.", "success");
      } else {
        const errorText = result?.error_text || "Failed to export flow sequence CSV.";
        state.analysisSequenceExportStatusText = errorText;
        state.analysisSequenceExportStatusKind = "error";
        setStatus(errorText, "error");
      }
    } catch (error) {
      const errorText = `Failed to export flow sequence CSV: ${String(error)}`;
      state.analysisSequenceExportStatusText = errorText;
      state.analysisSequenceExportStatusKind = "error";
      setStatus(errorText, "error");
    } finally {
      state.analysisSequenceExportInProgress = false;
      render();
    }
  }

  elements.openFileButton.addEventListener("click", openCaptureFromDialog);
  elements.openCancelButton?.addEventListener("click", async () => {
    if (state.openState !== "opening") {
      return;
    }

    try {
      await invoke("cancel_open_capture");
      state.openProgress.cancel_requested = true;
      render();
    } catch (error) {
      setStatus(`Failed to cancel open: ${String(error)}`, "error");
      render();
    }
  });
  elements.attachSourceButton.addEventListener("click", attachSourceCaptureFromDialog);
  for (const button of elements.menuButtons) {
    button.addEventListener("click", () => {
      const menuName = button.dataset.menuButton || null;
      state.openMenu = state.openMenu === menuName ? null : menuName;
      render();
    });
  }
  for (const item of elements.menuItems) {
    item.addEventListener("click", async () => {
      if (item.disabled) {
        return;
      }

      await handleMenuAction(item.dataset.menuAction || "");
    });
  }
  elements.aboutDialogCloseButton?.addEventListener("click", () => {
    state.aboutDialogVisible = false;
    render();
  });
  elements.aboutDialog?.addEventListener("click", (event) => {
    if (event.target === elements.aboutDialog) {
      state.aboutDialogVisible = false;
      render();
    }
  });
  elements.protocolPathLegendCloseButton?.addEventListener("click", closeProtocolPathLegendDialog);
  elements.protocolPathLegendDialog?.addEventListener("click", (event) => {
    if (event.target === elements.protocolPathLegendDialog) {
      closeProtocolPathLegendDialog();
    }
  });
  elements.settingsCancelButton?.addEventListener("click", closeSettingsDialog);
  elements.settingsSaveButton?.addEventListener("click", () => {
    void saveSettingsFromDialog();
  });
  elements.settingsDialog?.addEventListener("click", (event) => {
    if (event.target === elements.settingsDialog) {
      closeSettingsDialog();
    }
  });
  elements.smartExportCloseButton?.addEventListener("click", closeSmartExportDialog);
  elements.smartExportCancelButton?.addEventListener("click", closeSmartExportDialog);
  elements.smartExportRunButton?.addEventListener("click", () => {
    void runSmartExportFromDialog();
  });
  elements.smartExportBrowseFolderButton?.addEventListener("click", () => {
    void browseSmartExportDestinationFolder();
  });
  elements.smartExportDialog?.addEventListener("click", (event) => {
    if (event.target === elements.smartExportDialog) {
      closeSmartExportDialog();
    }
  });
  for (const control of [
    elements.smartExportScopeCurrent,
    elements.smartExportScopeMatchingFilter,
    elements.smartExportScopeSelected,
    elements.smartExportScopeNotMatchingFilter,
    elements.smartExportScopeUnselected,
    elements.smartExportScopeUnrecognized,
    elements.smartExportScopeAll,
    elements.smartExportBaseAllPackets,
    elements.smartExportBaseFirstNPackets,
    elements.smartExportBaseFirstMOriginalBytes,
    elements.smartExportOutputSingleFile,
    elements.smartExportOutputSeparateFiles,
    elements.smartExportIncludeLastPacket,
    elements.smartExportIncludeEveryKthPacket,
    elements.smartExportBufferBudget,
  ]) {
    control?.addEventListener("change", () => {
      clearSmartExportStatus();
      render();
    });
  }
  for (const control of [
    elements.smartExportFirstNPackets,
    elements.smartExportFirstMOriginalBytes,
    elements.smartExportEveryKthPacket,
    elements.smartExportDestinationFolder,
  ]) {
    control?.addEventListener("input", () => {
      clearSmartExportStatus();
      render();
    });
  }
  document.addEventListener("pointerdown", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }

    if (!target.closest(".menu-bar")) {
      if (state.openMenu != null) {
        closeMenus();
        render();
      }
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      const hadVisibleUi = state.openMenu != null
        || state.aboutDialogVisible
        || state.settingsDialogVisible
        || state.protocolPathLegendDialogVisible
        || state.smartExportDialogVisible;
      closeMenus();
      state.aboutDialogVisible = false;
      if (!state.settingsDialogLoading && !state.settingsSaveInProgress) {
        state.settingsDialogVisible = false;
        clearSettingsStatus();
      }
      if (!state.protocolPathLegendLoading) {
        state.protocolPathLegendDialogVisible = false;
        clearProtocolPathLegendStatus();
      }
      if (!state.smartExportInProgress) {
        state.smartExportDialogVisible = false;
        clearSmartExportStatus();
      }
      if (hadVisibleUi) {
        render();
      }
    }
  });
  elements.flowFilterInput.addEventListener("input", () => {
    applyFlowFilterState(elements.flowFilterInput.value);
    render();
  });
  elements.protocolPathStatsModeKindOverview?.addEventListener("click", () => {
    setProtocolPathStatsMode(0);
  });
  elements.protocolPathStatsModeIdentityTree?.addEventListener("click", () => {
    setProtocolPathStatsMode(1);
  });
  elements.protocolPathStatsModeTerminalPaths?.addEventListener("click", () => {
    setProtocolPathStatsMode(2);
  });
  elements.protocolPathStatsBody?.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }

    const expanderButton = event.target.closest("[data-protocol-path-node-id]");
    if (expanderButton) {
      event.stopPropagation();
      toggleProtocolPathNode(expanderButton.dataset.protocolPathNodeId);
      return;
    }

    const row = event.target.closest("[data-protocol-path-row-node-id]");
    if (!row) {
      return;
    }

    const nodeId = Number(row.dataset.protocolPathRowNodeId);
    const protocolPathMode = currentProtocolPathMode();
    const selectedRow = state.protocolPathStatsVisibleRows.find((candidate) => Number(candidate?.node_id) === nodeId);
    if (!selectedRow) {
      return;
    }

    state.selectedProtocolPathNode = {
      mode: Number(protocolPathMode),
      nodeId,
      label: protocolPathRowFilterLabel(selectedRow, protocolPathMode),
      flowCount: Number(selectedRow.flow_count ?? 0),
    };
    renderProtocolPathStatsSection();
  });
  elements.protocolPathShowFlowsButton?.addEventListener("click", () => {
    void showSelectedProtocolPathFlows();
  });
  elements.protocolPathExpandAllButton?.addEventListener("click", () => {
    const overview = state.overview;
    const protocolPathMode = Number(state.protocolPathStatsMode ?? overview?.protocol_path_statistics_default_mode ?? 0);
    if (!isProtocolPathTreeMode(protocolPathMode)) {
      return;
    }

    const protocolPathRows = protocolPathMode === 1
      ? (Array.isArray(overview?.protocol_path_statistics_identity_tree) ? overview.protocol_path_statistics_identity_tree : [])
      : (Array.isArray(overview?.protocol_path_statistics) ? overview.protocol_path_statistics : []);
    state.protocolPathExpandedNodeIds.clear();
    for (const row of protocolPathRows) {
      if (row?.has_children) {
        state.protocolPathExpandedNodeIds.add(Number(row.node_id));
      }
    }
    renderProtocolPathStatsSection();
  });
  elements.protocolPathCollapseAllButton?.addEventListener("click", () => {
    state.protocolPathExpandedNodeIds.clear();
    renderProtocolPathStatsSection();
  });
  elements.clearFlowFilterButton.addEventListener("click", () => {
    applyFlowFilterState("");
    render();
  });
  elements.clearProtocolPathFlowFilterButton?.addEventListener("click", () => {
    clearProtocolPathFlowFilter();
    render();
  });
  elements.copyWiresharkFilterButton.addEventListener("click", async () => {
    const selectedFlow = state.flows.find((flow) => flow.flow_index === state.selectedFlowIndex) || null;
    const filterText = String(selectedFlow?.wireshark_display_filter || "");
    if (!filterText) {
      setWiresharkFilterStatus("No Wireshark display filter is available for the selected flow.", "error");
      render();
      return;
    }

    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API is unavailable.");
      }

      await navigator.clipboard.writeText(filterText);
      setWiresharkFilterStatus("Wireshark filter copied to the clipboard.", "success");
    } catch (error) {
      setWiresharkFilterStatus(`Failed to copy filter: ${String(error)}`, "error");
    }

    render();
  });
  for (const header of elements.flowSortHeaders) {
    header.addEventListener("click", () => {
      const sortKey = header.dataset.flowSortKey || "index";
      resetFlowVirtualizationState();
      resetAnalysisFlowVirtualizationState();
      if (state.flowSortKey === sortKey) {
        state.flowSortDirection = state.flowSortDirection === "asc" ? "desc" : "asc";
      } else {
        state.flowSortKey = sortKey;
        state.flowSortDirection = isDescendingDefaultSortKey(sortKey) ? "desc" : "asc";
      }

      render();
    });
  }
  elements.unrecognizedPacketsButton?.addEventListener("click", async () => {
    await selectUnrecognizedPackets();
  });
  elements.flowTableViewport?.addEventListener("scroll", () => {
    scheduleFlowViewportRender();
  });
  elements.analysisFlowTableViewport?.addEventListener("scroll", () => {
    scheduleAnalysisFlowViewportRender();
  });
  elements.protocolPathStatsViewport?.addEventListener("scroll", () => {
    scheduleProtocolPathStatsViewportRender();
  });
  for (const button of elements.tabButtons) {
    button.addEventListener("click", async () => {
      state.activeTab = button.dataset.tab || "flows";
      render();
      await waitForNextPaint();
      ensureSelectedFlowVisibleForTab(state.activeTab);

      if (
        state.activeTab === "analysis"
        && state.selectedFlowIndex != null
        && state.analysisLoadedForFlowIndex !== state.selectedFlowIndex
      ) {
        await loadSelectedFlowAnalysis();
      }
    });
  }
  for (const button of elements.flowViewTabButtons) {
    button.addEventListener("click", async () => {
      state.flowViewTab = button.dataset.flowViewTab || "packets";
      render();

      if (
        state.flowViewTab === "packets"
        && state.selectedFlowIndex != null
        && state.packetState !== "loading"
        && state.packetsTotalCount === 0
        && state.packets.length === 0
      ) {
        await loadSelectedFlowPackets(state.flowSelectionRequestToken, { append: false });
      }

      if (
        state.flowViewTab === "stream"
        && state.selectedFlowIndex != null
        && state.streamLoadedForFlowIndex !== state.selectedFlowIndex
      ) {
        await loadSelectedFlowStream();
      }
    });
  }
  for (const button of elements.packetDetailsTabButtons) {
    button.addEventListener("click", () => {
      state.packetDetailsTab = button.dataset.packetDetailsTab || "summary";
      render();
    });
  }
  for (const button of elements.streamDetailsTabButtons) {
    button.addEventListener("click", () => {
      state.streamDetailsTab = button.dataset.streamDetailsTab || "summary";
      render();
    });
  }
  elements.packetLoadMoreButton.addEventListener("click", async () => {
    if (state.packetState === "loading" || !state.packetCanLoadMore) {
      return;
    }

    await loadSelectedFlowPackets(state.flowSelectionRequestToken, { append: true });
  });
  elements.streamLoadMoreButton.addEventListener("click", async () => {
    if (!state.streamCanLoadMore || state.streamState === "loading") {
      return;
    }

    state.streamRequestedPacketBudget += streamPacketBatchSize;
    state.streamRequestedItemLimit += streamItemBatchSize;
    await loadSelectedFlowStream();
  });
  elements.analysisOpenInFlowsButton.addEventListener("click", async () => {
    if (state.selectedFlowIndex == null) {
      return;
    }

    state.activeTab = "flows";
    render();
    await waitForNextPaint();
    ensureSelectedFlowVisibleForTab("flows");
  });
  elements.analysisExportSequenceCsvButton.addEventListener("click", exportAnalysisSequenceCsv);

  elements.analysisRateMetricModeData.addEventListener("click", () => {
    state.analysisRateMetricMode = "data";
    render();
  });
  elements.analysisRateMetricModePackets.addEventListener("click", () => {
    state.analysisRateMetricMode = "packets";
    render();
  });
  elements.analysisRateDirectionModeAToB.addEventListener("click", () => {
    state.analysisRateDirectionMode = "a_to_b";
    render();
  });
  elements.analysisRateDirectionModeBToA.addEventListener("click", () => {
    state.analysisRateDirectionMode = "b_to_a";
    render();
  });
  elements.analysisRateDirectionModeBoth.addEventListener("click", () => {
    state.analysisRateDirectionMode = "both";
    render();
  });

  elements.analysisPacketSizeHistogramModeAll.addEventListener("click", () => {
    state.analysisPacketSizeHistogramMode = "all";
    render();
  });
  elements.analysisPacketSizeHistogramModeAToB.addEventListener("click", () => {
    state.analysisPacketSizeHistogramMode = "a_to_b";
    render();
  });
  elements.analysisPacketSizeHistogramModeBToA.addEventListener("click", () => {
    state.analysisPacketSizeHistogramMode = "b_to_a";
    render();
  });
  elements.analysisInterArrivalHistogramModeAll.addEventListener("click", () => {
    state.analysisInterArrivalHistogramMode = "all";
    render();
  });
  elements.analysisInterArrivalHistogramModeAToB.addEventListener("click", () => {
    state.analysisInterArrivalHistogramMode = "a_to_b";
    render();
  });
  elements.analysisInterArrivalHistogramModeBToA.addEventListener("click", () => {
    state.analysisInterArrivalHistogramMode = "b_to_a";
    render();
  });

  initializeWorkspaceSplitters();
  render();
  void initializeMemoryDiagnostics();
})();

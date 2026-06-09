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
  const flowVirtualRowHeight = 36;
  const analysisFlowVirtualRowHeight = 44;
  const flowVirtualOverscanRows = 12;
  const analysisFlowVirtualOverscanRows = 10;

  const state = {
    memoryDiagnosticsEnabled: false,
    openMenu: null,
    aboutDialogVisible: false,
    settingsDialogVisible: false,
    settingsDialogLoading: false,
    settingsSaveInProgress: false,
    settingsStatusText: "",
    settingsStatusKind: "neutral",
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
    sourceAvailability: null,
    overview: null,
    flows: [],
    flowFilterText: "",
    flowSortKey: "index",
    flowSortDirection: "asc",
    flowVirtualWindowStart: 0,
    flowVirtualWindowEnd: 0,
    flowVirtualizationActive: false,
    checkedFlowIndices: new Set(),
    selectedFlowIndex: null,
    packets: [],
    packetsTotalCount: 0,
    packetOffset: 0,
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
    analysis: null,
    analysisState: "idle",
    analysisErrorText: "",
    analysisUnavailableText: "",
    analysisLoadedForFlowIndex: null,
    analysisFlowVirtualWindowStart: 0,
    analysisFlowVirtualWindowEnd: 0,
    analysisFlowVirtualizationActive: false,
    analysisSequenceExportInProgress: false,
    analysisSequenceExportStatusText: "",
    analysisSequenceExportStatusKind: "neutral",
    analysisPacketSizeHistogramMode: "all",
    analysisInterArrivalHistogramMode: "all",
    packetDetailsState: "idle",
    packetDetailsErrorText: "",
    packetDetailsTab: "summary",
    wiresharkFilterStatusText: "",
    wiresharkFilterStatusKind: "neutral",
    flowSelectionRequestToken: 0,
    packetRequestToken: 0,
    streamRequestToken: 0,
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
    settingsHttpUsePathAsServiceHint: document.getElementById("settingsHttpUsePathAsServiceHint"),
    settingsUsePossibleTlsQuic: document.getElementById("settingsUsePossibleTlsQuic"),
    settingsShowWiresharkFilterForSelectedFlow: document.getElementById("settingsShowWiresharkFilterForSelectedFlow"),
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
    smartExportScopeSelected: document.getElementById("smartExportScopeSelected"),
    smartExportScopeUnselected: document.getElementById("smartExportScopeUnselected"),
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
    openButton: document.getElementById("openButton"),
    attachSourceButton: document.getElementById("attachSourceButton"),
    openStateBadge: document.getElementById("openStateBadge"),
    openWorkflowNote: document.getElementById("openWorkflowNote"),
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
    overviewMeta: document.getElementById("overviewMeta"),
    flowMeta: document.getElementById("flowMeta"),
    flowFilterInput: document.getElementById("flowFilterInput"),
    clearFlowFilterButton: document.getElementById("clearFlowFilterButton"),
    flowSortHeaders: Array.from(document.querySelectorAll("[data-flow-sort-key]")),
    flowTableBody: document.getElementById("flowTableBody"),
    flowTableViewport: document.getElementById("flowTableViewport"),
    flowRenderCapBar: document.getElementById("flowRenderCapBar"),
    flowRenderCapText: document.getElementById("flowRenderCapText"),
    checkedFlowsStatusBar: document.getElementById("checkedFlowsStatusBar"),
    checkedFlowsStatusText: document.getElementById("checkedFlowsStatusText"),
    wiresharkFilterRow: document.getElementById("wiresharkFilterRow"),
    wiresharkFilterText: document.getElementById("wiresharkFilterText"),
    wiresharkFilterStatusText: document.getElementById("wiresharkFilterStatusText"),
    copyWiresharkFilterButton: document.getElementById("copyWiresharkFilterButton"),
    packetMeta: document.getElementById("packetMeta"),
    packetTableBody: document.getElementById("packetTableBody"),
    packetPrevButton: document.getElementById("packetPrevButton"),
    packetNextButton: document.getElementById("packetNextButton"),
    streamLoadMoreButton: document.getElementById("streamLoadMoreButton"),
    flowViewTitle: document.getElementById("flowViewTitle"),
    streamTableBody: document.getElementById("streamTableBody"),
    packetDetailsTitle: document.getElementById("packetDetailsTitle"),
    packetDetailsMeta: document.getElementById("packetDetailsMeta"),
    packetInspectorView: document.getElementById("packetInspectorView"),
    streamInspectorView: document.getElementById("streamInspectorView"),
    packetDetailsTabButtons: Array.from(document.querySelectorAll(".inspector-tab")),
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
    streamDetailsSummary: document.getElementById("streamDetailsSummary"),
    streamDetailsSourcePacketsText: document.getElementById("streamDetailsSourcePacketsText"),
    streamDetailsSourcePacketIndicesText: document.getElementById("streamDetailsSourcePacketIndicesText"),
    streamDetailsConstrictedNotesText: document.getElementById("streamDetailsConstrictedNotesText"),
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
    analysisTrafficTotals: document.getElementById("analysisTrafficTotals"),
    analysisDirectionSplit: document.getElementById("analysisDirectionSplit"),
    analysisDerivedMetricsSection: document.getElementById("analysisDerivedMetricsSection"),
    analysisDerivedMetrics: document.getElementById("analysisDerivedMetrics"),
    analysisTimingSize: document.getElementById("analysisTimingSize"),
    analysisBurstIdleSection: document.getElementById("analysisBurstIdleSection"),
    analysisBurstIdleSummary: document.getElementById("analysisBurstIdleSummary"),
    analysisTcpControlsSection: document.getElementById("analysisTcpControlsSection"),
    analysisTcpControls: document.getElementById("analysisTcpControls"),
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
    quicStatsBody: document.getElementById("quicStatsBody"),
    tlsStatsBody: document.getElementById("tlsStatsBody"),
    topEndpointsBody: document.getElementById("topEndpointsBody"),
    topPortsBody: document.getElementById("topPortsBody"),
  };

  function formatNumber(value) {
    return Number(value ?? 0).toLocaleString("en-US");
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
      state.flowsBottomLeftSizePx != null ? `${state.flowsBottomLeftSizePx}px` : "minmax(380px, 0.95fr)"
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
    clearHtml(elements.analysisTcpControls);
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

  function sourceAvailabilityNoteText() {
    const availability = currentSourceAvailability();
    const baseNote = "Use Open File for the native picker, or keep a typed path as a manual fallback.";

    if (state.openState !== "opened") {
      return baseNote;
    }

    if (availability.partial_open) {
      return `${baseNote} Opened with partial results; some byte-backed actions can stay limited.`;
    }

    if (!availability.byte_backed_inspection_available) {
      if (availability.expected_source_capture_path) {
        return `${baseNote} Byte-backed inspection is unavailable until the source capture is attached/readable: ${availability.expected_source_capture_path}`;
      }

      if (availability.opened_from_index) {
        return `${baseNote} Byte-backed inspection is unavailable in this index-backed session because the source capture is not attached or readable.`;
      }

      if (availability.has_source_capture && !availability.source_capture_accessible) {
        return `${baseNote} Byte-backed inspection is unavailable because the source capture cannot be read.`;
      }
    }

    if (availability.opened_from_index) {
      return `${baseNote} Source capture attached; byte-backed inspection is available.`;
    }

    return baseNote;
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
        return String(flow?.endpoint_a || `${flow?.address_a || ""}:${flow?.port_a ?? ""}`);
      case "endpoint_b":
        return String(flow?.endpoint_b || `${flow?.address_b || ""}:${flow?.port_b ?? ""}`);
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

  function formatPacketMarker(packet) {
    const markers = [];
    if (packet?.is_ip_fragmented) {
      markers.push("Frag");
    }
    if (packet?.suspected_tcp_retransmission) {
      markers.push("Retrans");
    }
    return markers.join(", ");
  }

  function formatStreamSourcePacketRefs(item) {
    const packetIndices = Array.isArray(item?.source_packet_indices) ? item.source_packet_indices : [];
    if (packetIndices.length === 0) {
      return "";
    }

    return packetIndices.map((packetIndex) => `#${packetIndex}`).join(", ");
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
    if (elements.smartExportScopeSelected?.checked) {
      return "selected";
    }
    if (elements.smartExportScopeUnselected?.checked) {
      return "unselected";
    }
    if (elements.smartExportScopeAll?.checked) {
      return "all";
    }
    return "current";
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
      case "selected":
        return Array.from(state.checkedFlowIndices).sort((left, right) => left - right);
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
      || state.statusText.startsWith("Failed to smart-export flows:")
    ) {
      setStatus("", "neutral");
    }
  }

  function applyFlowFilterState(filterText) {
    state.flowFilterText = String(filterText || "");
    resetFlowVirtualizationState();
    resetAnalysisFlowVirtualizationState();
    setWiresharkFilterStatus("", "neutral");

    const selectedFlowVisible = filteredFlows().some((flow) => flow.flow_index === state.selectedFlowIndex);
    if (!selectedFlowVisible) {
      state.selectedFlowIndex = null;
      clearPackets();
      clearStream();
      clearAnalysis();
      setStatus("Selected flow was cleared because it no longer matches the current filter.", "neutral");
    }
  }

  function applyFlowFilterFromStatistics(filterText, sourceLabel) {
    state.activeTab = "flows";
    applyFlowFilterState(filterText);
    setStatus(`Filtered flows by ${sourceLabel}.`, "success");
    render();
  }

  function clearOverview() {
    state.overview = null;
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
  }

  function clearAnalysis() {
    state.analysis = null;
    state.analysisState = "idle";
    state.analysisErrorText = "";
    state.analysisUnavailableText = "";
    state.analysisLoadedForFlowIndex = null;
    resetAnalysisFlowVirtualizationState();
    state.analysisSequenceExportInProgress = false;
    state.analysisSequenceExportStatusText = "";
    state.analysisSequenceExportStatusKind = "neutral";
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
    state.flowState = "idle";
    clearAnalysis();
    setWiresharkFilterStatus("", "neutral");
  }

  function clearPackets() {
    state.packets = [];
    state.packetsTotalCount = 0;
    state.packetOffset = 0;
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
    setStatus("", "neutral");
  }

  function setOpenControlsDisabled(disabled) {
    elements.capturePath.disabled = disabled;
    elements.openMode.disabled = disabled;
    elements.openFileButton.disabled = disabled;
    elements.openButton.disabled = disabled;
    elements.attachSourceButton.disabled = disabled || state.attachSourceInProgress || !canAttachSourceCapture();
  }

  function renderStatus() {
    elements.statusText.textContent = state.statusText;
    elements.statusText.className = "status-text";
    elements.openWorkflowNote.textContent = sourceAvailabilityNoteText();
    if (state.statusKind === "error") {
      elements.statusText.classList.add("is-error");
    } else if (state.statusKind === "success") {
      elements.statusText.classList.add("is-success");
    }
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

  function renderSmartExportDialog() {
    const extrasEnabled = smartExportExtrasEnabled();
    const perFlowMode = selectedSmartExportOutputMode() === "separate_files";
    const dialogDisabled = state.smartExportInProgress;

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
    if (filterText.length === 0) {
      return state.flows;
    }

    return state.flows.filter((flow) => {
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
    elements.analysisTcpControls && (elements.analysisTcpControls.innerHTML = "");
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

    elements.flowViewTitle.textContent = state.flowViewTab === "stream"
      ? "Selected-Flow Stream"
      : "Selected-Flow Packets";

    const showingPackets = state.flowViewTab === "packets";
    elements.packetPrevButton.style.display = showingPackets ? "" : "none";
    elements.packetNextButton.style.display = showingPackets ? "" : "none";
    elements.streamLoadMoreButton.style.display = showingPackets ? "none" : "";
  }

  function renderInspectorMode() {
    const showingPacketInspector = state.flowViewTab !== "stream";
    elements.packetInspectorView.classList.toggle("active", showingPacketInspector);
    elements.streamInspectorView.classList.toggle("active", !showingPacketInspector);
  }

  function renderPacketDetailsTabs() {
    for (const button of elements.packetDetailsTabButtons) {
      button.classList.toggle("active", button.dataset.packetDetailsTab === state.packetDetailsTab);
    }

    for (const panel of elements.packetDetailsTabPanels) {
      panel.classList.toggle("active", panel.dataset.packetDetailsPanel === state.packetDetailsTab);
    }
  }

  function renderOpenState() {
    const labels = {
      idle: "Idle",
      opening: "Opening",
      opened: "Opened",
      error: "Error",
    };

    elements.openStateBadge.textContent = labels[state.openState] || "Idle";
    elements.openStateBadge.className = `state-badge state-${state.openState}`;
    elements.openButton.style.display = state.openState === "opened" ? "none" : "";
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

  function renderOverview() {
    const overview = state.overview;
    const transportRows = overview ? [
      ["TCP", overview.protocol_summary?.tcp],
      ["UDP", overview.protocol_summary?.udp],
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
      elements.overviewMeta.textContent = "Overview, transport, family, protocol-hint, QUIC/TLS, and top-talker summaries loaded from the active capture or index.";
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
      elements.overviewMeta.textContent = "No overview available after open failure.";
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
  }

  function renderFlows() {
    const flows = state.flows;
    const visibleFlows = getVisibleFlows();
    const checkedCount = checkedFlowCount();

    elements.flowFilterInput.value = state.flowFilterText;
    elements.clearFlowFilterButton.disabled = state.flowFilterText.trim().length === 0;
    elements.checkedFlowsStatusBar.classList.toggle("is-visible", checkedCount > 0);
    elements.checkedFlowsStatusText.textContent = checkedCount === 1 ? "1 flow selected" : `${formatNumber(checkedCount)} flows selected`;

    if (state.openState === "opening" || state.flowState === "loading") {
      elements.flowMeta.textContent = "Loading flows...";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">Loading flows...</td></tr>`;
      return;
    }

    if (state.openState === "error") {
      elements.flowMeta.textContent = "No flows available after open failure.";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="11">Open failed. No flows were loaded.</td></tr>`;
      return;
    }

    if (state.openState !== "opened") {
      elements.flowMeta.textContent = "No capture loaded.";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">Open a capture or index to load flows.</td></tr>`;
      return;
    }

    if (flows.length === 0) {
      elements.flowMeta.textContent = "No flows were found in the opened capture.";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">No flows available.</td></tr>`;
      return;
    }

    if (visibleFlows.length === 0) {
      elements.flowMeta.textContent = state.flowFilterText.trim().length > 0
        ? `Filtered to 0 of ${formatNumber(flows.length)} flows.`
        : "";
      elements.flowRenderCapBar.classList.remove("is-visible");
      state.flowVirtualWindowStart = 0;
      state.flowVirtualWindowEnd = 0;
      state.flowVirtualizationActive = false;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">No flows match the current filter.</td></tr>`;
      return;
    }

    const virtualWindow = renderVirtualizedTableBody({
      tableBody: elements.flowTableBody,
      rows: visibleFlows,
      rowHeight: flowVirtualRowHeight,
      viewportElement: elements.flowTableViewport,
      overscanRows: flowVirtualOverscanRows,
      colspan: 11,
      renderRow: (flow) => {
        const selected = state.selectedFlowIndex === flow.flow_index ? " selected" : "";
        const checked = state.checkedFlowIndices.has(flow.flow_index) ? " checked" : "";
        return `
          <tr class="flow-row${selected}${checked}" data-flow-index="${flow.flow_index}">
            <td class="flow-check-cell"><input type="checkbox" class="flow-check-input" data-flow-check-index="${flow.flow_index}" ${state.checkedFlowIndices.has(flow.flow_index) ? "checked" : ""} aria-label="Select flow ${flowDisplayNumber(flow)} for batch actions" /></td>
            <td>${flowDisplayNumber(flow)}</td>
            <td>${escapeHtml(formatFlowFamily(flow))}</td>
            <td>${escapeHtml(flow.protocol_text)}</td>
            <td>${escapeHtml(formatProtocolHint(flow))}</td>
            <td>${escapeHtml(flow.service_hint)}</td>
            <td title="${escapeHtml(formatFlowFragmentMarker(flow))}">${escapeHtml(formatFlowFragmentMarker(flow))}</td>
            <td>${escapeHtml(flow.address_a)}:${flow.port_a}</td>
            <td>${escapeHtml(flow.address_b)}:${flow.port_b}</td>
            <td>${formatNumber(flow.packet_count)}</td>
            <td>${formatNumber(flow.total_bytes)}</td>
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

    elements.flowMeta.textContent = state.flowFilterText.trim().length > 0
      ? `Filtered to ${formatNumber(visibleFlows.length)} of ${formatNumber(flows.length)} flows.`
      : "";
    elements.flowRenderCapBar.classList.toggle("is-visible", state.flowVirtualizationActive);
    elements.flowRenderCapText.textContent = state.flowVirtualizationActive
      ? (
        selectedFlowOutsideRenderedSlice
          ? `Virtualized list active. Showing rows ${formatNumber(virtualWindow.startIndex + 1)}-${formatNumber(virtualWindow.endIndex)} of ${formatNumber(visibleFlows.length)}. The active flow is outside the current rendered window.`
          : `Virtualized list active. Showing rows ${formatNumber(virtualWindow.startIndex + 1)}-${formatNumber(virtualWindow.endIndex)} of ${formatNumber(visibleFlows.length)}.`
      )
      : "";

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

    if (state.packetState === "loading") {
      elements.packetMeta.textContent = state.selectedFlowIndex == null
        ? "Loading packets..."
        : `Loading packets for flow ${formatNumber(state.selectedFlowIndex + 1)}...`;
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="9">Loading packets...</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    if (state.packetState === "error") {
      elements.packetMeta.textContent = state.packetErrorText || "Failed to load packets.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="9">${escapeHtml(state.packetErrorText || "Failed to load packets.")}</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    if (state.selectedFlowIndex == null) {
      elements.packetMeta.textContent = "Select a flow to load packets.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="9">No selected flow.</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    if (state.packetsTotalCount === 0) {
      elements.packetMeta.textContent = `Flow ${formatNumber(state.selectedFlowIndex + 1)} has no packets.`;
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="9">No packets available for the selected flow.</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    const start = state.packetOffset + 1;
    const end = state.packetOffset + state.packets.length;
    elements.packetMeta.textContent = `Showing ${formatNumber(start)}-${formatNumber(end)} of ${formatNumber(state.packetsTotalCount)} packets for flow ${formatNumber(state.selectedFlowIndex + 1)}.`;

    elements.packetTableBody.innerHTML = state.packets
      .map((packet) => {
        const selected = state.selectedPacketIndex === packet.packet_index ? " selected" : "";
        return `
          <tr class="packet-row${selected}" data-packet-index="${packet.packet_index}">
            <td>${packet.row_number}</td>
            <td>${packet.packet_index}</td>
            <td>${escapeHtml(packet.direction_text)}</td>
            <td>${escapeHtml(packet.timestamp_text)}</td>
            <td>${packet.captured_length}</td>
            <td>${packet.original_length}</td>
            <td>${packet.payload_length}</td>
            <td>${escapeHtml(packet.tcp_flags_text)}</td>
            <td title="${escapeHtml(formatPacketMarker(packet))}">${escapeHtml(formatPacketMarker(packet))}</td>
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

    elements.packetPrevButton.disabled = state.packetOffset === 0;
    elements.packetNextButton.disabled = state.packetOffset + state.packets.length >= state.packetsTotalCount;
  }

  function renderStream() {
    if (state.flowViewTab !== "stream") {
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.openState === "opening" || state.streamState === "loading") {
      elements.packetMeta.textContent = "Loading stream items...";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row"><td colspan="7">Loading stream items...</td></tr>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.openState === "error") {
      elements.packetMeta.textContent = "No stream view is available after open failure.";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="7">Open failed. Stream items were cleared.</td></tr>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.openState !== "opened") {
      elements.packetMeta.textContent = "Open a capture or index to inspect stream items.";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row"><td colspan="7">Open a capture or index to load stream items.</td></tr>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.selectedFlowIndex == null) {
      elements.packetMeta.textContent = "Select a flow to inspect stream items.";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row"><td colspan="7">No selected flow.</td></tr>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamState === "error") {
      elements.packetMeta.textContent = state.streamErrorText || "Failed to load stream items.";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="7">${escapeHtml(state.streamErrorText || "Failed to load stream items.")}</td></tr>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamState === "unavailable") {
      elements.packetMeta.textContent = state.streamUnavailableText || "Stream view is unavailable for this flow.";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="7">${escapeHtml(state.streamUnavailableText || "Stream view is unavailable for this flow.")}</td></tr>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamState === "idle") {
      elements.packetMeta.textContent = "Stream items load on demand for the selected flow.";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row"><td colspan="7">Stream items have not been loaded for this flow yet.</td></tr>`;
      elements.streamLoadMoreButton.disabled = true;
      return;
    }

    if (state.streamItems.length === 0) {
      elements.packetMeta.textContent = "No stream items are available for the selected flow.";
      elements.streamTableBody.innerHTML = `<tr class="table-state-row"><td colspan="7">No stream items available for this flow.</td></tr>`;
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
        const sourcePacketsTitle = sourcePacketRefs.length > 0
          ? `Source packet indices: ${sourcePacketRefs}`
          : item.source_packets_text || "";
        const constrictedTitle = constrictedNotes.length > 0
          ? constrictedNotes.join("\n")
          : (item.has_constricted_contribution ? "Constricted contribution." : "");
        const selected = state.selectedStreamItemIndex === item.stream_item_index ? " selected" : "";

        return `
        <tr class="stream-row${selected}" data-stream-item-index="${item.stream_item_index}">
          <td>${item.stream_item_index}</td>
          <td>${escapeHtml(item.direction_text)}</td>
          <td>${escapeHtml(item.label)}</td>
          <td>${formatNumber(item.byte_count)}</td>
          <td>${formatNumber(item.packet_count)}</td>
          <td title="${escapeHtml(sourcePacketsTitle)}">${escapeHtml(item.source_packets_text)}</td>
          <td title="${escapeHtml(constrictedTitle)}">${item.has_constricted_contribution ? "Constricted" : ""}</td>
        </tr>
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
    elements.streamDetailsSummary.innerHTML = "";
    elements.streamDetailsSourcePacketsText.classList.remove("is-muted");
    elements.streamDetailsSourcePacketIndicesText.classList.remove("is-muted");
    elements.streamDetailsConstrictedNotesText.classList.remove("is-muted");

    if (state.flowViewTab !== "stream") {
      return;
    }

    if (state.streamState === "loading") {
      elements.packetDetailsTitle.textContent = "Selected Stream Item Details";
      elements.packetDetailsMeta.textContent = state.selectedFlowIndex == null
        ? "Loading stream items..."
        : `Loading stream items for flow ${formatNumber(state.selectedFlowIndex + 1)}...`;
      elements.streamDetailsStateText.textContent = "Loading stream items...";
      elements.streamDetailsSourcePacketsText.textContent = "Loading stream items...";
      elements.streamDetailsSourcePacketIndicesText.textContent = "Loading stream items...";
      elements.streamDetailsConstrictedNotesText.textContent = "Loading stream items...";
      return;
    }

    if (state.streamState === "error") {
      elements.packetDetailsTitle.textContent = "Selected Stream Item Details";
      elements.packetDetailsMeta.textContent = "Stream item details are unavailable.";
      elements.streamDetailsStateText.textContent = state.streamErrorText || "Failed to load stream items.";
      elements.streamDetailsStateText.classList.add("is-error");
      elements.streamDetailsSourcePacketsText.textContent = "Stream item details are unavailable because the stream request failed.";
      elements.streamDetailsSourcePacketIndicesText.textContent = "Stream item details are unavailable because the stream request failed.";
      elements.streamDetailsConstrictedNotesText.textContent = "Stream item details are unavailable because the stream request failed.";
      elements.streamDetailsSourcePacketsText.classList.add("is-muted");
      elements.streamDetailsSourcePacketIndicesText.classList.add("is-muted");
      elements.streamDetailsConstrictedNotesText.classList.add("is-muted");
      return;
    }

    if (state.streamState === "unavailable") {
      elements.packetDetailsTitle.textContent = "Selected Stream Item Details";
      elements.packetDetailsMeta.textContent = "Stream item details are unavailable for this flow.";
      elements.streamDetailsStateText.textContent = state.streamUnavailableText || "Stream item details are unavailable.";
      elements.streamDetailsStateText.classList.add("is-error");
      elements.streamDetailsSourcePacketsText.textContent = state.streamUnavailableText || "Stream item details are unavailable.";
      elements.streamDetailsSourcePacketIndicesText.textContent = state.streamUnavailableText || "Stream item details are unavailable.";
      elements.streamDetailsConstrictedNotesText.textContent = state.streamUnavailableText || "Stream item details are unavailable.";
      elements.streamDetailsSourcePacketsText.classList.add("is-muted");
      elements.streamDetailsSourcePacketIndicesText.classList.add("is-muted");
      elements.streamDetailsConstrictedNotesText.classList.add("is-muted");
      return;
    }

    if (state.selectedStreamItem == null) {
      elements.packetDetailsTitle.textContent = "Selected Stream Item Details";
      elements.packetDetailsMeta.textContent = "Select a stream item to inspect details.";
      elements.streamDetailsStateText.textContent = "";
      elements.streamDetailsSourcePacketsText.textContent = "Select a stream item to inspect details.";
      elements.streamDetailsSourcePacketIndicesText.textContent = "Select a stream item to inspect details.";
      elements.streamDetailsConstrictedNotesText.textContent = "Select a stream item to inspect details.";
      elements.streamDetailsSourcePacketsText.classList.add("is-muted");
      elements.streamDetailsSourcePacketIndicesText.classList.add("is-muted");
      elements.streamDetailsConstrictedNotesText.classList.add("is-muted");
      return;
    }

    const item = state.selectedStreamItem;
    const sourcePacketRefs = formatStreamSourcePacketRefs(item);
    const constrictedNotes = formatStreamConstrictedNotes(item);
    const summaryItems = [
      ["Stream Item", item.stream_item_index],
      ["Flow Index", state.selectedFlowIndex == null ? "-" : formatNumber(state.selectedFlowIndex + 1)],
      ["Direction", item.direction_text || "-"],
      ["Label", item.label || "-"],
      ["Bytes", formatNumber(item.byte_count)],
      ["Packets", formatNumber(item.packet_count)],
      ["Constricted", item.has_constricted_contribution ? "Yes" : "No"],
    ];

    elements.packetDetailsTitle.textContent = "Selected Stream Item Details";
    elements.packetDetailsMeta.textContent = `Stream item ${item.stream_item_index} loaded for flow ${formatNumber((state.selectedFlowIndex ?? 0) + 1)}.`;
    elements.streamDetailsStateText.textContent = "";
    elements.streamDetailsSummary.innerHTML = summaryItems
      .map(([label, value]) => `
        <div class="summary-row">
          <span class="summary-label">${escapeHtml(label)}</span>
          <span class="summary-value">${escapeHtml(value)}</span>
        </div>
      `)
      .join("");
    elements.streamDetailsSourcePacketsText.textContent = item.source_packets_text || "No source packet text is available for this stream item.";
    elements.streamDetailsSourcePacketIndicesText.textContent = sourcePacketRefs || "No structured source packet indices are available for this stream item.";
    elements.streamDetailsConstrictedNotesText.textContent = constrictedNotes.length > 0
      ? constrictedNotes.join("\n")
      : (item.has_constricted_contribution ? "Constricted contribution is marked for this stream item, but no notes were emitted." : "No constricted notes are available for this stream item.");

    if (!item.source_packets_text) {
      elements.streamDetailsSourcePacketsText.classList.add("is-muted");
    }
    if (!sourcePacketRefs) {
      elements.streamDetailsSourcePacketIndicesText.classList.add("is-muted");
    }
    if (constrictedNotes.length === 0 && !item.has_constricted_contribution) {
      elements.streamDetailsConstrictedNotesText.classList.add("is-muted");
    }
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
      elements.packetDetailsRawStateText.textContent = "Loading raw preview...";
      elements.packetDetailsPayloadStateText.textContent = "Loading payload preview...";
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
    const summaryItems = [
      ["Packet Index", selectedPacket.packet_index],
      ["Flow Index", state.selectedFlowIndex ?? "-"],
      ["Direction", selectedPacket.direction_text || "-"],
      ["Timestamp", details?.timestamp_text || selectedPacket.timestamp_text || "-"],
      ["Captured Length", formatNumber(details?.captured_length ?? selectedPacket.captured_length)],
      ["Original Length", formatNumber(details?.original_length ?? selectedPacket.original_length)],
      ["Payload Length", formatNumber(details?.payload_length ?? selectedPacket.payload_length)],
      ["TCP Flags", details?.tcp_flags_text || selectedPacket.tcp_flags_text || "-"],
    ];
    const checksumSummaryLines = Array.isArray(details?.checksum_summary_lines) ? details.checksum_summary_lines : [];
    const checksumWarningLines = Array.isArray(details?.checksum_warning_lines) ? details.checksum_warning_lines : [];
    const checksumEnabled = Boolean(details?.checksum_validation_enabled);
    const summaryRowsHtml = summaryItems
      .map(([label, value]) => `
        <div class="summary-row">
          <span class="summary-label">${escapeHtml(label)}</span>
          <span class="summary-value">${escapeHtml(value)}</span>
        </div>
      `)
      .join("");
    const checksumSectionHtml = checksumEnabled
      ? `
        <div class="details-section summary-full-width-section">
          <h3>Checksums</h3>
          <pre class="details-pre">${
            escapeHtml(
              checksumSummaryLines.length > 0
                ? checksumSummaryLines.join("\n")
                : "Checksum validation is enabled, but no checksum results are available for this packet."
            )
          }</pre>
          ${checksumWarningLines.length > 0
            ? `<p class="status-text is-error">${escapeHtml(checksumWarningLines.join(" "))}</p>`
            : ""}
        </div>
      `
      : "";

    elements.packetDetailsSummary.innerHTML = summaryRowsHtml + checksumSectionHtml;

    if (state.packetDetailsState === "error") {
      elements.packetDetailsMeta.textContent = `Packet ${selectedPacket.packet_index} details failed to load.`;
      elements.packetDetailsStateText.textContent = state.packetDetailsErrorText || "Failed to load packet details.";
      elements.packetDetailsStateText.classList.add("is-error");
      elements.packetDetailsRawStateText.textContent = "Raw preview unavailable.";
      elements.packetDetailsPayloadStateText.textContent = "Payload preview unavailable.";
      elements.packetDetailsProtocolStateText.textContent = "Protocol details unavailable.";
      elements.packetDetailsRawStateText.classList.add("is-error");
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsProtocolStateText.classList.add("is-error");
      elements.packetDetailsRawText.textContent = "Raw packet preview is unavailable because the backend request failed.";
      elements.packetDetailsProtocolText.textContent = "Packet details are unavailable because the backend request failed.";
      elements.packetDetailsPayloadText.textContent = "Packet payload preview is unavailable because the backend request failed.";
      elements.packetDetailsRawText.classList.add("is-muted");
      elements.packetDetailsProtocolText.classList.add("is-muted");
      elements.packetDetailsPayloadText.classList.add("is-muted");
      return;
    }

    const protocolSections = [
      details?.link_summary_text,
      details?.network_summary_text,
      details?.transport_summary_text,
      details?.protocol_details_text,
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
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_unavailable_text || "Packet payload preview is unavailable.";
      elements.packetDetailsRawText.classList.add("is-muted");
      if (!details?.protocol_details_text) {
        elements.packetDetailsProtocolText.classList.add("is-muted");
      }
      elements.packetDetailsPayloadText.classList.add("is-muted");
      return;
    }

    const rawLoaded = Boolean(details?.raw_preview_available);
    const payloadLoaded = Boolean(details?.payload_preview_available);
    const rawTruncated = Boolean(details?.raw_preview_truncated);
    const payloadTruncated = Boolean(details?.payload_preview_truncated);

    const metaSuffix = [];
    if (rawTruncated) {
      metaSuffix.push("raw preview truncated");
    }
    if (payloadTruncated) {
      metaSuffix.push("payload preview truncated");
    }

    elements.packetDetailsMeta.textContent = metaSuffix.length > 0
      ? `Packet ${selectedPacket.packet_index} details loaded (${metaSuffix.join(", ")}).`
      : `Packet ${selectedPacket.packet_index} details loaded.`;
    elements.packetDetailsStateText.textContent = "";
    elements.packetDetailsProtocolStateText.textContent = protocolSections.length > 0
      ? "Protocol details loaded."
      : "No additional protocol details are available.";
    elements.packetDetailsProtocolText.textContent = protocolText;
    if (protocolSections.length === 0) {
      elements.packetDetailsProtocolText.classList.add("is-muted");
    }

    if (rawLoaded) {
      elements.packetDetailsRawStateText.textContent = rawTruncated
        ? "Raw preview loaded (truncated)."
        : "Raw preview loaded.";
      elements.packetDetailsRawText.textContent = details?.raw_preview_text || "";
    } else {
      elements.packetDetailsRawStateText.textContent = details?.raw_preview_unavailable_text || "Raw preview is unavailable.";
      elements.packetDetailsRawStateText.classList.add("is-error");
      elements.packetDetailsRawText.textContent = details?.raw_preview_unavailable_text || "Raw preview is unavailable.";
      elements.packetDetailsRawText.classList.add("is-muted");
    }

    if (payloadLoaded) {
      elements.packetDetailsPayloadStateText.textContent = payloadTruncated
        ? "Payload preview loaded (truncated)."
        : "Payload preview loaded.";
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_text || "";
    } else if (details?.payload_preview_no_payload) {
      elements.packetDetailsPayloadStateText.textContent = "No payload is available for this packet.";
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_unavailable_text || "No transport payload is available for this packet.";
      elements.packetDetailsPayloadText.classList.add("is-muted");
    } else {
      elements.packetDetailsPayloadStateText.textContent = details?.payload_preview_unavailable_text || "No payload preview is available.";
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_unavailable_text || "No payload preview is available.";
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
        const endpointSummary = `${flow.address_a}:${flow.port_a} <-> ${flow.address_b}:${flow.port_b}`;
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
            <td>${formatNumber(flow.packet_count)}</td>
            <td>${formatNumber(flow.total_bytes)}</td>
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
    elements.analysisFlowRenderCapBar.classList.toggle("is-visible", state.analysisFlowVirtualizationActive);
    elements.analysisFlowRenderCapText.textContent = state.analysisFlowVirtualizationActive
      ? (
        selectedFlowOutsideRenderedSlice
          ? `Virtualized list active. Showing rows ${formatNumber(virtualWindow.startIndex + 1)}-${formatNumber(virtualWindow.endIndex)} of ${formatNumber(flows.length)}. The active flow is outside the current rendered window.`
          : `Virtualized list active. Showing rows ${formatNumber(virtualWindow.startIndex + 1)}-${formatNumber(virtualWindow.endIndex)} of ${formatNumber(flows.length)}.`
      )
      : "";

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
    elements.analysisTcpControls.innerHTML = "";
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
    elements.analysisTcpControlsSection.style.display = "none";
    elements.analysisPacketSizeHistogramSection.style.display = "none";
    elements.analysisInterArrivalHistogramSection.style.display = "none";
    elements.analysisSequencePreviewSection.style.display = "none";
    elements.analysisContent.classList.remove("is-hidden");
    elements.analysisOpenInFlowsButton.disabled = state.selectedFlowIndex == null;

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

    renderSummaryRows(elements.analysisFlowSummary, [
      ["Flow", formatNumber((analysis.flow_index ?? 0) + 1)],
      ["Endpoints", analysis.endpoint_summary_text || "-"],
      ["Protocol", analysis.protocol_text || "-"],
      ["Protocol Hint", analysis.protocol_hint_display || "-"],
      ["Service", analysis.service_hint_text || "-"],
    ]);

    const protocolPanelRows = [];
    if (analysis.protocol_text) {
      protocolPanelRows.push(["Protocol", analysis.protocol_text]);
    }
    if (analysis.protocol_hint_display) {
      protocolPanelRows.push(["Protocol Hint", analysis.protocol_hint_display]);
    }
    if (analysis.protocol_version_text) {
      protocolPanelRows.push(["Version", analysis.protocol_version_text]);
    }
    if (analysis.protocol_service_text) {
      protocolPanelRows.push(["SNI / Service", analysis.protocol_service_text]);
    }
    if (analysis.protocol_fallback_text) {
      protocolPanelRows.push(["Notes", analysis.protocol_fallback_text]);
    }
    if (protocolPanelRows.length > 0) {
      elements.analysisProtocolPanelSection.style.display = "";
      renderSummaryRows(elements.analysisProtocolPanel, protocolPanelRows);
    }

    renderSummaryRows(elements.analysisTrafficTotals, [
      ["Total Packets", analysis.total_packets_text || formatNumber(analysis.total_packets)],
      ["Original Bytes", analysis.total_bytes_text || formatNumber(analysis.total_bytes)],
      ["Captured Bytes", analysis.captured_bytes_text || formatNumber(analysis.captured_bytes)],
      ["Packets / sec", analysis.packets_per_second_text || "-"],
      ["Data Rate", analysis.bytes_per_second_text || "-"],
    ]);

    renderSummaryRows(elements.analysisDirectionSplit, [
      ["A->B Packets", analysis.packets_a_to_b_text || formatNumber(analysis.packets_a_to_b)],
      ["A->B Bytes", analysis.bytes_a_to_b_text || formatNumber(analysis.bytes_a_to_b)],
      ["B->A Packets", analysis.packets_b_to_a_text || formatNumber(analysis.packets_b_to_a)],
      ["B->A Bytes", analysis.bytes_b_to_a_text || formatNumber(analysis.bytes_b_to_a)],
      ["Packet Ratio", analysis.packet_ratio_text || "-"],
      ["Byte Ratio", analysis.byte_ratio_text || "-"],
      ["Packet Direction", analysis.packet_direction_text || "-"],
      ["Data Direction", analysis.data_direction_text || "-"],
    ]);

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

    renderSummaryRows(elements.analysisTimingSize, [
      ["First Packet", analysis.first_packet_time_text || "-"],
      ["Last Packet", analysis.last_packet_time_text || "-"],
      ["Duration", analysis.duration_text || "-"],
      ["Largest Gap", analysis.largest_gap_text || "-"],
      ["Packets Considered", analysis.packets_considered_text || "-"],
      ["Avg Packet Size", analysis.average_packet_size_text || "-"],
      ["Avg Inter-arrival", analysis.average_inter_arrival_text || "-"],
      ["Min Packet Size", analysis.min_packet_size_text || "-"],
      ["Max Packet Size", analysis.max_packet_size_text || "-"],
    ]);

    const burstIdleRows = [
      ["Burst Count", analysis.burst_count_text || "-"],
      ["Longest Burst", analysis.longest_burst_packet_count_text || "-"],
      ["Largest Burst Bytes", analysis.largest_burst_bytes_text || "-"],
      ["Idle Gap Count", analysis.idle_gap_count_text || "-"],
      ["Largest Idle Gap", analysis.largest_idle_gap_text || "-"],
    ];
    elements.analysisBurstIdleSection.style.display = "";
    renderSummaryRows(elements.analysisBurstIdleSummary, burstIdleRows);

    if (analysis.has_tcp_control_counts) {
      elements.analysisTcpControlsSection.style.display = "";
      renderSummaryRows(elements.analysisTcpControls, [
        ["SYN Packets", analysis.tcp_syn_packets_text || formatNumber(analysis.tcp_syn_packets)],
        ["FIN Packets", analysis.tcp_fin_packets_text || formatNumber(analysis.tcp_fin_packets)],
        ["RST Packets", analysis.tcp_rst_packets_text || formatNumber(analysis.tcp_rst_packets)],
      ]);
    }

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
      ["smart export dialog", renderSmartExportDialog],
      ["tabs", renderTabs],
      ["flow view tabs", renderFlowViewTabs],
      ["inspector mode", renderInspectorMode],
      ["packet detail tabs", renderPacketDetailsTabs],
      ["flow sort headers", renderFlowSortHeaders],
      ["open state", renderOpenState],
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

  async function loadOverviewAndFlows() {
    state.flowState = "loading";
    render();

    const [overview, flows] = await Promise.all([
      invoke("get_overview"),
      invoke("get_flows"),
    ]);

    state.overview = overview;
    await logMemoryPhase("after_get_overview");
    state.flows = flows || [];
    state.flowState = "loaded";
    await logMemoryPhase("after_get_flows");
  }

  async function loadSelectedFlowPackets(selectionToken = state.flowSelectionRequestToken) {
    if (state.selectedFlowIndex == null) {
      clearPackets();
      render();
      return;
    }

    const requestedFlowIndex = state.selectedFlowIndex;
    const requestedOffset = state.packetOffset;
    const requestedLimit = packetPageSize;
    const requestToken = ++state.packetRequestToken;
    clearPacketDetails();
    state.packetState = "loading";
    state.packetErrorText = "";
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

      state.packets = packetResult?.packets || [];
      state.packetsTotalCount = packetResult?.total_count || 0;
      state.packetOffset = packetResult?.offset ?? requestedOffset;
      state.packetState = "loaded";
      state.diagnosticsPacketReturnedRowCount = state.packets.length;
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
      } else {
        state.selectedStreamItemIndex = null;
        state.selectedStreamItem = null;
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
      const details = await invoke("get_selected_flow_packet_details", {
        packet_index: state.selectedPacketIndex,
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
    clearCurrentFlowExportStatusIfPresent();
    clearSmartExportMainStatusIfPresent();
    state.packetOffset = 0;
    clearPackets();
    clearStream();
    clearAnalysis();
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
        clearAnalysis();
        setStatus(`Failed to select flow ${flowIndex}.`, "error");
        render();
        return;
      }

      if (state.activeTab === "flows" && state.flowViewTab === "packets") {
        await loadSelectedFlowPackets(selectionToken);
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
      clearAnalysis();
      state.packetState = "error";
      state.packetErrorText = `Failed to select flow ${flowIndex}: ${String(error)}`;
      setStatus(state.packetErrorText, "error");
      render();
    }
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
      setStatus("The selected stream item is not available in the current stream window.", "error");
      render();
      return;
    }

    state.selectedStreamItemIndex = streamItemIndex;
    state.selectedStreamItem = item;
    render();
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
    state.openState = "opening";
    state.flowState = "loading";
    setStatus("Opening capture...", "neutral");
    render();

    try {
      await logMemoryPhase("before_open_capture", path);
      const result = await invoke("open_capture", {
        path,
        open_mode: openMode,
      });
      await logMemoryPhase("after_open_capture", path);

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
      await loadOverviewAndFlows();
      state.openState = "opened";

      const sourceSuffix = result?.opened_from_index ? " (opened from index)" : "";
      setStatus(`Opened ${path}${sourceSuffix}.`, "success");
      render();
      await logMemoryPhase("after_render_flows", path);
      await logMemoryPhase("after_statistics_loaded", path);
      if (hadLoadedSession) {
        await logMemoryPhase("after_next_open", path);
      }
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
      const selectedPath = await invoke("pick_open_path");
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

  function closeSettingsDialog() {
    if (state.settingsDialogLoading || state.settingsSaveInProgress) {
      return;
    }

    state.settingsDialogVisible = false;
    clearSettingsStatus();
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
    const flowIndices = getSmartExportFlowIndices(flowScope);
    if (flowIndices.length === 0) {
      const emptySelectionMessage = flowScope === "current"
        ? "No current flow selected for smart export."
        : (flowScope === "selected"
          ? "No selected flows for smart export."
          : (flowScope === "unselected"
            ? "No unselected flows for smart export."
            : "No flows available for smart export."));
      setSmartExportStatus(emptySelectionMessage, "error");
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
    if (outputMode === "separate_files") {
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

      const result = await invoke("export_smart_flows", {
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
        const errorText = result?.error_text || "Failed to smart-export flows.";
        setStatus(errorText, "error");
      }
    } catch (error) {
      setStatus(`Failed to smart-export flows: ${String(error)}`, "error");
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
  elements.openButton.addEventListener("click", () => {
    void openCapture();
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
    elements.smartExportScopeSelected,
    elements.smartExportScopeUnselected,
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
      const hadVisibleUi = state.openMenu != null || state.aboutDialogVisible || state.settingsDialogVisible || state.smartExportDialogVisible;
      closeMenus();
      state.aboutDialogVisible = false;
      if (!state.settingsDialogLoading && !state.settingsSaveInProgress) {
        state.settingsDialogVisible = false;
        clearSettingsStatus();
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
  elements.clearFlowFilterButton.addEventListener("click", () => {
    applyFlowFilterState("");
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
  elements.flowTableViewport?.addEventListener("scroll", () => {
    scheduleFlowViewportRender();
  });
  elements.analysisFlowTableViewport?.addEventListener("scroll", () => {
    scheduleAnalysisFlowViewportRender();
  });
  for (const button of elements.tabButtons) {
    button.addEventListener("click", async () => {
      state.activeTab = button.dataset.tab || "flows";
      render();

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
        await loadSelectedFlowPackets();
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
  elements.packetPrevButton.addEventListener("click", async () => {
    if (state.packetOffset === 0 || state.packetState === "loading") {
      return;
    }

    state.packetOffset = Math.max(0, state.packetOffset - packetPageSize);
    clearPacketDetails();
    await loadSelectedFlowPackets();
  });
  elements.packetNextButton.addEventListener("click", async () => {
    if (state.packetState === "loading") {
      return;
    }

    const nextOffset = state.packetOffset + packetPageSize;
    if (nextOffset >= state.packetsTotalCount) {
      return;
    }

    state.packetOffset = nextOffset;
    clearPacketDetails();
    await loadSelectedFlowPackets();
  });
  elements.streamLoadMoreButton.addEventListener("click", async () => {
    if (!state.streamCanLoadMore || state.streamState === "loading") {
      return;
    }

    state.streamRequestedPacketBudget += streamPacketBatchSize;
    state.streamRequestedItemLimit += streamItemBatchSize;
    await loadSelectedFlowStream();
  });
  elements.analysisOpenInFlowsButton.addEventListener("click", () => {
    if (state.selectedFlowIndex == null) {
      return;
    }

    state.activeTab = "flows";
    render();
  });
  elements.analysisExportSequenceCsvButton.addEventListener("click", exportAnalysisSequenceCsv);

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

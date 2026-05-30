(function () {
  const invoke = (...args) => {
    const tauriInvoke = window.__TAURI__?.core?.invoke;
    if (typeof tauriInvoke !== "function") {
      throw new Error("Tauri API is unavailable in this frontend.");
    }

    return tauriInvoke(...args);
  };
  const packetPageSize = 60;
  const initialStreamItems = 15;
  const streamItemBatchSize = 15;
  const initialStreamPacketBudget = 30;
  const streamPacketBatchSize = 30;

  const state = {
    openMenu: null,
    aboutDialogVisible: false,
    activeTab: "flows",
    flowViewTab: "packets",
    openState: "idle",
    attachSourceInProgress: false,
    saveIndexInProgress: false,
    exportCurrentFlowInProgress: false,
    exportSelectedFlowsInProgress: false,
    statusKind: "neutral",
    statusText: "",
    sourceAvailability: null,
    overview: null,
    flows: [],
    flowFilterText: "",
    flowSortKey: "index",
    flowSortDirection: "asc",
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
  };

  const elements = {
    menuButtons: Array.from(document.querySelectorAll("[data-menu-button]")),
    menuPanels: Array.from(document.querySelectorAll("[data-menu-panel]")),
    menuItems: Array.from(document.querySelectorAll("[data-menu-action]")),
    menuSaveIndex: document.getElementById("menuSaveIndex"),
    aboutDialog: document.getElementById("aboutDialog"),
    aboutDialogCloseButton: document.getElementById("aboutDialogCloseButton"),
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
    flowViewTabButtons: Array.from(document.querySelectorAll(".subtab-button")),
    flowViewPanels: Array.from(document.querySelectorAll(".flow-view-panel")),
    overviewMeta: document.getElementById("overviewMeta"),
    flowMeta: document.getElementById("flowMeta"),
    flowFilterInput: document.getElementById("flowFilterInput"),
    clearFlowFilterButton: document.getElementById("clearFlowFilterButton"),
    flowSortHeaders: Array.from(document.querySelectorAll("[data-flow-sort-key]")),
    flowTableBody: document.getElementById("flowTableBody"),
    checkedFlowsStatusBar: document.getElementById("checkedFlowsStatusBar"),
    checkedFlowsStatusText: document.getElementById("checkedFlowsStatusText"),
    wiresharkFilterMeta: document.getElementById("wiresharkFilterMeta"),
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
      && !state.exportSelectedFlowsInProgress;
  }

  function canExportSelectedFlows() {
    const availability = currentSourceAvailability();
    return state.openState === "opened"
      && checkedFlowCount() > 0
      && availability.byte_backed_inspection_available
      && !state.attachSourceInProgress
      && !state.saveIndexInProgress
      && !state.exportCurrentFlowInProgress
      && !state.exportSelectedFlowsInProgress;
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

  function clearCurrentFlowExportStatusIfPresent() {
    if (
      state.statusText === "Flow exported successfully."
      || state.statusText === "Failed to export selected flow."
      || state.statusText.startsWith("Failed to export selected flow:")
    ) {
      setStatus("", "neutral");
    }
  }

  function applyFlowFilterState(filterText) {
    state.flowFilterText = String(filterText || "");
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
    clearPacketDetails();
  }

  function resetForNewOpen() {
    clearOverview();
    clearFlows();
    clearPackets();
    clearStream();
    clearAnalysis();
    state.attachSourceInProgress = false;
    state.saveIndexInProgress = false;
    state.exportCurrentFlowInProgress = false;
    state.exportSelectedFlowsInProgress = false;
    state.openMenu = null;
    state.aboutDialogVisible = false;
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
        } else if (
          action === "open-capture-fast"
          || action === "open-capture-deep"
          || action === "open-index"
        ) {
          item.disabled = state.openState === "opening"
            || state.attachSourceInProgress
            || state.saveIndexInProgress
            || state.exportCurrentFlowInProgress
            || state.exportSelectedFlowsInProgress;
        } else if (
          action === "export-unselected-flows"
          || action === "smart-export"
          || action === "settings"
        ) {
          item.disabled = true;
          if (action === "export-unselected-flows") {
            item.title = "Checked-flow selection is available, but batch export is still deferred.";
          }
        }
      }

      if (elements.aboutDialog) {
        elements.aboutDialog.classList.toggle("is-visible", state.aboutDialogVisible);
        elements.aboutDialog.setAttribute("aria-hidden", state.aboutDialogVisible ? "false" : "true");
      }
    } catch (error) {
      console.error("Failed to render menu state.", error);
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
    setOpenControlsDisabled(state.openState === "opening");
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
    const selectedFlowVisible = visibleFlows.some((flow) => flow.flow_index === state.selectedFlowIndex);
    const checkedCount = checkedFlowCount();

    elements.flowFilterInput.value = state.flowFilterText;
    elements.clearFlowFilterButton.disabled = state.flowFilterText.trim().length === 0;
    elements.checkedFlowsStatusBar.classList.toggle("is-visible", checkedCount > 0);
    elements.checkedFlowsStatusText.textContent = checkedCount === 1 ? "1 flow selected" : `${formatNumber(checkedCount)} flows selected`;

    if (state.openState === "opening" || state.flowState === "loading") {
      elements.flowMeta.textContent = "Loading flows...";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">Loading flows...</td></tr>`;
      return;
    }

    if (state.openState === "error") {
      elements.flowMeta.textContent = "No flows available after open failure.";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="11">Open failed. No flows were loaded.</td></tr>`;
      return;
    }

    if (state.openState !== "opened") {
      elements.flowMeta.textContent = "No capture loaded.";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">Open a capture or index to load flows.</td></tr>`;
      return;
    }

    if (flows.length === 0) {
      elements.flowMeta.textContent = "No flows were found in the opened capture.";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">No flows available.</td></tr>`;
      return;
    }

    if (visibleFlows.length === 0) {
      elements.flowMeta.textContent = `Showing 0 of ${formatNumber(flows.length)} flows.`;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="11">No flows match the current filter.</td></tr>`;
      return;
    }

    elements.flowMeta.textContent = `Showing ${formatNumber(visibleFlows.length)} of ${formatNumber(flows.length)} flows. Click a row to load packets.`;
    elements.flowTableBody.innerHTML = visibleFlows
      .map((flow) => {
        const selected = selectedFlowVisible && state.selectedFlowIndex === flow.flow_index ? " selected" : "";
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
      })
      .join("");

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
      elements.wiresharkFilterMeta.textContent = "Select a flow to generate a filter.";
      elements.wiresharkFilterText.textContent = "No flow selected.";
      elements.copyWiresharkFilterButton.disabled = true;
      return;
    }

    elements.wiresharkFilterMeta.textContent = `Generated from flow ${flowDisplayNumber(selectedFlow)} using shared flow DTO fields.`;
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

    elements.packetDetailsSummary.innerHTML = summaryItems
      .map(([label, value]) => `
        <div class="summary-row">
          <span class="summary-label">${escapeHtml(label)}</span>
          <span class="summary-value">${escapeHtml(value)}</span>
        </div>
      `)
      .join("");

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
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="5">Loading analysis flows...</td></tr>`;
      return;
    }

    if (state.openState === "error") {
      elements.analysisFlowMeta.textContent = "No analysis flows available after open failure.";
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="5">Open failed. Analysis flows were cleared.</td></tr>`;
      return;
    }

    if (state.openState !== "opened") {
      elements.analysisFlowMeta.textContent = "No capture loaded.";
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="5">Open a capture or index to inspect analysis flows.</td></tr>`;
      return;
    }

    if (flows.length === 0) {
      elements.analysisFlowMeta.textContent = "No flows are available for analysis.";
      elements.analysisFlowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="5">No flows available.</td></tr>`;
      return;
    }

    elements.analysisFlowMeta.textContent = state.selectedFlowIndex == null
      ? `Showing ${formatNumber(flows.length)} flows. Select one to load analysis.`
      : `Showing ${formatNumber(flows.length)} flows. Flow ${formatNumber(state.selectedFlowIndex + 1)} is active.`;

    elements.analysisFlowTableBody.innerHTML = flows
      .map((flow) => {
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
      })
      .join("");

    for (const row of elements.analysisFlowTableBody.querySelectorAll(".analysis-flow-row")) {
      row.addEventListener("click", async () => {
        const flowIndex = Number(row.dataset.analysisFlowIndex);
        state.flowFilterText = "";
        elements.flowFilterInput.value = "";
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
      ["tabs", renderTabs],
      ["flow view tabs", renderFlowViewTabs],
      ["inspector mode", renderInspectorMode],
      ["packet detail tabs", renderPacketDetailsTabs],
      ["flow sort headers", renderFlowSortHeaders],
      ["open state", renderOpenState],
      ["source warning banner", renderSourceWarningBanner],
      ["status", renderStatus],
      ["overview", renderOverview],
      ["flows", renderFlows],
      ["Wireshark filter", renderWiresharkFilter],
      ["packets", renderPackets],
      ["stream", renderStream],
      ["packet details", renderPacketDetails],
      ["stream details", renderStreamDetails],
      ["analysis", renderAnalysis],
    ];

    for (const [name, renderStep] of renderSteps) {
      try {
        renderStep();
      } catch (error) {
        console.error(`Failed to render ${name}.`, error);
      }
    }
  }

  async function loadOverviewAndFlows() {
    state.flowState = "loading";
    render();

    const [overview, flows] = await Promise.all([
      invoke("get_overview"),
      invoke("get_flows"),
    ]);

    state.overview = overview;
    state.flows = flows || [];
    state.flowState = "loaded";
  }

  async function loadSelectedFlowPackets() {
    if (state.selectedFlowIndex == null) {
      clearPackets();
      render();
      return;
    }

    clearPacketDetails();
    state.packetState = "loading";
    state.packetErrorText = "";
    render();

    try {
      const packetResult = await invoke("get_selected_flow_packets", {
        offset: state.packetOffset,
        limit: packetPageSize,
      });

      state.packets = packetResult?.packets || [];
      state.packetsTotalCount = packetResult?.total_count || 0;
      state.packetOffset = packetResult?.offset || state.packetOffset;
      state.packetState = "loaded";
    } catch (error) {
      state.packets = [];
      state.packetsTotalCount = 0;
      state.packetState = "error";
      state.packetErrorText = `Failed to load packets: ${String(error)}`;
      setStatus(state.packetErrorText, "error");
    }

    render();
  }

  async function loadSelectedFlowStream() {
    if (state.selectedFlowIndex == null) {
      clearStream();
      render();
      return;
    }

    state.streamState = "loading";
    state.streamErrorText = "";
    state.streamUnavailableText = "";
    render();

    try {
      const streamResult = await invoke("get_selected_flow_stream", {
        max_packets_to_scan: state.streamRequestedPacketBudget,
        limit: state.streamRequestedItemLimit,
      });
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
      state.streamItems = [];
      state.streamState = "error";
      state.streamErrorText = `Failed to load stream items: ${String(error)}`;
      state.streamLoadedForFlowIndex = null;
      state.selectedStreamItemIndex = null;
      state.selectedStreamItem = null;
      setStatus(state.streamErrorText, "error");
    }

    render();
  }

  async function loadSelectedFlowAnalysis() {
    if (state.selectedFlowIndex == null) {
      clearAnalysis();
      render();
      return;
    }

    const requestedFlowIndex = state.selectedFlowIndex;
    state.analysisState = "loading";
    state.analysisErrorText = "";
    state.analysisUnavailableText = "";
    state.analysis = null;
    render();

    try {
      const analysis = await invoke("get_selected_flow_analysis");
      if (state.selectedFlowIndex !== requestedFlowIndex) {
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
      if (state.selectedFlowIndex !== requestedFlowIndex) {
        return;
      }

      state.analysis = null;
      state.analysisLoadedForFlowIndex = null;
      state.analysisState = "error";
      state.analysisErrorText = `Failed to load selected-flow analysis: ${String(error)}`;
      setStatus(state.analysisErrorText, "error");
    }

    render();
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

    try {
      const selection = await invoke("select_flow", { flow_index: flowIndex });
      if (!selection?.selected) {
        setStatus(`Failed to select flow ${flowIndex}.`, "error");
        render();
        return;
      }

      state.selectedFlowIndex = flowIndex;
      clearCurrentFlowExportStatusIfPresent();
      state.packetOffset = 0;
      state.packets = [];
      state.packetsTotalCount = 0;
      state.packetErrorText = "";
      state.packetState = "loading";
      clearStream();
      clearAnalysis();
      clearPacketDetails();
      setWiresharkFilterStatus("", "neutral");
      render();
      await loadSelectedFlowPackets();
      if (state.flowViewTab === "stream") {
        await loadSelectedFlowStream();
      }
      if (state.activeTab === "analysis") {
        await loadSelectedFlowAnalysis();
      }
    } catch (error) {
      state.packetState = "error";
      state.packetErrorText = `Failed to select flow ${flowIndex}: ${String(error)}`;
      clearStream();
      clearAnalysis();
      clearPacketDetails();
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

    resetForNewOpen();
    state.openState = "opening";
    state.flowState = "loading";
    setStatus("Opening capture...", "neutral");
    render();

    try {
      const result = await invoke("open_capture", {
        path,
        open_mode: openMode,
      });

      if (!result?.opened) {
        resetForNewOpen();
        state.openState = "error";
        setStatus(result?.error_text || "Open failed.", "error");
        render();
        return;
      }

      state.sourceAvailability = sourceAvailabilityOrDefault(result?.source_availability);
      await loadOverviewAndFlows();
      state.openState = "opened";

      const sourceSuffix = result?.opened_from_index ? " (opened from index)" : "";
      setStatus(`Opened ${path}${sourceSuffix}.`, "success");
      render();
    } catch (error) {
      resetForNewOpen();
      state.openState = "error";
      setStatus(`Open failed: ${String(error)}`, "error");
      render();
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
      case "settings":
        setStatus("Settings are not implemented yet in the Tauri spike.", "neutral");
        render();
        return;
      case "export-unselected-flows":
      case "smart-export":
        setStatus("Flow export actions are not implemented yet in the Tauri spike.", "neutral");
        render();
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
      const hadVisibleUi = state.openMenu != null || state.aboutDialogVisible;
      closeMenus();
      state.aboutDialogVisible = false;
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
      if (state.flowSortKey === sortKey) {
        state.flowSortDirection = state.flowSortDirection === "asc" ? "desc" : "asc";
      } else {
        state.flowSortKey = sortKey;
        state.flowSortDirection = isDescendingDefaultSortKey(sortKey) ? "desc" : "asc";
      }

      render();
    });
  }
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

  render();
})();

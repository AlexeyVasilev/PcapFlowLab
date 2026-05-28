(function () {
  const invoke = window.__TAURI__?.core?.invoke;
  const packetPageSize = 60;

  const state = {
    activeTab: "flows",
    openState: "idle",
    statusKind: "neutral",
    statusText: "",
    overview: null,
    flows: [],
    flowFilterText: "",
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
    packetDetailsState: "idle",
    packetDetailsErrorText: "",
    packetDetailsTab: "summary",
    wiresharkFilterStatusText: "",
    wiresharkFilterStatusKind: "neutral",
  };

  const elements = {
    capturePath: document.getElementById("capturePath"),
    openMode: document.getElementById("openMode"),
    openButton: document.getElementById("openButton"),
    openStateBadge: document.getElementById("openStateBadge"),
    statusText: document.getElementById("statusText"),
    tabButtons: Array.from(document.querySelectorAll(".tab-button")),
    tabPanels: Array.from(document.querySelectorAll(".tab-panel")),
    overviewMeta: document.getElementById("overviewMeta"),
    flowMeta: document.getElementById("flowMeta"),
    flowFilterInput: document.getElementById("flowFilterInput"),
    clearFlowFilterButton: document.getElementById("clearFlowFilterButton"),
    flowTableBody: document.getElementById("flowTableBody"),
    wiresharkFilterMeta: document.getElementById("wiresharkFilterMeta"),
    wiresharkFilterText: document.getElementById("wiresharkFilterText"),
    wiresharkFilterStatusText: document.getElementById("wiresharkFilterStatusText"),
    copyWiresharkFilterButton: document.getElementById("copyWiresharkFilterButton"),
    packetMeta: document.getElementById("packetMeta"),
    packetTableBody: document.getElementById("packetTableBody"),
    packetPrevButton: document.getElementById("packetPrevButton"),
    packetNextButton: document.getElementById("packetNextButton"),
    packetDetailsMeta: document.getElementById("packetDetailsMeta"),
    packetDetailsTabButtons: Array.from(document.querySelectorAll(".inspector-tab")),
    packetDetailsTabPanels: Array.from(document.querySelectorAll(".packet-details-tab-panel")),
    packetDetailsStateText: document.getElementById("packetDetailsStateText"),
    packetDetailsSummary: document.getElementById("packetDetailsSummary"),
    packetDetailsRawStateText: document.getElementById("packetDetailsRawStateText"),
    packetDetailsRawText: document.getElementById("packetDetailsRawText"),
    packetDetailsPayloadStateText: document.getElementById("packetDetailsPayloadStateText"),
    packetDetailsProtocolText: document.getElementById("packetDetailsProtocolText"),
    packetDetailsProtocolStateText: document.getElementById("packetDetailsProtocolStateText"),
    packetDetailsPayloadText: document.getElementById("packetDetailsPayloadText"),
    metricPackets: document.getElementById("metricPackets"),
    metricFlows: document.getElementById("metricFlows"),
    metricBytes: document.getElementById("metricBytes"),
    metricTcpFlows: document.getElementById("metricTcpFlows"),
    metricUdpFlows: document.getElementById("metricUdpFlows"),
    metricQuicFlows: document.getElementById("metricQuicFlows"),
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

  function setStatus(text, kind = "neutral") {
    state.statusText = text || "";
    state.statusKind = kind;
  }

  function setWiresharkFilterStatus(text, kind = "neutral") {
    state.wiresharkFilterStatusText = text || "";
    state.wiresharkFilterStatusKind = kind;
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

  function clearFlows() {
    state.flows = [];
    state.flowFilterText = "";
    state.selectedFlowIndex = null;
    state.flowState = "idle";
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
    setStatus("", "neutral");
  }

  function setOpenControlsDisabled(disabled) {
    elements.capturePath.disabled = disabled;
    elements.openMode.disabled = disabled;
    elements.openButton.disabled = disabled;
  }

  function renderStatus() {
    elements.statusText.textContent = state.statusText;
    elements.statusText.className = "status-text";
    if (state.statusKind === "error") {
      elements.statusText.classList.add("is-error");
    } else if (state.statusKind === "success") {
      elements.statusText.classList.add("is-success");
    }
  }

  function filteredFlows() {
    const filterText = state.flowFilterText.trim().toLowerCase();
    if (filterText.length === 0) {
      return state.flows;
    }

    return state.flows.filter((flow) => {
      const haystack = [
        flow.protocol_text,
        flow.protocol_hint,
        flow.service_hint,
        flow.endpoint_a,
        flow.endpoint_b,
        flow.address_a,
        flow.address_b,
        String(flow.port_a ?? ""),
        String(flow.port_b ?? ""),
        String(flow.packet_count ?? ""),
        String(flow.total_bytes ?? ""),
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(filterText);
    });
  }

  function buildWiresharkDisplayFilter(flow) {
    if (!flow) {
      return "";
    }

    const addressField = flow.family === "ipv6" ? "ipv6.addr" : "ip.addr";
    const protocolText = String(flow.protocol_text || "").toLowerCase();
    const portField = protocolText === "udp"
      ? "udp.port"
      : protocolText === "tcp"
        ? "tcp.port"
        : "";

    const clauses = [
      `${addressField} == ${flow.address_a}`,
      `${addressField} == ${flow.address_b}`,
    ];

    if (portField) {
      clauses.push(`${portField} == ${flow.port_a}`);
      clauses.push(`${portField} == ${flow.port_b}`);
    }

    return clauses.join(" && ");
  }

  function renderTabs() {
    for (const button of elements.tabButtons) {
      button.classList.toggle("active", button.dataset.tab === state.activeTab);
    }

    for (const panel of elements.tabPanels) {
      panel.classList.toggle("active", panel.dataset.tabPanel === state.activeTab);
    }
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
    setOpenControlsDisabled(state.openState === "opening");
  }

  function renderOverview() {
    const overview = state.overview;

    elements.metricPackets.textContent = overview ? formatNumber(overview.summary?.packet_count) : "-";
    elements.metricFlows.textContent = overview ? formatNumber(overview.summary?.flow_count) : "-";
    elements.metricBytes.textContent = overview ? formatNumber(overview.summary?.total_bytes) : "-";
    elements.metricTcpFlows.textContent = overview ? formatNumber(overview.protocol_summary?.tcp?.flow_count) : "-";
    elements.metricUdpFlows.textContent = overview ? formatNumber(overview.protocol_summary?.udp?.flow_count) : "-";
    elements.metricQuicFlows.textContent = overview ? formatNumber(overview.quic_recognition?.total_flows) : "-";

    if (state.openState === "opening") {
      elements.overviewMeta.textContent = "Loading overview...";
    } else if (state.openState === "opened" && overview) {
      elements.overviewMeta.textContent = "Overview loaded from the active capture or index.";
    } else if (state.openState === "error") {
      elements.overviewMeta.textContent = "No overview available after open failure.";
    } else {
      elements.overviewMeta.textContent = "No capture loaded.";
    }
  }

  function renderFlows() {
    const flows = state.flows;
    const visibleFlows = filteredFlows();
    const selectedFlowVisible = visibleFlows.some((flow) => flow.flow_index === state.selectedFlowIndex);

    elements.flowFilterInput.value = state.flowFilterText;
    elements.clearFlowFilterButton.disabled = state.flowFilterText.trim().length === 0;

    if (state.openState === "opening" || state.flowState === "loading") {
      elements.flowMeta.textContent = "Loading flows...";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="8">Loading flows...</td></tr>`;
      return;
    }

    if (state.openState === "error") {
      elements.flowMeta.textContent = "No flows available after open failure.";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="8">Open failed. No flows were loaded.</td></tr>`;
      return;
    }

    if (state.openState !== "opened") {
      elements.flowMeta.textContent = "No capture loaded.";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="8">Open a capture or index to load flows.</td></tr>`;
      return;
    }

    if (flows.length === 0) {
      elements.flowMeta.textContent = "No flows were found in the opened capture.";
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="8">No flows available.</td></tr>`;
      return;
    }

    if (visibleFlows.length === 0) {
      elements.flowMeta.textContent = `Showing 0 of ${formatNumber(flows.length)} flows.`;
      elements.flowTableBody.innerHTML = `<tr class="table-state-row"><td colspan="8">No flows match the current filter.</td></tr>`;
      return;
    }

    elements.flowMeta.textContent = `Showing ${formatNumber(visibleFlows.length)} of ${formatNumber(flows.length)} flows. Click a row to load packets.`;
    elements.flowTableBody.innerHTML = visibleFlows
      .map((flow) => {
        const selected = selectedFlowVisible && state.selectedFlowIndex === flow.flow_index ? " selected" : "";
        return `
          <tr class="flow-row${selected}" data-flow-index="${flow.flow_index}">
            <td>${flow.flow_index}</td>
            <td>${escapeHtml(flow.protocol_text)}</td>
            <td>${escapeHtml(flow.protocol_hint)}</td>
            <td>${escapeHtml(flow.service_hint)}</td>
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
  }

  function renderWiresharkFilter() {
    const selectedFlow = state.flows.find((flow) => flow.flow_index === state.selectedFlowIndex) || null;
    const filterText = buildWiresharkDisplayFilter(selectedFlow);

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

    elements.wiresharkFilterMeta.textContent = `Generated from flow ${selectedFlow.flow_index} using current flow DTO fields.`;
    elements.wiresharkFilterText.textContent = filterText || "No conservative display filter is available for this flow.";
    elements.copyWiresharkFilterButton.disabled = filterText.length === 0;
  }

  function renderPackets() {
    if (state.packetState === "loading") {
      elements.packetMeta.textContent = state.selectedFlowIndex == null
        ? "Loading packets..."
        : `Loading packets for flow ${state.selectedFlowIndex}...`;
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="8">Loading packets...</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    if (state.packetState === "error") {
      elements.packetMeta.textContent = state.packetErrorText || "Failed to load packets.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row is-error"><td colspan="8">${escapeHtml(state.packetErrorText || "Failed to load packets.")}</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    if (state.selectedFlowIndex == null) {
      elements.packetMeta.textContent = "Select a flow to load packets.";
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="8">No selected flow.</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    if (state.packetsTotalCount === 0) {
      elements.packetMeta.textContent = `Flow ${state.selectedFlowIndex} has no packets.`;
      elements.packetTableBody.innerHTML = `<tr class="table-state-row"><td colspan="8">No packets available for the selected flow.</td></tr>`;
      elements.packetPrevButton.disabled = true;
      elements.packetNextButton.disabled = true;
      return;
    }

    const start = state.packetOffset + 1;
    const end = state.packetOffset + state.packets.length;
    elements.packetMeta.textContent = `Showing ${formatNumber(start)}-${formatNumber(end)} of ${formatNumber(state.packetsTotalCount)} packets for flow ${state.selectedFlowIndex}.`;

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

  function renderPacketDetails() {
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

    const details = state.packetDetails;
    const selectedPacket = state.selectedPacketRow;
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
      const unavailableText = details?.unavailable_text || "Packet details are unavailable for this session.";
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
    } else {
      elements.packetDetailsPayloadStateText.textContent = details?.payload_preview_unavailable_text || "No payload preview is available.";
      elements.packetDetailsPayloadStateText.classList.add("is-error");
      elements.packetDetailsPayloadText.textContent = details?.payload_preview_unavailable_text || "No payload preview is available.";
      elements.packetDetailsPayloadText.classList.add("is-muted");
    }
  }

  function render() {
    renderTabs();
    renderPacketDetailsTabs();
    renderOpenState();
    renderStatus();
    renderOverview();
    renderFlows();
    renderWiresharkFilter();
    renderPackets();
    renderPacketDetails();
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

      state.packetDetails = details;
      if (details?.error_text) {
        state.packetDetailsState = "error";
        state.packetDetailsErrorText = details.error_text;
        setStatus(details.error_text, "error");
      } else if (details?.unavailable_text && !details?.details_available) {
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
      state.packetOffset = 0;
      state.packets = [];
      state.packetsTotalCount = 0;
      state.packetErrorText = "";
      state.packetState = "loading";
      clearPacketDetails();
      setWiresharkFilterStatus("", "neutral");
      setStatus(`Selected flow ${flowIndex}.`, "success");
      render();
      await loadSelectedFlowPackets();
    } catch (error) {
      state.packetState = "error";
      state.packetErrorText = `Failed to select flow ${flowIndex}: ${String(error)}`;
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
    setStatus(`Selected packet ${packetIndex}.`, "success");
    render();
    await loadSelectedPacketDetails();
  }

  async function openCapture() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", "error");
      render();
      return;
    }

    const path = elements.capturePath.value.trim();
    const openMode = elements.openMode.value;

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

  elements.openButton.addEventListener("click", openCapture);
  elements.flowFilterInput.addEventListener("input", () => {
    state.flowFilterText = elements.flowFilterInput.value;
    setWiresharkFilterStatus("", "neutral");

    const selectedFlowVisible = filteredFlows().some((flow) => flow.flow_index === state.selectedFlowIndex);
    if (!selectedFlowVisible) {
      state.selectedFlowIndex = null;
      clearPackets();
      setStatus("Selected flow was cleared because it no longer matches the current filter.", "neutral");
    }

    render();
  });
  elements.clearFlowFilterButton.addEventListener("click", () => {
    state.flowFilterText = "";
    setWiresharkFilterStatus("", "neutral");
    render();
  });
  elements.copyWiresharkFilterButton.addEventListener("click", async () => {
    const selectedFlow = state.flows.find((flow) => flow.flow_index === state.selectedFlowIndex) || null;
    const filterText = buildWiresharkDisplayFilter(selectedFlow);
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
  for (const button of elements.tabButtons) {
    button.addEventListener("click", () => {
      state.activeTab = button.dataset.tab || "flows";
      render();
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

  render();
})();

(function () {
  const invoke = window.__TAURI__?.core?.invoke;
  const packetPageSize = 60;

  const state = {
    openState: "idle",
    statusKind: "neutral",
    statusText: "",
    overview: null,
    flows: [],
    selectedFlowIndex: null,
    packets: [],
    packetsTotalCount: 0,
    packetOffset: 0,
    flowState: "idle",
    packetState: "idle",
    packetErrorText: "",
  };

  const elements = {
    capturePath: document.getElementById("capturePath"),
    openMode: document.getElementById("openMode"),
    openButton: document.getElementById("openButton"),
    openStateBadge: document.getElementById("openStateBadge"),
    statusText: document.getElementById("statusText"),
    overviewMeta: document.getElementById("overviewMeta"),
    flowMeta: document.getElementById("flowMeta"),
    flowTableBody: document.getElementById("flowTableBody"),
    packetMeta: document.getElementById("packetMeta"),
    packetTableBody: document.getElementById("packetTableBody"),
    packetPrevButton: document.getElementById("packetPrevButton"),
    packetNextButton: document.getElementById("packetNextButton"),
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

  function clearOverview() {
    state.overview = null;
  }

  function clearFlows() {
    state.flows = [];
    state.selectedFlowIndex = null;
    state.flowState = "idle";
  }

  function clearPackets() {
    state.packets = [];
    state.packetsTotalCount = 0;
    state.packetOffset = 0;
    state.packetState = "idle";
    state.packetErrorText = "";
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

    elements.flowMeta.textContent = `${formatNumber(flows.length)} flows loaded. Click a row to load packets.`;
    elements.flowTableBody.innerHTML = flows
      .map((flow) => {
        const selected = state.selectedFlowIndex === flow.flow_index ? " selected" : "";
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
      .map((packet) => `
        <tr>
          <td>${packet.row_number}</td>
          <td>${packet.packet_index}</td>
          <td>${escapeHtml(packet.direction_text)}</td>
          <td>${escapeHtml(packet.timestamp_text)}</td>
          <td>${packet.captured_length}</td>
          <td>${packet.original_length}</td>
          <td>${packet.payload_length}</td>
          <td>${escapeHtml(packet.tcp_flags_text)}</td>
        </tr>
      `)
      .join("");

    elements.packetPrevButton.disabled = state.packetOffset === 0;
    elements.packetNextButton.disabled = state.packetOffset + state.packets.length >= state.packetsTotalCount;
  }

  function render() {
    renderOpenState();
    renderStatus();
    renderOverview();
    renderFlows();
    renderPackets();
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
      setStatus(`Selected flow ${flowIndex}.`, "success");
      render();
      await loadSelectedFlowPackets();
    } catch (error) {
      state.packetState = "error";
      state.packetErrorText = `Failed to select flow ${flowIndex}: ${String(error)}`;
      setStatus(state.packetErrorText, "error");
      render();
    }
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
  elements.packetPrevButton.addEventListener("click", async () => {
    if (state.packetOffset === 0 || state.packetState === "loading") {
      return;
    }

    state.packetOffset = Math.max(0, state.packetOffset - packetPageSize);
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
    await loadSelectedFlowPackets();
  });

  render();
})();

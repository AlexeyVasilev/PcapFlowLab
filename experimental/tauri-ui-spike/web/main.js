(function () {
  const invoke = window.__TAURI__?.core?.invoke;

  const state = {
    flows: [],
    selectedFlowIndex: null,
  };

  const elements = {
    capturePath: document.getElementById("capturePath"),
    openMode: document.getElementById("openMode"),
    openButton: document.getElementById("openButton"),
    statusText: document.getElementById("statusText"),
    flowMeta: document.getElementById("flowMeta"),
    flowTableBody: document.getElementById("flowTableBody"),
    packetMeta: document.getElementById("packetMeta"),
    packetTableBody: document.getElementById("packetTableBody"),
    metricPackets: document.getElementById("metricPackets"),
    metricFlows: document.getElementById("metricFlows"),
    metricBytes: document.getElementById("metricBytes"),
    metricTcpFlows: document.getElementById("metricTcpFlows"),
    metricUdpFlows: document.getElementById("metricUdpFlows"),
    metricQuicFlows: document.getElementById("metricQuicFlows"),
  };

  function setStatus(text, isError = false) {
    elements.statusText.textContent = text || "";
    elements.statusText.style.color = isError ? "#9f2b2b" : "#687782";
  }

  function formatNumber(value) {
    return Number(value ?? 0).toLocaleString("en-US");
  }

  function setOverview(overview) {
    elements.metricPackets.textContent = formatNumber(overview?.summary?.packet_count);
    elements.metricFlows.textContent = formatNumber(overview?.summary?.flow_count);
    elements.metricBytes.textContent = formatNumber(overview?.summary?.total_bytes);
    elements.metricTcpFlows.textContent = formatNumber(overview?.protocol_summary?.tcp?.flow_count);
    elements.metricUdpFlows.textContent = formatNumber(overview?.protocol_summary?.udp?.flow_count);
    elements.metricQuicFlows.textContent = formatNumber(overview?.quic_recognition?.total_flows);
  }

  function renderFlows(flows) {
    state.flows = flows || [];
    elements.flowMeta.textContent = `${formatNumber(state.flows.length)} flows loaded.`;

    if (state.flows.length === 0) {
      elements.flowTableBody.innerHTML = `<tr class="empty-row"><td colspan="8">No flows available.</td></tr>`;
      return;
    }

    elements.flowTableBody.innerHTML = state.flows
      .map((flow) => {
        const selected = state.selectedFlowIndex === flow.flow_index ? " selected" : "";
        return `
          <tr class="flow-row${selected}" data-flow-index="${flow.flow_index}">
            <td>${flow.flow_index}</td>
            <td>${flow.protocol_text || ""}</td>
            <td>${flow.protocol_hint || ""}</td>
            <td>${flow.service_hint || ""}</td>
            <td>${flow.address_a}:${flow.port_a}</td>
            <td>${flow.address_b}:${flow.port_b}</td>
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

  function renderPackets(packetResult) {
    const packets = packetResult?.packets || [];
    const totalCount = packetResult?.total_count || 0;

    elements.packetMeta.textContent = packetResult?.has_selected_flow
      ? `Showing ${formatNumber(packets.length)} of ${formatNumber(totalCount)} packets for flow ${packetResult.flow_index}.`
      : "Select a flow to load packets.";

    if (packets.length === 0) {
      elements.packetTableBody.innerHTML = `<tr class="empty-row"><td colspan="8">No packets loaded.</td></tr>`;
      return;
    }

    elements.packetTableBody.innerHTML = packets
      .map((packet) => `
        <tr>
          <td>${packet.row_number}</td>
          <td>${packet.packet_index}</td>
          <td>${packet.direction_text || ""}</td>
          <td>${packet.timestamp_text || ""}</td>
          <td>${packet.captured_length}</td>
          <td>${packet.original_length}</td>
          <td>${packet.payload_length}</td>
          <td>${packet.tcp_flags_text || ""}</td>
        </tr>
      `)
      .join("");
  }

  async function loadOverviewAndFlows() {
    const [overview, flows] = await Promise.all([
      invoke("get_overview"),
      invoke("get_flows"),
    ]);

    setOverview(overview);
    renderFlows(flows);
  }

  async function selectFlow(flowIndex) {
    const selection = await invoke("select_flow", { flow_index: flowIndex });
    if (!selection?.selected) {
      setStatus(`Failed to select flow ${flowIndex}.`, true);
      return;
    }

    state.selectedFlowIndex = flowIndex;
    renderFlows(state.flows);

    const packets = await invoke("get_selected_flow_packets", { offset: 0, limit: 60 });
    renderPackets(packets);
    setStatus(`Selected flow ${flowIndex}.`);
  }

  async function openCapture() {
    if (typeof invoke !== "function") {
      setStatus("Tauri API is unavailable in this frontend.", true);
      return;
    }

    const path = elements.capturePath.value.trim();
    const openMode = elements.openMode.value;

    setStatus("Opening capture...");
    state.selectedFlowIndex = null;
    renderPackets({ has_selected_flow: false, packets: [] });

    try {
      const result = await invoke("open_capture", {
        path,
        open_mode: openMode,
      });

      if (!result?.opened) {
        setOverview(null);
        renderFlows([]);
        setStatus(result?.error_text || "Open failed.", true);
        return;
      }

      await loadOverviewAndFlows();

      const sourceSuffix = result?.opened_from_index ? " (opened from index)" : "";
      setStatus(`Opened ${path}${sourceSuffix}.`);
    } catch (error) {
      setOverview(null);
      renderFlows([]);
      renderPackets({ has_selected_flow: false, packets: [] });
      setStatus(String(error), true);
    }
  }

  elements.openButton.addEventListener("click", openCapture);
})();

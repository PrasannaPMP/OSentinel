// REST & WebSocket client service for OSentinel Backend

const API_BASE = "http://localhost:8000/api";
const WS_URL = "ws://localhost:8000/ws/live";

export async function fetchSystemStatus() {
  const res = await fetch(`${API_BASE}/status`);
  if (!res.ok) throw new Error("Failed to fetch system status");
  return res.json();
}

export async function fetchIncidents() {
  const res = await fetch(`${API_BASE}/incidents`);
  if (!res.ok) throw new Error("Failed to fetch incidents");
  return res.json();
}

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts`);
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}

export async function fetchMLMetrics() {
  const res = await fetch(`${API_BASE}/metrics`);
  if (!res.ok) throw new Error("Failed to fetch ML metrics");
  return res.json();
}

export async function simulateAttack(attackType) {
  const res = await fetch(`${API_BASE}/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attack_type: attackType })
  });
  if (!res.ok) throw new Error("Failed to trigger attack simulation");
  return res.json();
}

export async function containIncident(incidentId, pid, processName, action = "TERMINATE") {
  const res = await fetch(`${API_BASE}/contain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      incident_id: incidentId,
      pid: pid,
      process_name: processName,
      action: action
    })
  });
  if (!res.ok) throw new Error("Failed to execute containment action");
  return res.json();
}

export async function retrainMLModels() {
  const res = await fetch(`${API_BASE}/retrain`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to trigger model retraining");
  return res.json();
}

export async function fetchRestrictedNetworks() {
  const res = await fetch(`${API_BASE}/network/restricted`);
  if (!res.ok) throw new Error("Failed to fetch restricted networks");
  return res.json();
}

export async function addRestrictedNetwork(networkCidr, description, action = "BLOCK") {
  const res = await fetch(`${API_BASE}/network/restricted`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      network_cidr: networkCidr,
      description: description,
      action: action
    })
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || "Failed to add restricted network");
  }
  return res.json();
}

export async function deleteRestrictedNetwork(networkId) {
  const res = await fetch(`${API_BASE}/network/restricted/${networkId}`, {
    method: "DELETE"
  });
  if (!res.ok) throw new Error("Failed to delete restricted network");
  return res.json();
}

export async function toggleRestrictedNetwork(networkId) {
  const res = await fetch(`${API_BASE}/network/restricted/${networkId}/toggle`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to toggle restricted network");
  return res.json();
}

export function connectWebSocket(onMessage, onError, onClose) {
  const socket = new WebSocket(WS_URL);

  socket.onopen = () => {
    console.log("[OSentinel WS] Connected to live telemetry stream.");
  };

  socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error("[OSentinel WS] JSON Parse error:", e);
    }
  };

  socket.onerror = (err) => {
    if (onError) onError(err);
  };

  socket.onclose = () => {
    console.log("[OSentinel WS] Telemetry stream disconnected. Reconnecting in 3s...");
    if (onClose) onClose();
  };

  return socket;
}

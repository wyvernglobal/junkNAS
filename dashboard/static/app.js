// junkNAS dashboard frontend
// Adds setup prompts for new devices and a merge-cluster utility.

let config = null;
let readonly = false;
let lastNodes = [];
let sambaGateway = null;
let sambaClientPrivateKey = null;

const SAMBA_CLIENT_KEY_CACHE_KEY = "junknasSambaClientKey";

const knownNodeIds = new Set(
  JSON.parse(localStorage.getItem("junknasKnownNodes") || "[]")
);

const setupPlans = JSON.parse(
  localStorage.getItem("junknasSetupPlans") || "{}"
);

let setupQueue = [];
let activeSetupNode = null;

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return v.toFixed(1) + " " + units[i];
}

async function loadConfig() {
  const res = await fetch("config.json");
  config = await res.json();
  readonly = !!config.readonly;
  sambaGateway = config.sambaGateway || null;
  document.getElementById("title").innerText = config.clusterName || "junkNAS";
  document.getElementById("subtitle").innerText =
    `API: ${config.apiBaseUrl} · Poll every ${config.pollIntervalSeconds}s`;

  renderSambaCard();
}

async function fetchNodes() {
  const res = await fetch(config.apiBaseUrl + "/nodes");
  const nodes = await res.json();
  lastNodes = nodes;
  renderNodes(nodes);
  renderNatMap(nodes);
  enqueueNewNodes(nodes);
}

function renderSambaCard() {
  const card = document.getElementById("samba-card");
  const missing = document.getElementById("samba-missing");
  if (!card || !missing) return;

  if (!sambaGateway || !sambaGateway.enabled) {
    card.classList.add("hidden");
    missing.classList.remove("hidden");
    return;
  }

  missing.classList.add("hidden");
  card.classList.remove("hidden");

  const preview = document.getElementById("samba-config-preview");
  const meshPublic = document.getElementById("samba-mesh-public");
  const notes = document.getElementById("samba-notes");

  document.getElementById("samba-public-key").innerText =
    sambaGateway.publicKey || "unknown";
  document.getElementById("samba-endpoint").innerText =
    sambaGateway.endpoint || "(no endpoint)";
  document.getElementById("samba-allowed").innerText =
    sambaGateway.allowedIps || "(none)";
  document.getElementById("samba-address").innerText =
    sambaGateway.clientAddressCidr || "(not assigned)";

  meshPublic.innerText = sambaGateway.meshPublicKey || "n/a";
  notes.innerText =
    sambaGateway.note ||
    "Use the peer info above when adding the Samba sidecar to the WireGuard mesh.";

  preview.innerText = buildSambaClientConfig();

  initSambaModal();
}

function buildSambaClientConfig() {
  return buildSambaClientConfigInternal(false);
}

function buildSambaClientConfigWithPrivateKey() {
  return buildSambaClientConfigInternal(true);
}

function buildSambaClientConfigInternal(includePrivateKey) {
  const template = (sambaGateway?.clientConfigTemplate || "").trim();
  if (template) return template;

  const lines = ["[Interface]"];
  if (includePrivateKey) {
    lines.push(`PrivateKey = ${getSambaClientPrivateKey()}`);
  } else {
    lines.push("PrivateKey = <generate on your device>");
  }
  if (sambaGateway?.clientAddressCidr) {
    lines.push(`Address = ${sambaGateway.clientAddressCidr}`);
  }
  if (sambaGateway?.dns) {
    lines.push(`DNS = ${sambaGateway.dns}`);
  }
  lines.push("", "[Peer]");
  if (sambaGateway?.publicKey) {
    lines.push(`PublicKey = ${sambaGateway.publicKey}`);
  }
  if (sambaGateway?.presharedKey) {
    lines.push(`PresharedKey = ${sambaGateway.presharedKey}`);
  }
  if (sambaGateway?.allowedIps) {
    lines.push(`AllowedIPs = ${sambaGateway.allowedIps}`);
  }
  if (sambaGateway?.endpoint) {
    lines.push(`Endpoint = ${sambaGateway.endpoint}`);
  }
  lines.push("PersistentKeepalive = 25");
  return lines.join("\n");
}

function getSambaClientPrivateKey() {
  if (!sambaClientPrivateKey) {
    const cached = sessionStorage.getItem(SAMBA_CLIENT_KEY_CACHE_KEY);
    sambaClientPrivateKey = cached || generateWireGuardPrivateKey();

    if (!cached) {
      sessionStorage.setItem(SAMBA_CLIENT_KEY_CACHE_KEY, sambaClientPrivateKey);
    }
  }

  return sambaClientPrivateKey;
}

function generateWireGuardPrivateKey() {
  try {
    const buf = new Uint8Array(32);
    (crypto || window.crypto).getRandomValues(buf);
    return base64FromBytes(buf);
  } catch (e) {
    console.warn("Falling back to Math.random for key generation", e);
    let arr = [];
    for (let i = 0; i < 32; i++) {
      arr.push(Math.floor(Math.random() * 256));
    }
    return base64FromBytes(arr);
  }
}

function base64FromBytes(bytes) {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin);
}

function renderNodes(nodes) {
  const tbody = document.getElementById("nodes-body");
  tbody.innerHTML = "";

  nodes.forEach((node) => {
    const tr = document.createElement("tr");

    const totalUsed = (node.drives || []).reduce(
      (sum, d) => sum + (d.used_bytes || 0),
      0
    );

    const drivesText = (node.drives || [])
      .map(
        (d) =>
          `${d.id}: ${formatBytes(d.used_bytes || 0)} / ${formatBytes(
            d.allocated_bytes || 0
          )}`
      )
      .join("\n");

    const plan = setupPlans[node.node_id];
    const displayNickname = plan?.nickname || node.nickname || "New device";
    const planText = plan
      ? `${plan.allocationGb} GB planned`
      : "Awaiting setup";

    const natType = node.mesh_nat_type || "unknown";
    const meshEndpoint = node.mesh_endpoint || "n/a";
    const meshScore = node.mesh_score != null ? node.mesh_score.toFixed(3) : "n/a";

    tr.innerHTML = `
      <td>${node.node_id}</td>
      <td>${node.hostname}</td>
      <td>${displayNickname}</td>
      <td>${natType}</td>
      <td>${meshEndpoint}</td>
      <td>${meshScore}</td>
      <td><pre style="margin:0">${drivesText}</pre></td>
      <td>${formatBytes(totalUsed)}</td>
      <td>${planText}</td>
      <td></td>
    `;

    const actionsTd = tr.querySelector("td:last-child");
    if (readonly) {
      actionsTd.innerText = "readonly";
    } else {
      const btnAlloc = document.createElement("button");
      btnAlloc.innerText = "+1GB";
      btnAlloc.onclick = () => alert("TODO: allocate for " + node.node_id);

      const btnEject = document.createElement("button");
      btnEject.innerText = "Eject";
      btnEject.onclick = () => alert("TODO: eject " + node.node_id);

      actionsTd.appendChild(btnAlloc);
      actionsTd.appendChild(document.createTextNode(" "));
      actionsTd.appendChild(btnEject);
    }

    tbody.appendChild(tr);
  });
}

function renderNatMap(nodes) {
  const natDiv = document.getElementById("nat-map");
  if (!natDiv) return;

  let html = "<h2>NAT Map</h2>";
  if (!nodes.length) {
    html += "No nodes connected.";
  } else {
    html += nodes
      .map((n) => {
        const type = n.mesh_nat_type || "unknown";
        const score = n.mesh_score != null ? n.mesh_score.toFixed(3) : "n/a";
        return `${n.node_id} → NAT=${type}, score=${score}`;
      })
      .join("<br/>");
  }

  natDiv.innerHTML = html;
}

function persistSetupPlans() {
  localStorage.setItem("junknasSetupPlans", JSON.stringify(setupPlans));
}

function persistKnownNodes() {
  localStorage.setItem("junknasKnownNodes", JSON.stringify([...knownNodeIds]));
}

function enqueueNewNodes(nodes) {
  const newOnes = nodes.filter((n) => !knownNodeIds.has(n.node_id));
  setupQueue.push(...newOnes);
  updateSetupBanner();
  maybeShowSetupPrompt();
}

function maybeShowSetupPrompt() {
  if (activeSetupNode || !setupQueue.length) return;
  activeSetupNode = setupQueue.shift();
  openSetupModal(activeSetupNode);
  updateSetupBanner();
}

function updateSetupBanner() {
  const banner = document.getElementById("setup-banner");
  if (!banner) return;

  const count = setupQueue.length + (activeSetupNode ? 1 : 0);
  if (count === 0) {
    banner.classList.add("hidden");
    banner.innerText = "";
  } else {
    banner.classList.remove("hidden");
    banner.innerText = `${count} new device${count === 1 ? "" : "s"} waiting for setup`;
  }
}

function openSetupModal(node) {
  const modal = document.getElementById("setup-modal");
  const nicknameInput = document.getElementById("setup-nickname");
  const allocInput = document.getElementById("setup-allocation");
  const deviceLabel = document.getElementById("setup-device-label");

  nicknameInput.value = node.nickname || node.hostname || node.node_id;
  allocInput.value = setupPlans[node.node_id]?.allocationGb || 10;
  deviceLabel.innerText = `${node.hostname || "New host"} (${node.node_id})`;

  modal.classList.remove("hidden");
}

function closeSetupModal() {
  const modal = document.getElementById("setup-modal");
  modal.classList.add("hidden");
  activeSetupNode = null;
  maybeShowSetupPrompt();
}

function saveSetupPlan() {
  if (!activeSetupNode) return;
  const nicknameInput = document.getElementById("setup-nickname");
  const allocInput = document.getElementById("setup-allocation");
  const status = document.getElementById("setup-status");

  const nickname = nicknameInput.value.trim() || activeSetupNode.hostname || "Unnamed device";
  const allocationGb = parseInt(allocInput.value, 10) || 1;

  setupPlans[activeSetupNode.node_id] = { nickname, allocationGb };
  knownNodeIds.add(activeSetupNode.node_id);
  persistSetupPlans();
  persistKnownNodes();

  status.innerText = `Saved plan for ${activeSetupNode.node_id}: ${allocationGb} GB as "${nickname}"`;
  closeSetupModal();
  renderNodes(lastNodes);
}

function skipSetupPlan() {
  const status = document.getElementById("setup-status");
  if (activeSetupNode) {
    knownNodeIds.add(activeSetupNode.node_id);
    persistKnownNodes();
    status.innerText = `Deferred setup for ${activeSetupNode.node_id}; you can revisit later.`;
  }
  closeSetupModal();
}

function initSetupModal() {
  document.getElementById("setup-save").addEventListener("click", saveSetupPlan);
  document.getElementById("setup-skip").addEventListener("click", skipSetupPlan);
}

function initMergeForm() {
  const submitBtn = document.getElementById("merge-submit");
  const status = document.getElementById("merge-status");
  const clusterInput = document.getElementById("merge-cluster-name");
  const wgInput = document.getElementById("merge-config");

  submitBtn.addEventListener("click", () => {
    const clusterName = clusterInput.value.trim() || "unnamed cluster";
    const configText = wgInput.value.trim();

    if (!configText) {
      status.innerText = "Please paste a WireGuard config to continue.";
      status.classList.add("error");
      return;
    }

    status.classList.remove("error");
    status.innerText = "WireGuard config captured. Ready to sync with cluster.";

    const history = JSON.parse(localStorage.getItem("junknasMergeHistory") || "[]");
    history.unshift({ clusterName, configText, ts: Date.now() });
    localStorage.setItem("junknasMergeHistory", JSON.stringify(history.slice(0, 5)));

    wgInput.value = "";
  });
}

function renderSambaQr(text) {
  const container = document.getElementById("samba-qr");
  if (!container) return;
  container.innerHTML = "";

  if (typeof qrcode !== "function") {
    container.innerText = "QR generator unavailable";
    return;
  }

  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const img = document.createElement("img");
  img.alt = "WireGuard config QR";
  img.src = qr.createDataURL(6, 12);
  container.appendChild(img);
}

function openSambaModal() {
  const modal = document.getElementById("samba-modal");
  if (!modal) return;

  const cfg = buildSambaClientConfigWithPrivateKey();
  document.getElementById("samba-config-block").innerText = cfg;
  renderSambaQr(cfg);

  modal.classList.remove("hidden");
}

function closeSambaModal() {
  const modal = document.getElementById("samba-modal");
  if (modal) {
    modal.classList.add("hidden");
  }
}

function downloadSambaConfig() {
  const cfg = buildSambaClientConfigWithPrivateKey();
  const blob = new Blob([cfg], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "junknas-samba.conf";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function initSambaModal() {
  const openBtn = document.getElementById("samba-connect");
  const closeBtn = document.getElementById("samba-close");
  const downloadBtn = document.getElementById("samba-download");

  if (openBtn && !openBtn.dataset.bound) {
    openBtn.dataset.bound = "true";
    openBtn.addEventListener("click", openSambaModal);
  }

  if (closeBtn && !closeBtn.dataset.bound) {
    closeBtn.dataset.bound = "true";
    closeBtn.addEventListener("click", closeSambaModal);
  }

  if (downloadBtn && !downloadBtn.dataset.bound) {
    downloadBtn.dataset.bound = "true";
    downloadBtn.addEventListener("click", downloadSambaConfig);
  }
}

async function main() {
  try {
    await loadConfig();
    initSetupModal();
    initMergeForm();
    await fetchNodes();
    setInterval(fetchNodes, (config.pollIntervalSeconds || 5) * 1000);
  } catch (e) {
    console.error(e);
    document.getElementById("subtitle").innerText = "Failed to load dashboard";
  }
}

document.addEventListener("DOMContentLoaded", main);

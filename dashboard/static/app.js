// junkNAS dashboard frontend
// Adds setup prompts for new devices and a merge-cluster utility.

let config = null;
let readonly = false;
let lastNodes = [];

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
  document.getElementById("title").innerText = config.clusterName || "junkNAS";
  document.getElementById("subtitle").innerText =
    `API: ${config.apiBaseUrl} · Poll every ${config.pollIntervalSeconds}s`;
}

async function fetchNodes() {
  const res = await fetch(config.apiBaseUrl + "/nodes");
  const nodes = await res.json();
  lastNodes = nodes;
  renderNodes(nodes);
  renderNatMap(nodes);
  enqueueNewNodes(nodes);
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

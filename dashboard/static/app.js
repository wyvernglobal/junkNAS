// junkNAS dashboard frontend
//
// Fetches config.json to locate the API, then polls /nodes
// and renders a table of node stats + a NAT "map" summary.

let config = null;
let readonly = false;

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
  renderNodes(nodes);
  renderNatMap(nodes);
}

function renderNodes(nodes) {
  const tbody = document.getElementById("nodes-body");
  tbody.innerHTML = "";

  nodes.forEach((node) => {
    const tr = document.createElement("tr");

    const totalUsed = node.drives.reduce(
      (sum, d) => sum + (d.used_bytes || 0),
      0
    );

    const drivesText = node.drives
      .map(
        (d) =>
          `${d.id}: ${formatBytes(d.used_bytes || 0)} / ${formatBytes(
            d.allocated_bytes || 0
          )}`
      )
      .join("\n");

    // These fields are not yet in NodeState; you can extend the controller
    // to include NAT info there if you want the dashboard to read it directly.
    const natType = node.mesh_nat_type || "unknown";
    const meshEndpoint = node.mesh_endpoint || "n/a";
    const meshScore = node.mesh_score != null ? node.mesh_score.toFixed(3) : "n/a";

    tr.innerHTML = `
      <td>${node.node_id}</td>
      <td>${node.hostname}</td>
      <td>${node.nickname}</td>
      <td>${natType}</td>
      <td>${meshEndpoint}</td>
      <td>${meshScore}</td>
      <td><pre style="margin:0">${drivesText}</pre></td>
      <td>${formatBytes(totalUsed)}</td>
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

  // Simple "map": one line per node with NAT + score
  let html = "<strong>NAT Map</strong><br/>";
  if (!nodes.length) {
    html += "No nodes connected.";
  } else {
    html += nodes
      .map((n) => {
        const type = n.mesh_nat_type || "unknown";
        const score =
          n.mesh_score != null ? n.mesh_score.toFixed(3) : "n/a";
        return `${n.node_id} → NAT=${type}, score=${score}`;
      })
      .join("<br/>");
  }

  natDiv.innerHTML = html;
}

(async function main() {
  try {
    await loadConfig();
    await fetchNodes();
    setInterval(fetchNodes, (config.pollIntervalSeconds || 5) * 1000);
  } catch (e) {
    console.error(e);
    document.getElementById("subtitle").innerText = "Failed to load dashboard";
  }
})();

const form = document.querySelector("#scan-form");
const statusMessage = document.querySelector("#status");
const results = document.querySelector("#results");
const serviceList = document.querySelector("#service-list");

function setStatus(message, isError = false) {
  statusMessage.textContent = message;
  statusMessage.className = isError ? "status error" : "status";
}

function renderScan(scan) {
  document.querySelector("#overall-score").textContent = `${scan.overall_risk_score}/10`;
  document.querySelector("#overall-severity").textContent = scan.overall_severity;
  document.querySelector("#service-count").textContent = scan.results.length;
  serviceList.replaceChildren();

  if (!scan.results.length) {
    serviceList.textContent = "No open services found.";
    results.hidden = false;
    return;
  }

  scan.results.forEach((service) => {
    const item = document.createElement("article");
    item.className = "service";
    const title = document.createElement("div");
    title.className = "service-title";
    title.textContent = `Port ${service.port} · ${service.service}`;
    const meta = document.createElement("div");
    meta.className = "service-meta";
    meta.textContent = [
      service.product,
      service.version,
      `Risk ${service.risk_score}/10 (${service.risk_severity})`,
      `${service.vulnerability_count} CVE(s)`,
    ].filter(Boolean).join(" · ");
    const reasons = document.createElement("div");
    reasons.className = "service-reasons";
    reasons.textContent = service.reasons.join(" ");
    item.append(title, meta, reasons);
    serviceList.append(item);
  });
  results.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  results.hidden = true;
  setStatus("Scanning target and checking vulnerabilities...");

  const payload = {
    target: document.querySelector("#target").value.trim(),
    start_port: Number(document.querySelector("#start-port").value),
    end_port: Number(document.querySelector("#end-port").value),
    internet_facing: document.querySelector("#internet-facing").checked,
  };

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Scan failed.");
    }
    renderScan(data);
    setStatus(`Scan ${data.id} completed.`);
  } catch (error) {
    setStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
});

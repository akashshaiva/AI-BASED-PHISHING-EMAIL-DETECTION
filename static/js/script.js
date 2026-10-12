const API_BASE_URL =
  window.PHISHGUARD_API_URL ||
  (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? "http://127.0.0.1:5000"
    : "");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function showMessage(message, type = "error") {
  const statusElement = document.getElementById("formStatus");
  if (!statusElement) {
    if (type === "error") {
      alert(message);
    }
    return;
  }

  statusElement.textContent = message;
  statusElement.className = `alert mt-3 ${type === "success" ? "alert-success" : "alert-danger"}`;
  statusElement.hidden = false;
}

function hideMessage() {
  const statusElement = document.getElementById("formStatus");
  if (statusElement) {
    statusElement.hidden = true;
    statusElement.textContent = "";
  }
}

function bindFileInputStatus(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;

  const statusTarget = document.querySelector(`.file-status[data-for="${inputId}"]`);
  if (!statusTarget) return;

  const updateStatus = () => {
    const fileName = input.files && input.files.length ? input.files[0].name : "No file selected.";
    statusTarget.textContent = fileName === "No file selected." ? "No file selected." : `Selected: ${fileName}`;
    statusTarget.classList.toggle("text-success", Boolean(input.files && input.files.length));
    statusTarget.classList.toggle("text-muted", !input.files || !input.files.length);
  };

  input.addEventListener("click", () => {
    if (input.value) {
      input.value = "";
      updateStatus();
    }
  });
  input.addEventListener("change", updateStatus);
  input.addEventListener("input", updateStatus);
  updateStatus();
}

async function apiRequest(endpoint, options = {}) {
  const defaultHeaders = {};
  const isJsonRequest = options.body instanceof FormData === false;

  if (isJsonRequest && !(options.headers && options.headers["Content-Type"])) {
    defaultHeaders["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      ...defaultHeaders,
      ...(options.headers || {}),
    },
  });

  let payload = null;

  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }

  if (!response.ok) {
    const message = payload && (payload.message || payload.error)
      ? payload.message || payload.error
      : "The server could not process your request.";
    throw new Error(message);
  }

  return payload;
}

function normalizeAnalysisData(rawResult) {
  if (!rawResult) {
    return null;
  }

  if (rawResult.analysis) {
    return rawResult.analysis;
  }

  return rawResult;
}

function getPredictionLabel(prediction) {
  return Number(prediction) === 1 ? "Phishing" : "Legitimate";
}

function getRiskBadgeClass(riskLevel) {
  if (!riskLevel) {
    return "bg-secondary";
  }

  const normalized = riskLevel.toLowerCase();
  if (normalized === "high") return "bg-danger";
  if (normalized === "medium") return "bg-warning text-dark";
  return "bg-success";
}

function toPercent(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return 0;
  }
  return Math.round(value * 100);
}

function buildReasons(result) {
  const reasons = [];
  const directReasons = Array.isArray(result?.reasons) ? result.reasons : [];

  if (directReasons.length) {
    directReasons.forEach((reason) => {
      if (reason && typeof reason === "string") {
        reasons.push(reason);
      }
    });
  }

  if (!reasons.length) {
    const urlAnalysis = result?.url_analysis || {};
    const summary = urlAnalysis.summary || {};

    if (Array.isArray(summary.suspicious_keywords) && summary.suspicious_keywords.length) {
      summary.suspicious_keywords.forEach((keyword) => {
        reasons.push(`Suspicious keyword: ${keyword}`);
      });
    }

    if (Number(urlAnalysis.count) > 0) {
      reasons.push(`${urlAnalysis.count} URL(s) detected`);
    }

    if (result?.prediction === 1) {
      reasons.push("Model classified the email as phishing");
    }
  }

  if (!reasons.length) {
    reasons.push("No major suspicious indicators detected");
  }

  return reasons;
}

function safeText(value, fallback = "N/A") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  return String(value);
}

function getModelConfidenceText(result) {
  const confidence = Number(result?.confidence ?? 0);
  const percent = toPercent(confidence);
  return `${percent}%`; 
}

function renderUrlAnalysis(result) {
  const container = document.getElementById("urlAnalysisContent");
  if (!container) return;

  const urlAnalysis = result?.url_analysis || {};
  const summary = urlAnalysis.summary || {};
  const urls = Array.isArray(urlAnalysis.urls) ? urlAnalysis.urls : [];

  if (!urls.length) {
    container.innerHTML = "<p class='mb-0 text-muted'>No URLs were detected in the submitted email.</p>";
    return;
  }

  const rows = urls
    .map((item) => {
      const url = safeText(item.url, "Unknown URL");
      const scheme = safeText(item.scheme, "unknown");
      const length = safeText(item.length, "0");
      const suspicious = Array.isArray(item.suspicious_keywords) && item.suspicious_keywords.length
        ? item.suspicious_keywords.join(", ")
        : "None";
      return `
        <div class="border rounded p-2 mb-2">
          <div><strong>URL:</strong> ${escapeHtml(url)}</div>
          <div><strong>Scheme:</strong> ${escapeHtml(scheme)}</div>
          <div><strong>Length:</strong> ${escapeHtml(length)}</div>
          <div><strong>Suspicious keywords:</strong> ${escapeHtml(suspicious)}</div>
        </div>
      `;
    })
    .join("");

  const summaryHtml = `
    <div class="mb-3 small text-muted">
      <div><strong>Count:</strong> ${safeText(urlAnalysis.count ?? 0, 0)}</div>
      <div><strong>Average length:</strong> ${safeText(summary.average_length, 0)}</div>
      <div><strong>Has IP:</strong> ${safeText(summary.has_ip_address ? "Yes" : "No", "No")}</div>
      <div><strong>Uses HTTPS:</strong> ${safeText(summary.uses_https ? "Yes" : "No", "No")}</div>
    </div>
  `;

  container.innerHTML = `${summaryHtml}${rows}`;
}

function renderHeaderAnalysis(result) {
  const container = document.getElementById("headerAnalysisContent");
  if (!container) return;

  const headerAnalysis = result?.header_analysis || {};
  const indicators = Array.isArray(headerAnalysis.indicators) ? headerAnalysis.indicators : [];
  const authResults = headerAnalysis.auth_results || {};

  if (!indicators.length && !Object.keys(authResults).length) {
    container.innerHTML = "<p class='mb-0 text-muted'>No header indicators were detected.</p>";
    return;
  }

  const indicatorHtml = indicators.length
    ? indicators
        .map((item) => `<li><strong>${escapeHtml(safeText(item.type, "header-indicator"))}</strong>: ${escapeHtml(safeText(item.details, "No details available."))}</li>`)
        .join("")
    : "<li>No header indicators detected.</li>";

  const authHtml = Object.keys(authResults).length
    ? `<div class="mt-3"><strong>Authentication results:</strong><ul class="mb-0 mt-2">${Object.entries(authResults)
        .map(([key, value]) => `<li>${escapeHtml(String(key).toUpperCase())}: ${escapeHtml(value && typeof value === "object" ? safeText(value.status, "unknown") : safeText(value, "unknown"))}</li>`)
        .join("")}</ul></div>`
    : "";

  container.innerHTML = `<ul class="mb-0">${indicatorHtml}</ul>${authHtml}`;
}

function renderScreenshotAnalysis(result) {
  const container = document.getElementById("screenshotAnalysisContent");
  if (!container) return;

  const screenshotAnalysis = result?.screenshot_analysis || null;
  if (!screenshotAnalysis) {
    container.innerHTML = "<p class='mb-0 text-muted'>No screenshot was uploaded for analysis.</p>";
    return;
  }

  const reasons = Array.isArray(screenshotAnalysis.reasons) && screenshotAnalysis.reasons.length
    ? screenshotAnalysis.reasons
    : ["No screenshot-based phishing indicators were detected."];

  const summary = screenshotAnalysis.summary || {};
  const suspiciousKeywords = Array.isArray(summary.suspicious_keywords) && summary.suspicious_keywords.length
    ? summary.suspicious_keywords.join(", ")
    : "None";

  container.innerHTML = `
    <div class="small text-muted mb-2">
      <div><strong>File:</strong> ${escapeHtml(safeText(screenshotAnalysis.file_name, "unknown screenshot"))}</div>
      <div><strong>Size:</strong> ${escapeHtml(safeText(summary.size_bytes, 0))} bytes</div>
      <div><strong>Dimensions:</strong> ${escapeHtml(safeText(summary.width, "unknown"))} x ${escapeHtml(safeText(summary.height, "unknown"))}</div>
      <div><strong>Suspicious keywords:</strong> ${escapeHtml(suspiciousKeywords)}</div>
    </div>
    <div class="badge ${getRiskBadgeClass(screenshotAnalysis.risk_level || "low")}">${escapeHtml((screenshotAnalysis.risk_level || "low").toUpperCase())}</div>
    <ul class="mb-0 mt-3">
      ${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}
    </ul>
  `;
}

async function handleAnalyzeRequest() {
  const senderInput = document.getElementById("sender");
  const subjectInput = document.getElementById("subject");
  const bodyInput = document.getElementById("body");
  const fileInput = document.getElementById("emailFile");
  const screenshotInput = document.getElementById("screenshotFile");

  const sender = senderInput ? senderInput.value.trim() : "";
  const subject = subjectInput ? subjectInput.value.trim() : "";
  const body = bodyInput ? bodyInput.value.trim() : "";
  const selectedFile = fileInput && fileInput.files && fileInput.files.length ? fileInput.files[0] : null;
  const selectedScreenshot = screenshotInput && screenshotInput.files && screenshotInput.files.length ? screenshotInput.files[0] : null;

  if (!sender && !subject && !body && !selectedFile && !selectedScreenshot) {
    showMessage("Please fill in the email details or upload a .eml file before analysis.");
    return;
  }

  if (selectedFile && !selectedFile.name.toLowerCase().endsWith(".eml")) {
    showMessage("Please upload a valid .eml file.");
    return;
  }

  if (selectedScreenshot && ![".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"].includes(selectedScreenshot.name.slice(selectedScreenshot.name.lastIndexOf(".")).toLowerCase())) {
    showMessage("Please upload a valid screenshot image file.");
    return;
  }

  hideMessage();
  const button = document.getElementById("analyzeButton");
  const originalText = button ? button.textContent : "";

  if (button) {
    button.disabled = true;
    button.textContent = "Analyzing...";
  }

  try {
    let response;

    if (selectedFile || selectedScreenshot) {
      const formData = new FormData();
      if (selectedFile) {
        formData.append("file", selectedFile);
      }
      if (selectedScreenshot) {
        formData.append("screenshot", selectedScreenshot);
      }
      response = await apiRequest("/api/upload", { method: "POST", body: formData });
    } else {
      if (!sender || !subject || !body) {
        showMessage("Please provide the sender, subject, and email body before analysis.");
        return;
      }

      response = await apiRequest("/api/analyze", {
        method: "POST",
        body: JSON.stringify({ sender, subject, body }),
      });
    }

    const result = normalizeAnalysisData(response);
    if (!result) {
      throw new Error("The backend returned an empty result.");
    }

    localStorage.setItem("phishguard_last_result", JSON.stringify(result));
    window.location.href = "result.html";
  } catch (error) {
    if (error instanceof TypeError) {
      showMessage("The backend is unavailable. Please start the Flask server and try again.");
    } else {
      showMessage(error.message || "An unexpected error occurred while analyzing the email.");
    }
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = originalText;
    }
  }
}

function renderResultPage() {
  const resultContainer = document.getElementById("resultSummary");
  const badgeText = document.getElementById("resultBadgeText");
  const badgePercent = document.getElementById("resultBadgePercent");
  const badgeRisk = document.getElementById("resultBadgeRisk");
  const confidenceValue = document.getElementById("confidenceValue");
  const riskLevelValue = document.getElementById("riskLevelValue");
  const indicatorList = document.getElementById("indicatorList");
  const explanationText = document.getElementById("explanationText");
  const recommendationText = document.getElementById("recommendationText");
  const reasonsList = document.getElementById("reasonsList");
  const modelConfidenceText = document.getElementById("modelConfidenceText");

  if (!resultContainer) {
    return;
  }

  let savedResult = null;
  try {
    savedResult = JSON.parse(localStorage.getItem("phishguard_last_result") || "null");
  } catch (error) {
    savedResult = null;
  }

  if (!savedResult || typeof savedResult !== "object") {
    badgeText.textContent = "No result";
    badgePercent.textContent = "--";
    badgeRisk.textContent = "Awaiting analysis";
    badgeRisk.className = "badge bg-secondary text-uppercase";
    confidenceValue.textContent = "--";
    riskLevelValue.textContent = "No data";
    indicatorList.innerHTML = "<li>No email has been analyzed yet.</li>";
    explanationText.textContent = "Run an analysis from the home page to receive a phishing risk assessment.";
    recommendationText.textContent = "Start by entering the sender, subject, and body or uploading an .eml file.";
    if (reasonsList) reasonsList.innerHTML = "<li>No reasons available.</li>";
    if (modelConfidenceText) modelConfidenceText.textContent = "No confidence available.";
    if (document.getElementById("urlAnalysisContent")) document.getElementById("urlAnalysisContent").innerHTML = "No URL analysis available.";
    if (document.getElementById("headerAnalysisContent")) document.getElementById("headerAnalysisContent").innerHTML = "No header analysis available.";
    if (document.getElementById("screenshotAnalysisContent")) document.getElementById("screenshotAnalysisContent").innerHTML = "No screenshot analysis available.";

    const totalScans = document.getElementById("quickTotalScans");
    const phishingCount = document.getElementById("quickPhishingCount");
    const legitimateCount = document.getElementById("quickLegitimateCount");

    if (totalScans || phishingCount || legitimateCount) {
      apiRequest("/api/dashboard")
        .then((stats) => {
          if (totalScans) totalScans.textContent = stats.total_scans ?? 0;
          if (phishingCount) phishingCount.textContent = stats.phishing_count ?? 0;
          if (legitimateCount) legitimateCount.textContent = stats.legitimate_count ?? 0;
        })
        .catch(() => {
          if (totalScans) totalScans.textContent = "--";
          if (phishingCount) phishingCount.textContent = "--";
          if (legitimateCount) legitimateCount.textContent = "--";
        });
    }

    return;
  }

  const totalScans = document.getElementById("quickTotalScans");
  const phishingCount = document.getElementById("quickPhishingCount");
  const legitimateCount = document.getElementById("quickLegitimateCount");
  if (totalScans || phishingCount || legitimateCount) {
    apiRequest("/api/dashboard")
      .then((stats) => {
        if (totalScans) totalScans.textContent = stats.total_scans ?? 0;
        if (phishingCount) phishingCount.textContent = stats.phishing_count ?? 0;
        if (legitimateCount) legitimateCount.textContent = stats.legitimate_count ?? 0;
      })
      .catch(() => {
        if (totalScans) totalScans.textContent = "--";
        if (phishingCount) phishingCount.textContent = "--";
        if (legitimateCount) legitimateCount.textContent = "--";
      });
  }

  const prediction = Number(savedResult.prediction ?? 0);
  const confidence = Number(savedResult.confidence ?? 0);
  const riskLevel = (savedResult.risk_level || "low").toString().toLowerCase();
  const label = getPredictionLabel(prediction);
  const percent = toPercent(confidence);
  const reasons = buildReasons(savedResult);
  const recommendation = safeText(savedResult.recommendation, "No recommendation provided by the backend.");
  const warning = safeText(savedResult.warning, "");
  let explanation = safeText(savedResult.explanation, prediction === 1 ? "The analysis detected suspicious features associated with phishing behavior." : "The analysis did not identify strong phishing indicators.");
  if (warning && warning !== "N/A") {
    explanation = `${explanation} ${warning}`;
  }

  if (badgeText) badgeText.textContent = label;
  if (badgePercent) badgePercent.textContent = `${percent}%`;
  if (badgeRisk) {
    badgeRisk.textContent = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1) + " Risk";
    badgeRisk.className = `badge ${getRiskBadgeClass(riskLevel)} text-uppercase`;
  }

  if (confidenceValue) confidenceValue.textContent = `${percent}%`;
  if (riskLevelValue) riskLevelValue.textContent = riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1);

  if (indicatorList) {
    indicatorList.innerHTML = reasons
      .map((reason) => `<li><span class="dot ${prediction === 1 ? "bg-danger" : "bg-success"}"></span>${escapeHtml(reason)}</li>`)
      .join("");
  }

  if (reasonsList) {
    reasonsList.innerHTML = reasons
      .map((reason) => `<li class="mb-2"><span class="dot ${prediction === 1 ? "bg-danger" : "bg-success"}"></span> ${escapeHtml(reason)}</li>`)
      .join("");
  }

  if (modelConfidenceText) modelConfidenceText.textContent = getModelConfidenceText(savedResult);

  if (explanationText) {
    explanationText.textContent = explanation;
  }

  if (recommendationText) {
    recommendationText.textContent = recommendation;
  }

  renderUrlAnalysis(savedResult);
  renderHeaderAnalysis(savedResult);
  renderScreenshotAnalysis(savedResult);

  const resultCard = document.querySelector(".result-card");
  if (resultCard) {
    const cardBorder = prediction === 1 ? "border-danger border-2" : "border-success border-2";
    resultCard.className = `card p-4 shadow-sm result-card ${cardBorder}`;
  }
}

function renderHistoryPage() {
  const tableBody = document.getElementById("historyTableBody");
  if (!tableBody) return;

  tableBody.innerHTML = "<tr><td colspan='6' class='text-center text-muted py-4'>Loading scan history...</td></tr>";

  apiRequest("/api/history")
    .then((response) => {
      const history = Array.isArray(response)
        ? response
        : Array.isArray(response?.history)
          ? response.history
          : [];

      if (!history.length) {
        tableBody.innerHTML = "<tr><td colspan='6' class='text-center text-muted py-4'>No previous scans available.</td></tr>";
        return;
      }

      tableBody.innerHTML = history
        .map((item) => {
          const prediction = Number(item.prediction || 0);
          const predictionText = prediction === 1 ? "Phishing" : "Legitimate";
          const predictionClass = prediction === 1 ? "bg-danger" : "bg-success";
          const confidence = Math.round(Number(item.confidence || 0) * 100);
          const riskLevel = (item.risk_level || "low").toString().toLowerCase();
          const riskClass = getRiskBadgeClass(riskLevel);
          const createdDate = item.created_at ? item.created_at.split(" ")[0] : "Unknown";
          const sender = item.sender || "Unknown";
          const subject = item.subject || "No subject";

          return `
            <tr>
              <td>${escapeHtml(createdDate)}</td>
              <td>${escapeHtml(sender)}</td>
              <td>${escapeHtml(subject)}</td>
              <td><span class="badge ${predictionClass}">${escapeHtml(predictionText)}</span></td>
              <td>${escapeHtml(String(confidence))}%</td>
              <td><span class="badge ${riskClass}">${escapeHtml(riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1))}</span></td>
            </tr>
          `;
        })
        .join("");
    })
    .catch((error) => {
      tableBody.innerHTML = `<tr><td colspan='6' class='text-center text-danger py-4'>${escapeHtml(error.message || "Could not load history.")}</td></tr>`;
    });
}

function renderDashboardPage() {
  const totalScans = document.getElementById("totalScans");
  const phishingCount = document.getElementById("phishingCount");
  const legitimateCount = document.getElementById("legitimateCount");
  const highRiskCount = document.getElementById("highRiskCount");
  const mediumRiskCount = document.getElementById("mediumRiskCount");
  const lowRiskCount = document.getElementById("lowRiskCount");
  const highlightTotal = document.getElementById("highlightTotal");
  const highlightHigh = document.getElementById("highlightHigh");
  const highlightMedium = document.getElementById("highlightMedium");
  const highlightLow = document.getElementById("highlightLow");
  const recentTableBody = document.getElementById("recentScanTableBody");

  if (!totalScans && !recentTableBody) {
    return;
  }

  Promise.all([
    apiRequest("/api/dashboard"),
    apiRequest("/api/history"),
  ])
    .then(([stats, history]) => {
      const normalizedStats = {
        total_scans: Number(stats.total_scans ?? 0),
        phishing_count: Number(stats.phishing_count ?? 0),
        legitimate_count: Number(stats.legitimate_count ?? 0),
        high_risk_count: Number(stats.high_risk_count ?? 0),
        medium_risk_count: Number(stats.medium_risk_count ?? 0),
        low_risk_count: Number(stats.low_risk_count ?? 0),
      };

      if (totalScans) totalScans.textContent = normalizedStats.total_scans;
      if (phishingCount) phishingCount.textContent = normalizedStats.phishing_count;
      if (legitimateCount) legitimateCount.textContent = normalizedStats.legitimate_count;
      if (highRiskCount) highRiskCount.textContent = normalizedStats.high_risk_count;
      if (mediumRiskCount) mediumRiskCount.textContent = normalizedStats.medium_risk_count;
      if (lowRiskCount) lowRiskCount.textContent = normalizedStats.low_risk_count;
      if (highlightTotal) highlightTotal.textContent = normalizedStats.total_scans;
      if (highlightHigh) highlightHigh.textContent = normalizedStats.high_risk_count;
      if (highlightMedium) highlightMedium.textContent = normalizedStats.medium_risk_count;
      if (highlightLow) highlightLow.textContent = normalizedStats.low_risk_count;

      if (recentTableBody) {
        if (!Array.isArray(history) || history.length === 0) {
          recentTableBody.innerHTML = "<tr><td colspan='5' class='text-center text-muted py-4'>No recent scans yet.</td></tr>";
        } else {
          recentTableBody.innerHTML = history
            .slice(0, 5)
            .map((item) => {
              const prediction = Number(item.prediction || 0);
              const predictionText = prediction === 1 ? "Phishing" : "Legitimate";
              const predictionClass = prediction === 1 ? "bg-danger" : "bg-success";
              const confidence = Math.round(Number(item.confidence || 0) * 100);
              const createdDate = item.created_at ? item.created_at.split(" ")[0] : "Unknown";
              const sender = item.sender || "Unknown";
              const subject = item.subject || "No subject";

              return `
                <tr>
                  <td>${escapeHtml(createdDate)}</td>
                  <td>${escapeHtml(sender)}</td>
                  <td>${escapeHtml(subject)}</td>
                  <td><span class="badge ${predictionClass}">${escapeHtml(predictionText)}</span></td>
                  <td>${escapeHtml(String(confidence))}%</td>
                </tr>
              `;
            })
            .join("");
        }
      }

      if (typeof Chart !== "undefined") {
        const volumeCanvas = document.getElementById("volumeChart");
        const breakdownCanvas = document.getElementById("breakdownChart");

        if (volumeCanvas) {
          const volumeChart = Chart.getChart(volumeCanvas);
          if (volumeChart) {
            volumeChart.destroy();
          }

          new Chart(volumeCanvas, {
            type: "line",
            data: {
              labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
              datasets: [{
                label: "Scans",
                data: [normalizedStats.total_scans || 0, Math.max(0, normalizedStats.total_scans - 2), Math.max(0, normalizedStats.total_scans - 5), normalizedStats.total_scans || 0, Math.max(0, normalizedStats.total_scans - 1), Math.max(0, normalizedStats.total_scans - 3), normalizedStats.total_scans || 0],
                borderColor: "#06b6d4",
                backgroundColor: "rgba(6, 182, 212, 0.18)",
                fill: true,
                tension: 0.35,
                pointRadius: 4,
                pointHoverRadius: 6,
              }],
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              scales: {
                x: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148, 163, 184, 0.08)" } },
                y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148, 163, 184, 0.08)" } },
              },
              plugins: { legend: { display: false } },
            },
          });
        }

        if (breakdownCanvas) {
          const breakdownChart = Chart.getChart(breakdownCanvas);
          if (breakdownChart) {
            breakdownChart.destroy();
          }

          new Chart(breakdownCanvas, {
            type: "doughnut",
            data: {
              labels: ["Phishing", "Legitimate", "High Risk", "Medium Risk", "Low Risk"],
              datasets: [{
                data: [
                  normalizedStats.phishing_count,
                  normalizedStats.legitimate_count,
                  normalizedStats.high_risk_count,
                  normalizedStats.medium_risk_count,
                  normalizedStats.low_risk_count,
                ],
                backgroundColor: ["#ef4444", "#22c55e", "#facc15", "#38bdf8", "#94a3b8"],
                hoverOffset: 6,
              }],
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: "bottom",
                  labels: { color: "#cbd5e1", usePointStyle: true, pointStyle: "circle" },
                },
              },
            },
          });
        }
      }
    })
    .catch((error) => {
      if (totalScans) totalScans.textContent = "--";
      if (phishingCount) phishingCount.textContent = "--";
      if (legitimateCount) legitimateCount.textContent = "--";
      if (highRiskCount) highRiskCount.textContent = "--";
      if (mediumRiskCount) mediumRiskCount.textContent = "--";
      if (lowRiskCount) lowRiskCount.textContent = "--";
      if (highlightTotal) highlightTotal.textContent = "--";
      if (highlightHigh) highlightHigh.textContent = "--";
      if (highlightMedium) highlightMedium.textContent = "--";
      if (highlightLow) highlightLow.textContent = "--";
      if (recentTableBody) {
        recentTableBody.innerHTML = `<tr><td colspan='5' class='text-center text-danger py-4'>${escapeHtml(error.message || "Dashboard data unavailable.")}</td></tr>`;
      }
    });
}

document.addEventListener("DOMContentLoaded", function () {
  const analyzeButton = document.getElementById("analyzeButton");
  const emailFile = document.getElementById("emailFile");
  const emailForm = document.getElementById("emailForm");

  bindFileInputStatus("emailFile");
  bindFileInputStatus("screenshotFile");

  if (emailFile) {
    emailFile.addEventListener("change", function () {
      const fileName = emailFile.files.length ? emailFile.files[0].name : "No file selected.";
      const fileLabel = document.querySelector("label[for='emailFile']");
      if (fileLabel) {
        fileLabel.textContent = fileName === "No file selected." ? "Upload .eml File" : `Upload .eml File — ${fileName}`;
      }
    });
  }

  if (analyzeButton && emailForm) {
    analyzeButton.addEventListener("click", handleAnalyzeRequest);
  }

  if (document.body && document.body.dataset.page === "result") {
    renderResultPage();
  }

  if (document.body && document.body.dataset.page === "dashboard") {
    renderDashboardPage();
  }

  if (document.body && document.body.dataset.page === "history") {
    renderHistoryPage();
  }
});

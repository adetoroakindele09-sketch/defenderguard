/* ==========================================
   File Activity Monitor
   Local Windows Monitoring Agent integration
========================================== */

const API = (
    window.DAVE_API ||
    ((location.hostname === "localhost" || location.hostname === "127.0.0.1")
        ? "http://127.0.0.1:5000"
        : "https://david-defenderguard.vercel.app")
).replace(/\/$/, "");

if (localStorage.getItem("loggedIn") !== "true") {
    window.location.href = "login.html";
}

const user = JSON.parse(localStorage.getItem("user") || "null");
if (!user?.email) {
    window.location.href = "login.html";
}

const $ = id => document.getElementById(id);
const activityTable = $("activityData");
const monitorStatus = $("monitorStatus");
const logBox = $("logBox");
const createdCount = $("createdCount");
const modifiedCount = $("modifiedCount");
const deletedCount = $("deletedCount");
const threatCount = $("threatCount");
const safeFiles = $("safeFiles");
const warningFiles = $("warningFiles");
const malwareFiles = $("malwareFiles");
const alertBanner = $("alertBanner");
const detailName = $("detailName");
const detailExtension = $("detailExtension");
const detailPrediction = $("detailPrediction");
const detailConfidence = $("detailConfidence");
const detailEntropy = $("detailEntropy");
const detailProcess = $("detailProcess");
const searchInput = $("searchInput");
const activityFilter = $("activityFilter");

let latestEvents = [];
let poller = null;
let agentToken = localStorage.getItem(`agentToken_${user.email}`) || "";

function clock() {
    const n = new Date();
    if ($("clock")) $("clock").textContent = n.toLocaleTimeString();
    if ($("todayDate")) $("todayDate").textContent = n.toDateString();
}
setInterval(clock, 1000);
clock();

function esc(v) {
    const d = document.createElement("div");
    d.textContent = v ?? "";
    return d.innerHTML;
}

function addLog(message) {
    if (!logBox) return;
    logBox.innerHTML += `<p>[${new Date().toLocaleTimeString()}] ${esc(message)}</p>`;
    logBox.scrollTop = logBox.scrollHeight;
}

function statusClass(status) {
    const s = String(status || "Safe").toLowerCase();
    if (s.includes("malware") || s.includes("malicious") || s.includes("suspicious")) return "danger";
    if (s.includes("warning") || s.includes("medium")) return "warning";
    return "safe";
}

async function api(path, options = {}) {
    const response = await fetch(API + path, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        },
        cache: "no-store"
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.success === false) {
        throw new Error(data.message || `HTTP ${response.status}`);
    }
    return data;
}

function render(data) {
    const events = Array.isArray(data.events) ? data.events : [];
    latestEvents = events;

    const totals = data.totals || {};
    const features = data.features || {};
    const set = (id, value) => {
        if ($(id)) $(id).textContent = value;
    };

    set("createdCount", totals.Created || 0);
    set("modifiedCount", totals.Modified || 0);
    set("deletedCount", totals.Deleted || 0);
    set("featureWriteCount", features.write_count || 0);
    set("featureRenameCount", features.rename_count || 0);
    set("featureDeleteCount", features.delete_count || 0);
    set("featureCreateCount", features.create_count || 0);
    set("featureExtDiversity", features.ext_diversity || 0);
    set("featureSensitive", features.sensitive_path_access || 0);
    set("featureRatio", features.read_write_ratio || 0);
    set("featureScore", features.score || 0);
    set("featureEntropy", features.write_entropy || 0);
    set("featureWindow", `${features.window_seconds || 10}s`);
    set("mlStatus", features.ml_status || "LEARNING BASELINE");
    set("mlAnomalyScore", features.ml_anomaly_score ?? "-");

    const suspicious = events.filter(e => /suspicious|malware|malicious/i.test(String(e.status))).length;
    const warnings = events.filter(e => /warning|medium/i.test(String(e.status))).length;
    const safe = events.filter(e => String(e.status).toLowerCase() === "safe").length;

    set("threatCount", suspicious + warnings);
    set("safeFiles", safe);
    set("warningFiles", warnings);
    set("malwareFiles", suspicious);

    const connected = Boolean(data.connected);
    if (monitorStatus) {
        monitorStatus.textContent = connected
            ? (data.monitoring_enabled ? "🟢 MONITORING ACTIVE" : "⏸️ MONITORING PAUSED")
            : "🔴 AGENT OFFLINE";
    }

    if ($("watchingFolder")) {
        $("watchingFolder").textContent = connected
            ? (data.monitoring_enabled
                ? "Watching: all accessible Windows drives"
                : "Monitoring paused — existing activity is preserved")
            : "Monitoring agent is offline";
    }

    if (alertBanner) {
        if (suspicious) {
            alertBanner.className = "danger-banner";
            alertBanner.textContent = "🔴 Suspicious file-activity pattern detected.";
        } else if (warnings) {
            alertBanner.className = "warning-banner";
            alertBanner.textContent = "🟡 Elevated file activity detected.";
        } else {
            alertBanner.className = "safe-banner";
            alertBanner.textContent = connected
                ? "🟢 Monitoring agent is active. No elevated threat pattern detected."
                : "🟡 Monitoring agent is not connected.";
        }
    }

    if (!events.length) {
        if (activityTable) {
            activityTable.innerHTML = `<tr><td colspan="6">Waiting for real file activity...</td></tr>`;
        }
        return;
    }

    activityTable.innerHTML = events.map((e, i) => `
        <tr data-index="${i}">
            <td>${esc(e.filename)}</td>
            <td>${esc(e.extension)}</td>
            <td>${esc(e.activity)}</td>
            <td>${esc(e.process)}</td>
            <td>${esc(e.time)}</td>
            <td class="${statusClass(e.status)}">${esc(e.status || "Safe")}</td>
        </tr>
    `).join("");

    applyFilters();
}

async function pairAndDownloadAgent() {
    // Pairing/downloading belongs on the Dashboard. Activity only controls
    // an already-paired agent.
    window.location.href = "dashboard.html#download-agent";
}

$("startMonitor")?.addEventListener("click", async () => {
    try {
        if (!agentToken) {
            addLog("No paired Monitoring Agent found. Opening Dashboard to download it.");
            window.location.href = "dashboard.html#download-agent";
            return;
        }

        await api("/api/agent/control", {
            method: "POST",
            headers: { Authorization: `Bearer ${agentToken}` },
            body: JSON.stringify({ action: "start" })
        });

        addLog("Start command sent. Monitoring will resume from the current point.");
        startPolling();
        await load();
    } catch (error) {
        console.error(error);
        addLog("ERROR: " + error.message);
        alert("Unable to start monitoring: " + error.message);
    }
});

$("stopMonitor")?.addEventListener("click", async () => {
    try {
        if (!agentToken) {
            stopPolling();
            if (monitorStatus) monitorStatus.textContent = "🟡 AGENT NOT CONNECTED";
            addLog("No paired Monitoring Agent is available.");
            return;
        }

        await api("/api/agent/control", {
            method: "POST",
            headers: { Authorization: `Bearer ${agentToken}` },
            body: JSON.stringify({ action: "stop" })
        });

        addLog("Monitoring stopped. No new filesystem events will be collected until Start Monitoring is pressed again.");
        await load();
    } catch (error) {
        console.error(error);
        alert("Unable to stop monitoring: " + error.message);
    }
});

$("clearLog")?.addEventListener("click", async () => {
    const ok = confirm("Clear all saved file-activity events for this account? This cannot be undone.");
    if (!ok) return;

    try {
        const payload = agentToken
            ? { token: agentToken }
            : { email: user.email };

        await api("/api/agent/clear-log", {
            method: "POST",
            body: JSON.stringify(payload)
        });

        latestEvents = [];
        if (activityTable) {
            activityTable.innerHTML = `<tr><td colspan="6">Waiting for real file activity...</td></tr>`;
        }
        setText("createdCount", 0);
        setText("modifiedCount", 0);
        setText("deletedCount", 0);
        setText("threatCount", 0);
        setText("safeFiles", 0);
        setText("warningFiles", 0);
        setText("malwareFiles", 0);
        addLog("Activity log cleared successfully.");
    } catch (error) {
        console.error(error);
        addLog("ERROR: " + error.message);
        alert("Unable to clear activity log: " + error.message);
    }
});

function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
}


async function load() {
    try {
        const data = await api(`/api/agent/status?email=${encodeURIComponent(user.email)}&_= ${Date.now()}`.replace("_= ", "_="));
        render(data);
        if (data.connected) startPolling();
    } catch (error) {
        console.error("Agent status error:", error);
        if (monitorStatus) monitorStatus.textContent = "🔴 BACKEND UNAVAILABLE";
    }
}

function startPolling() {
    if (poller) return;
    poller = setInterval(load, 1500);
}

function stopPolling() {
    if (!poller) return;
    clearInterval(poller);
    poller = null;
}

function showDetails(e) {
    if (!e) return;
    if (detailName) detailName.textContent = e.filename || "-";
    if (detailExtension) detailExtension.textContent = e.extension || "-";
    if (detailPrediction) detailPrediction.textContent = e.status || "Safe";
    if (detailConfidence) detailConfidence.textContent = `${e.score ?? 0} / 100 behaviour score`;
    if (detailEntropy) detailEntropy.textContent = e.feature_snapshot?.write_entropy ?? 0;
    if (detailProcess) detailProcess.textContent = e.process || "Unknown";
    if ($("detailPath")) $("detailPath").textContent = e.path || "-";
    if ($("detailReasons")) $("detailReasons").textContent = (e.reasons || []).join("; ") || "No elevated activity indicators";
}

activityTable?.addEventListener("click", e => {
    const row = e.target.closest("tr[data-index]");
    if (!row) return;
    showDetails(latestEvents[Number(row.dataset.index)]);
});

function applyFilters() {
    const query = (searchInput?.value || "").toLowerCase();
    const filter = activityFilter?.value || "All";
    activityTable?.querySelectorAll("tr[data-index]").forEach(row => {
        const event = latestEvents[Number(row.dataset.index)];
        const matchesQuery = !query || JSON.stringify(event).toLowerCase().includes(query);
        const matchesFilter = filter === "All" || event.activity === filter;
        row.style.display = matchesQuery && matchesFilter ? "" : "none";
    });
}

searchInput?.addEventListener("input", applyFilters);
activityFilter?.addEventListener("change", applyFilters);
$("logoutBtn")?.addEventListener("click", () => {
    localStorage.removeItem("loggedIn");
    localStorage.removeItem("user");
    localStorage.removeItem("currentUser");
    window.location.href = "login.html";
});

load();

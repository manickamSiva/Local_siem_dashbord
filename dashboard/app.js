const API = "http://127.0.0.1:8000";

async function fetchJSON(url, options = {}) {
    const response = await fetch(url, options);

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
}

async function loadStats() {
    try {
        const data = await fetchJSON(`${API}/api/stats`);

        document.getElementById("total-events").textContent =
            data.total_events;

        document.getElementById("failed-logins").textContent =
            data.failed_logins;

        document.getElementById("successful-logins").textContent =
            data.successful_logins;

        document.getElementById("active-alerts").textContent =
            data.active_alerts;

        document.getElementById("source-ips").textContent =
            data.unique_source_ips;

    } catch (error) {
        console.error("Failed to load statistics:", error);

        document.getElementById("total-events").textContent = "Failed";
        document.getElementById("failed-logins").textContent = "Failed";
        document.getElementById("successful-logins").textContent = "Failed";
        document.getElementById("active-alerts").textContent = "Failed";
        document.getElementById("source-ips").textContent = "Failed";

        throw error;
    }
}

async function checkAPIStatus() {
    const statusText = document.getElementById("api-status-text");
    const statusDot = document.getElementById("api-status-dot");

    try {
        const response = await fetch(`${API}/`, {
            method: "GET",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`API returned ${response.status}`);
        }

        if (statusText) {
            statusText.textContent = "API Online";
        }

        if (statusDot) {
            statusDot.classList.remove("offline");
            statusDot.classList.add("online");
        }

        return true;

    } catch (error) {

        console.error("API status check failed:", error);

        if (statusText) {
            statusText.textContent = "API Offline";
        }

        if (statusDot) {
            statusDot.classList.remove("online");
            statusDot.classList.add("offline");
        }

        return false;
    }
}

async function loadEvents() {
    const table = document.getElementById("events-table");

    try {
        const data = await fetchJSON(`${API}/api/events?limit=20`);

        table.innerHTML = "";

        if (!data.events || data.events.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="9" class="loading">
                        No events found
                    </td>
                </tr>
            `;

            return;
        }

        data.events.forEach(event => {
            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${escapeHtml(event.timestamp || "-")}</td>
                <td>${escapeHtml(String(event.event_id || "-"))}</td>
                <td>${escapeHtml(event.event_name || "Other")}</td>
                <td>${escapeHtml(event.category || "-")}</td>

                <td>
                    <span class="severity ${getSeverityClass(event.severity)}">
                        ${escapeHtml(event.severity || "UNKNOWN")}
                    </span>
                </td>

                <td>${escapeHtml(event.username || "-")}</td>
                <td>${escapeHtml(event.source_ip || "-")}</td>
                <td>${escapeHtml(event.mitre_technique || "-")}</td>

                <td class="event-action-cell"></td>
            `;

            const button = document.createElement("button");

            button.className = "view-event-button";
            button.textContent = "View Event";

            button.addEventListener("click", () => {
                viewEvent(event);
            });

            row
                .querySelector(".event-action-cell")
                .appendChild(button);

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Failed to load events:", error);

        table.innerHTML = `
            <tr>
                <td colspan="9" class="loading">
                    ❌ Failed to load events
                </td>
            </tr>
        `;

        throw error;
    }
}

async function loadAlerts() {
    const container = document.getElementById("alerts-container");

    try {
        const data = await fetchJSON(`${API}/api/alerts`);

        container.innerHTML = "";

        if (!data.alerts?.length) {
            container.innerHTML = `<div class="loading">No active alerts</div>`;
            return;
        }

        data.alerts.forEach(alert => {
            const element = document.createElement("div");
            const severity = (alert.severity || "UNKNOWN").toLowerCase();

            element.className = `alert alert-${severity}`;

            element.innerHTML = `
                <div class="alert-title">
                    🚨 ${escapeHtml(alert.alert_type)}
                    <span class="severity-${severity}">
                        [${escapeHtml(alert.severity || "UNKNOWN")}]
                    </span>
                </div>

                <div class="alert-info">User: ${escapeHtml(alert.username || "-")}</div>
                <div class="alert-info">Source: ${escapeHtml(alert.source_ip || "-")}</div>
                <div class="alert-info">MITRE: ${escapeHtml(alert.mitre_technique || "-")}</div>
                <div class="alert-info">Status: <strong>${escapeHtml(alert.status || "-")}</strong></div>
                <div class="alert-info">${escapeHtml(alert.description || "")}</div>

                <div class="alert-actions">
                    <button onclick="viewRelatedEvents(${alert.id})">View Events</button>
                    <button onclick="investigateAlert(${alert.id})">Investigate</button>
                    <button class="resolve-button" onclick="updateAlertStatus(${alert.id}, 'RESOLVED')">Resolve</button>
                </div>

                <div id="related-events-${alert.id}" class="related-events"></div>
            `;

            container.appendChild(element);
        });

    } catch (error) {
        console.error("Failed to load alerts:", error);

        container.innerHTML = `
            <div class="loading">
                ❌ Failed to load active alerts
            </div>
        `;

        throw error;
    }
}

async function loadResolvedAlerts() {
    const container = document.getElementById("resolved-alerts-container");

    if (!container) {
        return;
    }

    try {
        const data = await fetchJSON(`${API}/api/alerts?status=RESOLVED`);

        container.innerHTML = "";

        if (!data.alerts || data.alerts.length === 0) {
            container.innerHTML = `
                <div class="loading">
                    No resolved alerts
                </div>
            `;
            return;
        }

        data.alerts.forEach(alert => {
            const severity = (alert.severity || "UNKNOWN").toLowerCase();

            const element = document.createElement("div");

            element.className = `alert resolved-alert alert-${severity}`;

            element.innerHTML = `
                <div class="alert-title">
                    ✅ ${escapeHtml(alert.alert_type || "Alert")}
                    <span class="severity-${severity}">
                        [${escapeHtml(alert.severity || "UNKNOWN")}]
                    </span>
                </div>

                <div class="alert-info">
                    User: ${escapeHtml(alert.username || "-")}
                </div>

                <div class="alert-info">
                    Source: ${escapeHtml(alert.source_ip || "-")}
                </div>

                <div class="alert-info">
                    MITRE: ${escapeHtml(alert.mitre_technique || "-")}
                </div>

                <div class="alert-info">
                    Status:
                    <strong>RESOLVED</strong>
                </div>

                <div class="alert-info">
                    ${escapeHtml(alert.description || "")}
                </div>

                <div class="alert-actions">
                    <button onclick="viewRelatedEvents(${alert.id})">
                        View Events
                    </button>

                    <button onclick="investigateAlert(${alert.id})">
                        View Investigation
                    </button>
                </div>

                <div id="related-events-${alert.id}"
                     class="related-events">
                </div>
            `;

            container.appendChild(element);
        });

    } catch (error) {
        console.error("Failed to load resolved alerts:", error);

        container.innerHTML = `
            <div class="loading">
                ❌ Failed to load resolved alerts
            </div>
        `;

        throw error;
    }
}

async function viewRelatedEvents(alertId) {
    const container = document.getElementById(`related-events-${alertId}`);

    if (!container) {
        return;
    }

    container.innerHTML = `<div class="loading">Loading related events...</div>`;

    try {
        const data = await fetchJSON(`${API}/api/alerts/${alertId}/events`);

        if (!data.events?.length) {
            container.innerHTML = `<div class="loading">No related events found</div>`;
            return;
        }

        container.innerHTML = `
            <div class="related-title">Related Events (${data.count})</div>

            <div class="related-event-list">
                ${data.events.map(event => `
                    <div class="related-event">
                        <div>
                            <strong>Event ${event.event_id}</strong> -
                            ${escapeHtml(event.event_name || "Unknown")}
                        </div>
                        <div class="alert-info">Time: ${escapeHtml(event.timestamp || "-")}</div>
                        <div class="alert-info">User: ${escapeHtml(event.username || "-")}</div>
                        <div class="alert-info">Source: ${escapeHtml(event.source_ip || "-")}</div>
                    </div>
                `).join("")}
            </div>
        `;

    } catch (error) {
        console.error("Failed to load related events:", error);

        container.innerHTML = `<div class="loading">Failed to load related events</div>`;
    }
}

async function investigateAlert(alertId) {
    const modal = document.getElementById("investigation-modal");
    const content = document.getElementById("investigation-content");

    modal.classList.remove("hidden");
    content.innerHTML = `<div class="loading">Loading investigation...</div>`;

    try {
        const alertData = await fetchJSON(`${API}/api/alerts/${alertId}`);
        const eventData = await fetchJSON(`${API}/api/alerts/${alertId}/events`);

        const severity = alertData.severity || "UNKNOWN";

        content.innerHTML = `
            <div class="investigation-header">
                <div>
                    <h2>🚨 ${escapeHtml(alertData.alert_type)}</h2>
                    <span class="severity-${severity.toLowerCase()}">
                        ${escapeHtml(severity)}
                    </span>
                </div>

                <button class="close-button" onclick="closeInvestigation()">✕</button>
            </div>

            <div class="investigation-grid">
                <div class="investigation-item">
                    <span>Alert ID</span>
                    <strong>#${alertData.id}</strong>
                </div>

                <div class="investigation-item">
                    <span>Status</span>
                    <strong>${escapeHtml(alertData.status)}</strong>
                </div>

                <div class="investigation-item">
                    <span>Source IP</span>
                    <strong>${escapeHtml(alertData.source_ip || "-")}</strong>
                </div>

                <div class="investigation-item">
                    <span>Username</span>
                    <strong>${escapeHtml(alertData.username || "-")}</strong>
                </div>

                <div class="investigation-item">
                    <span>MITRE Technique</span>
                    <strong>${escapeHtml(alertData.mitre_technique || "-")}</strong>
                </div>

                <div class="investigation-item">
                    <span>Related Events</span>
                    <strong>${eventData.count}</strong>
                </div>
            </div>

            <div class="investigation-section">
                <h3>Description</h3>
                <p>${escapeHtml(alertData.description || "-")}</p>
            </div>

            <div class="investigation-section">
                <h3>Related Events</h3>

                <div class="investigation-timeline">
                    ${eventData.events.length
                        ? eventData.events.slice().reverse().map((event, index) => `
                            <div class="timeline-item">
                                <div class="timeline-marker">${index + 1}</div>
                                <div class="timeline-line"></div>

                                <div class="timeline-content">
                                    <div class="timeline-header">
                                        <strong>Event ${event.event_id}</strong>
                                        <span>${escapeHtml(event.event_name || "Unknown")}</span>
                                    </div>

                                    <div class="timeline-time">${escapeHtml(event.timestamp || "-")}</div>

                                    <div class="timeline-details">
                                        <div>
                                            <span>User</span>
                                            <strong>${escapeHtml(event.username || "-")}</strong>
                                        </div>
                                        <div>
                                            <span>Source IP</span>
                                            <strong>${escapeHtml(event.source_ip || "-")}</strong>
                                        </div>
                                        <div>
                                            <span>Event Type</span>
                                            <strong>${escapeHtml(event.event_type || "-")}</strong>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `).join("")
                        : `<div class="loading">No related events</div>`
                    }
                </div>
            </div>

            <div class="investigation-actions">
    ${
        alertData.status === "RESOLVED"
        ? `
            <div class="resolved-status-message">
                ✅ This alert has been resolved.
            </div>
        `
        : `
            <button
                onclick="updateAlertStatus(${alertData.id}, 'INVESTIGATING'); closeInvestigation();"
                ${alertData.status === "INVESTIGATING" ? "disabled" : ""}
            >
                Investigating
            </button>

            <button
                class="resolve-button"
                onclick="updateAlertStatus(${alertData.id}, 'RESOLVED'); closeInvestigation();"
            >
                Resolve Alert
            </button>
        `
    }
</div>
        `;

    } catch (error) {
        console.error("Failed to investigate alert:", error);

        content.innerHTML = `
            <div class="loading">
                Failed to load investigation data.
                <br><br>
                <button onclick="closeInvestigation()">Close</button>
            </div>
        `;
    }
}

function closeInvestigation() {
    const modal = document.getElementById("investigation-modal");
    modal.classList.add("hidden");
}

async function updateAlertStatus(alertId, status) {
    try {
        const data = await fetchJSON(`${API}/api/alerts/${alertId}/status`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status })
        });

        console.log(`Alert ${alertId} → ${data.status}`);

        await Promise.all([
            loadAlerts(),
            loadStats()
        ]);

    } catch (error) {
        console.error("Failed to update alert status:", error);
        alert("Failed to update alert status.");
    }
}

function getSeverityClass(severity) {
    return severity ? severity.toLowerCase() : "unknown";
}

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value;
    return div.innerHTML;
}

async function loadCategories() {
    const container = document.getElementById("category-chart");

    if (!container) {
        return;
    }

    try {
        const data = await fetchJSON(`${API}/api/categories`);

        container.innerHTML = "";

        if (!data.categories?.length) {
            container.innerHTML = `<div class="loading">No category data</div>`;
            return;
        }

        const maxCount = Math.max(...data.categories.map(item => item.count));

        data.categories.forEach(item => {
            const percentage = (item.count / maxCount) * 100;
            const row = document.createElement("div");

            row.className = "chart-row";

            row.innerHTML = `
                <div class="chart-label">
                    <span class="category-name">${escapeHtml(item.category)}</span>
                    <span class="chart-count">${item.count}</span>
                </div>

                <div class="chart-bar-container">
                    <div class="chart-bar" style="width: ${percentage}%"></div>
                </div>
            `;

            container.appendChild(row);
        });

    } catch (error) {
        console.error("Failed to load categories:", error);

        container.innerHTML = `
            <div class="loading">
                ❌ Failed to load category data
            </div>
        `;

        throw error;
    }
}

async function loadSeverity() {
    const container = document.getElementById("severity-chart");

    if (!container) {
        return;
    }

    try {
        const data = await fetchJSON(`${API}/api/severity`);

        container.innerHTML = "";

        if (!data.severity?.length) {
            container.innerHTML = `<div class="loading">No severity data</div>`;
            return;
        }

        const maxCount = Math.max(...data.severity.map(item => item.count));

        data.severity.forEach(item => {
            const severity = item.severity || "UNKNOWN";
            const percentage = (item.count / maxCount) * 100;
            const row = document.createElement("div");

            row.className = "chart-row";

            row.innerHTML = `
                <div class="chart-label">
                    <span class="category-name">${escapeHtml(severity)}</span>
                    <span class="chart-count">${item.count}</span>
                </div>

                <div class="chart-bar-container">
                    <div class="chart-bar severity-${severity}" style="width: ${percentage}%"></div>
                </div>
            `;

            container.appendChild(row);
        });

    } catch (error) {
        console.error("Failed to load severity:", error);

        container.innerHTML = `
            <div class="loading">
                ❌ Failed to load severity data
            </div>
        `;

        throw error;
    }
}

function viewEvent(event) {
    const modal = document.getElementById("event-modal");

    if (!modal) {
        console.error("Event modal not found.");
        return;
    }

    document.getElementById("modal-event-id").textContent = event.event_id || "-";
    document.getElementById("modal-event-name").textContent = event.event_name || "Other";
    document.getElementById("modal-event-time").textContent = event.timestamp || "-";
    document.getElementById("modal-event-user").textContent = event.username || "-";
    document.getElementById("modal-event-ip").textContent = event.source_ip || "-";
    document.getElementById("modal-event-category").textContent = event.category || "-";
    document.getElementById("modal-event-mitre").textContent = event.mitre_technique || "-";
    document.getElementById("modal-event-type").textContent = event.event_type || "-";

    const severity = event.severity || "UNKNOWN";
    const severityElement = document.getElementById("modal-event-severity");

    severityElement.textContent = severity;
    severityElement.className = `severity-badge severity-${severity.toLowerCase()}`;

    const detailsElement = document.getElementById("modal-event-details");

    detailsElement.textContent =
        event.description || event.message || "No additional event details available.";

    const relatedAlert = document.getElementById("modal-related-alert");

    relatedAlert.innerHTML = `
        <div>
            <strong>Event ID ${escapeHtml(String(event.event_id || "-"))}</strong> is being viewed.
        </div>
        <div style="margin-top: 8px;">Source: ${escapeHtml(event.source_ip || "-")}</div>
        <div>User: ${escapeHtml(event.username || "-")}</div>
    `;

    modal.classList.remove("hidden");
}

function closeEventModal() {
    const modal = document.getElementById("event-modal");

    if (modal) {
        modal.classList.add("hidden");
    }
}

document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        closeEventModal();
    }
});

document.getElementById("event-modal")?.addEventListener("click", event => {
    if (event.target.id === "event-modal") {
        closeEventModal();
    }
});

async function manualRefresh() {
    const button = document.getElementById("refresh-button");

    if (button) {
        button.disabled = true;
        button.textContent = "↻ Refreshing...";
    }

    try {
        await checkAPIStatus();

        await refreshDashboard();

        const lastUpdated =
            document.getElementById("last-updated");

        if (lastUpdated) {
            lastUpdated.textContent =
                `Last updated: ${new Date().toLocaleTimeString()}`;
        }

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "↻ Refresh";
        }
    }
}

async function refreshDashboard() {
    console.log(
        "🔄 Dashboard refresh:",
        new Date().toLocaleTimeString()
    );

    const results = await Promise.allSettled([
        loadStats(),
        loadEvents(),
        loadAlerts(),
        loadResolvedAlerts(),
        loadCategories(),
        loadSeverity()
    ]);

    results.forEach((result, index) => {
        if (result.status === "rejected") {
            console.error(
                `Dashboard section ${index + 1} failed:`,
                result.reason
            );
        }
    });
}


manualRefresh();

setInterval(manualRefresh, 5000);
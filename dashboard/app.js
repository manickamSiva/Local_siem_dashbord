const API = "http://127.0.0.1:8000";

function dashboard() {
  return {
    // status
    apiOnline: false,
    refreshing: false,
    lastUpdated: "Last updated: never",
    toast: "",
    toastTimer: null,

    // data
    stats: { total_events: 0, failed_logins: 0, successful_logins: 0, active_alerts: 0, unique_source_ips: 0 },
    events: [],
    eventsError: false,
    alerts: [],
    alertsError: false,
    resolvedAlerts: [],
    resolvedOpen: false,
    categories: [],
    severities: [],
    eventFilter: null, // { type: 'category' | 'severity', value: string }

    // events pagination
    pageSize: 20,
    currentPage: 1,
    totalEvents: 0,

    // collected Windows security-event trend
    trendDays: 14,
    trend: [],

    // related events (inline, per alert)
    openRelated: null,
    relatedLoading: null,
    relatedEvents: {},

    // investigation modal
    investigationOpen: false,
    investigationLoading: false,
    investigationAlert: null,
    investigationEvents: [],

    // event modal
    eventModalOpen: false,
    selectedEvent: null,

    get kpis() {
      const s = this.stats;
      const denom = Math.max(s.total_events, 1);
      return [
        { label: "Total events", value: s.total_events, tone: "text-ink", barTone: "bg-info", bar: 100 },
        { label: "Failed logins", value: s.failed_logins, tone: "text-critical", barTone: "bg-critical", bar: Math.min(100, (s.failed_logins / denom) * 100) },
        { label: "Successful logins", value: s.successful_logins, tone: "text-signal", barTone: "bg-signal", bar: Math.min(100, (s.successful_logins / denom) * 100) },
        { label: "Active alerts", value: s.active_alerts, tone: "text-warning", barTone: "bg-warning", bar: Math.min(100, (s.active_alerts / denom) * 100) },
        { label: "Source IPs", value: s.unique_source_ips, tone: "text-ink", barTone: "bg-info", bar: Math.min(100, (s.unique_source_ips / denom) * 100) },
      ];
    },

    // ---- pagination helpers ----
    get totalPages() {
      return Math.max(1, Math.ceil(this.totalEvents / this.pageSize));
    },

    // Window of up to 5 page numbers centered on the current page,
    // e.g. current=6 -> [4,5,6,7,8], clamped at both ends.
    get pageNumbers() {
      const total = this.totalPages;
      const windowSize = 5;
      let start = Math.max(1, this.currentPage - Math.floor(windowSize / 2));
      let end = Math.min(total, start + windowSize - 1);
      start = Math.max(1, end - windowSize + 1);
      const pages = [];
      for (let i = start; i <= end; i++) pages.push(i);
      return pages;
    },

    get pageRangeLabel() {
      if (this.totalEvents === 0) return "0 of 0";
      const from = (this.currentPage - 1) * this.pageSize + 1;
      const to = Math.min(this.currentPage * this.pageSize, this.totalEvents);
      return `${from}–${to} of ${this.totalEvents}`;
    },

    setPageSize(size) {
      if (this.pageSize === size) return;
      this.pageSize = size;
      this.currentPage = 1;
      this.loadEvents();
    },

    goToPage(page) {
      const clamped = Math.min(Math.max(1, page), this.totalPages);
      if (clamped === this.currentPage) return;
      this.currentPage = clamped;
      this.loadEvents();
    },

    async init() {
      await this.manualRefresh();
      setInterval(() => this.manualRefresh(), 5000);
    },

    async fetchJSON(url, options = {}) {
      const response = await fetch(url, options);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    },

    showToast(message) {
      this.toast = message;
      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() => (this.toast = ""), 4000);
    },

    async checkAPIStatus() {
      try {
        const res = await fetch(`${API}/`, { method: "GET", cache: "no-store" });
        this.apiOnline = res.ok;
      } catch {
        this.apiOnline = false;
      }
      return this.apiOnline;
    },

    async loadStats() {
      try {
        this.stats = await this.fetchJSON(`${API}/api/stats`);
      } catch (e) {
        console.error("Failed to load statistics:", e);
      }
    },

    async loadEvents() {
      try {
        const params = new URLSearchParams();
        params.set("limit", this.pageSize);
        params.set("offset", (this.currentPage - 1) * this.pageSize);
        if (this.eventFilter) {
          params.set(this.eventFilter.type, this.eventFilter.value);
        }
        const data = await this.fetchJSON(`${API}/api/events?${params.toString()}`);
        this.events = data.events || [];
        this.totalEvents = data.total || 0;
        this.eventsError = false;
      } catch (e) {
        console.error("Failed to load events:", e);
        this.events = [];
        this.totalEvents = 0;
        this.eventsError = true;
      }
    },

    filterByCategory(category) {
      const isSame = this.eventFilter?.type === "category" && this.eventFilter?.value === category;
      this.eventFilter = isSame ? null : { type: "category", value: category };
      this.currentPage = 1;
      this.loadEvents();
    },

    filterBySeverity(severity) {
      const isSame = this.eventFilter?.type === "severity" && this.eventFilter?.value === severity;
      this.eventFilter = isSame ? null : { type: "severity", value: severity };
      this.currentPage = 1;
      this.loadEvents();
    },

    clearEventFilter() {
      this.eventFilter = null;
      this.currentPage = 1;
      this.loadEvents();
    },

    async loadAlerts() {
      try {
        const data = await this.fetchJSON(`${API}/api/alerts`);
        this.alerts = data.alerts || [];
        this.alertsError = false;
      } catch (e) {
        console.error("Failed to load alerts:", e);
        this.alerts = [];
        this.alertsError = true;
      }
    },

    async loadResolvedAlerts() {
      try {
        const data = await this.fetchJSON(`${API}/api/alerts?status=RESOLVED`);
        this.resolvedAlerts = data.alerts || [];
      } catch (e) {
        console.error("Failed to load resolved alerts:", e);
      }
    },

    async loadCategories() {
      try {
        const data = await this.fetchJSON(`${API}/api/categories`);
        const cats = data.categories || [];
        const max = Math.max(...cats.map((c) => c.count), 1);
        this.categories = cats.map((c) => ({ ...c, pct: (c.count / max) * 100 }));
      } catch (e) {
        console.error("Failed to load categories:", e);
      }
    },

    async loadSeverity() {
      try {
        const data = await this.fetchJSON(`${API}/api/severity`);
        const sev = data.severity || [];
        const max = Math.max(...sev.map((s) => s.count), 1);
        this.severities = sev.map((s) => ({ ...s, pct: (s.count / max) * 100 }));
      } catch (e) {
        console.error("Failed to load severity data:", e);
      }
    },

    async loadTrend() {
      const BAR_HEIGHT_PX = 150;
      const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
      const labelStep = this.trendDays <= 7 ? 1 : this.trendDays <= 14 ? 2 : 5;

      try {
        const data = await this.fetchJSON(`${API}/api/event-trend?days=${this.trendDays}`);
        const rows = data.trend || [];

        const totals = rows.map((r) => Object.values(r.severities || {}).reduce((a, b) => a + b, 0));
        const maxTotal = Math.max(...totals, 1);

        this.trend = rows.map((r, idx) => {
          const severities = r.severities || {};
          const total = totals[idx];
          const segments = severityOrder
            .filter((sev) => severities[sev])
            .map((sev) => ({
              severity: sev,
              count: severities[sev],
              px: Math.max(2, (severities[sev] / maxTotal) * BAR_HEIGHT_PX),
            }));
          const d = new Date(`${r.day}T00:00:00`);
          return {
            day: r.day,
            total,
            segments,
            label: idx % labelStep === 0 ? `${d.getMonth() + 1}/${d.getDate()}` : "",
          };
        });
      } catch (e) {
        console.error("Failed to load security event trend:", e);
        this.trend = [];
      }
    },

    setTrendDays(days) {
      this.trendDays = days;
      this.loadTrend();
    },

    async toggleRelated(alertId) {
      if (this.openRelated === alertId) {
        this.openRelated = null;
        return;
      }
      this.openRelated = alertId;
      this.relatedLoading = alertId;
      try {
        const data = await this.fetchJSON(`${API}/api/alerts/${alertId}/events`);
        this.relatedEvents[alertId] = data.events || [];
      } catch (e) {
        console.error("Failed to load related events:", e);
        this.relatedEvents[alertId] = [];
      } finally {
        this.relatedLoading = null;
      }
    },

    async investigate(alertId) {
      this.investigationOpen = true;
      this.investigationLoading = true;
      this.investigationAlert = null;
      this.investigationEvents = [];
      try {
        const [alertData, eventData] = await Promise.all([
          this.fetchJSON(`${API}/api/alerts/${alertId}`),
          this.fetchJSON(`${API}/api/alerts/${alertId}/events`),
        ]);
        this.investigationAlert = alertData;
        this.investigationEvents = eventData.events || [];
      } catch (e) {
        console.error("Failed to investigate alert:", e);
        this.investigationOpen = false;
        this.showToast("Failed to load investigation data.");
      } finally {
        this.investigationLoading = false;
      }
    },

    async setStatus(alertId, status) {
      try {
        const data = await this.fetchJSON(`${API}/api/alerts/${alertId}/status`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status }),
        });
        await Promise.all([this.loadAlerts(), this.loadResolvedAlerts(), this.loadStats()]);
        console.log(`Alert ${alertId} -> ${data.status}`);
      } catch (e) {
        console.error("Failed to update alert status:", e);
        this.showToast(`Failed to update alert #${alertId}. Check whether the API is running.`);
      }
    },

    viewEvent(event) {
      this.selectedEvent = event;
      this.eventModalOpen = true;
    },

    async manualRefresh() {
      this.refreshing = true;
      try {
        await this.checkAPIStatus();
        const results = await Promise.allSettled([
          this.loadStats(),
          this.loadEvents(),
          this.loadAlerts(),
          this.loadCategories(),
          this.loadSeverity(),
          this.loadTrend(),
          ...(this.resolvedOpen ? [this.loadResolvedAlerts()] : []),
        ]);
        results.forEach((r, i) => {
          if (r.status === "rejected") console.error(`Dashboard section ${i + 1} failed:`, r.reason);
        });
        this.lastUpdated = `Last updated: ${new Date().toLocaleTimeString()}`;
      } finally {
        this.refreshing = false;
      }
    },

    // ---- MITRE ATT&CK ----
    // Turns "T1110" -> https://attack.mitre.org/techniques/T1110/
    // and "T1555.004" -> https://attack.mitre.org/techniques/T1555/004/
    // Returns null for anything that isn't a recognizable technique ID,
    // so the template can fall back to plain text instead of a dead link.
    mitreUrl(technique) {
      if (technique === null || technique === undefined) return null;

      const value = String(technique).trim().toUpperCase();

      // Supports T1059 and sub-techniques such as T1059.001.
      const match = value.match(/^T(\d{4})(?:\.(\d{3}))?$/);

      if (!match) return null;

      const [, base, sub] = match;

      return sub
        ? `https://attack.mitre.org/techniques/T${base}/${sub}/`
        : `https://attack.mitre.org/techniques/T${base}/`;
    },

    // ---- styling helpers ----
    severityText(sev) {
      const s = (sev || "").toUpperCase();
      if (s === "HIGH" || s === "CRITICAL") return "text-critical";
      if (s === "MEDIUM") return "text-warning";
      if (s === "LOW") return "text-signal";
      return "text-muted";
    },
    severityDot(sev) {
      const s = (sev || "").toUpperCase();
      if (s === "HIGH" || s === "CRITICAL") return "bg-critical";
      if (s === "MEDIUM") return "bg-warning";
      if (s === "LOW") return "bg-signal";
      return "bg-faint";
    },
    severityBorder(sev) {
      const s = (sev || "").toUpperCase();
      if (s === "HIGH" || s === "CRITICAL") return "border-critical";
      if (s === "MEDIUM") return "border-warning";
      if (s === "LOW") return "border-signal";
      return "border-faint";
    },
    severityBg(sev) {
      const s = (sev || "").toUpperCase();
      if (s === "HIGH" || s === "CRITICAL") return "bg-criticaldim";
      if (s === "MEDIUM") return "bg-warningdim";
      if (s === "LOW") return "bg-signaldim";
      return "bg-raised";
    },
    severityBarTone(sev) {
      const s = (sev || "").toUpperCase();
      if (s === "HIGH" || s === "CRITICAL") return "bg-critical";
      if (s === "MEDIUM") return "bg-warning";
      if (s === "LOW") return "bg-signal";
      if (s === "INFO") return "bg-info";
      return "bg-faint";
    },
    statusTone(status) {
      const s = (status || "NEW").toUpperCase();
      if (s === "NEW") return "bg-criticaldim text-critical";
      if (s === "INVESTIGATING") return "bg-warningdim text-warning";
      if (s === "RESOLVED") return "bg-signaldim text-signal";
      return "bg-raised text-muted";
    },
  };
}
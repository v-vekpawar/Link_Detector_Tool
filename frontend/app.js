/* ---------------------------------------------------------------------
   Link & Navigation Audit Tool — frontend logic.

   Pure helper functions (no DOM) live in the `logic` object below and are
   exported via module.exports when running under Node, so they can be
   unit-tested without a browser. Everything DOM-dependent is wired up
   inside initApp(), which only runs in an actual browser.
   --------------------------------------------------------------------- */

const CATEGORY_LABELS = {
  broken: "Broken",
  inactive: "Inactive",
  ip_based: "IP-based",
  internet: "Internet",
};

const CATEGORY_ORDER = ["broken", "inactive", "ip_based", "internet"];

const COMMENT_CATEGORY_LABELS = {
  commented_link: "Commented Link",
  internal_css: "Internal CSS",
  inline_css: "Inline CSS",
  internal_js: "Internal JS",
  inline_js: "Inline JS",
};

const COMMENT_CATEGORY_ORDER = [
  "commented_link",
  "internal_css",
  "inline_css",
  "internal_js",
  "inline_js",
];

const SEVERITY_LABELS = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

/** Matches a literal IPv4 host (e.g. "10.0.0.1"), same rule as config.py's is_literal_ip for dotted-quad hosts. */
function isLiteralIPv4(host) {
  if (typeof host !== "string") return false;
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return false;
  return match.slice(1).every((octet) => Number(octet) >= 0 && Number(octet) <= 255);
}

/** Extracts the hostname from a URL string, or null if it doesn't parse as a URL at all. */
function extractHost(urlString) {
  try {
    return new URL(urlString).hostname;
  } catch (e) {
    return null;
  }
}

/**
 * Builds the POST /api/scan/start JSON body from the form's current state.
 * `state` shape:
 *   { targetUrl, siteType, requiresLogin, username, password }
 * Returns { payload } on success, or { error } if the state is invalid —
 * caller is responsible for displaying `error` and not submitting.
 */
function buildScanPayload(state) {
  const targetUrl = (state.targetUrl || "").trim();
  if (!targetUrl) {
    return { error: "Target URL is required." };
  }

  const payload = {
    target_url: targetUrl,
    site_type: state.siteType === "dynamic" ? "dynamic" : "static",
  };

  // Basic URL validation — must have a non-empty host (IP or hostname both fine).
  try {
    const parsed = new URL(targetUrl);
    if (!parsed.hostname) {
      return { error: "Target URL must include a valid host (e.g. https://10.0.0.1 or https://portal.company.local)." };
    }
  } catch (e) {
    return { error: "Target URL is not a valid URL (e.g. https://10.0.0.1 or https://portal.company.local)." };
  }

  if (state.requiresLogin) {
    if (payload.site_type !== "dynamic") {
      return { error: "Login requires site type 'Dynamic' — login runs through the browser engine." };
    }
    const username = (state.username || "").trim();
    const password = state.password || "";
    if (!username || !password) {
      return { error: "Username and password are required when login is enabled." };
    }
    payload.login = { mode: "recorded", username, password };
  }

  return { payload };
}

/** Splits a possibly comma-separated category string ("internet,broken") into an ordered, deduped list. `order` defaults to the Links category order; pass COMMENT_CATEGORY_ORDER for Commented Code rows. */
function parseCategories(categoryString, order = CATEGORY_ORDER) {
  const present = new Set(
    (categoryString || "")
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean)
  );
  return order.filter((c) => present.has(c));
}

function formatDuration(totalSeconds) {
  if (totalSeconds == null || Number.isNaN(totalSeconds)) return "—";
  const seconds = Math.max(0, Math.round(totalSeconds));
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

/**
 * Renders the single continuously-updating progress line from one SSE
 * event payload. Never promises a remaining-time estimate before the
 * backend actually provides one (still warming up -> null).
 */
function formatProgressLine(event) {
  if (event.status === "not_found") {
    return "Scan not found.";
  }
  if (event.status === "failed") {
    return `Scan failed after ${formatDuration(event.elapsed_seconds)} — ${event.error || "unknown error"}`;
  }

  const parts = [
    `Pages crawled: ${event.pages_crawled}`,
    `Links checked: ${event.links_checked}`,
    `Elapsed: ${formatDuration(event.elapsed_seconds)}`,
  ];

  if (event.status === "completed") {
    parts.push("Done.");
  } else if (event.estimated_remaining_seconds == null) {
    parts.push("Estimating remaining time…");
  } else {
    parts.push(`Est. remaining: ~${formatDuration(event.estimated_remaining_seconds)}`);
  }

  return parts.join("  ·  ");
}

const logic = {
  isLiteralIPv4,
  extractHost,
  buildScanPayload,
  parseCategories,
  formatDuration,
  formatProgressLine,
  CATEGORY_LABELS,
  CATEGORY_ORDER,
  COMMENT_CATEGORY_LABELS,
  COMMENT_CATEGORY_ORDER,
  SEVERITY_LABELS,
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = logic;
}

/* ----------------------------------------------------------------------
   DOM wiring — only runs in a real browser.
   ---------------------------------------------------------------------- */

if (typeof window !== "undefined" && typeof document !== "undefined") {
  initApp();
}

function initApp() {
  const els = {
    lastScanSection: document.getElementById("last-scan"),
    lastScanUrl: document.getElementById("last-scan-url"),
    lastScanIp: document.getElementById("last-scan-ip"),
    lastScanSiteType: document.getElementById("last-scan-site-type"),
    lastScanDate: document.getElementById("last-scan-date"),
    lastScanPages: document.getElementById("last-scan-pages"),
    lastScanLinks: document.getElementById("last-scan-links"),
    lastScanCounts: document.getElementById("last-scan-counts"),
    viewLastResultsBtn: document.getElementById("view-last-results-btn"),

    form: document.getElementById("scan-form"),
    targetUrl: document.getElementById("target-url"),
    requiresLogin: document.getElementById("requires-login"),
    loginFields: document.getElementById("login-fields"),
    loginRecordedFields: document.getElementById("login-recorded-fields"),
    loginUsername: document.getElementById("login-username"),
    loginPassword: document.getElementById("login-password"),
    recordedFlowStatus: document.getElementById("recorded-flow-status"),
    recordFlowBtn: document.getElementById("record-flow-btn"),
    recordFlowPanel: document.getElementById("record-flow-panel"),
    recordFlowMessage: document.getElementById("record-flow-message"),
    recordFlowDoneBtn: document.getElementById("record-flow-done-btn"),
    formError: document.getElementById("form-error"),
    startScanBtn: document.getElementById("start-scan-btn"),

    progressSection: document.getElementById("progress-section"),
    progressLine: document.getElementById("progress-line"),

    resultsSection: document.getElementById("results-section"),
    tabLinks: document.getElementById("tab-links"),
    tabCommented: document.getElementById("tab-commented"),
    tabLinksCount: document.getElementById("tab-links-count"),
    tabCommentedCount: document.getElementById("tab-commented-count"),
    categoryFilters: document.getElementById("category-filters"),
    resultsMeta: document.getElementById("results-meta"),
    resultsTbody: document.getElementById("results-tbody"),
    resultsEmpty: document.getElementById("results-empty"),
    exportXlsxBtn: document.getElementById("export-xlsx-btn"),
    exportPdfBtn: document.getElementById("export-pdf-btn"),
    exportStatus: document.getElementById("export-status"),
  };

  let activeRecordSessionId = null;
  let activeEventSource = null;
  let currentScanId = null;

  // Results-section tab/filter state. currentResults holds the full
  // payload from the last /results (or /scan/last) fetch; activeTab picks
  // which of its two finding lists is showing; activeCategory (if set)
  // further filters that list down to one category. Switching tabs always
  // clears the category filter — a category from one tab's set wouldn't
  // mean anything in the other.
  let currentResults = null;
  let activeTab = "links";
  let activeCategory = null;

  function showFormError(message) {
    els.formError.textContent = message;
    els.formError.hidden = false;
  }

  function clearFormError() {
    els.formError.hidden = true;
    els.formError.textContent = "";
  }

  function currentSiteType() {
    const checked = els.form.querySelector('input[name="site_type"]:checked');
    return checked ? checked.value : "static";
  }

  function updateLoginFieldsVisibility() {
    const requiresLogin = els.requiresLogin.checked;
    els.loginFields.hidden = !requiresLogin;
    if (!requiresLogin) return;
    refreshRecordedFlowStatus();
  }

  async function refreshRecordedFlowStatus() {
    const host = logic.extractHost(els.targetUrl.value.trim());
    if (!host) {
      els.recordedFlowStatus.textContent = "Enter a valid target URL above to check for a recorded flow.";
      return;
    }
    els.recordedFlowStatus.textContent = "Checking for a recorded flow…";
    try {
      const resp = await fetch(`/api/login-config?target_ip=${encodeURIComponent(host)}`);
      const data = await resp.json();
      els.recordedFlowStatus.textContent = data.exists
        ? `A recorded login flow exists for ${host}.`
        : `No recorded flow yet for ${host} — record one below.`;
    } catch (e) {
      els.recordedFlowStatus.textContent = "Couldn't check for a recorded flow — is the backend running?";
    }
  }

  els.requiresLogin.addEventListener("change", updateLoginFieldsVisibility);
  els.targetUrl.addEventListener("blur", () => {
    if (els.requiresLogin.checked) {
      refreshRecordedFlowStatus();
    }
  });

  els.recordFlowBtn.addEventListener("click", async () => {
    const targetUrl = els.targetUrl.value.trim();
    if (!targetUrl) {
      showFormError("Enter a target URL before recording a login flow.");
      return;
    }
    clearFormError();
    els.recordFlowBtn.disabled = true;
    els.recordFlowPanel.hidden = false;
    els.recordFlowMessage.textContent = "Opening a browser window on this machine — click through the login flow, then click \u201cFinish Recording\u201d in that window.";

    try {
      const resp = await fetch("/api/login/record/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        throw new Error(err.detail || `Request failed (${resp.status})`);
      }
      const data = await resp.json();
      activeRecordSessionId = data.session_id;
    } catch (e) {
      els.recordFlowMessage.textContent = `Couldn't start recording: ${e.message}`;
      els.recordFlowBtn.disabled = false;
    }
  });

  els.recordFlowDoneBtn.addEventListener("click", async () => {
    const host = logic.extractHost(els.targetUrl.value.trim());
    if (!activeRecordSessionId || !host) {
      els.recordFlowMessage.textContent = "Nothing to save — start a recording first.";
      return;
    }
    els.recordFlowMessage.textContent = "Saving…";
    try {
      const resp = await fetch("/api/login/record/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: activeRecordSessionId, target_ip: host }),
      });
      const data = await resp.json().catch(() => ({}));
      if (resp.status === 409) {
        els.recordFlowMessage.textContent = "Still recording — finish and click \u201cFinish Recording\u201d in the browser window first, then try again.";
        return;
      }
      if (!resp.ok) {
        throw new Error(data.detail || `Request failed (${resp.status})`);
      }
      els.recordFlowMessage.textContent = "Recording saved.";
      activeRecordSessionId = null;
      els.recordFlowBtn.disabled = false;
      refreshRecordedFlowStatus();
    } catch (e) {
      els.recordFlowMessage.textContent = `Couldn't save recording: ${e.message}`;
    }
  });

  function currentFormState() {
    return {
      targetUrl: els.targetUrl.value,
      siteType: currentSiteType(),
      requiresLogin: els.requiresLogin.checked,
      username: els.loginUsername.value,
      password: els.loginPassword.value,
    };
  }

  function renderCategoryBadges(container, summary) {
    container.innerHTML = "";
    logic.CATEGORY_ORDER.forEach((cat) => {
      const count = summary[cat] || 0;
      const li = document.createElement("li");
      li.className = `badge badge-${cat}`;
      li.textContent = `${logic.CATEGORY_LABELS[cat]}: ${count}`;
      container.appendChild(li);
    });
  }

  /**
   * Renders the clickable category-filter badge row for the currently
   * active tab. `order`/`labels` are the Links or Commented Code sets;
   * `findings` is that tab's full (unfiltered) list, used to compute each
   * badge's count. Clicking a badge sets it as the active filter; clicking
   * the already-active one clears the filter back to "show everything in
   * this tab". A badge with a zero count is shown but not clickable —
   * nothing to filter to.
   */
  function renderCategoryFilterBadges(order, labels, findings) {
    els.categoryFilters.innerHTML = "";
    order.forEach((cat) => {
      const count = findings.filter((f) => logic.parseCategories(f.category, order).includes(cat)).length;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `badge badge-filter badge-${cat}`;
      if (count === 0) btn.classList.add("zero");
      if (activeCategory === cat) btn.classList.add("active");
      btn.textContent = `${labels[cat]} (${count})`;
      btn.disabled = count === 0;
      btn.addEventListener("click", () => {
        activeCategory = activeCategory === cat ? null : cat;
        renderActiveTab();
      });
      els.categoryFilters.appendChild(btn);
    });
  }

  function renderResultsTable(findings, order) {
    els.resultsTbody.innerHTML = "";
    els.resultsEmpty.hidden = findings.length !== 0;

    findings.forEach((finding) => {
      const tr = document.createElement("tr");

      const foundOnTd = document.createElement("td");
      foundOnTd.className = "mono";
      foundOnTd.textContent = finding.found_on_page;
      tr.appendChild(foundOnTd);

      const linkTd = document.createElement("td");
      linkTd.className = "mono";
      linkTd.textContent = finding.link;
      tr.appendChild(linkTd);

      const categoryTd = document.createElement("td");
      logic.parseCategories(finding.category, order).forEach((cat) => {
        const span = document.createElement("span");
        span.className = `badge badge-${cat}`;
        span.textContent = (logic.CATEGORY_LABELS[cat] || logic.COMMENT_CATEGORY_LABELS[cat]);
        span.style.marginRight = "4px";
        categoryTd.appendChild(span);
      });
      tr.appendChild(categoryTd);

      const severityTd = document.createElement("td");
      if (finding.severity) {
        const span = document.createElement("span");
        span.className = `badge badge-severity-${finding.severity}`;
        span.textContent = logic.SEVERITY_LABELS[finding.severity] || finding.severity;
        severityTd.appendChild(span);
      }
      tr.appendChild(severityTd);

      const snippetTd = document.createElement("td");
      snippetTd.className = "mono";
      snippetTd.textContent = finding.code_snippet || "";
      tr.appendChild(snippetTd);

      const evidenceTd = document.createElement("td");
      evidenceTd.textContent = finding.evidence || "";
      tr.appendChild(evidenceTd);

      const locationTd = document.createElement("td");
      locationTd.className = "mono";
      locationTd.textContent = finding.element_location || "";
      tr.appendChild(locationTd);

      els.resultsTbody.appendChild(tr);
    });
  }

  /**
   * Redraws everything below the tab row for the current activeTab/
   * activeCategory state, without re-fetching anything. Called on load,
   * on tab switch, and on category-filter click.
   */
  function renderActiveTab() {
    if (!currentResults) return;

    const isLinks = activeTab === "links";
    const order = isLinks ? logic.CATEGORY_ORDER : logic.COMMENT_CATEGORY_ORDER;
    const labels = isLinks ? logic.CATEGORY_LABELS : logic.COMMENT_CATEGORY_LABELS;
    const tabFindings = isLinks ? currentResults.findings : currentResults.commented_findings;

    els.tabLinks.classList.toggle("active", isLinks);
    els.tabCommented.classList.toggle("active", !isLinks);
    els.tabLinksCount.textContent = currentResults.findings.length;
    els.tabCommentedCount.textContent = currentResults.commented_findings.length;

    const theadRow = document.querySelector("#results-table thead tr");
    if (theadRow) {
      if (isLinks) {
        theadRow.innerHTML = `
          <th>Found on page</th>
          <th>Link</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Code snippet</th>
          <th>Evidence / reason</th>
          <th>Element location</th>
        `;
      } else {
        theadRow.innerHTML = `
          <th>Found On Page</th>
          <th>Extracted Value / Target</th>
          <th>Finding Type</th>
          <th>Severity</th>
          <th>Code Snippet</th>
          <th>Details</th>
          <th>DOM Location</th>
        `;
      }
    }

    renderCategoryFilterBadges(order, labels, tabFindings);

    const shown = activeCategory
      ? tabFindings.filter((f) => logic.parseCategories(f.category, order).includes(activeCategory))
      : tabFindings;

    renderResultsTable(shown, order);

    const tabLabel = isLinks ? "Links" : "Code Findings";
    els.resultsMeta.textContent = activeCategory
      ? `${tabLabel} — ${labels[activeCategory]}: ${shown.length} of ${tabFindings.length} shown.`
      : `${tabLabel}: ${tabFindings.length} shown. ${currentResults.scan.pages_crawled} pages crawled, ${currentResults.scan.total_links_checked} links checked.`;
  }

  function setActiveTab(tab) {
    if (activeTab === tab) return;
    activeTab = tab;
    activeCategory = null;
    renderActiveTab();
  }

  els.tabLinks.addEventListener("click", () => setActiveTab("links"));
  els.tabCommented.addEventListener("click", () => setActiveTab("commented"));

  function renderResults(results) {
    currentScanId = results.scan.id;
    currentResults = results;
    activeTab = "links";
    activeCategory = null;
    renderActiveTab();
    els.resultsSection.hidden = false;
    els.viewLastResultsBtn.textContent = "Hide Last Results";
  }

  /**
   * Export buttons just navigate to the export endpoint — the response
   * carries Content-Disposition: attachment, so the browser downloads
   * the file instead of replacing the page. No fetch/blob plumbing
   * needed, which keeps this dependency-free per the frontend constraint.
   */
  function triggerExport(format) {
    if (!currentScanId) {
      els.exportStatus.textContent = "No scan results to export yet.";
      return;
    }
    els.exportStatus.textContent = `Preparing ${format.toUpperCase()} export…`;
    window.location.href = `/api/scan/${currentScanId}/export?format=${format}`;
    setTimeout(() => {
      els.exportStatus.textContent = "";
    }, 2000);
  }

  els.exportXlsxBtn.addEventListener("click", () => triggerExport("xlsx"));
  els.exportPdfBtn.addEventListener("click", () => triggerExport("pdf"));

  els.viewLastResultsBtn.addEventListener("click", () => {
    if (!currentResults) return;
    const isShowing = !els.resultsSection.hidden;
    if (isShowing) {
      // Just hide it back — the table stays fully rendered underneath so
      // showing it again (or switching tabs) doesn't need a re-render.
      els.resultsSection.hidden = true;
      els.viewLastResultsBtn.textContent = "View Last Results";
      return;
    }
    renderResults(currentResults);
    els.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  function renderLastScan(results) {
    els.lastScanUrl.textContent = results.scan.target_url;
    els.lastScanIp.textContent = results.scan.target_ip;
    els.lastScanSiteType.textContent = results.scan.site_type;
    els.lastScanDate.textContent = results.scan.completed_at || results.scan.started_at || "—";
    els.lastScanPages.textContent = results.scan.pages_crawled ?? "—";
    els.lastScanLinks.textContent = results.scan.total_links_checked ?? "—";
    renderCategoryBadges(els.lastScanCounts, results.summary);
    els.lastScanSection.hidden = false;
  }

  async function loadLastScan() {
    try {
      const resp = await fetch("/api/scan/last");
      if (!resp.ok) return; // 404 = no scans yet, leave the section hidden
      const data = await resp.json();
      renderLastScan(data);
      // Cache the data (scan id + full findings) so Export and "View
      // Last Results" work immediately, without re-running a scan — but
      // don't expand the full Results table itself. That table should
      // only appear after a scan the user actually just ran (or after
      // they explicitly ask to see the last one), not silently on every
      // page load.
      currentScanId = data.scan.id;
      currentResults = data;
    } catch (e) {
      // Backend not reachable yet — last-scan panel just stays hidden.
    }
  }

  function streamProgress(scanId) {
    if (activeEventSource) {
      activeEventSource.close();
    }
    els.progressSection.hidden = false;
    els.progressLine.textContent = "Starting scan…";

    const source = new EventSource(`/api/scan/${scanId}/progress`);
    activeEventSource = source;

    source.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      els.progressLine.textContent = logic.formatProgressLine(data);

      if (data.status === "completed" || data.status === "failed" || data.status === "not_found") {
        source.close();
        activeEventSource = null;
        els.startScanBtn.disabled = false;

        if (data.status === "completed") {
          try {
            const resp = await fetch(`/api/scan/${scanId}/results`);
            const results = await resp.json();
            renderResults(results);
            renderLastScan(results);
          } catch (e) {
            showFormError("Scan completed, but results could not be loaded.");
          }
        }
      }
    };

    source.onerror = () => {
      els.progressLine.textContent = "Lost connection to the progress stream.";
      source.close();
      activeEventSource = null;
      els.startScanBtn.disabled = false;
    };
  }

  els.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearFormError();

    const { payload, error } = logic.buildScanPayload(currentFormState());
    if (error) {
      showFormError(error);
      return;
    }

    els.startScanBtn.disabled = true;
    els.resultsSection.hidden = true;

    try {
      const resp = await fetch("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(data.detail || `Request failed (${resp.status})`);
      }
      streamProgress(data.scan_id);
    } catch (e) {
      showFormError(`Couldn't start scan: ${e.message}`);
      els.startScanBtn.disabled = false;
    }
  });

  updateLoginFieldsVisibility();
  loadLastScan();
}
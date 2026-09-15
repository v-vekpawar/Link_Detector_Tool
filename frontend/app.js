/* ---------------------------------------------------------------------
   Link & Navigation Audit Tool — frontend logic.

   Pure helper functions (no DOM) live in the `logic` object below and are
   exported via module.exports when running under Node, so they can be
   unit-tested without a browser. Everything DOM-dependent is wired up
   inside initApp(), which only runs in an actual browser.
   --------------------------------------------------------------------- */

const LINK_CATEGORY_LABELS = {
  broken: "Broken",
  inactive: "Inactive",
  ip_based: "IP-based",
  internet: "Internet",
};

const LINK_CATEGORY_ORDER = ["broken", "inactive", "ip_based", "internet"];

// Kept as aliases for backward compatibility with any external callers that
// referenced the pre-two-section names.
const CATEGORY_LABELS = LINK_CATEGORY_LABELS;
const CATEGORY_ORDER = LINK_CATEGORY_ORDER;

const SOURCE_CATEGORY_LABELS = {
  commented_link: "Commented Link",
  inline_css: "Inline CSS",
  internal_css: "Internal CSS",
  inline_js: "Inline JS",
  internal_js: "Internal JS",
};

const SOURCE_CATEGORY_ORDER = ["commented_link", "inline_css", "internal_css", "inline_js", "internal_js"];

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
 *   { targetUrl, siteType, requiresLogin, loginMode, loginUrl, username, password }
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

  if (state.requiresLogin) {
    if (payload.site_type !== "dynamic") {
      return { error: "Login requires site type 'Dynamic' — login runs through the browser engine." };
    }
    const username = (state.username || "").trim();
    const password = state.password || "";
    if (!username || !password) {
      return { error: "Username and password are required when login is enabled." };
    }

    if (state.loginMode === "recorded") {
      payload.login = { mode: "recorded", username, password };
    } else {
      const loginUrl = (state.loginUrl || "").trim();
      if (!loginUrl) {
        return { error: "Login page URL is required for auto-fill login." };
      }
      payload.login = { mode: "auto", login_url: loginUrl, username, password };
    }
  }

  return { payload };
}

/** Splits a possibly comma-separated category string ("internet,broken") into an ordered, deduped list, per `order`. */
function parseCategories(categoryString, order = CATEGORY_ORDER) {
  const present = new Set(
    (categoryString || "")
      .split(",")
      .map((c) => c.trim())
      .filter(Boolean)
  );
  return order.filter((c) => present.has(c));
}

/** Returns the subset of `findings` matching `category` ("all" or one of `order`). */
function filterFindingsByCategory(findings, category, order = CATEGORY_ORDER) {
  if (!category || category === "all") return findings;
  return findings.filter((f) => parseCategories(f.category, order).includes(category));
}

/**
 * Splits findings into the two result sections: `source` for the
 * source-code-scan categories (comments + inline/internal css/js),
 * `links` for everything else (the four original link categories). A
 * finding only ever carries tags from one family (classify_link and
 * scan_source_code never mix), so exact partitioning is safe.
 */
function partitionFindings(findings) {
  const linkFindings = [];
  const sourceFindings = [];
  findings.forEach((f) => {
    const isSource = (f.category || "").split(",").some((c) => SOURCE_CATEGORY_ORDER.includes(c.trim()));
    (isSource ? sourceFindings : linkFindings).push(f);
  });
  return { linkFindings, sourceFindings };
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
  filterFindingsByCategory,
  partitionFindings,
  formatDuration,
  formatProgressLine,
  CATEGORY_LABELS,
  CATEGORY_ORDER,
  LINK_CATEGORY_LABELS,
  LINK_CATEGORY_ORDER,
  SOURCE_CATEGORY_LABELS,
  SOURCE_CATEGORY_ORDER,
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
    lastScanStatus: document.getElementById("last-scan-status"),
    lastScanCounts: document.getElementById("last-scan-counts"),

    form: document.getElementById("scan-form"),
    targetUrl: document.getElementById("target-url"),
    requiresLogin: document.getElementById("requires-login"),
    loginFields: document.getElementById("login-fields"),
    loginAutoFields: document.getElementById("login-auto-fields"),
    loginRecordedFields: document.getElementById("login-recorded-fields"),
    loginUrl: document.getElementById("login-url"),
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
    resultsSectionSwitch: document.getElementById("results-section-switch"),
    resultsTabs: document.getElementById("results-tabs"),
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
  let linkFindings = [];
  let sourceFindings = [];
  let latestSummary = {};
  let latestCrawlStats = { pages_crawled: null, total_links_checked: null };
  let currentResultsSection = "links";

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

  function currentLoginMode() {
    const checked = els.form.querySelector('input[name="login_mode"]:checked');
    return checked ? checked.value : "auto";
  }

  function updateLoginFieldsVisibility() {
    const requiresLogin = els.requiresLogin.checked;
    els.loginFields.hidden = !requiresLogin;
    if (!requiresLogin) return;

    const mode = currentLoginMode();
    els.loginAutoFields.hidden = mode !== "auto";
    els.loginRecordedFields.hidden = mode !== "recorded";
    if (mode === "recorded") {
      refreshRecordedFlowStatus();
    }
  }

  async function refreshRecordedFlowStatus() {
    const host = logic.extractHost(els.targetUrl.value.trim());
    if (!host || !logic.isLiteralIPv4(host)) {
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
  els.form.querySelectorAll('input[name="login_mode"]').forEach((el) => {
    el.addEventListener("change", updateLoginFieldsVisibility);
  });
  els.targetUrl.addEventListener("blur", () => {
    if (els.requiresLogin.checked && currentLoginMode() === "recorded") {
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
      loginMode: currentLoginMode(),
      loginUrl: els.loginUrl.value,
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

  // Two independently-filterable result sections: Links (existing four
  // categories) and Source Code (comments + inline/internal css/js, per
  // the source-code-scan feature). Each keeps its own active tab so
  // switching sections doesn't lose the other's filter selection.
  const RESULT_SECTIONS = {
    links: { order: logic.LINK_CATEGORY_ORDER, labels: logic.LINK_CATEGORY_LABELS },
    source: { order: logic.SOURCE_CATEGORY_ORDER, labels: logic.SOURCE_CATEGORY_LABELS },
  };
  let activeFilters = { links: "all", source: "all" };

  function currentSectionConfig() {
    return RESULT_SECTIONS[currentResultsSection];
  }

  function currentSectionFindings() {
    return currentResultsSection === "links" ? linkFindings : sourceFindings;
  }

  /**
   * Single-select filter tabs for the active section's results table: "All"
   * plus one per category, each labeled with its count (pulled straight
   * from the scan's summary, which already covers every category across
   * both sections). Selecting a tab re-filters the table and updates the
   * meta line to reflect the active filter.
   */
  function renderResultsTabs() {
    const { order, labels } = currentSectionConfig();
    const activeFilter = activeFilters[currentResultsSection];
    const sectionTotal = order.reduce((sum, cat) => sum + (latestSummary[cat] || 0), 0);

    els.resultsTabs.innerHTML = "";
    const tabs = [{ key: "all", label: "All", count: sectionTotal }].concat(
      order.map((cat) => ({ key: cat, label: labels[cat], count: latestSummary[cat] || 0 }))
    );

    tabs.forEach(({ key, label, count }) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `tab tab-${key}`;
      btn.setAttribute("role", "tab");
      btn.setAttribute("aria-selected", String(key === activeFilter));
      if (key === activeFilter) btn.classList.add("active");
      btn.textContent = `${label} (${count})`;
      btn.addEventListener("click", () => {
        activeFilters[currentResultsSection] = key;
        refreshResultsView();
      });
      els.resultsTabs.appendChild(btn);
    });
  }

  function renderSectionSwitch() {
    els.resultsSectionSwitch.querySelectorAll(".section-switch-btn").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.section === currentResultsSection);
    });
  }

  function applyResultsFilter() {
    const { order, labels } = currentSectionConfig();
    const activeFilter = activeFilters[currentResultsSection];
    const sectionFindings = currentSectionFindings();
    const filtered = logic.filterFindingsByCategory(sectionFindings, activeFilter, order);
    renderResultsTable(filtered, order, labels, activeFilter);

    const shownLabel =
      activeFilter === "all"
        ? `${sectionFindings.length} finding${sectionFindings.length === 1 ? "" : "s"}`
        : `${filtered.length} of ${sectionFindings.length} findings (${labels[activeFilter]})`;
    els.resultsMeta.textContent =
      `${latestCrawlStats.pages_crawled} pages crawled, ${latestCrawlStats.total_links_checked} links checked. Showing ${shownLabel}.`;
  }

  /** Re-renders the section switch, tabs, and table together — call after any filter/section change. */
  function refreshResultsView() {
    renderSectionSwitch();
    renderResultsTabs();
    applyResultsFilter();
  }

  function renderResultsTable(findings, order, labels, activeFilter) {
    els.resultsTbody.innerHTML = "";
    els.resultsEmpty.hidden = findings.length !== 0;
    els.resultsEmpty.textContent =
      findings.length === 0 && activeFilter !== "all"
        ? `No ${labels[activeFilter].toLowerCase()} findings in this scan.`
        : "No issues found in this section.";

    findings.forEach((finding) => {
      const tr = document.createElement("tr");

      const foundOnTd = document.createElement("td");
      foundOnTd.className = "mono";
      foundOnTd.textContent = finding.found_on_page;
      tr.appendChild(foundOnTd);

      const linkTd = document.createElement("td");
      linkTd.className = "mono";
      linkTd.textContent = finding.link || "—";
      tr.appendChild(linkTd);

      const categoryTd = document.createElement("td");
      logic.parseCategories(finding.category, order).forEach((cat) => {
        const span = document.createElement("span");
        span.className = `badge badge-${cat}`;
        span.textContent = labels[cat];
        span.style.marginRight = "4px";
        categoryTd.appendChild(span);
      });
      tr.appendChild(categoryTd);

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

  function renderResults(results) {
    currentScanId = results.scan.id;
    latestSummary = results.summary;
    latestCrawlStats = {
      pages_crawled: results.scan.pages_crawled,
      total_links_checked: results.scan.total_links_checked,
    };
    const partitioned = logic.partitionFindings(results.findings);
    linkFindings = partitioned.linkFindings;
    sourceFindings = partitioned.sourceFindings;

    currentResultsSection = "links";
    activeFilters = { links: "all", source: "all" };
    refreshResultsView();
    els.resultsSection.hidden = false;
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

  els.resultsSectionSwitch.querySelectorAll(".section-switch-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      currentResultsSection = btn.dataset.section;
      refreshResultsView();
    });
  });

  function renderLastScan(results) {
    const status = results.scan.status;
    els.lastScanUrl.textContent = results.scan.target_url;
    els.lastScanIp.textContent = results.scan.target_ip;
    els.lastScanSiteType.textContent = results.scan.site_type;
    els.lastScanDate.textContent = results.scan.completed_at || results.scan.started_at || "—";
    els.lastScanPages.textContent = status === "completed" ? results.scan.pages_crawled ?? "—" : "—";
    els.lastScanLinks.textContent = status === "completed" ? results.scan.total_links_checked ?? "—" : "—";

    if (status === "failed") {
      els.lastScanStatus.textContent = "This scan failed — the numbers above aren't meaningful. Check the target/login and try again.";
      els.lastScanStatus.className = "field-hint status-failed";
      els.lastScanStatus.hidden = false;
    } else if (status === "running") {
      els.lastScanStatus.textContent = "This scan is still running.";
      els.lastScanStatus.className = "field-hint status-running";
      els.lastScanStatus.hidden = false;
    } else {
      els.lastScanStatus.hidden = true;
    }

    renderCategoryBadges(els.lastScanCounts, status === "completed" ? results.summary : {});
    els.lastScanSection.hidden = false;
  }

  async function loadLastScan() {
    try {
      const resp = await fetch("/api/scan/last");
      if (!resp.ok) return; // 404 = no scans yet, leave the section hidden
      const data = await resp.json();
      renderLastScan(data);
      // Also populate the full results table + export buttons on load, so
      // a returning user can export the last scan without re-running it —
      // but only for a scan that actually completed. A failed/running
      // scan has no real findings/pages/links yet (those are only written
      // after crawl_site() returns successfully), so rendering it here
      // would misleadingly look like a clean, empty, completed scan.
      if (data.scan.status === "completed") {
        renderResults(data);
      }
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
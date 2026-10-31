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
  data_uri: "Malformed Data URI",
};

const CATEGORY_ORDER = ["broken", "inactive", "ip_based", "internet", "data_uri"];

/**
 * Broken drill-down (display-only): clicking the Broken badge reveals
 * Images / Files / Pages / Other options that filter the already-fetched
 * rows by target kind. Nothing is stored — the backend still reports plain
 * "broken", and export is unaffected (Feature B wires export-follows).
 */
const BROKEN_DRILLDOWN_ORDER = ["image", "file", "page", "other"];
const BROKEN_DRILLDOWN_LABELS = {
  image: "Images",
  file: "Files",
  page: "Pages",
  other: "Other",
};

const DRILLDOWN_IMAGE_EXTS = new Set([
  "png", "jpg", "jpeg", "jpe", "gif", "webp", "svg", "svgz", "ico",
  "bmp", "tif", "tiff", "avif", "heic", "heif",
]);

const DRILLDOWN_FILE_EXTS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "csv",
  "txt", "rtf", "odt", "ods", "odp",
  "zip", "tar", "gz", "tgz", "bz2", "xz", "rar", "7z", "jar", "war",
  "mp3", "wav", "ogg", "oga", "m4a", "aac", "flac", "mid", "midi",
  "mp4", "webm", "ogv", "avi", "mov", "mpeg", "mpg", "flv", "wmv",
  "woff", "woff2", "ttf", "otf", "eot",
  "css", "js", "mjs", "map", "json",
]);

/**
 * Multi-select filter (Feature B): rows matching ANY selected category.
 * Empty selection means everything. Pure — unit-tested under Node.
 */
function filterByCategories(findings, order, selected) {
  if (!selected || selected.size === 0) return findings;
  return findings.filter((f) => parseCategories(f.category, order).some((c) => selected.has(c)));
}

/**
 * Broken drill-down refinement (display-only): keep rows in one bucket.
 * Null/undefined selection means all. Pure — unit-tested under Node.
 */
function applyBrokenDrill(findings, sub) {
  return findings.filter((f) => matchesBrokenDrill(f, sub));
}

/**
 * Single-row half of applyBrokenDrill: true when the finding passes the
 * drill selection. Lets the table compose "drill refines Broken only,
 * other selected categories pass through". Pure — Node-tested.
 */
function matchesBrokenDrill(finding, sub) {
  if (!sub) return true;
  return brokenDrilldownKind(finding.link) === sub;
}

/**
 * Which drill-down bucket a broken link falls in, from its target URL
 * alone (query/fragment ignored, case-insensitive). Pure — Node-tested.
 * Non-http(s) and unparseable links land in "other", never silently.
 */
function brokenDrilldownKind(link) {
  let path = "";
  try {
    const parsed = new URL(link);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "other";
    path = parsed.pathname || "";
  } catch (e) {
    return "other";
  }
  const seg = path.split("/").pop() || "";
  const dot = seg.lastIndexOf(".");
  const ext = dot >= 0 ? seg.slice(dot + 1).toLowerCase() : "";
  if (DRILLDOWN_IMAGE_EXTS.has(ext)) return "image";
  if (DRILLDOWN_FILE_EXTS.has(ext)) return "file";
  if (!ext) return "page";
  if (/^(html?|xhtml|php|asp|aspx|jsp)$/.test(ext)) return "page";
  return "other";
}

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
    payload.login = {
      mode: "recorded",
      username,
      password,
      extra_fields: state.extraFields && Object.keys(state.extraFields).length > 0 ? state.extraFields : null,
      captcha_answer: (state.captchaAnswer || "").trim() || null,
    };
  }

  if (state.scanOptions) {
    const { options, error } = parseScanOptions(state.scanOptions, state.scanBounds);
    if (error) {
      return { error };
    }
    if (options && Object.keys(options).length > 0) {
      payload.options = options;
    }
  }

  // "Only on UI" is a Dynamic-only option. The checkbox is hidden/cleared on
  // Static by the UI, but guard here too: a stale state must never set it
  // for a static scan. Merge even when the settings popover never opened —
  // the options object may not exist yet.
  if (state.onlyOnUi) {
    if (payload.site_type !== "dynamic") {
      return { error: "Only on UI requires site type 'Dynamic' — visibility is a rendered-page property." };
    }
    payload.options = { ...(payload.options || {}), only_on_ui: true };
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

/**
 * Parses the settings-popover fields into a scan-start options object.
 * `fields`: {maxPages, maxDepth, timeout, delay (raw strings, "" = untouched),
 * headless (bool), excluded (raw text)}. `bounds`: {key: [lo, hi]} from the
 * backend defaults endpoint (or null when unfetched — range checks then
 * wait for the server, which re-validates everything with HTTP 400).
 * Returns {options} with only touched entries, or {error}.
 * Pure — unit-tested under Node.
 */
function parseScanOptions(fields, bounds) {
  const defs = [
    ["max_pages", fields.maxPages, true, "Max pages", "opt-max-pages"],
    ["max_depth", fields.maxDepth, true, "Max depth", "opt-max-depth"],
    ["timeout_seconds", fields.timeout, false, "Timeout", "opt-timeout"],
    ["delay_seconds", fields.delay, false, "Delay", "opt-delay"],
  ];
  const options = {};
  for (const [key, value, integer, label, errId] of defs) {
    const text = (value || "").trim();
    if (!text) continue;
    const num = Number(text);
    if (!Number.isFinite(num) || (integer && !Number.isInteger(num))) {
      return { error: `${label} must be a number.`, field: errId };
    }
    const range = bounds && bounds[key];
    if (range && (num < range[0] || num > range[1])) {
      return { error: `${label} must be between ${range[0]} and ${range[1]}.`, field: errId };
    }
    options[key] = num;
  }
  if (fields.headless) options.headless = true;
  const excluded = (fields.excluded || "").trim();
  if (excluded) {
    const entries = excluded.split(/[\s,]+/).filter(Boolean);
    const bad = entries.find((e) => e.includes("..") || !/^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/.test(e));
    if (bad) {
      return { error: `"${bad}" doesn't look like a plain domain (one per line, no scheme).`, field: "opt-excluded" };
    }
    options.excluded_domains = entries;
  }
  return { options };
}

/**
 * Scan timestamp ("YYYY-MM-DD HH:MM:SS" UTC, as SQLite CURRENT_TIMESTAMP
 * stores it) rendered in the viewer's local timezone. Offset-aware stamps
 * pass through untouched; garbage passes through unchanged. Pure — tested.
 */
function formatScanTime(stamp) {
  if (!stamp) return "—";
  const iso = String(stamp).trim().replace(" ", "T");
  const dated = new Date(/Z|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : `${iso}Z`);
  if (Number.isNaN(dated.getTime())) return String(stamp);
  return dated.toLocaleString();
}

/**
 * Display form of a found-on-page URL: path (+ query) only, e.g.
 * "https://127.0.0.1:5051/public" -> "/public", root -> "/".
 * Non-http(s) values and unparseable text pass through unchanged.
 */
function displayPath(urlString) {
  if (!urlString) return "";
  try {
    const parsed = new URL(urlString);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return urlString;
    return (parsed.pathname || "/") + (parsed.search || "");
  } catch (e) {
    return urlString;
  }
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
  if (event.status === "stopped") {
    return `Scan stopped after ${formatDuration(event.elapsed_seconds)} — partial results kept`;
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
  filterByCategories,
  applyBrokenDrill,
  matchesBrokenDrill,
  brokenDrilldownKind,
  parseScanOptions,
  formatScanTime,
  formatDuration,
  formatProgressLine,
  displayPath,
  CATEGORY_LABELS,
  CATEGORY_ORDER,
  BROKEN_DRILLDOWN_ORDER,
  BROKEN_DRILLDOWN_LABELS,
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
    lastScanCommentCounts: document.getElementById("last-scan-comment-counts"),
    viewLastResultsBtn: document.getElementById("view-last-results-btn"),

    form: document.getElementById("scan-form"),
    targetUrl: document.getElementById("target-url"),
    onlyOnUiField: document.getElementById("only-on-ui-field"),
    onlyOnUi: document.getElementById("only-on-ui"),
    loginCheckboxField: document.getElementById("login-checkbox-field"),
    requiresLogin: document.getElementById("requires-login"),
    loginFields: document.getElementById("login-fields"),
    loginRecordedFields: document.getElementById("login-recorded-fields"),
    loginUsername: document.getElementById("login-username"),
    loginPassword: document.getElementById("login-password"),
    loginExtraFields: document.getElementById("login-extra-fields"),
    flowStatus: document.getElementById("flow-status"),
    flowLoginBtn: document.getElementById("flow-login-btn"),
    flowLogoutBtn: document.getElementById("flow-logout-btn"),
    flowSaveBtn: document.getElementById("flow-save-btn"),
    flowMessage: document.getElementById("flow-message"),
    flowLogoutUrl: document.getElementById("flow-logout-url"),
    flowUrlSaveBtn: document.getElementById("flow-url-save-btn"),
    flowUrlStatus: document.getElementById("flow-url-status"),
    flowCaptcha: document.getElementById("flow-captcha"),

    formError: document.getElementById("form-error"),
    startScanBtn: document.getElementById("start-scan-btn"),

    progressSection: document.getElementById("progress-section"),
    progressLine: document.getElementById("progress-line"),
    stopScanBtn: document.getElementById("stop-scan-btn"),

    resultsSection: document.getElementById("results-section"),
    tabLinks: document.getElementById("tab-links"),
    tabCommented: document.getElementById("tab-commented"),
    tabShots: document.getElementById("tab-shots"),
    tabLinksCount: document.getElementById("tab-links-count"),
    tabCommentedCount: document.getElementById("tab-commented-count"),
    tabShotsCount: document.getElementById("tab-shots-count"),
    tableScroll: document.getElementById("table-scroll"),
    pagerRow: document.getElementById("pager-row"),
    categoryFilters: document.getElementById("category-filters"),
    brokenDrilldown: document.getElementById("broken-drilldown"),
    resultsMeta: document.getElementById("results-meta"),
    resultsTbody: document.getElementById("results-tbody"),
    uniqueToggle: document.getElementById("unique-toggle"),
    rowsPerPageSelect: document.getElementById("rows-per-page"),
    pagerInfo: document.getElementById("pager-info"),
    pagerPrev: document.getElementById("pager-prev"),
    pagerNext: document.getElementById("pager-next"),
    resultsEmpty: document.getElementById("results-empty"),
    exportXlsxBtn: document.getElementById("export-xlsx-btn"),
    exportPdfBtn: document.getElementById("export-pdf-btn"),
    exportDocxBtn: document.getElementById("export-docx-btn"),
    exportBoth: document.getElementById("export-both"),
    exportStatus: document.getElementById("export-status"),
    screenshotsSection: document.getElementById("screenshots-section"),
    screenshotsNote: document.getElementById("screenshots-note"),
    screenshotsGallery: document.getElementById("screenshots-gallery"),
    screenshotsZipBtn: document.getElementById("screenshots-zip-btn"),
    screenshotsStatus: document.getElementById("screenshots-status"),
    settingsGear: document.getElementById("settings-gear"),
    settingsPop: document.getElementById("settings-pop"),
    optMaxPages: document.getElementById("opt-max-pages"),
    optMaxDepth: document.getElementById("opt-max-depth"),
    optTimeout: document.getElementById("opt-timeout"),
    optDelay: document.getElementById("opt-delay"),
    optHeadless: document.getElementById("opt-headless"),
    optExcluded: document.getElementById("opt-excluded"),
    settingsHint: document.getElementById("settings-pop-hint"),
    settingsError: document.getElementById("settings-pop-error"),
    settingsResetBtn: document.getElementById("settings-reset-btn"),
    settingsSetBtn: document.getElementById("settings-set-btn"),
  };

  let activeFlowId = null;
  let flowPhase = "idle"; // idle | login-recording | login-done | logout-recording | logout-done
  let knownLoginConfig = false; // a saved login flow exists for the current target
  let knownLogoutConfig = false; // a saved logout URL or steps exists for the current target
  let logoutPrefillHost = null; // host the logout URL input was last synced from (don't clobber typing)
  let activeEventSource = null;
  let currentScanId = null;
  let streamingScanId = null;
  let progressReconnects = 0; // EventSource retry budget (persists across streamProgress re-entries)

  // Results-section tab/filter/pager state. currentResults holds the full
  // payload from the last /results (or /scan/last) fetch; activeTab picks
  // which of its two finding lists is showing; activeCategories (a Set,
  // possibly empty) filters that list down to rows matching ANY selected
  // category (Feature B multi-select); currentPage slices the
  // filtered list to rowsPerPage rows ("all" disables paging). Switching
  // tabs always clears the category filter — a category from one tab's set
  // wouldn't mean anything in the other.
  let currentResults = null;
  let activeTab = "links";
  let activeCategories = new Set();
  // Broken drill-down refinement (null = all broken). Only meaningful while
  // the Links tab filters on "broken"; cleared whenever that stops holding.
  let activeBrokenDrill = null;
  let rowsPerPage = 25;
  let currentPage = 1;
  let uniqueOnly = false;
  // Per-tab hidden column indices (header checkboxes). Selections persist
  // across scans; export sends the visible indices for each tab.
  let hiddenCols = { links: new Set(), commented: new Set() };

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

  /**
   * The "This site requires login" checkbox only makes sense on Dynamic
   * scans — Static site-type can't run a browser-based login. Hide the
   * checkbox entirely on Static, and if the user had it checked before
   * switching away from Dynamic, clear it (and the login fields under it)
   * so a stale login stays out of the submitted payload.
   */
  function updateLoginCheckboxVisibility() {
    const isDynamic = currentSiteType() === "dynamic";
    els.loginCheckboxField.hidden = !isDynamic;
    if (!isDynamic && els.requiresLogin.checked) {
      els.requiresLogin.checked = false;
      updateLoginFieldsVisibility();
    }
  }

  /**
   * "Only on UI" is a Dynamic-only option: it gates broken-link results to
   * links that are actually visible in the rendered page (hidden anchors,
   * commented/scripted URLs and runtime captures stay out). Hide it on
   * Static and force-clear it when switching away so a stale flag can't
   * ride into the payload.
   */
  function updateOnlyOnUiVisibility() {
    const isDynamic = currentSiteType() === "dynamic";
    els.onlyOnUiField.hidden = !isDynamic;
    if (!isDynamic) els.onlyOnUi.checked = false;
  }

  async function refreshRecordedFlowStatus() {
    const host = logic.extractHost(els.targetUrl.value.trim());
    if (!host) {
      els.flowStatus.textContent = "Enter a valid target URL above to check for a recorded flow.";
      return;
    }
    els.flowStatus.textContent = "Checking for a recorded flow…";
    try {
      const resp = await fetch(`/api/login-config?target_ip=${encodeURIComponent(host)}`);
      const data = await resp.json();
      if (data.exists) {
        knownLoginConfig = true;
        const logoutNote = data.has_logout_url
          ? " Logout URL configured."
          : data.has_logout_steps
            ? " Recorded logout configured."
            : " No logout configured.";
        els.flowStatus.textContent = data.has_captcha
          ? `A recorded login flow exists for ${host} (includes a captcha field).${logoutNote}`
          : `A recorded login flow exists for ${host}.${logoutNote}`;
        knownLogoutConfig = Boolean(data.has_logout_url || data.has_logout_steps);
        // Single captcha field: prefill the dedicated input (saved answer,
        // else recorded code) without clobbering anything typed. Captcha
        // steps never render as extra inputs.
        if (!els.flowCaptcha.value && data.captcha_default) {
          els.flowCaptcha.value = data.captcha_default;
        }
        // Prefill the saved logout URL once per target — never while the user
        // may be typing (only syncs when the looked-up host changes).
        if (host !== logoutPrefillHost) {
          els.flowLogoutUrl.value = data.logout_url || "";
          logoutPrefillHost = host;
        }
        if (flowPhase === "idle") updateLogoutBtnLabel();
        if (data.extra_fields && data.extra_fields.length > 0) {
          if (els.loginExtraFields) {
            els.loginExtraFields.innerHTML = "";
            data.extra_fields.forEach((field, idx) => {
              const fieldDiv = document.createElement("div");
              fieldDiv.className = "field";
              const labelEl = document.createElement("label");
              labelEl.htmlFor = `extra-field-${idx}`;
              labelEl.textContent = field.label || field.placeholder || field.name || `Extra field ${idx + 1}`;
              const inputEl = document.createElement("input");
              inputEl.type = "text";
              inputEl.id = `extra-field-${idx}`;
              inputEl.className = "login-extra-field-input";
              inputEl.dataset.selector = field.selector || "";
              inputEl.dataset.name = field.name || "";
              inputEl.dataset.label = field.label || "";
              inputEl.value = field.default_value || "";
              inputEl.autocomplete = "off";
              if (field.placeholder) inputEl.placeholder = field.placeholder;
              fieldDiv.appendChild(labelEl);
              fieldDiv.appendChild(inputEl);
              els.loginExtraFields.appendChild(fieldDiv);
            });
          }
        } else if (els.loginExtraFields) {
          els.loginExtraFields.innerHTML = "";
        }
      } else {
        els.flowStatus.textContent = `No recorded flow yet for ${host} — record one below.`;
        if (els.loginExtraFields) els.loginExtraFields.innerHTML = "";
        knownLoginConfig = false;
        knownLogoutConfig = false;
        if (host !== logoutPrefillHost) {
          els.flowLogoutUrl.value = "";
          logoutPrefillHost = host;
        }
        if (flowPhase === "idle") updateLogoutBtnLabel();
      }
    } catch (e) {
      els.flowStatus.textContent = "Couldn't check for a recorded flow — is the backend running?";
      if (els.loginExtraFields) els.loginExtraFields.innerHTML = "";
    }
  }

  function updateLogoutBtnLabel() {
    if (flowPhase !== "idle") return;
    els.flowLogoutBtn.textContent = knownLogoutConfig ? "Re-record Logout" : "Start Logout Record";
    // Standalone logout recording (saved login reused, auto sign-in) needs no
    // open flow — just a saved login to replay.
    els.flowLogoutBtn.disabled = !knownLoginConfig;
  }

  /**
   * Phased flow button states. One window spans the whole flow: Start Login
   * opens it, Finish Login freezes+saves login steps (window stays open),
   * Start/Finish Logout records in the same logged-in window, Save Record
   * finalizes (logout-URL check + captcha) and closes the window. The target
   * URL stays locked while a flow is active.
   */
  function setFlowPhase(phase) {
    flowPhase = phase;
    // Toggle buttons stay clickable during their own recording phase so the
    // user can finish; only unrelated actions lock while recording.
    els.targetUrl.disabled = phase !== "idle";
    // Logout URL input stays editable in every phase (view/prefill in idle,
    // edit during flow); only its standalone Save is idle-only so it can't
    // race an open recording window.
    els.flowUrlSaveBtn.disabled = phase !== "idle";
    els.flowLoginBtn.disabled = phase === "logout-recording" || phase === "logout-done";
    // In idle the logout button is the standalone entry (needs a saved login
    // to auto-sign the window); inside a flow it follows the phase machine.
    if (phase === "idle") {
      els.flowLogoutBtn.disabled = !knownLoginConfig;
    } else {
      els.flowLogoutBtn.disabled = phase !== "login-done" && phase !== "logout-recording";
    }
    els.flowSaveBtn.disabled = phase !== "login-done" && phase !== "logout-done";
    els.flowLoginBtn.textContent =
      phase === "login-recording" ? "Finish Login Record"
      : phase === "idle" ? "Start Login Record"
      : "Re-record Login";
    els.flowLogoutBtn.textContent =
      phase === "logout-recording" ? "Finish Logout Record"
      : phase === "logout-done" ? "Logout Recorded"
      : knownLogoutConfig ? "Re-record Logout"
      : "Start Logout Record";
  }

  // Standalone logout-URL save (idle only): persists/clears without opening
  // a window. Unlike flow Save (which preserves on empty), an explicit empty
  // save here clears the URL — that is the way to remove one.
  els.flowUrlSaveBtn.addEventListener("click", async () => {
    const host = flowHost();
    if (!host) {
      els.flowUrlStatus.textContent = "Enter a target URL first.";
      return;
    }
    const logoutUrl = els.flowLogoutUrl.value.trim();
    els.flowUrlStatus.textContent = "Saving…";
    try {
      await flowPost("/api/login/logout-config", {
        target_ip: host,
        logout_url: logoutUrl || null,
      });
      els.flowUrlStatus.textContent = logoutUrl ? "Logout URL saved." : "Logout URL cleared.";
      logoutPrefillHost = null; // force re-sync from saved state
      refreshRecordedFlowStatus();
    } catch (e) {
      els.flowUrlStatus.textContent = `Couldn't save logout URL: ${e.message}`;
    }
  });

  function flowHost() {
    return logic.extractHost(els.targetUrl.value.trim());
  }

  async function flowPost(path, body) {
    const resp = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(data.detail || `Request failed (${resp.status})`);
    }
    return data;
  }

  function resetFlowToIdle(message) {
    activeFlowId = null;
    if (message) els.flowMessage.textContent = message;
    setFlowPhase("idle");
    refreshRecordedFlowStatus();
  }

  // Liveness probe: a worker that dies (bad target, no display, failed
  // auto-login) would otherwise fail silently. Runs detached. quickAlive
  // returns on first alive sighting (manual login flow); otherwise watches
  // the full budget so a slow auto-login failure is still caught.
  async function watchFlowAlive(flowId, expectPhase, quickAlive = true) {
    for (let i = 0; i < 24; i++) {
      await new Promise((r) => setTimeout(r, 500));
      if (flowPhase !== expectPhase || activeFlowId !== flowId) return;
      try {
        const st = await (await fetch(`/api/login/flow/${flowId}/status`)).json();
        if (st && st.alive) {
          if (quickAlive) return;
        } else if (st && !st.alive) {
          resetFlowToIdle(`Browser window closed${st.error ? `: ${st.error}` : ""} — check the target, credentials, and that a display is available.`);
          return;
        }
      } catch (e) { /* transient — keep polling */ }
    }
  }

  els.flowLoginBtn.addEventListener("click", async () => {
    clearFormError();
    try {
      if (flowPhase === "idle") {
        const targetUrl = els.targetUrl.value.trim();
        if (!targetUrl) {
          showFormError("Enter a target URL before recording a login flow.");
          return;
        }
        const data = await flowPost("/api/login/flow/start", { target_url: targetUrl });
        activeFlowId = data.flow_id;
        els.flowMessage.textContent = "Browser window opened. Log in there, then click “Finish Login Record” — the window stays open.";
        setFlowPhase("login-recording");
        // Liveness probe: a worker that dies instantly (bad target, no
        // display, browser failure) would otherwise fail silently.
        watchFlowAlive(data.flow_id, "login-recording");
      } else if (flowPhase === "login-recording") {
        const host = flowHost();
        await flowPost("/api/login/flow/finish-login", { flow_id: activeFlowId, target_ip: host });
        els.flowMessage.textContent = "Login steps saved. Optionally record a logout below, or click Save Record.";
        setFlowPhase("login-done");
        refreshRecordedFlowStatus();
      } else {
        // Re-record: same window is reset to the logged-out target.
        await flowPost("/api/login/flow/rerecord-login", { flow_id: activeFlowId });
        els.flowMessage.textContent = "Window reset to the logged-out page. Log in again, then click “Finish Login Record”.";
        setFlowPhase("login-recording");
      }
    } catch (e) {
      if (/404|closed|respond/.test(e.message)) {
        resetFlowToIdle(`Recording window is gone (${e.message}). Start again if needed.`);
      } else {
        els.flowMessage.textContent = `Couldn't update login recording: ${e.message}`;
      }
    }
  });

  els.flowLogoutBtn.addEventListener("click", async () => {
    clearFormError();
    try {
      if (flowPhase === "idle") {
        // Standalone logout recording: reuses the saved login, auto-signing
        // the fresh window with the scan-form credentials.
        const targetUrl = els.targetUrl.value.trim();
        if (!targetUrl) {
          showFormError("Enter a target URL before recording a logout flow.");
          return;
        }
        const username = els.loginUsername.value.trim();
        const password = els.loginPassword.value;
        if (!username || !password) {
          showFormError("Enter the scan username and password above — they sign the recording window in.");
          return;
        }
        const data = await flowPost("/api/login/flow/start-logout-only", {
          target_url: targetUrl,
          username,
          password,
        });
        activeFlowId = data.flow_id;
        els.flowMessage.textContent = "Browser window opened and signed in automatically. Perform your logout clicks, then click “Finish Logout Record”.";
        setFlowPhase("logout-recording");
        watchFlowAlive(data.flow_id, "logout-recording", false);
      } else if (flowPhase === "login-done") {
        await flowPost("/api/login/flow/start-logout", { flow_id: activeFlowId });
        els.flowMessage.textContent = "Recording logout in the same window. Perform your logout clicks, then click “Finish Logout Record”.";
        setFlowPhase("logout-recording");
      } else if (flowPhase === "logout-recording") {
        const host = flowHost();
        await flowPost("/api/login/flow/finish-logout", { flow_id: activeFlowId, target_ip: host });
        els.flowMessage.textContent = "Logout steps saved. Click Save Record to finish.";
        setFlowPhase("logout-done");
        refreshRecordedFlowStatus();
      }
    } catch (e) {
      if (/404|closed|respond/.test(e.message)) {
        resetFlowToIdle(`Recording window is gone (${e.message}). Start again if needed.`);
      } else {
        els.flowMessage.textContent = `Couldn't update logout recording: ${e.message}`;
      }
    }
  });

  els.flowSaveBtn.addEventListener("click", async () => {
    clearFormError();
    try {
      const host = flowHost();
      const data = await flowPost("/api/login/flow/save", {
        flow_id: activeFlowId,
        target_ip: host,
        captcha_answer: els.flowCaptcha.value.trim() || null,
        logout_url: els.flowLogoutUrl.value.trim() || null,
      });
      els.flowLogoutUrl.value = "";
      els.flowCaptcha.value = "";
      logoutPrefillHost = null; // force re-sync (prefill/empty) from saved state
      resetFlowToIdle(data.warning || "Recording saved and window closed.");
    } catch (e) {
      if (/404|closed|respond/.test(e.message)) {
        resetFlowToIdle(`Recording window is gone (${e.message}). Progress up to the last finish was kept.`);
      } else {
        els.flowMessage.textContent = `Couldn't save recording: ${e.message}`;
      }
    }
  });

  els.requiresLogin.addEventListener("change", updateLoginFieldsVisibility);
  els.form.querySelectorAll('input[name="site_type"]').forEach((radio) => {
    radio.addEventListener("change", updateLoginCheckboxVisibility);
    radio.addEventListener("change", updateOnlyOnUiVisibility);
  });
  els.targetUrl.addEventListener("blur", () => {
    if (els.requiresLogin.checked) {
      refreshRecordedFlowStatus();
    }
  });

  // Settings popover (Feature C): per-scan overrides, in-memory only.
  // Placeholders show live backend defaults; empty fields are omitted from
  // the payload (backend fills defaults); refresh wipes everything.
  let settingsDefaults = null;
  let settingsBounds = null;

  async function fillSettingsPlaceholders() {
    if (settingsDefaults) return settingsDefaults;
    try {
      const resp = await fetch("/api/settings/defaults");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      settingsDefaults = await resp.json();
      settingsBounds = (settingsDefaults && settingsDefaults.bounds) || null;
    } catch (e) {
      els.settingsError.textContent = "Backend defaults unavailable — empty still means default.";
      els.settingsError.hidden = false;
      return null;
    }
    const values = (settingsDefaults && settingsDefaults.values) || {};
    els.optMaxPages.placeholder = values.max_pages ?? "";
    els.optMaxDepth.placeholder = values.max_depth ?? "";
    els.optTimeout.placeholder = values.timeout_seconds ?? "";
    els.optDelay.placeholder = values.delay_seconds ?? "";
    const builtins = values.excluded_domains || [];
    els.settingsHint.textContent = builtins.length > 0
      ? `Always excluded: ${builtins.join(", ")}.`
      : "";
    return settingsDefaults;
  }

  function setSettingsOpen(open) {
    els.settingsPop.hidden = !open;
    els.settingsGear.setAttribute("aria-expanded", String(open));
    if (open) {
      fillSettingsPlaceholders();
      els.optMaxPages.focus();
    }
  }

  els.settingsGear.addEventListener("click", (event) => {
    event.stopPropagation();
    setSettingsOpen(els.settingsPop.hidden);
  });
  // Set validates now (red inline error under the offending field, stays
  // open) and auto-closes on success. Values live in the fields either
  // way — submit re-validates as backup.
  const SETTINGS_ERR_IDS = ["err-opt-max-pages", "err-opt-max-depth", "err-opt-timeout", "err-opt-delay", "err-opt-excluded"];
  function clearSettingsFieldErrors() {
    SETTINGS_ERR_IDS.forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.hidden = true;
    });
  }
  els.settingsSetBtn.addEventListener("click", () => {
    clearSettingsFieldErrors();
    const { error, field } = logic.parseScanOptions(collectScanOptionFields(), settingsBounds);
    if (error) {
      const slot = field ? document.getElementById("err-" + field) : null;
      if (slot) {
        slot.textContent = error;
        slot.hidden = false;
      } else {
        els.settingsError.textContent = error;
        els.settingsError.hidden = false;
      }
      return;
    }
    els.settingsError.hidden = true;
    updateSettingsGearBadge();
    setSettingsOpen(false);
  });
  els.settingsResetBtn.addEventListener("click", () => {
    els.optMaxPages.value = "";
    els.optMaxDepth.value = "";
    els.optTimeout.value = "";
    els.optDelay.value = "";
    els.optHeadless.checked = false;
    els.optExcluded.value = "";
    els.settingsError.hidden = true;
    clearSettingsFieldErrors();
    updateSettingsGearBadge();
  });
  // Staged-values dot on the gear: on when any override is filled in.
  function updateSettingsGearBadge() {
    const f = collectScanOptionFields();
    const staged = ["maxPages", "maxDepth", "timeout", "delay", "excluded"]
      .some((k) => (f[k] || "").trim() !== "") || f.headless === true;
    els.settingsGear.classList.toggle("has-values", staged);
  }
  els.settingsPop.addEventListener("input", updateSettingsGearBadge);
  document.addEventListener("click", (event) => {
    if (!els.settingsPop.hidden
        && !els.settingsPop.contains(event.target)
        && !els.settingsGear.contains(event.target)) {
      setSettingsOpen(false);
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !els.settingsPop.hidden) {
      setSettingsOpen(false);
    }
  });


  function collectScanOptionFields() {
    return {
      maxPages: els.optMaxPages.value,
      maxDepth: els.optMaxDepth.value,
      timeout: els.optTimeout.value,
      delay: els.optDelay.value,
      headless: els.optHeadless.checked,
      excluded: els.optExcluded.value,
    };
  }

  function currentFormState() {
    const extraFields = {};
    if (els.loginExtraFields) {
      const inputs = els.loginExtraFields.querySelectorAll(".login-extra-field-input");
      inputs.forEach((input) => {
        const val = input.value;
        if (input.dataset.selector) extraFields[input.dataset.selector] = val;
        if (input.dataset.name) extraFields[input.dataset.name] = val;
        if (input.dataset.label) extraFields[input.dataset.label] = val;
      });
    }
    return {
      targetUrl: els.targetUrl.value,
      siteType: currentSiteType(),
      onlyOnUi: els.onlyOnUi.checked,
      requiresLogin: els.requiresLogin.checked,
      username: els.loginUsername.value,
      password: els.loginPassword.value,
      captchaAnswer: els.flowCaptcha.value,
      extraFields,
      scanOptions: collectScanOptionFields(),
      scanBounds: settingsBounds,
    };
  }

  function renderCategoryBadges(container, summary, order = logic.CATEGORY_ORDER, labels = logic.CATEGORY_LABELS) {
    container.innerHTML = "";
    order.forEach((cat) => {
      const count = summary[cat] || 0;
      const li = document.createElement("li");
      li.className = `badge badge-${cat}`;
      li.textContent = `${labels[cat]}: ${count}`;
      container.appendChild(li);
    });
  }

  /**
   * Renders the clickable category-filter badge row for the currently
   * active tab. `order`/`labels` are the Links or Commented Code sets;
   * `findings` is that tab's full (unfiltered) list, used to compute each
   * badge's count. Badges multi-select (Feature B): clicking toggles the
   * category in the active set (rows matching ANY selected category show);
   * an empty set shows everything. A badge with a zero count is shown but
   * not clickable — nothing to filter to.
   */
  function renderCategoryFilterBadges(order, labels, findings) {
    els.categoryFilters.innerHTML = "";
    order.forEach((cat) => {
      const count = findings.filter((f) => logic.parseCategories(f.category, order).includes(cat)).length;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `badge badge-filter badge-${cat}`;
      if (count === 0) btn.classList.add("zero");
      if (activeCategories.has(cat)) btn.classList.add("active");
      btn.textContent = `${labels[cat]} (${count})`;
      btn.disabled = count === 0;
      btn.setAttribute("aria-pressed", String(activeCategories.has(cat)));
      btn.addEventListener("click", () => {
        if (activeCategories.has(cat)) {
          activeCategories.delete(cat);
        } else {
          activeCategories.add(cat);
        }
        if (!activeCategories.has("broken")) activeBrokenDrill = null;
        currentPage = 1;
        renderActiveTab();
      });
      els.categoryFilters.appendChild(btn);
    });
  }

  /**
   * Second-row drill-down under an active Broken filter: All broken plus
   * Images / Files / Pages / Other, each with its row count. Table-only
   * refinement by design (buckets have no backend representation —
   * export follows the top-level multi-selection via the CSV category
   * param, then the drill narrows just the table). Hidden unless the
   * Links tab filters on broken.
   */
  function renderBrokenDrilldown(brokenFindings) {
    els.brokenDrilldown.innerHTML = "";
    const kinds = ["all", ...logic.BROKEN_DRILLDOWN_ORDER];
    kinds.forEach((kind) => {
      const count = kind === "all"
        ? brokenFindings.length
        : brokenFindings.filter((f) => logic.brokenDrilldownKind(f.link) === kind).length;
      const btn = document.createElement("button");
      btn.type = "button";
      const selected = (kind === "all" && activeBrokenDrill === null) || activeBrokenDrill === kind;
      btn.className = `badge badge-filter badge-drill badge-drill-${kind}${selected ? " active" : ""}${count === 0 ? " zero" : ""}`;
      btn.textContent = kind === "all" ? `All broken (${count})` : `${logic.BROKEN_DRILLDOWN_LABELS[kind]} (${count})`;
      btn.disabled = count === 0;
      btn.setAttribute("aria-label", kind === "all" ? "Show all broken links" : `Show only broken ${logic.BROKEN_DRILLDOWN_LABELS[kind].toLowerCase()}`);
      btn.addEventListener("click", () => {
        activeBrokenDrill = kind === "all" ? null : kind;
        currentPage = 1;
        renderActiveTab();
      });
      els.brokenDrilldown.appendChild(btn);
    });
  }

  function renderResultsTable(findings, order, hidden) {
    els.resultsTbody.innerHTML = "";
    els.resultsEmpty.hidden = findings.length !== 0;

    findings.forEach((finding) => {
      const tr = document.createElement("tr");
      const cells = [];

      const foundOnTd = document.createElement("td");
      foundOnTd.className = "mono";
      foundOnTd.textContent = logic.displayPath(finding.found_on_page);
      cells.push(foundOnTd);

      const linkTd = document.createElement("td");
      linkTd.className = "mono";
      linkTd.textContent = finding.link;
      cells.push(linkTd);

      const categoryTd = document.createElement("td");
      logic.parseCategories(finding.category, order).forEach((cat) => {
        const span = document.createElement("span");
        span.className = `badge badge-${cat}`;
        span.textContent = (logic.CATEGORY_LABELS[cat] || logic.COMMENT_CATEGORY_LABELS[cat]);
        span.style.marginRight = "4px";
        categoryTd.appendChild(span);
      });
      cells.push(categoryTd);

      const severityTd = document.createElement("td");
      if (finding.severity) {
        const span = document.createElement("span");
        span.className = `badge badge-severity-${finding.severity}`;
        span.textContent = logic.SEVERITY_LABELS[finding.severity] || finding.severity;
        severityTd.appendChild(span);
      }
      cells.push(severityTd);

      const evidenceTd = document.createElement("td");
      evidenceTd.textContent = finding.evidence || "";
      cells.push(evidenceTd);

      const locationTd = document.createElement("td");      locationTd.className = "location-cell";
      // Friendly locator: ancestors muted, own name in ink. Supports both
      // separators — "→" (Order 9 breadcrumbs) and legacy "›" (pre-Order-9
      // scans) — anything else renders as plain text.
      const locText = finding.element_location || "";
      const locSep = locText.indexOf("→") !== -1 ? "→" : (locText.indexOf("›") !== -1 ? "›" : null);
      if (locSep !== null) {
        const parts = locText.split(locSep).map((s) => s.trim()).filter(Boolean);
        const own = parts.pop();
        parts.forEach((part) => {
          const ancestor = document.createElement("span");
          ancestor.className = "location-ancestor";
          ancestor.textContent = part;
          locationTd.appendChild(ancestor);
          const sep = document.createElement("span");
          sep.className = "location-sep";
          sep.textContent = ` ${locSep} `;
          locationTd.appendChild(sep);
        });
        const ownSpan = document.createElement("span");
        ownSpan.className = "location-own";
        ownSpan.textContent = own || "";
        locationTd.appendChild(ownSpan);
      } else {
        locationTd.textContent = locText;
      }
      cells.push(locationTd);

      cells.forEach((td, i) => {
        if (hidden.has(i)) {
          // Narrow empty placeholder keeps this row aligned under its header.
          const ph = document.createElement("td");
          ph.className = "col-hidden";
          tr.appendChild(ph);
        } else {
          tr.appendChild(td);
        }
      });
      els.resultsTbody.appendChild(tr);
    });
  }

  // Column header labels per tab, in backend export order (indices shared
  // with the export columns= query param).
  const LINK_COLUMNS = ["Found on page", "Link", "Category", "Severity", "Evidence / reason", "Element location"];
  const COMMENT_COLUMNS = ["Found On Page", "Extracted Value / Target", "Finding Type", "Severity", "Details", "DOM Location"];

  /**
   * Builds the thead with a visibility checkbox per column. At least one
   * column stays visible — hiding the last one is refused. A hidden column
   * keeps a narrow placeholder cell (checkbox only) so body columns never
   * shift under the wrong headers.
   */
  function renderThead(headers, hidden) {
    const theadRow = document.querySelector("#results-table thead tr");
    if (!theadRow) return;
    theadRow.innerHTML = "";
    headers.forEach((label, i) => {
      const th = document.createElement("th");
      const isHidden = hidden.has(i);
      if (isHidden) th.className = "col-hidden";
      const lab = document.createElement("label");
      lab.className = "col-toggle";
      lab.title = "Toggle column (export follows visibility)";
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = !isHidden;
      box.setAttribute("aria-label", `Toggle ${label} column`);
      box.addEventListener("change", () => {
        if (box.checked) {
          hidden.delete(i);
        } else {
          if (hidden.size >= headers.length - 1) {
            box.checked = true; // keep at least one column
            return;
          }
          hidden.add(i);
        }
        renderActiveTab();
      });
      lab.appendChild(box);
      if (!isHidden) lab.appendChild(document.createTextNode(label));
      th.appendChild(lab);
      theadRow.appendChild(th);
    });
  }

  /**
   * Redraws everything below the tab row for the current activeTab/
   * activeCategories state, without re-fetching anything. Called on load,
   * on tab switch, and on category-filter click.
   */
  function renderActiveTab() {
    if (!currentResults) return;

    const isLinks = activeTab === "links";
    const isShots = activeTab === "screenshots";
    els.tabLinks.classList.toggle("active", isLinks);
    els.tabCommented.classList.toggle("active", activeTab === "commented");
    els.tabShots.classList.toggle("active", isShots);
    els.tabLinksCount.textContent = currentResults.findings.length;
    els.tabCommentedCount.textContent = currentResults.commented_findings.length;

    if (isShots) {
      // Screenshots live in their own tab (same switching mechanics as the
      // other two): table blocks hide, gallery section shows + loads.
      els.categoryFilters.hidden = true;
      els.brokenDrilldown.hidden = true;
      els.tableScroll.hidden = true;
      els.pagerRow.hidden = true;
      els.resultsMeta.hidden = true;
      els.resultsEmpty.hidden = true;
      syncExportRow(true);
      openScreenshotsTab();
      return;
    }
    els.categoryFilters.hidden = false;
    els.tableScroll.hidden = false;
    els.pagerRow.hidden = false;
    els.resultsMeta.hidden = false;
    els.screenshotsSection.hidden = true;
    syncExportRow(false);

    const order = isLinks ? logic.CATEGORY_ORDER : logic.COMMENT_CATEGORY_ORDER;
    const labels = isLinks ? logic.CATEGORY_LABELS : logic.COMMENT_CATEGORY_LABELS;
    const tabFindings = isLinks ? currentResults.findings : currentResults.commented_findings;

    const theadRow = document.querySelector("#results-table thead tr");
    if (theadRow) {
      renderThead(isLinks ? LINK_COLUMNS : COMMENT_COLUMNS, hiddenCols[activeTab]);
    }

    // Unique collapse runs before badges + filter so badge counts, the
    // table, and the pager all agree on the deduped list.
    const uniqueBase = uniqueOnly ? applyUnique(tabFindings) : tabFindings;

    renderCategoryFilterBadges(order, labels, uniqueBase);

    const showDrilldown = isLinks && activeCategories.has("broken");
    els.brokenDrilldown.hidden = !showDrilldown;
    if (showDrilldown) {
      renderBrokenDrilldown(uniqueBase.filter((f) => logic.parseCategories(f.category, order).includes("broken")));
    } else {
      activeBrokenDrill = null;
    }

    let shown = logic.filterByCategories(uniqueBase, order, activeCategories);
    if (showDrilldown && activeBrokenDrill) {
      // The drill refines the Broken selection only — rows from other
      // selected categories pass through untouched.
      const sub = activeBrokenDrill;
      shown = shown.filter((f) =>
        logic.parseCategories(f.category, order).includes("broken")
          ? logic.matchesBrokenDrill(f, sub)
          : true);
    }

    // Pager slice: clamp first so a rows-per-page change can't strand us on
    // an empty page; an empty slice then always means an empty filter.
    // Paging (and its counts) run on the deduped list when Unique is on.
    const showAll = rowsPerPage === "all";
    const pageSize = showAll ? Math.max(shown.length, 1) : rowsPerPage;
    const totalPages = Math.max(1, Math.ceil(shown.length / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    const start = (currentPage - 1) * pageSize;
    const pageSlice = showAll ? shown : shown.slice(start, start + pageSize);

    renderResultsTable(pageSlice, order, hiddenCols[activeTab]);
    updatePager(shown.length, showAll ? 0 : start, pageSlice.length, totalPages);

    const uniqueNote = uniqueOnly ? " (unique)" : "";
    const tabLabel = isLinks ? "Links" : "Code Findings";
    const selectedLabels = order.filter((c) => activeCategories.has(c)).map((c) => labels[c]);
    if (showDrilldown && activeBrokenDrill) {
      selectedLabels[selectedLabels.indexOf(labels["broken"])] =
        `${labels["broken"]} › ${logic.BROKEN_DRILLDOWN_LABELS[activeBrokenDrill]}`;
    }
    els.resultsMeta.textContent = selectedLabels.length > 0
      ? `${tabLabel} — ${selectedLabels.join(", ")}: ${shown.length} of ${uniqueBase.length} shown${uniqueNote}.`
      : `${tabLabel}: ${uniqueBase.length} shown${uniqueNote}. ${currentResults.scan.pages_crawled} pages crawled, ${currentResults.scan.total_links_checked} links checked.`;
  }

  function setActiveTab(tab) {
    if (activeTab === tab) return;
    activeTab = tab;
    activeCategories = new Set();
    activeBrokenDrill = null;
    currentPage = 1;
    renderActiveTab();
  }

  /**
   * Unique collapse (same LINK only — page and category ignored): first
   * occurrence kept in table order, extras counted into its evidence as xN.
   * The marker carries the link's total occurrence count. Returns copies,
   * never mutates.
   */
  function applyUnique(list) {
    const seen = new Map();
    const out = [];
    for (const f of list) {
      const key = f.link || "";
      const entry = seen.get(key);
      if (entry) {
        entry.n += 1;
      } else {
        const copy = { ...f };
        seen.set(key, { row: copy, n: 1 });
        out.push(copy);
      }
    }
    for (const { row, n } of seen.values()) {
      if (n > 1) {
        row.evidence = row.evidence ? `${row.evidence} (×${n} occurrences)` : `×${n} occurrences`;
      }
    }
    return out;
  }

  /**
   * Pager readout + Prev/Next enablement for the current slice.
   * `total` is the filtered (pre-slice) count; `start`/`count` describe the
   * rendered slice; `totalPages` already accounts for "All".
   */
  function updatePager(total, start, count, totalPages) {
    if (total === 0) {
      els.pagerInfo.textContent = "0 of 0";
    } else if (rowsPerPage === "all") {
      els.pagerInfo.textContent = `All ${total} shown`;
    } else {
      els.pagerInfo.textContent = `${start + 1}–${start + count} of ${total}`;
    }
    els.pagerPrev.disabled = currentPage <= 1;
    els.pagerNext.disabled = currentPage >= totalPages;
  }

  els.rowsPerPageSelect.addEventListener("change", () => {
    const value = els.rowsPerPageSelect.value;
    rowsPerPage = value === "all" ? "all" : parseInt(value, 10);
    currentPage = 1;
    renderActiveTab();
  });

  els.pagerPrev.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage -= 1;
      renderActiveTab();
    }
  });

  els.pagerNext.addEventListener("click", () => {
    currentPage += 1;
    renderActiveTab();
  });

  els.uniqueToggle.addEventListener("click", () => {
    uniqueOnly = !uniqueOnly;
    els.uniqueToggle.textContent = uniqueOnly ? "Unique: on" : "Unique: off";
    els.uniqueToggle.setAttribute("aria-pressed", String(uniqueOnly));
    currentPage = 1;
    renderActiveTab();
  });

  els.tabLinks.addEventListener("click", () => setActiveTab("links"));
  els.tabCommented.addEventListener("click", () => setActiveTab("commented"));
  els.tabShots.addEventListener("click", () => setActiveTab("screenshots"));

  function renderResults(results) {
    currentScanId = results.scan.id;
    currentResults = results;
    activeTab = "links";
    activeCategories = new Set();
    activeBrokenDrill = null;
    currentPage = 1;
    renderActiveTab();
    els.resultsSection.hidden = false;
    els.viewLastResultsBtn.textContent = "Hide Last Results";
    // Gallery belongs to a screenshots fetch, never to the table render —
    // mid-stream renders must not flash a stale gallery.
    els.screenshotsSection.hidden = true;
    els.screenshotsGallery.innerHTML = "";
  }

  // Screenshots feature: gallery + ZIP download, fed by
  // GET /api/scan/{id}/screenshots (metadata) and the PNG/ZIP endpoints.
  // Anything missing (none taken, evicted, restarted) hides the section
  // silently — screenshots are a bonus, never a blocker.
  const SHOT_GROUP_ORDER = ["broken", "inactive", "ip_based", "internet"];
  const SHOT_GROUP_LABELS = { broken: "Broken", inactive: "Inactive", ip_based: "IP-based", internet: "Internet" };

  function renderScreenshotGallery(scanId, data) {
    els.screenshotsGallery.innerHTML = "";
    const shots = data.shots || [];
    const status = data.status || "";
    // ZIP needs at least one shot — never a dead download button.
    els.screenshotsZipBtn.disabled = shots.length === 0;
    if (status === "capturing") {
      els.screenshotsNote.textContent = "Getting screenshots…";
    } else if (status === "ready") {
      els.screenshotsNote.textContent = `${shots.length} screenshot${shots.length === 1 ? "" : "s"} captured.`;
    } else if (status === "partial") {
      els.screenshotsNote.textContent =
        `${shots.length} of ${data.targets || "?"} captured — the rest had nothing frameable.`;
    } else if (status === "stopped") {
      els.screenshotsNote.textContent =
        `Capture stopped — ${shots.length} screenshot${shots.length === 1 ? "" : "s"} kept.`;
    } else {
      els.screenshotsNote.textContent = "Screenshot capture didn't finish — partial gallery below, if any.";
    }
    const byGroup = {};
    shots.forEach((shot) => {
      const group = (shot.categories || []).find((c) => SHOT_GROUP_ORDER.includes(c)) || "other";
      (byGroup[group] = byGroup[group] || []).push(shot);
    });
    let shotNo = 0;
    [...SHOT_GROUP_ORDER, "other"].forEach((group) => {
      const list = byGroup[group] || [];
      if (!list.length) return;
      const h = document.createElement("h3");
      h.className = "shot-group-title";
      h.textContent = `${SHOT_GROUP_LABELS[group] || "Other"} (${list.length})`;
      els.screenshotsGallery.appendChild(h);
      list.forEach((shot) => {
        shotNo += 1;
        const fig = document.createElement("figure");
        fig.className = "screenshot-figure";
        const fullLink = document.createElement("a");
        fullLink.href = `/api/scan/${scanId}/screenshots/${shot.id}`;
        fullLink.target = "_blank";
        fullLink.rel = "noopener";
        fullLink.title = "Open full-size proof";
        fullLink.className = "shot-thumb";
        const img = document.createElement("img");
        img.src = fullLink.href;
        img.alt = `Proof screenshot: ${shot.link}`;
        img.loading = "lazy";
        fullLink.appendChild(img);
        fig.appendChild(fullLink);
        const cap = document.createElement("figcaption");
        const fullPath = logic.displayPath(shot.link);
        const shortPath = fullPath.length > 42 ? `${fullPath.slice(0, 41)}…` : fullPath;
        const titleLine = document.createElement("div");
        titleLine.className = "shot-cap-title";
        titleLine.textContent = `${String(shotNo).padStart(2, "0")} · ${SHOT_GROUP_LABELS[group] || "Other"} · ${shortPath}`;
        titleLine.title = shot.link;
        cap.appendChild(titleLine);
        const metaParts = [`Found on ${logic.displayPath(shot.found_on_page)}`];
        if (shot.two_panel) metaParts.push("two panels");
        if (shot.note) metaParts.push(shot.note);
        const metaLine = document.createElement("div");
        metaLine.className = "shot-cap-meta";
        metaLine.textContent = metaParts.join(" · ");
        metaLine.title = shot.breadcrumb || metaLine.textContent;
        if (shot.note) metaLine.classList.add("screenshot-note-flag");
        cap.appendChild(metaLine);
        fig.appendChild(cap);
        els.screenshotsGallery.appendChild(fig);
      });
    });
    els.screenshotsSection.hidden = shots.length === 0 && status !== "capturing";
  }

  // Screenshots tab: badge count refreshes silently everywhere; the
  // gallery itself loads only when its tab opens (looping while capturing,
  // bounded, tab-gated) — never a blocker for the other tabs.
  // Screenshots tab swaps the head-row exports: Excel/PDF hide, the ZIP
  // download takes their place (and back when leaving). Table-only here —
  // the gallery's own status text stays in its section.
  function syncExportRow(isShots) {
    els.exportXlsxBtn.hidden = isShots;
    els.exportPdfBtn.hidden = isShots;
    els.exportDocxBtn.hidden = isShots;
    const bothLabel = els.exportBoth.closest("label");
    if (bothLabel) bothLabel.hidden = isShots;
    els.exportStatus.hidden = isShots;
    els.screenshotsZipBtn.hidden = !isShots;
  }

  async function refreshShotsBadge() {
    if (!currentScanId) return;
    try {
      const resp = await fetch(`/api/scan/${currentScanId}/screenshots`);
      if (!resp.ok) {
        els.tabShotsCount.textContent = "0";
        return;
      }
      const data = await resp.json();
      els.tabShotsCount.textContent = String((data.shots || []).length);
    } catch (e) {
      // Transient — leave the last count in place.
    }
  }

  async function openScreenshotsTab() {
    els.screenshotsSection.hidden = false;
    els.screenshotsNote.textContent = "Getting screenshots…";
    els.screenshotsGallery.innerHTML = "";
    for (let attempt = 0; attempt < 150; attempt++) {
      if (activeTab !== "screenshots" || !currentScanId) return;
      try {
        const resp = await fetch(`/api/scan/${currentScanId}/screenshots`);
        if (resp.ok) {
          const data = await resp.json();
          if (data.status !== "capturing") {
            renderScreenshotGallery(currentScanId, data);
            els.tabShotsCount.textContent = String((data.shots || []).length);
            return;
          }
          els.tabShotsCount.textContent = "…";
        } else if (resp.status === 404) {
          els.screenshotsNote.textContent = "No screenshots available for this scan.";
          els.tabShotsCount.textContent = "0";
          return;
        }
      } catch (e) {
        // Transient — retry on the next tick.
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
    els.screenshotsNote.textContent = "Still capturing — reopen this tab in a bit.";
  }

  els.screenshotsZipBtn.addEventListener("click", () => {
    if (!currentScanId) return;
    els.screenshotsStatus.textContent = "Preparing ZIP…";
    window.location.href = `/api/scan/${currentScanId}/screenshots.zip`;
    setTimeout(() => {
      els.screenshotsStatus.textContent = "";
    }, 2000);
  });

  /**
   * Export buttons navigate to the export endpoint with the current view
   * encoded as query params (visible columns per tab, active tab/category,
   * unique toggle) — the response carries Content-Disposition: attachment,
   * so the browser downloads the file instead of replacing the page.
   */
  function visibleColumns(tab) {
    const hidden = hiddenCols[tab];
    const out = [];
    for (let i = 0; i < 6; i++) {
      if (!hidden.has(i)) out.push(i);
    }
    return out;
  }

  function triggerExport(format) {
    if (!currentScanId) {
      els.exportStatus.textContent = "No scan results to export yet.";
      return;
    }
    const params = new URLSearchParams({
      format,
      tabs: els.exportBoth.checked ? "both" : "active",
      tab: activeTab,
      unique: uniqueOnly ? "1" : "0",
      link_columns: visibleColumns("links").join(","),
      code_columns: visibleColumns("commented").join(","),
    });
    if (activeCategories.size > 0) params.set("category", [...activeCategories].join(","));
    els.exportStatus.textContent = `Preparing ${format.toUpperCase()} export…`;
    window.location.href = `/api/scan/${currentScanId}/export?${params.toString()}`;
    setTimeout(() => {
      els.exportStatus.textContent = "";
    }, 2000);
  }

  els.exportXlsxBtn.addEventListener("click", () => triggerExport("xlsx"));
  els.exportPdfBtn.addEventListener("click", () => triggerExport("pdf"));
  els.exportDocxBtn.addEventListener("click", () => triggerExport("docx"));

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
    refreshShotsBadge();
    els.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  function renderLastScan(results) {
    els.lastScanUrl.textContent = results.scan.target_url;
    els.lastScanIp.textContent = results.scan.target_ip;
    els.lastScanSiteType.textContent = results.scan.site_type;
    // Stored UTC ("YYYY-MM-DD HH:MM:SS") → viewer's local timezone.
    els.lastScanDate.textContent = logic.formatScanTime(results.scan.completed_at || results.scan.started_at);
    els.lastScanPages.textContent = results.scan.pages_crawled ?? "—";
    els.lastScanLinks.textContent = results.scan.total_links_checked ?? "—";
    renderCategoryBadges(els.lastScanCounts, results.summary);
    renderCategoryBadges(els.lastScanCommentCounts, results.summary, logic.COMMENT_CATEGORY_ORDER, logic.COMMENT_CATEGORY_LABELS);
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

  function streamProgress(scanId, isRetry = false) {
    if (activeEventSource) {
      activeEventSource.close();
    }
    els.progressSection.hidden = false;
    els.progressLine.textContent = isRetry
      ? "Progress stream interrupted — reconnecting…"
      : "Starting scan…";
    els.stopScanBtn.hidden = false;
    els.stopScanBtn.disabled = false;
    streamingScanId = scanId;
    if (!isRetry) progressReconnects = 0;
    let midResultsShown = false;
    let finished = false;

    const source = new EventSource(`/api/scan/${scanId}/progress`);
    activeEventSource = source;

    source.onmessage = async (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch (e) {
        return; // malformed tick — ignore; the stream keeps going
      }
      els.progressLine.textContent = logic.formatProgressLine(data);
      if (data.screenshots === "capturing") {
        els.progressLine.textContent += " Getting screenshots…";
      }

      // Terminal FIRST and synchronously: close the EventSource BEFORE any
      // await. The old order ran the mid-results fetch below first, which
      // delayed close() past Chrome's own EOF handling (the server closes
      // the stream right after the final event) — the browser then fired a
      // reconnect-cycle "error" against the still-open source and onerror
      // painted "Lost connection…" over an already-completed scan.
      if (data.status === "completed" || data.status === "failed" || data.status === "stopped" || data.status === "not_found") {
        finished = true;
        source.close();
        if (activeEventSource === source) activeEventSource = null;
        streamingScanId = null;
        els.startScanBtn.disabled = false;
        els.stopScanBtn.hidden = true;

        if (data.status === "completed" || data.status === "stopped") {
          try {
            const resp = await fetch(`/api/scan/${scanId}/results`);
            const results = await resp.json();
            renderResults(results);
            renderLastScan(results);
            refreshShotsBadge();
          } catch (e) {
            showFormError("Scan completed, but results could not be loaded.");
          }
        }
        return;
      }

      // Screenshots feature (two-stage): findings are durable as soon as
      // the crawl completes (worker publishes `screenshots`), so the table
      // renders mid-stream while shots capture — the gallery fills in at
      // the final event in the terminal branch above.
      if (!midResultsShown && data.screenshots && streamingScanId === scanId) {
        midResultsShown = true;
        try {
          const resp = await fetch(`/api/scan/${scanId}/results`);
          const results = await resp.json();
          renderResults(results);
          renderLastScan(results);
        } catch (e) {
          midResultsShown = false; // final event retries in the terminal branch above
        }
      }
    };

    source.onerror = () => {
      if (finished) return; // terminal already handled — ignore trailing EOF noise
      source.close();
      if (activeEventSource === source) activeEventSource = null;
      // The stream dropped, but the scan itself may still be running
      // server-side — retry the stream instead of giving up immediately.
      // A healthy backend delivers the terminal event on the next stream;
      // a dead one burns the retry budget first. Stop stays available the
      // whole time (streamingScanId is only cleared once we give up).
      if (progressReconnects < 2) {
        progressReconnects += 1;
        setTimeout(() => {
          if (streamingScanId === scanId) streamProgress(scanId, true);
        }, 1000);
      } else {
        els.progressLine.textContent = "Lost connection to the progress stream.";
        streamingScanId = null;
        els.startScanBtn.disabled = false;
      }
    };
  }

  els.stopScanBtn.addEventListener("click", async () => {
    if (streamingScanId == null) return;
    els.stopScanBtn.disabled = true;
    try {
      const resp = await fetch(`/api/scan/${streamingScanId}/stop`, { method: "POST" });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(data.detail || `Request failed (${resp.status})`);
      }
      els.progressLine.textContent = "Stopping scan…";
    } catch (e) {
      showFormError(`Couldn't stop scan: ${e.message}`);
      if (streamingScanId != null) {
        els.stopScanBtn.disabled = false;
      }
    }
  });

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

  updateLoginCheckboxVisibility();
  updateOnlyOnUiVisibility();
  updateLoginFieldsVisibility();
  loadLastScan();
}
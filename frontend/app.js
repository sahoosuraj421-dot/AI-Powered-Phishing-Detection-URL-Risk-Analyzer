/* ═══════════════════════════════════════════════════════════════════════════
   Tripwire – Frontend Application
   ═══════════════════════════════════════════════════════════════════════════ */

"use strict";

// ─── Utilities ───────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const TONES = { low: "#3ecf8e", medium: "#f4a535", high: "#ff5757" };

function levelOf(score) {
  return score >= 50 ? "high" : score >= 30 ? "medium" : "low";
}

// Toast notification
function toast(msg, type = "info") {
  const tc = $("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  tc.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ─── Auth token management ────────────────────────────────────────────────────
const Auth = {
  get token()    { return localStorage.getItem("tw_token"); },
  get username() { return localStorage.getItem("tw_username"); },
  get email()    { return localStorage.getItem("tw_email"); },

  save(data) {
    localStorage.setItem("tw_token",    data.access_token);
    localStorage.setItem("tw_username", data.username);
    localStorage.setItem("tw_email",    data.email || "");
  },

  clear() {
    localStorage.removeItem("tw_token");
    localStorage.removeItem("tw_username");
    localStorage.removeItem("tw_email");
  },

  isLoggedIn() { return !!this.token; },
};

// ─── API helper ───────────────────────────────────────────────────────────────
async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (Auth.token) headers["Authorization"] = "Bearer " + Auth.token;
  const res = await fetch(path, { ...options, headers });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON body */ }
  if (!res.ok) {
    let msg = "Something went wrong. Please try again.";
    if (res.status === 429) msg = "Too many requests – please wait a minute.";
    else if (typeof data?.detail === "string") msg = data.detail;
    else if (Array.isArray(data?.detail))
      msg = data.detail.map(e => e.msg?.replace(/^Value error,\s*/, "")).join("; ") || msg;
    throw new Error(msg);
  }
  return data;
}

// ─── SPA Router ──────────────────────────────────────────────────────────────
const PAGES = ["home", "history", "contact", "login", "register", "profile"];

function navigate(page) {
  PAGES.forEach(p => {
    const el = $(`page-${p}`);
    if (el) el.classList.toggle("active", p === page);
  });
  document.querySelectorAll(".nav-link").forEach(a => {
    a.classList.toggle("active", a.dataset.page === page);
  });
  updateNav();

  // Lazy-load per page
  if (page === "history")   loadFullHistory();
  if (page === "profile")   loadProfile();
}

function updateNav() {
  const loggedIn = Auth.isLoggedIn();
  $("nav-login-item").classList.toggle("hidden",  loggedIn);
  $("nav-user-item").classList.toggle("hidden",  !loggedIn);
  $("nav-logout-item").classList.toggle("hidden", !loggedIn);

  if (loggedIn) {
    const u = Auth.username || "?";
    $("nav-username").textContent = u;
    $("nav-avatar").textContent   = u[0].toUpperCase();
  }
}

// Nav link clicks
document.querySelectorAll(".nav-link").forEach(a => {
  a.addEventListener("click", e => {
    e.preventDefault();
    navigate(a.dataset.page);
  });
});

$("brand-link").addEventListener("click", e => { e.preventDefault(); navigate("home"); });
$("footer-contact").addEventListener("click", e => { e.preventDefault(); navigate("contact"); });

$("go-register").addEventListener("click", e => { e.preventDefault(); navigate("register"); });
$("go-login").addEventListener("click",    e => { e.preventDefault(); navigate("login"); });

// Logout
function logout() {
  Auth.clear();
  toast("You have been logged out.", "info");
  updateNav();
  navigate("home");
  loadHistory(); // reload public history
}

$("logout-btn").addEventListener("click", logout);
$("profile-logout-btn").addEventListener("click", logout);

// Nav user pill → go to profile
$("nav-user-item").addEventListener("click", () => navigate("profile"));

// ─── Scan Result Rendering ────────────────────────────────────────────────────
function setFlag(id, value, goodWhenTrue) {
  const el = $(id);
  el.textContent = value ? "Yes" : "No";
  el.style.color = (value === goodWhenTrue) ? TONES.low : TONES.high;
}

function chipClass(level) {
  return level === "high" ? "chip chip-danger" : level === "medium" ? "chip chip-warn" : "chip chip-safe";
}

function renderResult(r) {
  const level = r.risk_level || levelOf(r.risk_score);
  const d = r.details || {};

  $("result-panel").classList.remove("hidden");
  $("result-panel").classList.add("fade-up");

  $("r-verdict").textContent = r.status === "Phishing" ? "⚠ Likely Phishing" : "✓ Looks Legitimate";
  $("r-verdict").style.color = TONES[level];

  const chip = $("r-chip");
  chip.textContent = level.toUpperCase();
  chip.className = chipClass(level);

  $("r-url").textContent = r.url;
  $("r-score").textContent = r.risk_score;
  $("r-score").style.color = TONES[level];

  const fill = $("gauge-fill");
  fill.style.width = r.risk_score + "%";
  fill.style.backgroundColor = TONES[level];

  setFlag("r-https", d.uses_https, true);
  setFlag("r-ip",    d.uses_ip_address, false);
  setFlag("r-at",    d.has_at_symbol, false);
  $("r-sub").textContent = d.subdomain_count ?? "—";
  $("r-len").textContent = (d.url_length ?? "—") + " chars";

  const kw = $("r-kw");
  kw.replaceChildren();
  if (!d.keywords_found?.length) {
    kw.textContent = "None";
    kw.style.color = TONES.low;
  } else {
    kw.style.color = "";
    d.keywords_found.forEach(k => {
      const s = document.createElement("span");
      s.className = "chip chip-danger";
      s.style.fontFamily = "JetBrains Mono, monospace";
      s.textContent = k;
      kw.appendChild(s);
    });
  }

  // Threat intel tiles
  const ti = r.threat_intel || {};
  renderThreatIntel(ti);

  // Signals
  const signals = $("r-signals");
  signals.replaceChildren();
  const list = d.signals?.length ? d.signals : ["No suspicious traits found."];
  list.forEach(s => {
    const li = document.createElement("li");
    li.className = "signal-item";
    const dot = document.createElement("span");
    dot.className = "signal-dot";
    li.appendChild(dot);
    li.appendChild(document.createTextNode(s));
    signals.appendChild(li);
  });
}

function renderThreatIntel(ti) {
  const grid = $("ti-grid");
  grid.replaceChildren();

  // VirusTotal
  const vt = ti.virustotal || {};
  grid.appendChild(makeTiCard("🦠", "VirusTotal",
    vt.available
      ? (vt.positives > 0
          ? `<span class="text-danger">⛔ ${vt.positives}/${vt.total} vendors flagged</span>`
          : `<span class="text-safe">✓ ${vt.total} vendors – clean</span>`)
      : `<span class="text-muted">${vt.reason || "Not available"}</span>`)
  );

  // Google Safe Browsing
  const sb = ti.safe_browsing || {};
  grid.appendChild(makeTiCard("🌐", "Safe Browsing",
    sb.available
      ? (sb.flagged
          ? `<span class="text-danger">⛔ ${sb.threats?.join(", ") || "Flagged"}</span>`
          : `<span class="text-safe">✓ Not flagged</span>`)
      : `<span class="text-muted">${sb.reason || "Not configured"}</span>`)
  );

  // Domain Age
  const age = ti.domain_age || {};
  grid.appendChild(makeTiCard("📅", "Domain Age",
    age.available
      ? (age.very_new
          ? `<span class="text-danger">⚠ Only ${age.age_days} days old</span>`
          : `<span class="text-safe">✓ ${age.age_days} days (${age.created})</span>`)
      : `<span class="text-muted">${age.reason || "Not available"}</span>`)
  );

  // Typosquatting
  const typo = ti.typosquatting || {};
  grid.appendChild(makeTiCard("🕵️", "Brand Impersonation",
    typo.available
      ? (typo.suspicious
          ? `<span class="text-danger">⚠ Resembles '${typo.match}' (dist=${typo.distance})</span>`
          : typo.match
            ? `<span class="text-warn">Near match: '${typo.match}' (dist=${typo.distance})</span>`
            : `<span class="text-safe">✓ No brand match</span>`)
      : `<span class="text-muted">${typo.reason || "Not available"}</span>`)
  );
}

function makeTiCard(icon, title, innerHTML) {
  const div = document.createElement("div");
  div.className = "ti-card";
  div.innerHTML = `<div class="ti-card-header"><span class="ti-icon">${icon}</span>${title}</div><div>${innerHTML}</div>`;
  return div;
}

// ─── URL Scan Form ────────────────────────────────────────────────────────────
$("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = $("url-input").value.trim();
  const status = $("scan-status");
  if (!url) { status.textContent = "Please enter a URL."; status.className = "status-msg err"; return; }

  $("scan-btn").disabled = true;
  $("scan-btn-text").textContent = "Analyzing…";
  $("scan-spinner").classList.remove("hidden");
  status.textContent = "Running threat intelligence checks…";
  status.className = "status-msg info";

  try {
    const result = await api("/api/scan", { method: "POST", body: JSON.stringify({ url }) });
    renderResult(result);
    status.textContent = "";
    loadHistory();
    toast(`Scan complete – Risk score: ${result.risk_score}/100`, result.risk_score >= 50 ? "err" : "ok");
  } catch (err) {
    status.textContent = err.message;
    status.className = "status-msg err";
  } finally {
    $("scan-btn").disabled = false;
    $("scan-btn-text").textContent = "Analyze";
    $("scan-spinner").classList.add("hidden");
  }
});

// ─── Email NLP Scan ───────────────────────────────────────────────────────────
$("email-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const raw     = $("email-body").value.trim();
  const subject = $("email-subject").value.trim();
  const status  = $("email-status");

  if (!raw) { status.textContent = "Paste an email body first."; status.className = "status-msg err"; return; }

  $("email-btn").disabled = true;
  $("email-btn-text").textContent = "Analysing…";
  $("email-spinner").classList.remove("hidden");
  status.textContent = "Scanning for phishing indicators…";
  status.className = "status-msg info";

  try {
    const r = await api("/api/email-scan", { method: "POST", body: JSON.stringify({ raw, subject }) });
    renderEmailResult(r);
    status.textContent = "";
    toast(`Email scan complete – ${r.status}`, r.risk_score >= 50 ? "err" : "ok");
  } catch (err) {
    status.textContent = err.message;
    status.className = "status-msg err";
  } finally {
    $("email-btn").disabled = false;
    $("email-btn-text").textContent = "Analyse Email";
    $("email-spinner").classList.add("hidden");
  }
});

function renderEmailResult(r) {
  $("email-result").classList.remove("hidden");
  $("email-result").classList.add("fade-up");

  const level = r.risk_level || levelOf(r.risk_score);
  $("er-verdict").textContent = r.status;
  $("er-verdict").style.color = TONES[level];
  $("er-chip").textContent = level.toUpperCase();
  $("er-chip").className = chipClass(level);
  $("er-score").textContent = r.risk_score;
  $("er-score").style.color = TONES[level];
  $("er-gauge").style.width = r.risk_score + "%";
  $("er-gauge").style.backgroundColor = TONES[level];

  const fmtBool = (v) => v === true
    ? '<span class="text-safe">✓ PASS</span>'
    : v === false
    ? '<span class="text-danger">✗ FAIL</span>'
    : '<span class="text-muted">Not found in headers</span>';

  $("er-spf").innerHTML  = fmtBool(r.spf_pass);
  $("er-dkim").innerHTML = fmtBool(r.dkim_pass);
  $("er-urls").textContent = r.url_count > 0 ? `${r.url_count} URL(s) detected` : "None found";

  const sig = $("er-signals");
  sig.replaceChildren();
  const list = r.signals?.length ? r.signals : ["No suspicious signals detected."];
  list.forEach(s => {
    const li = document.createElement("li");
    li.className = "signal-item";
    const dot = document.createElement("span");
    dot.className = "signal-dot";
    li.appendChild(dot);
    li.appendChild(document.createTextNode(s));
    sig.appendChild(li);
  });
}

// ─── History (recent scans on home page) ─────────────────────────────────────
function renderHistoryRow(r, tbody, full = false) {
  const level = levelOf(r.risk_score);
  const tr = document.createElement("tr");

  const cells = [];

  if (full) {
    cells.push({ text: r.id, cls: "text-muted text-sm" });
  }

  // URL
  const td_url = document.createElement("td");
  td_url.className = "mono text-sm truncate";
  td_url.style.maxWidth = "240px";
  td_url.textContent = r.url;
  td_url.title = r.url;
  tr.appendChild(td_url);

  // Score
  const td_score = document.createElement("td");
  td_score.style.color = TONES[level];
  td_score.style.fontWeight = "600";
  td_score.textContent = r.risk_score;
  tr.appendChild(td_score);

  // Verdict
  const td_v = document.createElement("td");
  const chip = document.createElement("span");
  chip.className = r.status === "Phishing" ? "chip chip-danger" : "chip chip-safe";
  chip.textContent = r.status;
  td_v.appendChild(chip);
  tr.appendChild(td_v);

  // VirusTotal
  const td_vt = document.createElement("td");
  if (r.vt_positives !== null && r.vt_positives !== undefined) {
    td_vt.innerHTML = r.vt_positives > 0
      ? `<span class="text-danger">${r.vt_positives}/${r.vt_total}</span>`
      : `<span class="text-safe">Clean</span>`;
  } else {
    td_vt.innerHTML = '<span class="text-muted">—</span>';
  }
  tr.appendChild(td_vt);

  // Domain age
  const td_age = document.createElement("td");
  if (r.whois_age_days !== null && r.whois_age_days !== undefined) {
    td_age.innerHTML = r.whois_age_days < 30
      ? `<span class="text-danger">⚠ ${r.whois_age_days}d</span>`
      : `<span class="text-safe">${r.whois_age_days}d</span>`;
  } else {
    td_age.innerHTML = '<span class="text-muted">—</span>';
  }
  tr.appendChild(td_age);

  if (full) {
    // Brand match
    const td_brand = document.createElement("td");
    td_brand.innerHTML = r.brand_match
      ? `<span class="text-warn">⚠ ${r.brand_match}</span>`
      : '<span class="text-muted">—</span>';
    tr.appendChild(td_brand);
  }

  // Timestamp
  const td_ts = document.createElement("td");
  td_ts.className = "text-muted text-sm";
  td_ts.textContent = new Date(r.timestamp).toLocaleString();
  tr.appendChild(td_ts);

  tbody.appendChild(tr);
}

async function loadHistory() {
  try {
    const rows = await api("/api/logs?limit=15");
    const body  = $("history-body");
    body.replaceChildren();
    $("history-empty").classList.toggle("hidden", rows.length > 0);
    rows.forEach(r => renderHistoryRow(r, body, false));
  } catch { /* silent */ }
}

async function loadFullHistory() {
  const body = $("full-history-body");
  body.replaceChildren();

  const loggedIn = Auth.isLoggedIn();
  $("history-auth-warning").classList.toggle("hidden", loggedIn);
  $("report-btns").classList.toggle("hidden", !loggedIn);

  try {
    const rows = await api("/api/logs?limit=50");
    $("full-history-empty").classList.toggle("hidden", rows.length > 0);
    rows.forEach(r => renderHistoryRow(r, body, true));
  } catch (err) {
    $("full-history-empty").textContent = "Failed to load history: " + err.message;
    $("full-history-empty").classList.remove("hidden");
  }
}

// ─── Chat ─────────────────────────────────────────────────────────────────────
function addBubble(text, type = "ai") {
  const div = document.createElement("div");
  div.className = `bubble bubble-${type}`;
  div.textContent = text;
  const log = $("chat-log");
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return div;
}

$("chat-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input   = $("chat-input");
  const message = input.value.trim();
  if (!message) return;
  input.value = "";
  addBubble(message, "me");
  const pending = addBubble("Thinking…", "ai");
  $("chat-btn").disabled = true;
  try {
    const { reply } = await api("/api/chat", { method: "POST", body: JSON.stringify({ message }) });
    pending.textContent = reply;
  } catch (err) {
    pending.textContent = err.message;
    pending.className = "bubble bubble-err";
  } finally {
    $("chat-btn").disabled = false;
    $("chat-log").scrollTop = $("chat-log").scrollHeight;
  }
});

// ─── Auth – Login ─────────────────────────────────────────────────────────────
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("login-username").value.trim();
  const password = $("login-password").value;
  const status   = $("login-status");

  if (!username || !password) {
    status.textContent = "Please fill in all fields.";
    return;
  }

  $("login-btn").disabled = true;
  $("login-btn-text").textContent = "Signing in…";
  $("login-spinner").classList.remove("hidden");
  status.textContent = "";

  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    Auth.save(data);
    toast(`Welcome back, ${data.username}!`, "ok");
    navigate("home");
    loadHistory();
  } catch (err) {
    status.textContent = err.message;
  } finally {
    $("login-btn").disabled = false;
    $("login-btn-text").textContent = "Sign In";
    $("login-spinner").classList.add("hidden");
  }
});

// ─── Auth – Register ──────────────────────────────────────────────────────────
// Live password strength indicator
$("reg-password").addEventListener("input", function () {
  const v = this.value;
  const req = $("pw-strength");
  const checks = [
    v.length >= 12,
    /[A-Z]/.test(v),
    /[a-z]/.test(v),
    /\d/.test(v),
    /[!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]/.test(v),
  ];
  const passed = checks.filter(Boolean).length;
  if (passed === 5) {
    req.textContent = "✓ Strong password";
    req.className = "pw-req satisfied";
  } else {
    const missing = [];
    if (!checks[0]) missing.push("≥12 chars");
    if (!checks[1]) missing.push("uppercase");
    if (!checks[2]) missing.push("lowercase");
    if (!checks[3]) missing.push("digit");
    if (!checks[4]) missing.push("special char");
    req.textContent = "Still needs: " + missing.join(", ");
    req.className = "pw-req";
  }
});

$("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("reg-username").value.trim();
  const email    = $("reg-email").value.trim();
  const password = $("reg-password").value;
  const confirm  = $("reg-confirm").value;
  const status   = $("reg-status");

  if (!username || !email || !password) {
    status.textContent = "Please fill in all fields.";
    return;
  }
  if (password !== confirm) {
    status.textContent = "Passwords do not match.";
    return;
  }

  $("reg-btn").disabled = true;
  $("reg-btn-text").textContent = "Creating account…";
  $("reg-spinner").classList.remove("hidden");
  status.textContent = "";

  try {
    const data = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password }),
    });
    Auth.save(data);
    toast(`Account created! Welcome, ${data.username}!`, "ok");
    navigate("home");
    loadHistory();
  } catch (err) {
    status.textContent = err.message;
  } finally {
    $("reg-btn").disabled = false;
    $("reg-btn-text").textContent = "Create Account";
    $("reg-spinner").classList.add("hidden");
  }
});

// ─── Profile Page ─────────────────────────────────────────────────────────────
async function loadProfile() {
  if (!Auth.isLoggedIn()) { navigate("login"); return; }
  try {
    const me = await api("/api/auth/me");
    const initial = me.username[0].toUpperCase();
    $("profile-avatar").textContent  = initial;
    $("profile-username").textContent = me.username;
    $("profile-role").textContent     = me.role.toUpperCase();
    $("profile-uname").textContent    = me.username;
    $("profile-email").textContent    = me.email;
    $("profile-created").textContent  = new Date(me.created_at).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
    $("profile-last-login").textContent = me.last_login
      ? new Date(me.last_login).toLocaleString()
      : "First login";
  } catch (err) {
    toast("Failed to load profile: " + err.message, "err");
  }
}

// Nav user pill navigates to profile
$("nav-user-item").style.cursor = "pointer";

// ─── Change Password ─────────────────────────────────────────────────────────
$("change-pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const old_password = $("cp-old").value;
  const new_password = $("cp-new").value;
  const status = $("cp-status");

  $("cp-btn").disabled = true;
  status.textContent = "";
  try {
    await api("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ old_password, new_password }),
    });
    status.textContent = "✓ Password changed successfully!";
    status.className = "status-msg ok";
    $("cp-old").value = "";
    $("cp-new").value = "";
    toast("Password updated successfully.", "ok");
  } catch (err) {
    status.textContent = err.message;
    status.className = "status-msg err";
  } finally {
    $("cp-btn").disabled = false;
  }
});

// ─── Reports ─────────────────────────────────────────────────────────────────
function downloadReport(url, filename) {
  if (!Auth.isLoggedIn()) {
    toast("Please sign in to download reports.", "err");
    navigate("login");
    return;
  }
  // Fetch with auth header, then trigger download
  fetch(url, { headers: { Authorization: "Bearer " + Auth.token } })
    .then(res => {
      if (!res.ok) throw new Error("Download failed");
      return res.blob();
    })
    .then(blob => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
      URL.revokeObjectURL(a.href);
      toast("Report downloaded.", "ok");
    })
    .catch(err => toast("Download failed: " + err.message, "err"));
}

$("csv-btn").addEventListener("click", () => downloadReport("/api/report/csv?limit=200", "tripwire_report.csv"));
$("pdf-btn").addEventListener("click", () => downloadReport("/api/report/pdf?limit=200", "tripwire_report.pdf"));

// ─── Contact Form ─────────────────────────────────────────────────────────────
$("contact-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = $("contact-status");
  // Simulate send (no backend endpoint – static demo)
  $("contact-btn").disabled = true;
  status.textContent = "Sending…";
  status.className = "status-msg info";
  await new Promise(r => setTimeout(r, 1000));
  $("contact-btn").disabled = false;
  $("contact-form").reset();
  status.textContent = "✓ Message sent! We'll get back to you within 24-48 hours.";
  status.className = "status-msg ok";
  toast("Message sent!", "ok");
});

// ─── Init ─────────────────────────────────────────────────────────────────────
updateNav();
loadHistory();

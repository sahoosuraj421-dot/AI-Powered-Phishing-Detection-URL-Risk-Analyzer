const $ = (id) => document.getElementById(id);
const TONES = { low: "#10b981", medium: "#f59e0b", high: "#ef4444" };

async function api(path, options = {}) {
  const token = localStorage.getItem("token");
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(path, { headers, ...options });
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON body */ }
  if (!res.ok) {
    let msg = "Something went wrong. Try again.";
    if (res.status === 429) msg = "Too many requests. Wait a minute, then try again.";
    else if (typeof data?.detail === "string") msg = data.detail;
    else if (Array.isArray(data?.detail)) msg = data.detail[0]?.msg?.replace(/^Value error, /, "") || msg;
    throw new Error(msg);
  }
  return data;
}

const levelOf = (score) => (score >= 50 ? "high" : score >= 30 ? "medium" : "low");

function setFlag(id, value, goodWhenTrue) {
  const el = $(id);
  el.textContent = value ? "Yes" : "No";
  el.style.color = value === goodWhenTrue ? TONES.low : TONES.high;
}

// ─── Threat Intelligence cards ────────────────────────────────────────────────
function renderThreatIntel(intel) {
  const grid = $("ti-grid");
  grid.replaceChildren();

  function card(icon, title, body, danger) {
    const el = document.createElement("div");
    el.className = "ti-card" + (danger ? " border-danger" : "");
    el.innerHTML = `<div class="ti-card-header"><span class="ti-icon">${icon}</span> ${title}</div>
      <span style="color:${danger ? TONES.high : TONES.low}; font-weight:700;">${body}</span>`;
    grid.appendChild(el);
  }

  const vt = intel?.virustotal;
  if (vt?.available) {
    card("🦠", "VirusTotal", `${vt.positives}/${vt.total} vendors flagged`, vt.positives > 0);
  } else {
    card("🦠", "VirusTotal", "Clean / Not configured", false);
  }

  const sb = intel?.safe_browsing;
  if (sb?.available) {
    card("🛡", "Safe Browsing", sb.flagged ? sb.threats.join(", ") : "Clean", sb.flagged);
  } else {
    card("🛡", "Safe Browsing", "Not configured", false);
  }

  const age = intel?.domain_age;
  if (age?.available) {
    card("📅", "Domain Age", `${age.age_days} days (${age.created})`, age.very_new);
  } else {
    card("📅", "Domain Age", "Established domain", false);
  }

  const typo = intel?.typosquatting;
  if (typo?.available && typo?.suspicious) {
    card("🕵️", "Typosquatting", `Impersonating '${typo.match}' (dist=${typo.distance})`, true);
  } else {
    card("🕵️", "Typosquatting", "No brand match", false);
  }
}

function renderResult(r) {
  const level = r.risk_level || levelOf(r.risk_score);
  const d = r.details;
  const panel = $("result-panel");
  panel.classList.remove("hidden");

  // Prominently highlight suspicious / phishing content
  if (level === "high" || r.status === "Phishing") {
    panel.classList.add("suspicious-highlight");
  } else {
    panel.classList.remove("suspicious-highlight");
  }

  $("r-verdict").textContent = r.status === "Phishing" ? "⚠️ CRITICAL: LIKELY PHISHING DETECTED" : "✅ LOOKS LEGITIMATE";
  $("r-verdict").style.color = TONES[level];
  $("r-url").textContent = r.url;
  $("r-score").textContent = r.risk_score;
  $("r-score").style.color = TONES[level];
  $("gauge-fill").style.width = r.risk_score + "%";
  $("gauge-fill").style.backgroundColor = TONES[level];
  
  const chip = $("r-chip");
  chip.textContent = level.toUpperCase() + " RISK";
  chip.className = "chip chip-" + level;
  setFlag("r-https", d.uses_https, true);
  setFlag("r-ip", d.uses_ip_address, false);
  setFlag("r-at", d.has_at_symbol, false);
  $("r-sub").textContent = d.subdomain_count;
  $("r-len").textContent = d.url_length + " characters";

  const kw = $("r-kw");
  kw.replaceChildren();
  if (!d.keywords_found.length) {
    kw.textContent = "None";
    kw.style.color = TONES.low;
  } else {
    kw.style.color = "";
    d.keywords_found.forEach((k) => {
      const chip = document.createElement("span");
      chip.className = "keyword-highlight mono text-xs";
      chip.textContent = k;
      kw.appendChild(chip);
    });
  }

  const list = $("r-signals");
  list.replaceChildren();
  (d.signals.length ? d.signals : ["No suspicious traits found."]).forEach((s) => {
    const li = document.createElement("li");
    li.className = (level === "high" || level === "medium") ? "signal-item-danger" : "signal-item";
    li.textContent = "• " + s;
    list.appendChild(li);
  });

  renderThreatIntel(r.threat_intel);
}

// ─── History rendering ────────────────────────────────────────────────────────
function renderHistory(rows) {
  const body = $("history-body");
  body.replaceChildren();
  $("history-empty").classList.toggle("hidden", rows.length > 0);
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    const level = levelOf(r.risk_score);
    const vt = (r.vt_positives != null && r.vt_total != null)
      ? `${r.vt_positives}/${r.vt_total}`
      : "—";
    const age = r.whois_age_days != null ? `${r.whois_age_days}d` : "—";
    const cols = [
      { text: r.url,  cls: "mono text-xs max-w-[260px] truncate", title: r.url },
      { text: r.risk_score, color: TONES[level], cls: "font-bold" },
      { text: r.status, color: TONES[level], cls: "font-bold" },
      { text: vt },
      { text: age },
      { text: new Date(r.timestamp).toLocaleString(), cls: "whitespace-nowrap" },
    ];
    cols.forEach(({ text, cls, title, color }) => {
      const td = document.createElement("td");
      td.className = "py-2 pr-4 " + (cls || "whitespace-nowrap");
      td.textContent = text;
      if (title) td.title = title;
      if (color) td.style.color = color;
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
}

// ─── Full history page ────────────────────────────────────────────────────────
function renderFullHistory(rows) {
  const body = $("full-history-body");
  if (!body) return;
  body.replaceChildren();
  const empty = $("full-history-empty");
  if (empty) empty.classList.toggle("hidden", rows.length > 0);
  rows.forEach((r, i) => {
    const tr = document.createElement("tr");
    const level = levelOf(r.risk_score);
    const vt = (r.vt_positives != null && r.vt_total != null)
      ? `${r.vt_positives}/${r.vt_total}`
      : "—";
    const age = r.whois_age_days != null ? `${r.whois_age_days}d` : "—";
    const brand = r.brand_match || "—";
    const cols = [
      { text: i + 1 },
      { text: r.url, cls: "mono text-xs max-w-[260px] truncate", title: r.url },
      { text: r.risk_score, color: TONES[level], cls: "font-bold" },
      { text: r.status, color: TONES[level], cls: "font-bold" },
      { text: vt },
      { text: age },
      { text: brand },
      { text: new Date(r.timestamp).toLocaleString(), cls: "whitespace-nowrap" },
    ];
    cols.forEach(({ text, cls, title, color }) => {
      const td = document.createElement("td");
      td.className = "py-2 pr-4 " + (cls || "whitespace-nowrap");
      td.textContent = text;
      if (title) td.title = title;
      if (color) td.style.color = color;
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
}

async function loadHistory() {
  try {
    const rows = await api("/api/logs?limit=25");
    renderHistory(rows);
    renderFullHistory(rows);
  } catch { /* ignored */ }
}

// ─── Auth state ───────────────────────────────────────────────────────────────
let currentUser = null;

function getToken() { return localStorage.getItem("token"); }
function setToken(t) { localStorage.setItem("token", t); }
function clearToken() { localStorage.removeItem("token"); currentUser = null; }

function updateAuthUI(user) {
  currentUser = user;
  const loggedIn = !!user;
  $("nav-login-item").classList.toggle("hidden", loggedIn);
  $("nav-user-item").classList.toggle("hidden", !loggedIn);
  $("nav-logout-item").classList.toggle("hidden", !loggedIn);
  
  // Show Admin link only for Admin role
  const isAdmin = user && user.role === "admin";
  const navAdmin = $("nav-admin-item");
  if (navAdmin) navAdmin.classList.toggle("hidden", !isAdmin);

  const warn = $("history-auth-warning");
  if (warn) warn.classList.toggle("hidden", loggedIn);
  if (user) {
    const avatar = (user.username || "?")[0].toUpperCase();
    $("nav-avatar").textContent = avatar;
    $("nav-username").textContent = user.username + (isAdmin ? " (Admin)" : "");
  }
}

async function tryRestoreSession() {
  if (!getToken()) { updateAuthUI(null); return; }
  try {
    const user = await api("/api/auth/me");
    updateAuthUI(user);
  } catch {
    clearToken();
    updateAuthUI(null);
  }
}

// ─── Navigation ───────────────────────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
  const page = $("page-" + name);
  if (page) page.classList.add("active");
  document.querySelectorAll(".nav-link").forEach((a) => {
    a.classList.toggle("active", a.dataset.page === name);
  });
  if (name === "history") loadHistory();
  if (name === "profile") loadProfile();
  if (name === "admin") loadAdminPortal();
}

document.querySelectorAll(".nav-link").forEach((a) => {
  a.addEventListener("click", (e) => {
    e.preventDefault();
    showPage(a.dataset.page);
  });
});

$("brand-link").addEventListener("click", (e) => { e.preventDefault(); showPage("home"); });
$("footer-contact") && $("footer-contact").addEventListener("click", (e) => { e.preventDefault(); showPage("contact"); });
$("nav-user-item") && $("nav-user-item").addEventListener("click", () => showPage("profile"));

// ─── URL Scan ─────────────────────────────────────────────────────────────────
$("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = $("url-input").value.trim();
  const statusEl = $("scan-status");
  if (!url) { statusEl.textContent = "Enter a link to analyze."; return; }
  $("scan-btn").disabled = true;
  $("scan-spinner").classList.remove("hidden");
  $("scan-btn-text").textContent = "Analyzing…";
  statusEl.textContent = "";
  try {
    renderResult(await api("/api/scan", { method: "POST", body: JSON.stringify({ url }) }));
    loadHistory();
  } catch (err) {
    statusEl.textContent = err.message;
    statusEl.className = "status-msg err";
  } finally {
    $("scan-btn").disabled = false;
    $("scan-spinner").classList.add("hidden");
    $("scan-btn-text").textContent = "Analyze";
  }
});

// ─── Email Scan ───────────────────────────────────────────────────────────────
$("email-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const raw = $("email-body").value.trim();
  const subject = $("email-subject").value.trim();
  const statusEl = $("email-status");
  if (!raw) { statusEl.textContent = "Paste an email body first."; return; }
  $("email-btn").disabled = true;
  $("email-spinner").classList.remove("hidden");
  $("email-btn-text").textContent = "Analysing…";
  statusEl.textContent = "";
  try {
    const r = await api("/api/email-scan", { method: "POST", body: JSON.stringify({ raw, subject }) });
    const level = r.risk_level || levelOf(r.risk_score);
    const res = $("email-result");
    res.classList.remove("hidden");

    if (level === "high" || r.status === "Phishing") {
      res.classList.add("suspicious-highlight");
    } else {
      res.classList.remove("suspicious-highlight");
    }

    $("er-verdict").textContent = (r.status === "Phishing" ? "⚠️ PHISHING DETECTED" : "✅ " + r.status.toUpperCase());
    $("er-verdict").style.color = TONES[level];
    $("er-chip").textContent = level.toUpperCase() + " RISK";
    $("er-chip").className = "chip chip-" + level;
    $("er-score").textContent = r.risk_score;
    $("er-score").style.color = TONES[level];
    $("er-gauge").style.width = r.risk_score + "%";
    $("er-gauge").style.backgroundColor = TONES[level];
    $("er-spf").textContent = r.spf_pass == null ? "—" : r.spf_pass ? "✅ Pass" : "❌ Fail";
    $("er-dkim").textContent = r.dkim_pass == null ? "—" : r.dkim_pass ? "✅ Pass" : "❌ Fail";
    $("er-urls").textContent = r.url_count;
    const sigList = $("er-signals");
    sigList.replaceChildren();
    (r.signals.length ? r.signals : ["No suspicious signals detected."]).forEach((s) => {
      const li = document.createElement("li");
      li.className = (level === "high" || level === "medium") ? "signal-item-danger" : "signal-item";
      li.textContent = "• " + s;
      sigList.appendChild(li);
    });
  } catch (err) {
    statusEl.textContent = err.message;
    statusEl.className = "status-msg err";
  } finally {
    $("email-btn").disabled = false;
    $("email-spinner").classList.add("hidden");
    $("email-btn-text").textContent = "Analyse Email";
  }
});

// ─── AI Chat ──────────────────────────────────────────────────────────────────
function addBubble(text, mine) {
  const div = document.createElement("div");
  div.className = "bubble " + (mine ? "bubble-me" : "bubble-ai");
  div.textContent = text;
  $("chat-log").appendChild(div);
  $("chat-log").scrollTop = $("chat-log").scrollHeight;
  return div;
}

$("chat-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("chat-input");
  const message = input.value.trim();
  if (!message) return;
  input.value = "";
  addBubble(message, true);
  const pending = addBubble("Analyzing context…", false);
  $("chat-btn").disabled = true;
  try {
    const { reply } = await api("/api/chat", { method: "POST", body: JSON.stringify({ message }) });
    pending.textContent = reply;
  } catch (err) {
    pending.textContent = err.message;
    pending.style.color = TONES.high;
  } finally {
    $("chat-btn").disabled = false;
    $("chat-log").scrollTop = $("chat-log").scrollHeight;
  }
});

// ─── 2 Role Logins Pre-fill Helpers ───────────────────────────────────────────
$("btn-demo-admin") && $("btn-demo-admin").addEventListener("click", () => {
  $("login-username").value = "admin";
  $("login-password").value = "Admin@Tripwire2026!";
  $("btn-demo-admin").classList.add("active");
  $("btn-demo-user").classList.remove("active");
});

$("btn-demo-user") && $("btn-demo-user").addEventListener("click", () => {
  $("login-username").value = "user";
  $("login-password").value = "User@Tripwire2026!";
  $("btn-demo-user").classList.add("active");
  $("btn-demo-admin").classList.remove("active");
});

// ─── Auth forms ───────────────────────────────────────────────────────────────
$("login-form") && $("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("login-username").value.trim();
  const password = $("login-password").value;
  const statusEl = $("login-status");
  $("login-btn").disabled = true;
  $("login-spinner").classList.remove("hidden");
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    setToken(data.access_token);
    const profile = await api("/api/auth/me");
    updateAuthUI(profile);
    if (profile.role === "admin") {
      showPage("admin");
    } else {
      showPage("home");
    }
  } catch (err) {
    statusEl.textContent = err.message;
  } finally {
    $("login-btn").disabled = false;
    $("login-spinner").classList.add("hidden");
  }
});

$("register-form") && $("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("reg-username").value.trim();
  const email = $("reg-email").value.trim();
  const password = $("reg-password").value;
  const confirm = $("reg-confirm").value;
  const statusEl = $("reg-status");
  if (password !== confirm) { statusEl.textContent = "Passwords do not match."; return; }
  $("reg-btn").disabled = true;
  $("reg-spinner").classList.remove("hidden");
  try {
    const data = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password }),
    });
    setToken(data.access_token);
    const profile = await api("/api/auth/me");
    updateAuthUI(profile);
    showPage("home");
  } catch (err) {
    statusEl.textContent = err.message;
  } finally {
    $("reg-btn").disabled = false;
    $("reg-spinner").classList.add("hidden");
  }
});

$("go-register") && $("go-register").addEventListener("click", (e) => { e.preventDefault(); showPage("register"); });
$("go-login") && $("go-login").addEventListener("click", (e) => { e.preventDefault(); showPage("login"); });

function doLogout() {
  clearToken();
  updateAuthUI(null);
  showPage("home");
}
$("logout-btn") && $("logout-btn").addEventListener("click", doLogout);
$("profile-logout-btn") && $("profile-logout-btn").addEventListener("click", doLogout);

// ─── Profile page ─────────────────────────────────────────────────────────────
async function loadProfile() {
  if (!getToken()) return;
  try {
    const u = await api("/api/auth/me");
    const avatar = (u.username || "?")[0].toUpperCase();
    $("profile-avatar").textContent = avatar;
    $("profile-username").textContent = u.username;
    $("profile-role").textContent = u.role.toUpperCase();
    $("profile-uname").textContent = u.username;
    $("profile-email").textContent = u.email;
    $("profile-created").textContent = new Date(u.created_at).toLocaleDateString();
    $("profile-last-login").textContent = u.last_login
      ? new Date(u.last_login).toLocaleString() : "—";
  } catch { /* token may have expired */ }
}

$("change-pw-form") && $("change-pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const old_password = $("cp-old").value;
  const new_password = $("cp-new").value;
  const statusEl = $("cp-status");
  $("cp-btn").disabled = true;
  try {
    const res = await api("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ old_password, new_password }),
    });
    statusEl.textContent = res.detail || "Password changed.";
    statusEl.className = "status-msg ok mt-2";
    $("cp-old").value = "";
    $("cp-new").value = "";
  } catch (err) {
    statusEl.textContent = err.message;
    statusEl.className = "status-msg err mt-2";
  } finally {
    $("cp-btn").disabled = false;
  }
});

// ─── Admin Portal Logic ───────────────────────────────────────────────────────
async function loadAdminPortal() {
  if (!currentUser || currentUser.role !== "admin") {
    alert("Access restricted to administrators.");
    showPage("home");
    return;
  }
  try {
    const users = await api("/api/admin/users");
    const uBody = $("admin-users-body");
    uBody.replaceChildren();
    users.forEach((u) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${u.id}</td>
        <td class="font-bold">${u.username}</td>
        <td>${u.email}</td>
        <td><span class="chip ${u.role === 'admin' ? 'chip-info' : 'chip-safe'}">${u.role}</span></td>
        <td><span style="color:${u.is_active ? TONES.low : TONES.high}; font-weight:700;">${u.is_active ? 'Active' : 'Disabled'}</span></td>
        <td>${new Date(u.created_at).toLocaleDateString()}</td>
        <td>
          ${u.id !== currentUser.id ? `<button class="admin-action-btn" onclick="toggleUser(${u.id})">${u.is_active ? 'Disable' : 'Enable'}</button>` : '<em>Self</em>'}
        </td>
      `;
      uBody.appendChild(tr);
    });

    const scans = await api("/api/logs?limit=50");
    const sBody = $("admin-scans-body");
    sBody.replaceChildren();
    scans.forEach((s) => {
      const tr = document.createElement("tr");
      const level = levelOf(s.risk_score);
      tr.innerHTML = `
        <td>#${s.id}</td>
        <td class="mono text-xs max-w-[260px] truncate" title="${s.url}">${s.url}</td>
        <td style="color:${TONES[level]}; font-weight:bold;">${s.risk_score}</td>
        <td><span class="chip chip-${level}">${s.status}</span></td>
        <td>User #${s.user_id || 'Anon'}</td>
        <td class="whitespace-nowrap">${new Date(s.timestamp).toLocaleString()}</td>
        <td><button class="admin-action-btn text-danger" onclick="deleteScan(${s.id})">Delete</button></td>
      `;
      sBody.appendChild(tr);
    });
  } catch (err) {
    alert(err.message);
  }
}

window.toggleUser = async (userId) => {
  try {
    const res = await api(`/api/admin/users/${userId}/toggle-status`, { method: "POST" });
    alert(res.detail);
    loadAdminPortal();
  } catch (err) { alert(err.message); }
};

window.deleteScan = async (scanId) => {
  if (!confirm(`Delete scan #${scanId}?`)) return;
  try {
    const res = await api(`/api/admin/scans/${scanId}`, { method: "DELETE" });
    alert(res.detail);
    loadAdminPortal();
    loadHistory();
  } catch (err) { alert(err.message); }
};

// ─── Report downloads ─────────────────────────────────────────────────────────
async function downloadReport(path, filename) {
  const token = getToken();
  if (!token) {
    alert("Please sign in to download reports.");
    showPage("login");
    return;
  }
  try {
    const res = await fetch(path, {
      headers: { Authorization: "Bearer " + token },
    });
    if (!res.ok) {
      let errText = "Failed to download report.";
      try {
        const errJson = await res.json();
        errText = errJson.detail || errText;
      } catch {}
      alert(errText);
      return;
    }
    const blob = await res.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(blobUrl);
  } catch (err) {
    alert("Download error: " + err.message);
  }
}

$("csv-btn") && $("csv-btn").addEventListener("click", () => downloadReport("/api/report/csv", "tripwire_report.csv"));
$("pdf-btn") && $("pdf-btn").addEventListener("click", () => downloadReport("/api/report/pdf", "tripwire_report.pdf"));

// ─── Contact form ─────────────────────────────────────────────────────────────
$("contact-form") && $("contact-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const statusEl = $("contact-status");
  statusEl.textContent = "Message sent! We will get back to you within 24 hours.";
  statusEl.className = "status-msg ok mt-2";
  $("contact-form").reset();
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
tryRestoreSession();
loadHistory();

const $ = (s) => document.querySelector(s);

let csrfToken = null;
let currentUser = null;
let activeView = "overview";
let accPage = 1;
let studioPage = 1;
let secPage = 1;
let auditPage = 1;
let searchTimers = {};

function esc(value = "") {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

function formatMb(bytes) {
  return `${((bytes || 0) / (1024 * 1024)).toFixed(1)} MB`;
}

function roleBadge(role) {
  if (role === "super_admin") return '<span class="badge super">super_admin</span>';
  if (role === "studio_staff") return '<span class="badge neutral">studio_staff</span>';
  return '<span class="badge">studio_owner</span>';
}

function statusBadge(status) {
  if (status === "suspended") return '<span class="badge warn">suspended</span>';
  if (status === "deleted") return '<span class="badge danger">deleted</span>';
  return '<span class="badge">active</span>';
}

function plural(count, singular, pluralWord = `${singular}s`) {
  return count === 1 ? singular : pluralWord;
}

function securityEventBadge(eventType, success) {
  const type = String(eventType || "");
  if (!success || /(deleted|revoked|failed)/.test(type)) {
    return `<span class="badge danger">${esc(type)}</span>`;
  }
  if (/(suspended|reset|suspicious|force_password)/.test(type)) {
    return `<span class="badge warn">${esc(type)}</span>`;
  }
  return `<span class="badge">${esc(type)}</span>`;
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(url, {
    ...options,
    method,
    headers,
    credentials: "same-origin",
  });
  const data = await response.json().catch(() => ({}));
  if (
    response.status === 401 &&
    url.startsWith("/api/super-admin/") &&
    !url.startsWith("/api/super-admin/setup/")
  ) {
    document.querySelectorAll("dialog[open]").forEach((dlg) => dlg.close());
    currentUser = null;
    showGateError(data.error || "Session expired. Please sign in again.");
    if (!window.__saBooting) {
      window.__saBooting = true;
      boot()
        .catch(() => {})
        .finally(() => {
          window.__saBooting = false;
        });
    }
  }
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function setGlobalMsg(text, isError = false) {
  const el = $("#saGlobalMsg");
  el.textContent = text;
  el.className = isError ? "error" : "success-msg";
}

function setTableLoading(wrapSelector, label = "Loading…") {
  const el = $(wrapSelector);
  if (el) el.innerHTML = `<div class="empty-card">${esc(label)}</div>`;
}

function setTableError(wrapSelector, err, retryFn) {
  const msg = err?.message || "Failed to load data.";
  setGlobalMsg(msg, true);
  const el = $(wrapSelector);
  if (!el) return;
  el.innerHTML = `<div class="empty-card"><p class="error">${esc(msg)}</p><button class="btn sm ghost" type="button" data-retry-load>Retry</button></div>`;
  const btn = el.querySelector("[data-retry-load]");
  if (btn && retryFn) {
    btn.onclick = () => retryFn().catch(() => {});
  }
}

function showGateError(text) {
  $("#gateError").textContent = text || "";
}

function resetGateForms() {
  [
    "#setupInitForm",
    "#setupConfirmForm",
    "#setupRecoveryBox",
    "#saLoginForm",
    "#saMfaForm",
    "#accessDeniedBox",
  ].forEach((sel) => $(sel)?.classList.add("hidden"));
}

async function boot() {
  const meData = await api("/api/auth/me");
  const setupStatus = await api("/api/super-admin/setup/status");
  csrfToken = meData.csrfToken || setupStatus.csrfToken;
  currentUser = meData.user;
  resetGateForms();

  if (currentUser && currentUser.role !== "super_admin") {
    $("#portalGate").classList.remove("hidden");
    $("#consoleShell").classList.add("hidden");
    $("#gateTitle").textContent = "Restricted Area";
    $("#accessDeniedBox").classList.remove("hidden");
    return;
  }

  if (setupStatus.needsSetup) {
    $("#portalGate").classList.remove("hidden");
    $("#consoleShell").classList.add("hidden");
    $("#gateTitle").textContent = "Initialize Super Admin";
    $("#gateSubtitle").textContent = setupStatus.setupTokenConfigured
      ? "Controlled initial setup using SUPER_ADMIN_SETUP_TOKEN."
      : "Set SUPER_ADMIN_SETUP_TOKEN in .env or run `npm run setup:super-admin` in the terminal.";
    $("#setupInitForm").classList.remove("hidden");
    return;
  }

  if (meData.pendingMfa) {
    $("#portalGate").classList.remove("hidden");
    $("#consoleShell").classList.add("hidden");
    $("#gateTitle").textContent = "Two-Factor Verification";
    $("#saMfaForm").classList.remove("hidden");
    return;
  }

  if (!currentUser) {
    $("#portalGate").classList.remove("hidden");
    $("#consoleShell").classList.add("hidden");
    $("#gateTitle").textContent = "Super Admin Sign In";
    $("#saLoginForm").classList.remove("hidden");
    return;
  }

  $("#portalGate").classList.add("hidden");
  $("#consoleShell").classList.remove("hidden");
  $("#saSideEmail").textContent = currentUser.email;
  const hashView = location.hash.replace(/^#/, "");
  const initialView = VIEW_META[hashView] ? hashView : "overview";
  await switchView(initialView);
}

// Initial Super Admin Setup Handlers
$("#setupInitForm").onsubmit = async (e) => {
  e.preventDefault();
  showGateError("");
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    const res = await api("/api/super-admin/setup/init", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    $("#setupInitForm").classList.add("hidden");
    $("#setupQrImg").src = res.qr;
    $("#setupSecretText").textContent = res.secret;
    $("#setupConfirmForm").classList.remove("hidden");
  } catch (err) {
    showGateError(err.message);
  }
};

$("#setupConfirmForm").onsubmit = async (e) => {
  e.preventDefault();
  showGateError("");
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    const res = await api("/api/super-admin/setup/confirm", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    csrfToken = res.csrfToken;
    $("#setupConfirmForm").classList.add("hidden");
    $("#setupRecoveryGrid").innerHTML = res.recoveryCodes
      .map((c) => `<code>${esc(c)}</code>`)
      .join("");
    $("#setupRecoveryBox").classList.remove("hidden");
  } catch (err) {
    showGateError(err.message);
  }
};

$("#enterConsoleBtn").onclick = () => boot();

// Super Admin Login & MFA
$("#saLoginForm").onsubmit = async (e) => {
  e.preventDefault();
  showGateError("");
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    const res = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res.csrfToken) csrfToken = res.csrfToken;
    if (res.mfaRequired) {
      $("#saLoginForm").classList.add("hidden");
      $("#saMfaForm").classList.remove("hidden");
      $("#gateTitle").textContent = "Two-Factor Verification";
      return;
    }
    await boot();
  } catch (err) {
    showGateError(err.message);
  }
};

$("#saMfaForm").onsubmit = async (e) => {
  e.preventDefault();
  showGateError("");
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    const res = await api("/api/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res.csrfToken) csrfToken = res.csrfToken;
    $("#saMfaForm").classList.add("hidden");
    await boot();
  } catch (err) {
    showGateError(err.message);
  }
};

$("#deniedSignOutBtn").onclick = async () => {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    // ignore logout error during sign-out transition
  }
  location.reload();
};

async function performSaLogout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    // ignore logout error during sign-out transition
  }
  location.href = "/super-admin.html";
}

$("#saLogoutBtn").onclick = performSaLogout;
$("#saTopLogoutBtn").onclick = performSaLogout;

// Navigation
const VIEW_META = {
  overview: ["Platform overview", "Account lifecycle, multi-tenant studios, security telemetry, and immutable auditing."],
  accounts: ["Account management", "Search, create, edit, suspend, delete, reset passwords, and revoke sessions."],
  studios: ["Business & studio management", "Inspect studios, quotas, plans, owners, and suspend/activate tenants."],
  security: ["Login & security monitoring", "Authentication attempts, suspicious activity, IPs, and device/browser telemetry."],
  sessions: ["Active sessions", "Monitor currently authenticated devices and force-revoke sessions."],
  audit: ["Immutable audit logs", "Every privileged Super Admin action and platform change."],
};

async function switchView(view) {
  activeView = view;
  if (location.hash !== `#${view}` && history.replaceState) {
    history.replaceState(null, "", `#${view}`);
  }
  document.querySelectorAll("[data-sa-view]").forEach((el) => {
    el.classList.toggle("active", el.dataset.saView === view);
  });
  document.querySelectorAll(".sa-view, .dash-view").forEach((sec) => {
    sec.classList.toggle("hidden", sec.id !== `view-${view}`);
  });
  const [title, sub] = VIEW_META[view] || ["Super Admin", ""];
  $("#saViewTitle").textContent = title;
  $("#saViewSubtitle").textContent = sub;
  setGlobalMsg("");

  if (view === "overview") await loadOverview();
  else if (view === "accounts") await loadAccounts();
  else if (view === "studios") await loadStudios();
  else if (view === "security") await loadSecurity();
  else if (view === "sessions") await loadSessions();
  else if (view === "audit") await loadAuditLogs();
}

document.querySelectorAll("[data-sa-view]").forEach((link) => {
  link.onclick = (e) => {
    e.preventDefault();
    switchView(link.dataset.saView).catch((err) => setGlobalMsg(err.message, true));
  };
});

// Overview
async function loadOverview() {
  const d = await api("/api/super-admin/overview");
  const ownerWord = d.accounts.studio_owners === 1 ? "owner" : "owners";
  const sessionWord = d.sessions.active_sessions === 1 ? "active session" : "active sessions";
  $("#overviewKpis").innerHTML = `
    <div class="kpi-card"><span>Total accounts</span><b>${d.accounts.total}</b><small>${d.accounts.new_registrations_7d} new in 7d</small></div>
    <div class="kpi-card"><span>Active accounts</span><b>${d.accounts.active}</b><small>${d.accounts.studio_owners} ${ownerWord} · ${d.accounts.studio_staff} staff</small></div>
    <div class="kpi-card"><span>Suspended / Deleted</span><b>${d.accounts.suspended} / ${d.accounts.deleted}</b><small>Restricted or wiped</small></div>
    <div class="kpi-card"><span>Online users</span><b>${d.sessions.online_users}</b><small>${d.sessions.active_sessions} ${sessionWord}</small></div>
    <div class="kpi-card"><span>Total logins</span><b>${d.security.total_logins}</b><small>Successful sign-ins</small></div>
    <div class="kpi-card"><span>Failed / Suspicious</span><b>${d.security.failed_logins} / ${d.security.suspicious_events}</b><small>Security alerts</small></div>
    <div class="kpi-card"><span>Studios</span><b>${d.studios.total}</b><small>${d.studios.active} active · ${d.studios.suspended} suspended</small></div>
    <div class="kpi-card"><span>Platform media</span><b>${d.studios.total_photos}</b><small>${d.studios.total_events} ${plural(d.studios.total_events, "event")} · ${formatMb(d.studios.total_storage_bytes)}</small></div>
  `;

  $("#lastRegisteredWrap").innerHTML = `
    <table>
      <tr><th>Name</th><th>Email</th><th>Role</th><th>Studio</th><th>Registered</th></tr>
      ${d.last_registered
        .map(
          (u) => `
          <tr>
            <td>${esc(u.name)}</td>
            <td>${esc(u.email)}</td>
            <td>${roleBadge(u.role)}</td>
            <td>${esc(u.studio_name || u.studio || "—")}</td>
            <td>${esc(u.created_at)}</td>
          </tr>
        `
        )
        .join("")}
    </table>
  `;

  $("#recentLoginsWrap").innerHTML = `
    <table>
      <tr><th>Time</th><th>Email</th><th>Event</th><th>IP / Device</th></tr>
      ${d.recent_logins
        .map(
          (e) => `
          <tr>
            <td>${esc(e.created_at)}</td>
            <td>${esc(e.email || "—")}</td>
            <td>
              ${securityEventBadge(e.event_type, e.success)}
              ${e.suspicious ? '<span class="badge warn">suspicious</span>' : ""}
            </td>
            <td>${esc(e.ip || "")} · ${esc(e.device_label || "")}</td>
          </tr>
        `
        )
        .join("")}
    </table>
  `;
}

// Accounts
function renderPagination(containerSelector, pagination, onPage) {
  const el = $(containerSelector);
  const totalPages = Math.max(1, pagination.total_pages || 1);
  if (totalPages <= 1) {
    el.innerHTML = `<span class="muted">${pagination.total} total</span>`;
    return;
  }
  el.innerHTML = `
    <button class="btn sm ghost" data-pg-prev type="button" ${pagination.page <= 1 ? "disabled" : ""}>← Previous</button>
    <span class="muted">Page ${pagination.page} of ${totalPages} (${pagination.total} total)</span>
    <button class="btn sm ghost" data-pg-next type="button" ${pagination.page >= totalPages ? "disabled" : ""}>Next →</button>
  `;
  el.querySelector("[data-pg-prev]").onclick = () => onPage(pagination.page - 1);
  el.querySelector("[data-pg-next]").onclick = () => onPage(pagination.page + 1);
}

async function loadAccounts() {
  setTableLoading("#accountsTableWrap", "Loading accounts…");
  const params = new URLSearchParams({
    page: String(accPage),
    limit: "15",
    q: $("#accSearch").value.trim(),
    role: $("#accRoleFilter").value,
    status: $("#accStatusFilter").value,
  });
  let d;
  try {
    d = await api(`/api/super-admin/accounts?${params.toString()}`);
  } catch (err) {
    setTableError("#accountsTableWrap", err, loadAccounts);
    return;
  }

  $("#accountsTableWrap").innerHTML = d.accounts.length
    ? `<table>
        <tr><th>Name</th><th>Email</th><th>Role</th><th>Studio</th><th>Status</th><th>Last login</th><th>Registered</th><th>Action</th></tr>
        ${d.accounts
          .map(
            (a) => `
            <tr>
              <td>${esc(a.name)}</td>
              <td>${esc(a.email)}</td>
              <td>${roleBadge(a.role)}</td>
              <td>${esc(a.studio_name || "—")}</td>
              <td>${statusBadge(a.status)}</td>
              <td>${esc(a.last_login_at || "Never")}</td>
              <td>${esc(a.created_at)}</td>
              <td><button class="btn sm ghost" data-inspect-acc="${esc(a.id)}" type="button">Inspect →</button></td>
            </tr>
          `
          )
          .join("")}
      </table>`
    : '<div class="empty-card">No accounts match your filters.</div>';

  renderPagination("#accountsPagination", d.pagination, (nextPage) => {
    accPage = nextPage;
    loadAccounts();
  });

  document.querySelectorAll("[data-inspect-acc]").forEach((btn) => {
    btn.onclick = () =>
      inspectAccount(btn.dataset.inspectAcc).catch((err) => setGlobalMsg(err.message, true));
  });
}

function debounceLoad(key, fn) {
  clearTimeout(searchTimers[key]);
  searchTimers[key] = setTimeout(fn, 250);
}

$("#accSearch").oninput = () => {
  accPage = 1;
  debounceLoad("acc", loadAccounts);
};
$("#accRoleFilter").onchange = () => {
  accPage = 1;
  loadAccounts();
};
$("#accStatusFilter").onchange = () => {
  accPage = 1;
  loadAccounts();
};

async function inspectAccount(accountId) {
  const d = await api(`/api/super-admin/accounts/${encodeURIComponent(accountId)}`);
  const a = d.account;
  $("#accountDetailBody").innerHTML = `
    <button type="button" class="close" id="accDetClose" aria-label="Close">×</button>
    <p class="eyebrow">ACCOUNT RECORD</p>
    <h2>${esc(a.name)} ${roleBadge(a.role)} ${statusBadge(a.status)}</h2>
    <p class="muted">
      ID: <code>${esc(a.id)}</code> · Registered: ${esc(a.created_at)} · Last login: ${esc(a.last_login_at || "Never")}
      ${a.mfa_enabled ? " · MFA: Enabled" : " · MFA: Off"}
      ${a.must_change_password ? " · Password change required" : ""}
    </p>

    <div class="manage-actions">
      ${
        a.status === "active"
          ? `<button class="btn sm ghost" id="accSuspendBtn" type="button">Suspend account</button>`
          : a.status === "suspended"
            ? `<button class="btn sm" id="accReactivateBtn" type="button">Reactivate account</button>`
            : ""
      }
      ${
        a.status !== "deleted"
          ? `
            <button class="btn sm ghost" id="accResetPwBtn" type="button">Initiate password reset</button>
            <button class="btn sm ghost" id="accForcePwBtn" type="button">Force password change</button>
            <button class="btn sm ghost" id="accRevokeAllBtn" type="button">Revoke all sessions (${d.stats.active_sessions})</button>
          `
          : ""
      }
    </div>

    <div id="accActionResult"></div>

    ${
      a.status !== "deleted"
        ? `
      <form id="editAccForm" class="panel-box">
        <h3>Edit account details</h3>
        <div class="form-grid">
          <label>Name<input name="name" value="${esc(a.name)}" required></label>
          <label>Email<input name="email" type="email" value="${esc(a.email)}" required></label>
          <label>Phone<input name="phone" value="${esc(a.phone || "")}"></label>
          <label>Studio<input name="studio" value="${esc(a.studio_name || "")}"></label>
        </div>
        <div class="form-grid">
          <label>Role
            <select name="role">
              <option value="studio_owner" ${a.role === "studio_owner" ? "selected" : ""}>studio_owner</option>
              <option value="studio_staff" ${a.role === "studio_staff" ? "selected" : ""}>studio_staff</option>
              <option value="super_admin" ${a.role === "super_admin" ? "selected" : ""}>super_admin</option>
            </select>
          </label>
          <label class="inline"><input type="checkbox" name="must_change_password" ${a.must_change_password ? "checked" : ""}> Must change password on next login</label>
        </div>
        <button class="btn sm" type="submit">Save account changes</button>
      </form>`
        : ""
    }

    <div class="panel-box">
      <h3>Active sessions (${d.active_sessions.length})</h3>
      ${
        d.active_sessions.length
          ? `<div class="table-wrap"><table>
              <tr><th>Device</th><th>IP</th><th>Created</th><th>Last seen</th><th>Action</th></tr>
              ${d.active_sessions
                .map(
                  (s) => `
                <tr>
                  <td>${esc(s.device_label)}</td>
                  <td>${esc(s.ip)}</td>
                  <td>${esc(s.created_at)}</td>
                  <td>${esc(s.last_seen_at)}</td>
                  <td><button class="btn sm danger" data-revoke-sid="${esc(s.sid)}" type="button">Revoke</button></td>
                </tr>`
                )
                .join("")}
            </table></div>`
          : '<p class="muted">No active sessions.</p>'
      }
    </div>

    <div class="panel-box">
      <h3>Login &amp; security history (${d.stats.login_count} logins · ${d.stats.failed_count} failed)</h3>
      <div class="table-wrap">
        <table>
          <tr><th>Time</th><th>Event</th><th>IP / Device</th><th>Details</th></tr>
          ${d.login_history
            .map(
              (h) => `
            <tr>
              <td>${esc(h.created_at)}</td>
              <td>${esc(h.event_type)} ${h.suspicious ? '<span class="badge warn">suspicious</span>' : ""}</td>
              <td>${esc(h.ip)} · ${esc(h.device_label)}</td>
              <td>${esc(h.details || "")}</td>
            </tr>`
            )
            .join("")}
        </table>
      </div>
    </div>

    ${
      a.status !== "deleted" && a.id !== currentUser.id
        ? `
      <div class="danger-zone">
        <h3>Permanent account deletion</h3>
        <p class="muted">Deletes this account, revokes sessions, wipes PII, and removes owned events/media. Type <b>${esc(a.email)}</b> to confirm.</p>
        <div class="filter-bar">
          <input id="delConfirmEmail" placeholder="Type exact account email…">
          <button class="btn sm danger" id="delAccConfirmBtn" type="button">Permanently delete</button>
        </div>
      </div>`
        : ""
    }
  `;

  if (!$("#accountDetailDialog").open) $("#accountDetailDialog").showModal();
  $("#accDetClose").onclick = () => $("#accountDetailDialog").close();

  const showAccRes = (html, isErr = false) => {
    $("#accActionResult").innerHTML = `<div class="panel-box ${isErr ? "error" : "success-msg"}">${html}</div>`;
  };

  if ($("#accSuspendBtn")) {
    $("#accSuspendBtn").onclick = async () => {
      try {
        await api(`/api/super-admin/accounts/${encodeURIComponent(a.id)}/suspend`, {
          method: "POST",
          body: JSON.stringify({ reason: "Suspended by Super Admin" }),
        });
        await inspectAccount(a.id);
        await loadAccounts();
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  }

  if ($("#accReactivateBtn")) {
    $("#accReactivateBtn").onclick = async () => {
      try {
        await api(`/api/super-admin/accounts/${encodeURIComponent(a.id)}/reactivate`, {
          method: "POST",
        });
        await inspectAccount(a.id);
        await loadAccounts();
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  }

  if ($("#accResetPwBtn")) {
    $("#accResetPwBtn").onclick = async () => {
      try {
        const res = await api(
          `/api/super-admin/accounts/${encodeURIComponent(a.id)}/reset-password`,
          {
            method: "POST",
            body: JSON.stringify({ force_change_on_login: true, revoke_sessions: true }),
          }
        );
        showAccRes(
          `One-time password reset link (expires in 60m):<div class="code-box">${esc(res.resetUrl)}</div>`
        );
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  }

  if ($("#accForcePwBtn")) {
    $("#accForcePwBtn").onclick = async () => {
      try {
        await api(
          `/api/super-admin/accounts/${encodeURIComponent(a.id)}/force-password-change`,
          { method: "POST" }
        );
        await inspectAccount(a.id);
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  }

  if ($("#accRevokeAllBtn")) {
    $("#accRevokeAllBtn").onclick = async () => {
      try {
        const res = await api(
          `/api/super-admin/accounts/${encodeURIComponent(a.id)}/revoke-sessions`,
          { method: "POST" }
        );
        showAccRes(`Revoked ${res.revoked_count} active session(s).`);
        await inspectAccount(a.id);
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  }

  if ($("#editAccForm")) {
    $("#editAccForm").onsubmit = async (ev) => {
      ev.preventDefault();
      const fd = new FormData(ev.target);
      const payload = {
        name: fd.get("name"),
        email: fd.get("email"),
        phone: fd.get("phone"),
        studio: fd.get("studio"),
        role: fd.get("role"),
        must_change_password: fd.has("must_change_password"),
      };
      try {
        await api(`/api/super-admin/accounts/${encodeURIComponent(a.id)}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        });
        await inspectAccount(a.id);
        await loadAccounts();
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  }

  document.querySelectorAll("[data-revoke-sid]").forEach((btn) => {
    btn.onclick = async () => {
      try {
        await api(`/api/super-admin/sessions/${encodeURIComponent(btn.dataset.revokeSid)}/revoke`, {
          method: "POST",
        });
        await inspectAccount(a.id);
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  });

  if ($("#delAccConfirmBtn")) {
    $("#delAccConfirmBtn").onclick = async () => {
      try {
        await api(`/api/super-admin/accounts/${encodeURIComponent(a.id)}`, {
          method: "DELETE",
          body: JSON.stringify({ confirm_email: $("#delConfirmEmail").value }),
        });
        $("#accountDetailDialog").close();
        setGlobalMsg(`Account ${a.email} permanently deleted.`);
        await loadAccounts();
      } catch (err) {
        showAccRes(esc(err.message), true);
      }
    };
  }
}

// Create Account Modal
function syncCreateRoleFields() {
  const role = $("#caRole").value;
  $("#caStudioNameWrap").classList.toggle("hidden", role !== "studio_owner");
  $("#caStudioSelectWrap").classList.toggle("hidden", role !== "studio_staff");
  $("#caStaffPermsWrap").classList.toggle("hidden", role !== "studio_staff");
}

$("#openCreateAccountBtn").onclick = async () => {
  $("#createAccError").textContent = "";
  try {
    const studiosRes = await api("/api/super-admin/studios?limit=100");
    $("#caStudioId").innerHTML = studiosRes.studios
      .map((s) => `<option value="${esc(s.id)}">${esc(s.name)} (${esc(s.owner_email || "")})</option>`)
      .join("");
    if (activeView === "studios") {
      $("#caRole").value = "studio_owner";
    }
    syncCreateRoleFields();
    $("#createAccountDialog").showModal();
  } catch (err) {
    setGlobalMsg(err.message, true);
  }
};

$("#createAccClose").onclick = () => $("#createAccountDialog").close();

$("#caRole").onchange = syncCreateRoleFields;

$("#createAccountForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#createAccError").textContent = "";
  const fd = new FormData(e.target);
  const role = fd.get("role");
  const payload = {
    name: fd.get("name"),
    email: fd.get("email"),
    password: fd.get("password"),
    role,
    studio: fd.get("studio"),
    studio_id: fd.get("studio_id"),
    staff_permissions: fd.getAll("perm"),
    must_change_password: fd.has("must_change_password"),
  };
  try {
    await api("/api/super-admin/accounts", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    $("#createAccountDialog").close();
    e.target.reset();
    syncCreateRoleFields();
    const targetView = activeView === "studios" && role === "studio_owner" ? "studios" : "accounts";
    await switchView(targetView);
    setGlobalMsg(`Created account for ${payload.email}.`);
  } catch (err) {
    $("#createAccError").textContent = err.message;
  }
};

// Studios
async function loadStudios() {
  setTableLoading("#studiosTableWrap", "Loading studios…");
  const params = new URLSearchParams({
    page: String(studioPage),
    limit: "15",
    q: $("#studioSearch").value.trim(),
    status: $("#studioStatusFilter").value,
    plan: $("#studioPlanFilter").value,
  });
  let d;
  try {
    d = await api(`/api/super-admin/studios?${params.toString()}`);
  } catch (err) {
    setTableError("#studiosTableWrap", err, loadStudios);
    return;
  }

  $("#studiosTableWrap").innerHTML = d.studios.length
    ? `<table>
        <tr><th>Studio</th><th>Owner</th><th>Plan</th><th>Status</th><th>Usage</th><th>Registered</th><th>Action</th></tr>
        ${d.studios
          .map(
            (s) => `
          <tr>
            <td><b>${esc(s.name)}</b></td>
            <td>${esc(s.owner_name || "—")}<br><small class="muted">${esc(s.owner_email || "")}</small></td>
            <td><span class="badge neutral">${esc(s.plan)}</span></td>
            <td>${statusBadge(s.status)}</td>
            <td>${s.event_count} ${plural(s.event_count, "event")} · ${s.photo_count} ${plural(s.photo_count, "photo")} · ${s.staff_count} staff<br><small class="muted">${formatMb(s.storage_used_bytes)} / ${formatMb(s.storage_limit_bytes)}</small></td>
            <td>${esc(s.created_at)}</td>
            <td><button class="btn sm ghost" data-inspect-studio="${esc(s.id)}" type="button">Manage →</button></td>
          </tr>`
          )
          .join("")}
      </table>`
    : '<div class="empty-card">No studios match your filters.</div>';

  renderPagination("#studiosPagination", d.pagination, (p) => {
    studioPage = p;
    loadStudios();
  });

  document.querySelectorAll("[data-inspect-studio]").forEach((btn) => {
    btn.onclick = () =>
      inspectStudio(btn.dataset.inspectStudio).catch((err) => setGlobalMsg(err.message, true));
  });
}

$("#studioSearch").oninput = () => {
  studioPage = 1;
  debounceLoad("studio", loadStudios);
};
$("#studioStatusFilter").onchange = () => {
  studioPage = 1;
  loadStudios();
};
$("#studioPlanFilter").onchange = () => {
  studioPage = 1;
  loadStudios();
};
$("#refreshStudiosBtn").onclick = () => {
  loadStudios();
};

async function inspectStudio(studioId) {
  const d = await api(`/api/super-admin/studios/${encodeURIComponent(studioId)}`);
  const s = d.studio;
  const limitMb = Math.round((s.storage_limit_bytes || 524288000) / (1024 * 1024));

  $("#studioDetailBody").innerHTML = `
    <button type="button" class="close" id="studioDetClose" aria-label="Close">×</button>
    <p class="eyebrow">TENANT GOVERNANCE</p>
    <h2>${esc(s.name)} ${statusBadge(s.status)}</h2>
    <p class="muted">Owner: ${esc(s.owner_name || "None")} (${esc(s.owner_email || "—")}) · Registered: ${esc(s.created_at)}</p>

    <div class="manage-actions">
      ${
        s.status === "active"
          ? `<button class="btn sm danger" id="studioSuspendBtn" type="button">Suspend studio</button>`
          : `<button class="btn sm" id="studioActivateBtn" type="button">Activate studio</button>`
      }
    </div>
    <p id="studioActionErr" class="error"></p>

    <form id="editStudioForm" class="panel-box">
      <h3>Plan, quota &amp; notes</h3>
      <div class="form-grid">
        <label>Studio name<input name="name" value="${esc(s.name)}" required></label>
        <label>Plan
          <select name="plan">
            <option value="free" ${s.plan === "free" ? "selected" : ""}>free</option>
            <option value="standard" ${s.plan === "standard" ? "selected" : ""}>standard</option>
            <option value="pro" ${s.plan === "pro" ? "selected" : ""}>pro</option>
            <option value="enterprise" ${s.plan === "enterprise" ? "selected" : ""}>enterprise</option>
          </select>
        </label>
        <label>Storage limit (MB)<input name="storage_limit_mb" type="number" min="10" value="${limitMb}"></label>
        <label>Admin notes<input name="notes" value="${esc(s.notes || "")}"></label>
      </div>
      <button class="btn sm" type="submit">Update studio</button>
    </form>

    <div class="panel-box">
      <h3>Team members (${d.members.length})</h3>
      <div class="table-wrap"><table>
        <tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th></tr>
        ${d.members
          .map(
            (m) => `
          <tr>
            <td>${esc(m.name)}</td>
            <td>${esc(m.email)}</td>
            <td>${roleBadge(m.role)}</td>
            <td>${statusBadge(m.status)}</td>
            <td>${esc(m.last_login_at || "Never")}</td>
          </tr>`
          )
          .join("")}
      </table></div>
    </div>

    <div class="panel-box">
      <h3>Studio events (${d.events.length})</h3>
      <div class="table-wrap"><table>
        <tr><th>Title</th><th>Code</th><th>Photos</th><th>Selections</th><th>Status</th></tr>
        ${d.events
          .map(
            (ev) => `
          <tr>
            <td>${esc(ev.title)}</td>
            <td><code>${esc(ev.access_code)}</code></td>
            <td>${ev.photo_count}</td>
            <td>${ev.selection_count}</td>
            <td>
              <select data-sa-event-status="${esc(ev.id)}">
                <option value="active" ${ev.status === "active" ? "selected" : ""}>active</option>
                <option value="paused" ${ev.status === "paused" ? "selected" : ""}>paused</option>
                <option value="archived" ${ev.status === "archived" ? "selected" : ""}>archived</option>
              </select>
            </td>
          </tr>`
          )
          .join("")}
      </table></div>
    </div>
  `;

  if (!$("#studioDetailDialog").open) $("#studioDetailDialog").showModal();
  $("#studioDetClose").onclick = () => $("#studioDetailDialog").close();

  if ($("#studioSuspendBtn")) {
    $("#studioSuspendBtn").onclick = async () => {
      try {
        await api(`/api/super-admin/studios/${encodeURIComponent(s.id)}/suspend`, {
          method: "POST",
          body: JSON.stringify({ reason: "Suspended by Super Admin" }),
        });
        await inspectStudio(s.id);
        await loadStudios();
      } catch (err) {
        $("#studioActionErr").textContent = err.message;
      }
    };
  }

  if ($("#studioActivateBtn")) {
    $("#studioActivateBtn").onclick = async () => {
      try {
        await api(`/api/super-admin/studios/${encodeURIComponent(s.id)}/activate`, {
          method: "POST",
        });
        await inspectStudio(s.id);
        await loadStudios();
      } catch (err) {
        $("#studioActionErr").textContent = err.message;
      }
    };
  }

  $("#editStudioForm").onsubmit = async (ev) => {
    ev.preventDefault();
    const payload = Object.fromEntries(new FormData(ev.target));
    try {
      await api(`/api/super-admin/studios/${encodeURIComponent(s.id)}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      await inspectStudio(s.id);
      await loadStudios();
    } catch (err) {
      $("#studioActionErr").textContent = err.message;
    }
  };

  document.querySelectorAll("[data-sa-event-status]").forEach((sel) => {
    sel.onchange = async () => {
      try {
        await api(`/api/super-admin/events/${encodeURIComponent(sel.dataset.saEventStatus)}/status`, {
          method: "PATCH",
          body: JSON.stringify({ status: sel.value }),
        });
      } catch (err) {
        $("#studioActionErr").textContent = err.message;
      }
    };
  });
}

// Security Logs
async function loadSecurity() {
  setTableLoading("#securityTableWrap", "Loading security logs…");
  const params = new URLSearchParams({
    page: String(secPage),
    limit: "25",
    q: $("#secSearch").value.trim(),
    event_type: $("#secTypeFilter").value,
    suspicious: $("#secSuspiciousOnly").checked ? "1" : "",
  });
  let d;
  try {
    d = await api(`/api/super-admin/security?${params.toString()}`);
  } catch (err) {
    setTableError("#securityTableWrap", err, loadSecurity);
    return;
  }

  $("#securityTableWrap").innerHTML = d.events.length
    ? `<table>
        <tr><th>Time</th><th>Email</th><th>Event</th><th>IP</th><th>Device / Browser</th><th>Details</th></tr>
        ${d.events
          .map(
            (e) => `
          <tr>
            <td>${esc(e.created_at)}</td>
            <td>${esc(e.email || "—")}</td>
            <td>
              ${securityEventBadge(e.event_type, e.success)}
              ${e.suspicious ? '<span class="badge warn">suspicious</span>' : ""}
            </td>
            <td>${esc(e.ip || "")}</td>
            <td>${esc(e.device_label || "")}</td>
            <td>${esc(e.details || "")}</td>
          </tr>`
          )
          .join("")}
      </table>`
    : '<div class="empty-card">No security events match your filters.</div>';

  renderPagination("#securityPagination", d.pagination, (p) => {
    secPage = p;
    loadSecurity();
  });
}

$("#secSearch").oninput = () => {
  secPage = 1;
  debounceLoad("sec", loadSecurity);
};
$("#secTypeFilter").onchange = () => {
  secPage = 1;
  loadSecurity();
};
$("#secSuspiciousOnly").onchange = () => {
  secPage = 1;
  loadSecurity();
};

// Active Sessions
async function loadSessions() {
  setTableLoading("#sessionsTableWrap", "Loading active sessions…");
  let d;
  try {
    d = await api("/api/super-admin/sessions?active_only=1");
  } catch (err) {
    setTableError("#sessionsTableWrap", err, loadSessions);
    return;
  }
  $("#sessionsTableWrap").innerHTML = d.sessions.length
    ? `<table>
        <tr><th>User</th><th>Role</th><th>Studio</th><th>Device</th><th>IP</th><th>Last seen</th><th>Action</th></tr>
        ${d.sessions
          .map(
            (s) => `
          <tr>
            <td>${esc(s.user_name)}<br><small class="muted">${esc(s.user_email)}</small></td>
            <td>${roleBadge(s.user_role)}</td>
            <td>${esc(s.studio_name || "Platform")}</td>
            <td>${esc(s.device_label)} ${s.current ? '<span class="badge">current</span>' : ""}</td>
            <td>${esc(s.ip)}</td>
            <td>${esc(s.last_seen_at)}</td>
            <td>${
              s.current
                ? '<span class="muted">Active tab</span>'
                : `<button class="btn sm danger" data-sa-revoke-sid="${esc(s.sid)}" type="button">Revoke</button>`
            }</td>
          </tr>`
          )
          .join("")}
      </table>`
    : '<div class="empty-card">No active sessions.</div>';

  document.querySelectorAll("[data-sa-revoke-sid]").forEach((btn) => {
    btn.onclick = async () => {
      try {
        await api(`/api/super-admin/sessions/${encodeURIComponent(btn.dataset.saRevokeSid)}/revoke`, {
          method: "POST",
        });
        await loadSessions();
      } catch (err) {
        setGlobalMsg(err.message, true);
      }
    };
  });
}

$("#refreshSessionsBtn").onclick = () =>
  loadSessions().catch((err) => setGlobalMsg(err.message, true));

// Audit Logs
async function loadAuditLogs() {
  setTableLoading("#auditTableWrap", "Loading audit logs…");
  const params = new URLSearchParams({
    page: String(auditPage),
    limit: "25",
    q: $("#auditSearch").value.trim(),
  });
  let d;
  try {
    d = await api(`/api/super-admin/audit-logs?${params.toString()}`);
  } catch (err) {
    setTableError("#auditTableWrap", err, loadAuditLogs);
    return;
  }

  $("#auditTableWrap").innerHTML = d.logs.length
    ? `<table>
        <tr><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>Details</th><th>IP</th></tr>
        ${d.logs
          .map(
            (l) => `
          <tr>
            <td>${esc(l.created_at)}</td>
            <td>${esc(l.actor_email || l.user_id || "system")}</td>
            <td><b>${esc(l.action)}</b></td>
            <td>${esc([l.entity_type, l.entity_id].filter(Boolean).join(":"))}</td>
            <td>${esc(l.details || "")}</td>
            <td>${esc(l.ip || "")}</td>
          </tr>`
          )
          .join("")}
      </table>`
    : '<div class="empty-card">No audit logs found.</div>';

  renderPagination("#auditPagination", d.pagination, (p) => {
    auditPage = p;
    loadAuditLogs();
  });
}

$("#auditSearch").oninput = () => {
  auditPage = 1;
  debounceLoad("audit", loadAuditLogs);
};

boot().catch((err) => {
  showGateError(err.message);
});

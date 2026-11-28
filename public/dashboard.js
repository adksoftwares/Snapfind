const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

let csrfToken = null;
let currentUser = null;
let currentEventId = null;
let events = [];
let eventLibraryFilter = "all";
let eventLibraryQuery = "";
let indexingAbort = false;
let dashboardLoadSequence = 0;
let manageEventRequestSequence = 0;
let indexingRunSequence = 0;
let indexingSavePromise = null;
let photoUploadInProgress = false;
let workspaceNavigationInitialized = false;

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
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function setPhotoUploadUiBusy(busy) {
  const input = $("#photoUpload");
  const label = document.querySelector('label[for="photoUpload"]');
  const dropzone = $("#photoDropzone");
  if (input) input.disabled = busy;
  if (label) {
    label.classList.toggle("disabled", busy);
    if (busy) label.setAttribute("aria-disabled", "true");
    else label.removeAttribute("aria-disabled");
  }
  if (dropzone) {
    dropzone.classList.toggle("is-uploading", busy);
    if (busy) {
      dropzone.setAttribute("aria-disabled", "true");
      dropzone.setAttribute("aria-busy", "true");
    } else {
      dropzone.removeAttribute("aria-disabled");
      dropzone.removeAttribute("aria-busy");
    }
  }
}

function setStatusMsg(selector, text, isError = false) {
  const el = $(selector);
  el.textContent = text;
  el.className = isError ? "error" : "success-msg";
}

function hasPerm(perm) {
  if (!currentUser) return false;
  if (currentUser.role === "super_admin" || currentUser.role === "studio_owner") return true;
  return (currentUser.staff_permissions || []).includes(perm);
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(url, { ...options, method, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data.error || "Request failed");
    err.code = data.code;
    err.status = response.status;
    throw err;
  }
  return data;
}

function showToast(text) {
  $("#liveToastText").textContent = text;
  $("#liveToast").classList.remove("hidden");
}

$("#liveToastClose").onclick = () => $("#liveToast").classList.add("hidden");

function connectSocket() {
  if (typeof io !== "function") return;
  const socket = io();
  socket.on("selection:new", (payload) => {
    showToast(`New photo selection from ${payload.guest_name || "a guest"}!`);
    loadDashboard();
  });
  socket.on("event:updated", () => {
    loadDashboard();
  });
}

function initWorkspaceNavigation() {
  if (workspaceNavigationInitialized) return;
  workspaceNavigationInitialized = true;

  const links = Array.from(document.querySelectorAll(".side-nav a[href^='#']")).filter((link) => {
    const sectionId = link.getAttribute("href").slice(1);
    const section = document.getElementById(sectionId);
    return section && !link.classList.contains("hidden") && !section.classList.contains("hidden");
  });
  const sections = links.map((link) => document.getElementById(link.getAttribute("href").slice(1)));

  function setActiveSection(sectionId) {
    links.forEach((link) => {
      const active = link.getAttribute("href") === `#${sectionId}`;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
  }

  links.forEach((link) => {
    link.addEventListener("click", () => {
      setActiveSection(link.getAttribute("href").slice(1));
    });
  });

  window.addEventListener("hashchange", () => {
    const sectionId = location.hash.slice(1);
    if (sections.some((section) => section.id === sectionId)) {
      setActiveSection(sectionId);
    }
  });

  const visibleSections = sections.filter((section) => !section.classList.contains("hidden"));
  if ("IntersectionObserver" in window && visibleSections.length) {
    const observer = new IntersectionObserver((entries) => {
      const candidates = entries
        .filter((entry) => entry.isIntersecting && !entry.target.classList.contains("hidden"))
        .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (candidates.length) setActiveSection(candidates[0].target.id);
    }, {
      rootMargin: "-18% 0px -62% 0px",
      threshold: [0, 0.15, 0.3, 0.5, 0.75],
    });
    visibleSections.forEach((section) => observer.observe(section));
  }

  const initialSection = location.hash.slice(1);
  if (sections.some((section) => section.id === initialSection)) {
    setActiveSection(initialSection);
  } else if (visibleSections[0]) {
    setActiveSection(visibleSections[0].id);
  }
}

async function init() {
  const meData = await api("/api/auth/me");
  const me = meData.user;
  csrfToken = meData.csrfToken;
  currentUser = me;
  if (!me) {
    location.href = "/";
    return;
  }

  $("#welcomeName").textContent = String(me.name || "there").trim().split(/\s+/)[0];
  $("#sideName").textContent = me.email;
  $("#workspaceRoleLabel").textContent =
    me.role === "super_admin"
      ? "SUPER ADMIN STUDIO VIEW"
      : me.role === "studio_staff"
        ? "STUDIO STAFF WORKSPACE"
        : "STUDIO OWNER WORKSPACE";

  $("#profileForm").elements.name.value = me.name;
  $("#profileForm").elements.phone.value = me.phone || "";
  $("#profileForm").elements.studio.value = me.studio || "";
  if (me.role === "studio_staff") {
    $("#profileForm").elements.studio.readOnly = true;
  }

  if (me.role === "super_admin") {
    $("#superAdminLink").classList.remove("hidden");
  }
  if (me.role === "studio_owner") {
    $("#staffLink").classList.remove("hidden");
    $("#staff").classList.remove("hidden");
  }
  if (!hasPerm("events:write")) {
    $("#newEvent").classList.add("hidden");
  }

  initWorkspaceNavigation();

  if ($("#evAiEnabled") && $("#evSelfieOnly")) {
    $("#evAiEnabled").addEventListener("change", () => {
      const enabled = $("#evAiEnabled").checked;
      $("#evSelfieOnly").disabled = !enabled;
      if (!enabled) $("#evSelfieOnly").checked = false;
    });
  }

  renderMfaState();

  if (me.must_change_password) {
    $("#forcePwDialog").showModal();
    return;
  }

  connectSocket();
  await loadDashboard();
  if (me.role === "studio_owner") {
    await loadStaff();
  }
  await loadSelfSessions();
}

$("#forcePwForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#forcePwError").textContent = "";
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    const res = await api("/api/auth/password", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res.csrfToken) csrfToken = res.csrfToken;
    $("#forcePwDialog").close();
    await init();
  } catch (err) {
    $("#forcePwError").textContent = err.message;
  }
};

function renderMfaState() {
  if (!currentUser) return;
  if (currentUser.mfa_enabled) {
    $("#mfaStatusText").textContent = "Two-factor authentication (TOTP) is currently enabled on your account.";
    $("#startMfaSetupBtn").textContent = "Rotate 2FA secret";
    $("#disableMfaBtn").classList.toggle("hidden", currentUser.role === "super_admin");
  } else {
    $("#mfaStatusText").textContent = "Two-factor authentication is not enabled yet. Protect your studio with an authenticator app.";
    $("#startMfaSetupBtn").textContent = "Enable 2FA";
    $("#disableMfaBtn").classList.add("hidden");
  }
}

$("#startMfaSetupBtn").onclick = async () => {
  const area = $("#mfaSetupArea");
  area.classList.remove("hidden");
  area.innerHTML = '<p class="muted">Generating authenticator secret…</p>';
  try {
    const res = await api("/api/auth/mfa/setup", { method: "POST" });
    area.innerHTML = `
      <img class="qr-large" src="${res.qr}" alt="TOTP QR code">
      <p class="muted">Manual key: <code>${esc(res.secret)}</code></p>
      <form id="confirmMfaForm" class="profile-form">
        <label>6-digit code<input name="code" inputmode="numeric" maxlength="6" required></label>
        <button class="btn sm" type="submit">Confirm &amp; enable</button>
      </form>
      <p id="mfaErr" class="error"></p>
    `;
    $("#confirmMfaForm").onsubmit = async (ev) => {
      ev.preventDefault();
      $("#mfaErr").textContent = "";
      try {
        const out = await api("/api/auth/mfa/enable", {
          method: "POST",
          body: JSON.stringify({ code: new FormData(ev.target).get("code") }),
        });
        currentUser.mfa_enabled = true;
        renderMfaState();
        area.innerHTML = `
          <p class="success-msg">2FA enabled! Save these one-time recovery codes offline:</p>
          <div class="recovery-grid">${out.recoveryCodes.map((c) => `<code>${esc(c)}</code>`).join("")}</div>
        `;
      } catch (err) {
        $("#mfaErr").textContent = err.message;
      }
    };
  } catch (err) {
    area.innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
};

$("#disableMfaBtn").onclick = () => {
  const area = $("#mfaSetupArea");
  area.classList.remove("hidden");
  area.innerHTML = `
    <form id="disableMfaForm" class="profile-form">
      <label>Confirm current password<input name="password" type="password" required></label>
      <button class="btn sm danger" type="submit">Disable 2FA</button>
    </form>
    <p id="mfaDisErr" class="error"></p>
  `;
  $("#disableMfaForm").onsubmit = async (ev) => {
    ev.preventDefault();
    try {
      await api("/api/auth/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ password: new FormData(ev.target).get("password") }),
      });
      currentUser.mfa_enabled = false;
      renderMfaState();
      area.classList.add("hidden");
    } catch (err) {
      $("#mfaDisErr").textContent = err.message;
    }
  };
};

async function loadSelfSessions() {
  const wrap = $("#selfSessionsWrap");
  const message = $("#selfSessionsMsg");
  wrap.setAttribute("aria-busy", "true");
  wrap.innerHTML = '<p class="muted" role="status">Loading active sessions…</p>';
  if (message) {
    message.textContent = "";
    message.className = "muted";
  }

  try {
    const d = await api("/api/auth/sessions");
    const sessions = Array.isArray(d.sessions) ? d.sessions : [];
    wrap.innerHTML = sessions.length
      ? `<table>
          <caption class="sr-only">Active sign-in sessions for your account</caption>
          <thead><tr><th scope="col">Device / Browser</th><th scope="col">IP</th><th scope="col">Created</th><th scope="col">Last seen</th><th scope="col">Action</th></tr></thead>
          <tbody>
            ${sessions.map((s) => `
              <tr>
                <td>${esc(s.device_label)} ${s.current ? '<span class="badge">current</span>' : ""}</td>
                <td>${esc(s.ip)}</td>
                <td>${esc(s.created_at)}</td>
                <td>${esc(s.last_seen_at)}</td>
                <td>${s.current
                  ? '<span class="muted">This device</span>'
                  : `<button class="btn sm danger" data-revoke-self-sid="${esc(s.sid)}" type="button">Sign out</button>`}</td>
              </tr>`).join("")}
          </tbody>
        </table>`
      : '<p class="muted">No active sessions recorded.</p>';

    wrap.removeAttribute("aria-busy");
    wrap.querySelectorAll("[data-revoke-self-sid]").forEach((btn) => {
      btn.onclick = async () => {
        if (btn.disabled) return;
        btn.disabled = true;
        btn.textContent = "Signing out…";
        btn.setAttribute("aria-busy", "true");
        if (message) message.textContent = "";
        try {
          await api(`/api/auth/sessions/${encodeURIComponent(btn.dataset.revokeSelfSid)}`, {
            method: "DELETE",
          });
          const refreshed = await loadSelfSessions();
          if (message) {
            message.textContent = refreshed
              ? "The selected session has been signed out."
              : "The session was signed out, but the list could not refresh. Use Retry below.";
            message.className = "success-msg";
          }
        } catch (err) {
          btn.disabled = false;
          btn.textContent = "Sign out";
          btn.removeAttribute("aria-busy");
          setStatusMsg("#selfSessionsMsg", err.message, true);
        }
      };
    });
    return true;
  } catch (err) {
    wrap.removeAttribute("aria-busy");
    wrap.innerHTML = `<div class="empty-card"><p class="error" role="alert">${esc(err.message || "Failed to load active sessions.")}</p><button class="btn sm ghost" type="button" data-retry-self-sessions>Retry</button></div>`;
    const retry = wrap.querySelector("[data-retry-self-sessions]");
    if (retry) retry.onclick = () => loadSelfSessions();
    setStatusMsg("#selfSessionsMsg", "Active sessions could not be loaded.", true);
    return false;
  }
}

async function loadStaff() {
  const wrap = $("#staffListWrap");
  wrap.setAttribute("aria-busy", "true");
  wrap.innerHTML = '<p class="muted" role="status">Loading team members…</p>';

  try {
    const d = await api("/api/studio/staff");
    const staff = Array.isArray(d.staff) ? d.staff : [];
    const statusMessage = $("#staffMsg");
    if (statusMessage?.textContent === "Team members could not be loaded.") {
      statusMessage.textContent = "";
      statusMessage.className = "muted";
    }
    wrap.innerHTML = staff.length
      ? `<table>
          <caption class="sr-only">Studio staff members and permissions</caption>
          <thead><tr><th scope="col">Name</th><th scope="col">Email</th><th scope="col">Permissions</th><th scope="col">Status</th><th scope="col">Action</th></tr></thead>
          <tbody>
            ${staff.map((s) => `
              <tr>
                <td>${esc(s.name)}</td>
                <td>${esc(s.email)}</td>
                <td>${(s.staff_permissions || []).map((p) => `<span class="badge neutral">${esc(p)}</span>`).join(" ") || '<span class="muted">None</span>'}</td>
                <td><span class="badge ${s.status === "suspended" ? "warn" : ""}">${esc(s.status)}</span></td>
                <td>
                  <button class="btn sm ghost" data-toggle-staff="${esc(s.id)}" data-next-status="${s.status === "active" ? "suspended" : "active"}" type="button">${s.status === "active" ? "Suspend" : "Activate"}</button>
                  <button class="btn sm danger" data-del-staff="${esc(s.id)}" type="button">Remove</button>
                </td>
              </tr>`).join("")}
          </tbody>
        </table>`
      : '<p class="muted">No staff members added yet.</p>';

    wrap.removeAttribute("aria-busy");
    wrap.querySelectorAll("[data-toggle-staff]").forEach((btn) => {
      btn.onclick = async () => {
        if (btn.disabled) return;
        const nextStatus = btn.dataset.nextStatus;
        btn.disabled = true;
        btn.textContent = nextStatus === "suspended" ? "Suspending…" : "Activating…";
        btn.setAttribute("aria-busy", "true");
        try {
          await api(`/api/studio/staff/${encodeURIComponent(btn.dataset.toggleStaff)}`, {
            method: "PATCH",
            body: JSON.stringify({ status: nextStatus }),
          });
          const refreshed = await loadStaff();
          setStatusMsg(
            "#staffMsg",
            refreshed
              ? `Staff member ${nextStatus === "suspended" ? "suspended" : "activated"}.`
              : "The change was saved, but the team list could not refresh. Use Retry below.",
            false
          );
        } catch (err) {
          btn.disabled = false;
          btn.textContent = nextStatus === "suspended" ? "Suspend" : "Activate";
          btn.removeAttribute("aria-busy");
          setStatusMsg("#staffMsg", err.message, true);
        }
      };
    });

    wrap.querySelectorAll("[data-del-staff]").forEach((btn) => {
      let armed = false;
      btn.onclick = async () => {
        if (!armed) {
          armed = true;
          btn.textContent = "Confirm remove?";
          return;
        }
        if (btn.disabled) return;
        btn.disabled = true;
        btn.textContent = "Removing…";
        btn.setAttribute("aria-busy", "true");
        try {
          await api(`/api/studio/staff/${encodeURIComponent(btn.dataset.delStaff)}`, {
            method: "DELETE",
          });
          const refreshed = await loadStaff();
          setStatusMsg(
            "#staffMsg",
            refreshed
              ? "Staff member removed."
              : "The staff member was removed, but the team list could not refresh. Use Retry below.",
            false
          );
        } catch (err) {
          armed = false;
          btn.disabled = false;
          btn.textContent = "Remove";
          btn.removeAttribute("aria-busy");
          setStatusMsg("#staffMsg", err.message, true);
        }
      };
    });
    return true;
  } catch (err) {
    wrap.removeAttribute("aria-busy");
    wrap.innerHTML = `<div class="empty-card"><p class="error" role="alert">${esc(err.message || "Failed to load team members.")}</p><button class="btn sm ghost" type="button" data-retry-staff>Retry</button></div>`;
    const retry = wrap.querySelector("[data-retry-staff]");
    if (retry) retry.onclick = () => loadStaff();
    setStatusMsg("#staffMsg", "Team members could not be loaded.", true);
    return false;
  }
}

$("#staffForm").onsubmit = async (e) => {
  e.preventDefault();
  setStatusMsg("#staffMsg", "", false);
  const fd = new FormData(e.target);
  const payload = {
    name: fd.get("name"),
    email: fd.get("email"),
    password: fd.get("password"),
    staff_permissions: fd.getAll("perm"),
  };
  try {
    await api("/api/studio/staff", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    e.target.reset();
    setStatusMsg("#staffMsg", "Staff member added (password change required on first login).", false);
    await loadStaff();
  } catch (err) {
    setStatusMsg("#staffMsg", err.message, true);
  }
};

function renderDashboardEvents() {
  const query = eventLibraryQuery.trim().toLowerCase();
  const filtered = events.filter((event) => {
    const status = String(event.status || "").toLowerCase();
    const matchesStatus = eventLibraryFilter === "all" || status === eventLibraryFilter;
    const searchable = [event.title, event.event_date, event.venue, event.access_code, event.status]
      .filter(Boolean).join(" ").toLowerCase();
    return matchesStatus && (!query || searchable.includes(query));
  });

  const counts = {
    all: events.length,
    active: events.filter((e) => String(e.status || "").toLowerCase() === "active").length,
    paused: events.filter((e) => String(e.status || "").toLowerCase() === "paused").length,
    archived: events.filter((e) => String(e.status || "").toLowerCase() === "archived").length,
  };
  Object.entries(counts).forEach(([key, value]) => {
    const el = $(`#eventCount${key.charAt(0).toUpperCase()}${key.slice(1)}`);
    if (el) el.textContent = String(value);
  });

  document.querySelectorAll("[data-event-filter]").forEach((button) => {
    const isActive = button.dataset.eventFilter === eventLibraryFilter;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-pressed", String(isActive));
  });

  const summary = $("#eventLibrarySummary");
  if (summary) {
    summary.textContent = query || eventLibraryFilter !== "all"
      ? `Showing ${filtered.length} of ${events.length} event(s)`
      : `${events.length} event(s) in your workspace`;
  }

  if (!events.length) {
    $("#eventList").innerHTML = '<div class="empty event-library-empty"><h3>Your event library is ready</h3><p>Create your first event to start uploading photos and sharing a guest gallery.</p><button class="btn" type="button" data-empty-create-event>Create your first event</button></div>';
    const createButton = $("[data-empty-create-event]");
    if (createButton) createButton.onclick = () => $("#newEvent").click();
    return;
  }

  if (!filtered.length) {
    $("#eventList").innerHTML = '<div class="empty event-library-empty"><h3>No events match this view</h3><p>Try another status or clear your search.</p><button class="btn ghost" type="button" data-reset-event-library>Clear filters</button></div>';
    const resetButton = $("[data-reset-event-library]");
    if (resetButton) resetButton.onclick = () => {
      eventLibraryFilter = "all";
      eventLibraryQuery = "";
      $("#eventLibrarySearch").value = "";
      renderDashboardEvents();
      $("#eventLibrarySearch").focus();
    };
    return;
  }

  $("#eventList").innerHTML = filtered.map((e) => `
    <article class="event-card">
      <div class="event-icon" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>
        </svg>
      </div>
      <div class="event-info">
        <h3>
          ${esc(e.title)}
          <span class="badge ${esc(e.status)}">${esc(e.status)}</span>
          ${e.has_pin ? '<span class="badge">PIN</span>' : ""}
          ${e.is_public ? '<span class="badge">Public</span>' : ""}
          ${e.ai_enabled ? '<span class="badge">AI</span>' : ""}
        </h3>
        <p>${esc(e.event_date || "Date not set")} · ${esc(e.venue || "Venue not set")}</p>
        <small>${e.photos} ${e.photos === 1 ? "photo" : "photos"} · ${e.selections} ${e.selections === 1 ? "selection" : "selections"} · ${e.indexed_faces} ${e.indexed_faces === 1 ? "indexed face" : "indexed faces"} · Code ${esc(e.access_code)}</small>
      </div>
      <button class="btn ghost" data-manage="${esc(e.id)}" type="button">Manage →</button>
    </article>
  `).join("");

  document.querySelectorAll("[data-manage]").forEach((btn) => {
    btn.onclick = () => {
      if (btn.disabled) return;
      const originalLabel = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Opening…";
      btn.setAttribute("aria-busy", "true");
      manageEvent(btn.dataset.manage)
        .catch((err) => showToast(err.message))
        .finally(() => {
          if (!btn.isConnected) return;
          btn.disabled = false;
          btn.textContent = originalLabel;
          btn.removeAttribute("aria-busy");
        });
    };
  });
}

$("#eventLibrarySearch").oninput = () => {
  eventLibraryQuery = $("#eventLibrarySearch").value;
  renderDashboardEvents();
};
document.querySelectorAll("[data-event-filter]").forEach((button) => {
  button.onclick = () => {
    eventLibraryFilter = button.dataset.eventFilter;
    renderDashboardEvents();
  };
});

// Keyboard shortcuts keep the event library usable without reaching for the mouse.
window.addEventListener("keydown", (event) => {
  const target = event.target;
  const typing = target instanceof HTMLElement && target.closest("input, textarea, select, [contenteditable='true']");
  const command = event.ctrlKey || event.metaKey;
  const eventDialog = $("#eventDialog");
  const manageDialog = $("#manageDialog");

  if (command && event.key.toLowerCase() === "k" && !eventDialog?.open && !manageDialog?.open) {
    event.preventDefault();
    $("#eventLibrarySearch")?.focus();
    return;
  }

  if (command && event.key.toLowerCase() === "n" && !typing && !eventDialog?.open && !manageDialog?.open) {
    const createButton = $("#newEvent");
    if (createButton && !createButton.classList.contains("hidden")) {
      event.preventDefault();
      createButton.click();
    }
    return;
  }

  if (event.key === "Escape" && target === $("#eventLibrarySearch") && eventLibraryQuery) {
    eventLibraryQuery = "";
    $("#eventLibrarySearch").value = "";
    renderDashboardEvents();
  }
});

async function loadDashboard() {
  const requestId = ++dashboardLoadSequence;
  const eventList = $("#eventList");
  const summary = $("#eventLibrarySummary");
  eventList.setAttribute("aria-busy", "true");
  if (!events.length) {
    eventList.innerHTML = '<p class="muted" role="status" aria-live="polite">Loading your events…</p>';
  } else if (summary) {
    summary.textContent = "Refreshing your event library…";
  }

  try {
    const data = await api("/api/dashboard");
    if (requestId !== dashboardLoadSequence) return false;
    events = Array.isArray(data.events) ? data.events : [];
    $("#statEvents").textContent = data.totals.events;
    $("#statPhotos").textContent = data.totals.photos;
    $("#statSelections").textContent = data.totals.selections;

    const used = data.storage?.used_bytes || 0;
    const limit = data.storage?.limit_bytes || 1;
    const pct = Math.min(100, Math.round((used / limit) * 100));
    $("#statStorage").textContent = formatMb(used);
    $("#statStorageLimit").textContent = `of ${Math.round(limit / (1024 * 1024))} MB limit`;
    $("#storageProgress").value = pct;

    eventList.removeAttribute("aria-busy");
    renderDashboardEvents();
    return true;
  } catch (err) {
    if (requestId !== dashboardLoadSequence) return false;
    eventList.removeAttribute("aria-busy");
    if (err.status === 401) {
      location.href = "/";
      return false;
    }
    const message = err.message || "Your events could not be loaded.";
    if (events.length) {
      if (summary) {
        summary.textContent = `Could not refresh events: ${message} Showing the last loaded list.`;
        const retry = document.createElement("button");
        retry.type = "button";
        retry.className = "btn sm ghost";
        retry.textContent = "Retry";
        retry.onclick = () => loadDashboard();
        summary.append(" ", retry);
      }
    } else {
      eventList.innerHTML = `<div class="empty-card"><p class="error" role="alert">${esc(message)}</p><button class="btn sm ghost" type="button" data-retry-dashboard>Retry loading events</button></div>`;
      const retry = eventList.querySelector("[data-retry-dashboard]");
      if (retry) retry.onclick = () => loadDashboard();
      if (summary) summary.textContent = "The event library is temporarily unavailable.";
    }
    return false;
  }
}

async function manageEvent(eventId, options = {}) {
  const dialog = $("#manageDialog");
  const content = $("#manageContent");
  const sameOpenEvent = currentEventId === eventId && dialog.open;
  const previousManageFocusId = sameOpenEvent ? document.activeElement?.id || "" : "";
  const previousManagePhotoQuery = sameOpenEvent ? $("#managePhotoSearch")?.value || "" : "";
  const requestId = ++manageEventRequestSequence;
  const isSameEventWorkspaceVisible = () => currentEventId === eventId && dialog.open;
  if (!sameOpenEvent) {
    indexingAbort = true;
    indexingRunSequence += 1;
  }
  currentEventId = eventId;

  content.setAttribute("aria-busy", "true");
  content.innerHTML = '<div class="empty-card"><button class="close" id="manageLoadingClose" type="button" aria-label="Close">×</button><h2 id="manageDialogTitle" tabindex="-1">Event workspace</h2><p class="muted" role="status" aria-live="polite">Loading event details…</p></div>';
  if (!dialog.open) dialog.showModal();
  $("#manageLoadingClose").onclick = () => dialog.close();

  let data;
  try {
    data = await api(`/api/events/${encodeURIComponent(eventId)}`);
  } catch (err) {
    if (requestId !== manageEventRequestSequence || !dialog.open) return false;
    content.removeAttribute("aria-busy");
    content.innerHTML = `<div class="empty-card"><button class="close" id="manageErrorClose" type="button" aria-label="Close">×</button><h2 id="manageDialogTitle" tabindex="-1">Event workspace unavailable</h2><p class="error" role="alert">${esc(err.message || "Event details could not be loaded.")}</p><button class="btn sm ghost" id="manageRetryBtn" type="button">Retry</button></div>`;
    $("#manageErrorClose").onclick = () => dialog.close();
    $("#manageRetryBtn").onclick = () => manageEvent(eventId, options);
    return false;
  }
  if (requestId !== manageEventRequestSequence || !dialog.open) return false;
  content.removeAttribute("aria-busy");
  if (!sameOpenEvent) indexingAbort = false;
  const e = data.event;
  const canWrite = hasPerm("events:write");
  const canUpload = hasPerm("photos:upload");
  const canDeletePhoto = hasPerm("photos:delete");
  const canSelections = hasPerm("selections:read");
  const canAiIndex = hasPerm("ai:index");

  $("#manageContent").innerHTML = `
    <div class="manage-sticky-head">
      <button class="close" id="manageClose" type="button" aria-label="Close">×</button>
      <p class="eyebrow">EVENT CONTROL</p>
      <h2 id="manageDialogTitle" tabindex="-1">${esc(e.title)} <span class="badge ${esc(e.status)}">${esc(e.status)}</span></h2>
      <p class="muted">
        Access code: <b>${esc(e.access_code)}</b>
        · ${e.has_pin ? "PIN protected" : "No PIN"}
        · ${e.is_public ? "Publicly listed" : "Private link"}
        · AI Discovery: ${e.ai_enabled ? (e.selfie_only ? "Selfie-only delivery" : "Enabled (browse all)") : "Off"}
      </p>

      <div class="manage-actions">
        <button class="btn ghost" id="qrBtn" type="button" aria-controls="dynamicPanel" aria-pressed="false">Generate QR</button>
        ${
          canUpload
            ? `<label class="btn ghost upload-btn" for="photoUpload">
                ＋ Upload photos
                <input type="file" id="photoUpload" accept="image/jpeg,image/png,image/webp,image/gif" multiple hidden>
              </label>`
            : ""
        }
        ${
          canSelections
            ? `<button class="btn ghost" id="selectionBtn" type="button" aria-controls="dynamicPanel" aria-pressed="false">Selections (${data.stats.selections})</button>`
            : ""
        }
        ${
          canWrite
            ? `<button class="btn ghost" id="editToggleBtn" type="button" aria-controls="editEventBox" aria-expanded="false" aria-pressed="false">Event settings</button>`
            : ""
        }
        ${
          e.ai_enabled && canAiIndex
            ? `<button class="btn ghost" id="indexFacesBtn" type="button" aria-controls="dynamicPanel" aria-pressed="false">Index faces (${data.stats.indexed_faces})</button>`
            : ""
        }
        <a class="btn ghost" target="_blank" href="/gallery/${encodeURIComponent(e.access_code)}">Open gallery ↗</a>
      </div>
    </div>

    ${
      canUpload
        ? `<div id="photoDropzone" class="photo-dropzone" tabindex="0" role="button" aria-label="Drop photos here or choose files to upload">
            <span class="photo-dropzone-icon" aria-hidden="true">↥</span>
            <strong>Drop photos here</strong>
            <span>or use Upload photos above · JPEG, PNG, WebP or GIF</span>
          </div>`
        : ""
    }


    <p id="manageStatus" class="muted" role="status" aria-live="polite"></p>
    <progress id="uploadProgress" class="upload-progress hidden" max="100" value="0" aria-label="Photo upload progress"></progress>
    <p id="manageError" class="error" role="alert"></p>
    <div id="dynamicPanel" aria-live="polite"></div>

    ${
      canWrite
        ? `
      <div id="editEventBox" class="panel-box hidden">
        <form id="editEventForm">
          <h3>Edit event settings</h3>
          <div class="form-grid">
            <label>Title<input name="title" value="${esc(e.title)}" required></label>
            <label>Status
              <select name="status">
                <option value="active" ${e.status === "active" ? "selected" : ""}>Active</option>
                <option value="paused" ${e.status === "paused" ? "selected" : ""}>Paused</option>
                <option value="archived" ${e.status === "archived" ? "selected" : ""}>Archived</option>
              </select>
            </label>
            <label>Date<input name="event_date" type="date" value="${esc(e.event_date || "")}"></label>
            <label>Venue<input name="venue" value="${esc(e.venue || "")}"></label>
          </div>
          <label>Description<textarea name="description" rows="2">${esc(e.description || "")}</textarea></label>
          <label>New Guest PIN (leave blank to keep existing)<input name="pin" minlength="4" maxlength="16" placeholder="${e.has_pin ? "PIN is currently set" : "No PIN set"}"></label>
          ${e.has_pin ? '<label class="inline"><input type="checkbox" name="clear_pin"> Remove existing PIN</label>' : ""}
          <label class="inline"><input type="checkbox" name="is_public" ${e.is_public ? "checked" : ""}> Publicly listed event</label>
          <label class="inline"><input type="checkbox" name="ai_enabled" ${e.ai_enabled ? "checked" : ""}> Enable opt-in AI face discovery</label>
          <label class="inline"><input type="checkbox" name="selfie_only" ${e.selfie_only ? "checked" : ""} ${e.ai_enabled ? "" : "disabled"}> Private selfie-only delivery (guests only see photos matching their selfie)</label>
          <div class="manage-actions">
            <button class="btn" type="submit">Save changes</button>
            <button class="btn danger" id="deleteEventBtn" type="button">Delete event</button>
          </div>
        </form>
      </div>`
        : ""
    }

    ${
      canDeletePhoto && data.photos.length
        ? `
      <div class="bulk-photo-bar">
        <label class="inline"><input type="checkbox" id="selectAllPhotos"> <span>Select all (${data.photos.length})</span></label>
        <span id="selectedPhotosCount" class="muted">0 selected</span>
        <div class="bulk-photo-actions">
          <button class="btn sm ghost hidden" id="clearSelectedPhotosBtn" type="button">Clear</button>
          <button class="btn sm danger hidden" id="bulkDeletePhotosBtn" type="button">Delete selected (0)</button>
        </div>
      </div>`
        : ""
    }

    ${data.photos.length ? `<div class="manage-photo-tools">
      <label for="managePhotoSearch"><span class="sr-only">Search event photos</span><input id="managePhotoSearch" type="search" placeholder="Search photos by filename or caption…" autocomplete="off"></label>
      <span id="managePhotoSearchCount" class="muted">${data.photos.length} photos</span>
    </div>` : ""}

    <div class="manage-photo-grid">
      ${
        data.photos.length
          ? data.photos
              .map(
                (p) => `
              <div class="manage-photo-card" data-photo-card="${esc(p.id)}">
                ${
                  canDeletePhoto
                    ? `<label class="photo-select-toggle">
                        <input type="checkbox" class="photo-select-cb" data-select-photo="${esc(p.id)}" aria-label="Select ${esc(p.original_name)}">
                        <span>Select</span>
                      </label>`
                    : ""
                }
                <img src="${esc(p.thumb_url)}" alt="${esc(p.original_name)}">
                <div class="photo-card-meta">
                  <span class="photo-card-name" title="${esc(p.original_name)}">${esc(p.original_name)}</span>
                  <span class="photo-card-faces">${p.face_indexed ? `${p.face_count} faces` : "Not indexed"}</span>
                </div>
                <input type="text" value="${esc(p.caption || "")}" placeholder="Add caption…" aria-label="Caption for ${esc(p.original_name)}" data-caption-input="${esc(p.id)}" ${canWrite ? "" : "disabled"}>
                <div class="row">
                  ${canWrite ? `<button class="btn sm ghost" data-save-caption="${esc(p.id)}" aria-label="Save caption for ${esc(p.original_name)}" type="button">Save</button>` : ""}
                  ${canDeletePhoto ? `<button class="btn sm danger" data-delete-photo="${esc(p.id)}" aria-label="Remove photo ${esc(p.original_name)}" type="button">Remove</button>` : ""}
                </div>
              </div>
            `
              )
              .join("")
          : '<div class="empty-card"><span>No photos uploaded yet.</span><small>Use "＋ Upload photos" above to add images.</small></div>'
      }
    </div>
  `;

  setPhotoUploadUiBusy(photoUploadInProgress);

  const managePhotoSearch = $("#managePhotoSearch");
  if (managePhotoSearch) {
    managePhotoSearch.value = previousManagePhotoQuery;
    const photoCards = [...document.querySelectorAll(".manage-photo-card")];
    const count = $("#managePhotoSearchCount");
    const applyPhotoSearch = () => {
      const query = managePhotoSearch.value.trim().toLocaleLowerCase();
      let visible = 0;
      photoCards.forEach((card) => {
        const caption = card.querySelector("[data-caption-input]")?.value || "";
        const searchable = `${card.querySelector(".photo-card-name, small")?.textContent || ""} ${caption}`.toLocaleLowerCase();
        const matches = !query || searchable.includes(query);
        card.hidden = !matches;
        if (matches) visible++;
      });
      count.textContent = query ? `${visible} of ${photoCards.length} photos` : `${photoCards.length} photos`;
      let empty = $("#managePhotoNoResults");
      if (!visible && photoCards.length) {
        if (!empty) {
          empty = document.createElement("p");
          empty.id = "managePhotoNoResults";
          empty.className = "empty-card manage-photo-no-results";
          empty.textContent = "No photos match your search. Try another filename or caption.";
          $(".manage-photo-grid").append(empty);
        }
      } else if (empty) empty.remove();
    };
    managePhotoSearch.addEventListener("input", applyPhotoSearch);
    if (previousManagePhotoQuery) applyPhotoSearch();
  }

  if (!dialog.open) dialog.showModal();
  if (sameOpenEvent && previousManageFocusId) {
    const previousFocus = document.getElementById(previousManageFocusId);
    if (previousFocus && content.contains(previousFocus)) previousFocus.focus({ preventScroll: true });
    else $("#manageDialogTitle").focus({ preventScroll: true });
  } else {
    $("#manageClose").focus({ preventScroll: true });
  }

  const unindexedOnOpen = data.photos.filter((p) => !p.face_indexed).length;
  if (e.ai_enabled && e.selfie_only && unindexedOnOpen > 0 && canAiIndex) {
    $("#manageStatus").textContent = `Selfie-only mode is active (${unindexedOnOpen} unindexed photo(s)). Click Index faces (${data.stats.indexed_faces}) so guests can scan and unlock their photos.`;
  }

  $("#manageClose").onclick = () => {
    indexingAbort = true;
    $("#manageDialog").close();
  };

  let activeManageTab = "";
  let managePanelRequestSequence = 0;
  function setActiveManageTab(tabId) {
    const changed = activeManageTab !== tabId;
    activeManageTab = tabId;
    if (changed) {
      managePanelRequestSequence += 1;
      $("#dynamicPanel").removeAttribute("aria-busy");
    }
    document.querySelectorAll(".manage-sticky-head .manage-actions button").forEach((btn) => {
      const active = Boolean(tabId) && btn.id === tabId;
      btn.classList.toggle("is-active-tab", active);
      btn.setAttribute("aria-pressed", String(active));
    });
    const editToggle = $("#editToggleBtn");
    if (editToggle) editToggle.setAttribute("aria-expanded", String(tabId === "editToggleBtn"));
  }

  function isCurrentManagePanelRequest(panelRequestId, tabId) {
    return panelRequestId === managePanelRequestSequence &&
      activeManageTab === tabId &&
      requestId === manageEventRequestSequence &&
      currentEventId === eventId &&
      dialog.open;
  }

  if ($("#editToggleBtn")) {
    $("#editToggleBtn").onclick = () => {
      const box = $("#editEventBox");
      const opening = box.classList.contains("hidden");
      $("#dynamicPanel").innerHTML = "";
      box.classList.toggle("hidden", !opening);
      setActiveManageTab(opening ? "editToggleBtn" : "");
      if (opening) {
        box.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    };
  }

  $("#qrBtn").onclick = async () => {
    $("#manageError").textContent = "";
    if ($("#editEventBox")) $("#editEventBox").classList.add("hidden");
    if (activeManageTab === "qrBtn") {
      $("#dynamicPanel").innerHTML = "";
      setActiveManageTab("");
      return;
    }
    setActiveManageTab("qrBtn");
    const panelRequestId = managePanelRequestSequence;
    const panel = $("#dynamicPanel");
    const trigger = $("#qrBtn");
    const originalLabel = trigger.textContent;
    trigger.disabled = true;
    trigger.textContent = "Generating QR…";
    trigger.setAttribute("aria-busy", "true");
    panel.setAttribute("aria-busy", "true");
    panel.innerHTML = '<div class="panel-box"><p class="muted" role="status" aria-live="polite">Generating event QR code…</p></div>';
    try {
      const q = await api(`/api/events/${encodeURIComponent(eventId)}/qr`, { method: "POST" });
      if (!isCurrentManagePanelRequest(panelRequestId, "qrBtn")) return;
      panel.innerHTML = `
        <div class="panel-box qr-panel-row">
          <img class="qr-large" src="${q.qr}" alt="Event QR Code">
          <div class="qr-panel-meta">
            <h3>Guest Event QR Code</h3>
            <p class="muted">Share link: <a target="_blank" href="${esc(q.url)}">${esc(q.url)}</a></p>
            <div>
              <a class="btn sm" href="${q.qr}" download="snapfind-${esc(e.access_code)}.png">Download QR PNG</a>
            </div>
          </div>
        </div>
      `;
    } catch (err) {
      if (!isCurrentManagePanelRequest(panelRequestId, "qrBtn")) return;
      panel.innerHTML = `<div class="empty-card"><p class="error" role="alert">${esc(err.message || "QR code could not be generated.")}</p><button class="btn sm ghost" id="retryQrPanelBtn" type="button">Retry</button></div>`;
      setActiveManageTab("");
      $("#retryQrPanelBtn").onclick = () => $("#qrBtn").click();
    } finally {
      if (isCurrentManagePanelRequest(panelRequestId, "qrBtn")) panel.removeAttribute("aria-busy");
      if (trigger.isConnected) {
        trigger.disabled = false;
        trigger.textContent = originalLabel;
        trigger.removeAttribute("aria-busy");
      }
    }
  };

  if ($("#photoUpload")) {
    const handlePhotoUpload = async (incomingFiles) => {
      if (photoUploadInProgress) {
        if ($("#manageStatus")) $("#manageStatus").textContent = "A photo upload is already in progress. Please wait before starting another.";
        return;
      }
      const acceptedTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
      const files = [...incomingFiles].filter((file) => acceptedTypes.has(file.type));
      const rejectedTypes = [...incomingFiles].filter((file) => !acceptedTypes.has(file.type));
      if (!files.length) {
        if ($("#manageStatus")) $("#manageStatus").textContent = "";
        if (rejectedTypes.length && $("#manageError")) $("#manageError").textContent = "Choose JPEG, PNG, WebP or GIF photo files.";
        return;
      }

      photoUploadInProgress = true;
      setPhotoUploadUiBusy(true);
      const setManageStatus = (message) => {
        if ($("#manageDialog").open && currentEventId === eventId && $("#manageStatus")) {
          $("#manageStatus").textContent = message;
        }
      };
      let uploadProgress = null;

      try {
        const unsupportedMessage = rejectedTypes.length ? "Skipped " + rejectedTypes.length + " unsupported file(s). " : "";
        if ($("#manageError")) $("#manageError").textContent = "";
        uploadProgress = $("#uploadProgress");
        uploadProgress.value = 0;
        uploadProgress.classList.remove("hidden");


      const canIndexOnUpload = Boolean(e.ai_enabled && window.SnapFindFace);
      if (canIndexOnUpload) {
        setManageStatus("Loading face models to auto-index uploads…");
        try {
          await window.SnapFindFace.loadFaceModels();
        } catch {
          // Proceed with upload; fallback indexing will catch unindexed photos
        }
      }

      // Upload in <= 3 MB / max 3-file batches so serverless limits never reject large selections
      const batches = [];
      let currentBatch = [];
      let currentBytes = 0;
      for (const file of files) {
        if (
          currentBatch.length > 0 &&
          (currentBatch.length >= 3 || currentBytes + file.size > 3 * 1024 * 1024)
        ) {
          batches.push(currentBatch);
          currentBatch = [];
          currentBytes = 0;
        }
        currentBatch.push(file);
        currentBytes += file.size;
      }
      if (currentBatch.length) batches.push(currentBatch);

      let uploadedCount = 0;
      let indexedFacesTotal = 0;
      const allRejected = [];

      try {
        let processedOffset = 0;
        for (const batch of batches) {
          const fd = new FormData();
          const faceEntries = [];

          for (let i = 0; i < batch.length; i++) {
            const f = batch[i];
            const overallIdx = processedOffset + i + 1;
            fd.append("photos", f);

            if (canIndexOnUpload) {
              setManageStatus(`Scanning faces (${overallIdx}/${files.length}): ${f.name}…`);
              try {
                const extracted = await window.SnapFindFace.extractEventFaces(f);
                faceEntries.push({ indexed: true, descriptors: extracted.descriptors });
              } catch {
                faceEntries.push({ indexed: false, descriptors: [] });
              }
              uploadProgress.value = Math.round((overallIdx / files.length) * 50);
            }
          }

          if (canIndexOnUpload && faceEntries.length) {
            fd.append("face_entries", JSON.stringify(faceEntries));
          }

          uploadProgress.value = (canIndexOnUpload ? 50 : 0) + Math.round((processedOffset / files.length) * (canIndexOnUpload ? 50 : 100));
          setManageStatus(`Uploading & saving (${processedOffset + batch.length}/${files.length})…`);
          const result = await api(`/api/events/${encodeURIComponent(eventId)}/photos`, {
            method: "POST",
            body: fd,
          });
          uploadedCount += (result.photos || []).length;
          indexedFacesTotal += Number(result.faces_indexed_total || 0);
          if (result.rejected?.length) allRejected.push(...result.rejected);
          processedOffset += batch.length;
          uploadProgress.value = (canIndexOnUpload ? 50 : 0) + Math.round((processedOffset / files.length) * (canIndexOnUpload ? 50 : 100));
        }

        const refreshManage = $("#manageDialog").open && currentEventId === eventId
          ? manageEvent(eventId)
          : Promise.resolve(false);
        await Promise.all([loadDashboard(), refreshManage]);
        const manageIsCurrent = $("#manageDialog").open && currentEventId === eventId && $("#manageStatus") && $("#manageError");
        if (manageIsCurrent) {
          if (allRejected.length) {
            $("#manageError").textContent = unsupportedMessage + `Skipped ${allRejected.length} invalid file(s): ${allRejected.map((r) => r.name).join(", ")}`;
          } else if (unsupportedMessage) {
            $("#manageError").textContent = unsupportedMessage;
          }
          if (uploadedCount > 0) {
            $("#manageStatus").textContent = canIndexOnUpload
              ? `Uploaded ${uploadedCount} photo(s) and automatically indexed ${indexedFacesTotal} face(s).`
              : `Uploaded ${uploadedCount} photo(s) cleanly (EXIF stripped, WebP previews ready).`;
          }
        } else if (uploadedCount > 0) {
          showToast(`Uploaded ${uploadedCount} photo(s) to ${e.title}.`);
        }
      } catch (err) {
        const message = err.message || "Photo upload failed.";
        if ($("#manageDialog").open && currentEventId === eventId && $("#manageStatus") && $("#manageError")) {
          $("#manageStatus").textContent = "";
          $("#manageError").textContent = message;
        } else {
          showToast(`Photo upload failed: ${message}`);
        }
      }
      } catch (err) {
        const message = err.message || "Photo upload could not be prepared.";
        if ($("#manageDialog").open && currentEventId === eventId) {
          setManageStatus("");
          if ($("#manageError")) $("#manageError").textContent = message;
        } else {
          showToast(`Photo upload failed: ${message}`);
        }
      } finally {
        photoUploadInProgress = false;
        setPhotoUploadUiBusy(false);
        if (uploadProgress?.isConnected) {
          uploadProgress.classList.add("hidden");
          uploadProgress.value = 0;
        }
      }
    };

    $("#photoUpload").onchange = (ev) => {
      handlePhotoUpload(ev.target.files);
      ev.target.value = "";
    };

    const dropzone = $("#photoDropzone");
    if (dropzone) {
      dropzone.addEventListener("click", () => {
        if (!photoUploadInProgress) $("#photoUpload").click();
      });
      ["dragenter", "dragover"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (ev) => {
          ev.preventDefault(); ev.stopPropagation(); dropzone.classList.add("is-dragover");
        });
      });
      ["dragleave", "dragend"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (ev) => {
          ev.preventDefault();
          if (!dropzone.contains(ev.relatedTarget)) dropzone.classList.remove("is-dragover");
        });
      });
      dropzone.addEventListener("drop", (ev) => {
        ev.preventDefault(); ev.stopPropagation(); dropzone.classList.remove("is-dragover");
        if (!photoUploadInProgress && ev.dataTransfer && ev.dataTransfer.files.length) handlePhotoUpload(ev.dataTransfer.files);
      });
      dropzone.addEventListener("keydown", (ev) => {
        if (photoUploadInProgress) {
          if (ev.key === "Enter" || ev.key === " ") ev.preventDefault();
          return;
        }
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); $("#photoUpload").click(); }
      });
    }
  }

  if ($("#selectionBtn")) {
    $("#selectionBtn").onclick = async () => {
      $("#manageError").textContent = "";
      if ($("#editEventBox")) $("#editEventBox").classList.add("hidden");
      if (activeManageTab === "selectionBtn") {
        $("#dynamicPanel").innerHTML = "";
        setActiveManageTab("");
        return;
      }
      setActiveManageTab("selectionBtn");
      const panelRequestId = managePanelRequestSequence;
      const panel = $("#dynamicPanel");
      const trigger = $("#selectionBtn");
      const originalLabel = trigger.textContent;
      trigger.disabled = true;
      trigger.textContent = "Loading selections…";
      trigger.setAttribute("aria-busy", "true");
      panel.setAttribute("aria-busy", "true");
      panel.innerHTML = '<div class="panel-box"><p class="muted" role="status" aria-live="polite">Loading guest selections…</p></div>';
      try {
        const res = await api(`/api/events/${encodeURIComponent(eventId)}/selections`);
        if (!isCurrentManagePanelRequest(panelRequestId, "selectionBtn")) return;
        panel.innerHTML = `
          <div class="panel-box">
            <h3>Guest selections (${res.selections.length})</h3>
            <div class="selection-list">
              ${
                res.selections.length
                  ? res.selections
                      .map(
                        (x) => `
                      <div class="selection-item">
                        <img src="${esc(x.thumb_url)}" alt="${esc(x.original_name)}">
                        <div>
                          <b>${esc(x.original_name || x.filename)}</b>
                          <p class="muted">${esc(x.guest_name || "Guest")} · ${esc(x.guest_email || "No email")} · ${esc(x.created_at)}</p>
                        </div>
                      </div>
                    `
                      )
                      .join("")
                  : '<p class="muted">No guest selections yet.</p>'
              }
            </div>
          </div>
        `;
      } catch (err) {
        if (!isCurrentManagePanelRequest(panelRequestId, "selectionBtn")) return;
        panel.innerHTML = `<div class="empty-card"><p class="error" role="alert">${esc(err.message || "Guest selections could not be loaded.")}</p><button class="btn sm ghost" id="retrySelectionsPanelBtn" type="button">Retry</button></div>`;
        setActiveManageTab("");
        $("#retrySelectionsPanelBtn").onclick = () => $("#selectionBtn").click();
      } finally {
        if (isCurrentManagePanelRequest(panelRequestId, "selectionBtn")) panel.removeAttribute("aria-busy");
        if (trigger.isConnected) {
          trigger.disabled = false;
          trigger.textContent = originalLabel;
          trigger.removeAttribute("aria-busy");
        }
      }
    };
  }

  if ($("#editEventForm")) {
    const editAiCb = $("#editEventForm").elements.ai_enabled;
    const editSelfieCb = $("#editEventForm").elements.selfie_only;
    if (editAiCb && editSelfieCb) {
      editAiCb.onchange = () => {
        editSelfieCb.disabled = !editAiCb.checked;
        if (!editAiCb.checked) editSelfieCb.checked = false;
      };
    }
    $("#editEventForm").onsubmit = async (ev) => {
      ev.preventDefault();
      $("#manageError").textContent = "";
      const fd = new FormData(ev.target);
      const payload = {
        title: fd.get("title"),
        status: fd.get("status"),
        event_date: fd.get("event_date"),
        venue: fd.get("venue"),
        description: fd.get("description"),
        is_public: fd.has("is_public"),
        ai_enabled: fd.has("ai_enabled"),
        selfie_only: fd.has("selfie_only"),
        clear_pin: fd.has("clear_pin"),
      };
      const pin = String(fd.get("pin") || "").trim();
      if (pin) payload.pin = pin;

      try {
        await api(`/api/events/${encodeURIComponent(eventId)}`, {
          method: "PATCH",
          body: JSON.stringify(payload),
        });
        const refreshManage = isSameEventWorkspaceVisible() ? manageEvent(eventId) : Promise.resolve(false);
        await Promise.all([loadDashboard(), refreshManage]);
        if ($("#manageDialog").open && currentEventId === eventId && $("#manageStatus")) {
          $("#manageStatus").textContent = "Event settings updated.";
        } else {
          showToast("Event settings updated.");
        }
      } catch (err) {
        if (isSameEventWorkspaceVisible() && $("#manageError")) $("#manageError").textContent = err.message;
        else showToast(`Event settings update failed: ${err.message}`);
      }
    };
    addDashboardPendingState("editEventForm", "Saving event settings…");

    let deleteArmed = false;
    const deleteEventButton = $("#deleteEventBtn");
    const originalDeleteLabel = deleteEventButton.textContent;
    const originalDeleteAriaLabel = deleteEventButton.getAttribute("aria-label");
    deleteEventButton.onclick = async () => {
      if (!deleteArmed) {
        deleteArmed = true;
        deleteEventButton.textContent = "Click again to confirm delete";
        deleteEventButton.setAttribute("aria-label", "Confirm deletion of this event");
        return;
      }
      if (deleteEventButton.disabled) return;
      deleteEventButton.disabled = true;
      deleteEventButton.textContent = "Deleting event…";
      deleteEventButton.setAttribute("aria-busy", "true");
      $("#manageError").textContent = "";
      try {
        await api(`/api/events/${encodeURIComponent(eventId)}`, { method: "DELETE" });
        deleteArmed = false;
        const sameEventStillOpen = isSameEventWorkspaceVisible();
        if (sameEventStillOpen) dialog.close();
        await loadDashboard();
        if (!sameEventStillOpen) showToast(`Event "${e.title}" was deleted.`);
      } catch (err) {
        deleteArmed = false;
        if (isSameEventWorkspaceVisible() && $("#manageError")) $("#manageError").textContent = err.message;
        else showToast(`Event could not be deleted: ${err.message}`);
      } finally {
        if (deleteEventButton.isConnected) {
          deleteEventButton.disabled = false;
          deleteEventButton.textContent = originalDeleteLabel;
          if (originalDeleteAriaLabel) deleteEventButton.setAttribute("aria-label", originalDeleteAriaLabel);
          else deleteEventButton.removeAttribute("aria-label");
          deleteEventButton.removeAttribute("aria-busy");
        }
      }
    };
  }

  if ($("#indexFacesBtn")) {
    $("#indexFacesBtn").onclick = () => {
      if ($("#editEventBox")) $("#editEventBox").classList.add("hidden");
      $("#dynamicPanel").innerHTML = "";
      setActiveManageTab("indexFacesBtn");
      runStudioFaceIndexing(eventId, data.photos);
    };
  }

  document.querySelectorAll("[data-save-caption]").forEach((btn) => {
    btn.onclick = async () => {
      if (btn.disabled) return;
      const pid = btn.dataset.saveCaption;
      const input = document.querySelector(`[data-caption-input="${CSS.escape(pid)}"]`);
      if (!input) return;
      const originalLabel = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Saving…";
      btn.setAttribute("aria-busy", "true");
      $("#manageError").textContent = "";
      try {
        await api(`/api/photos/${encodeURIComponent(pid)}`, {
          method: "PATCH",
          body: JSON.stringify({ caption: input.value }),
        });
        if (isSameEventWorkspaceVisible() && $("#manageStatus")) $("#manageStatus").textContent = "Caption saved.";
        else showToast("Photo caption saved.");
      } catch (err) {
        if (isSameEventWorkspaceVisible() && $("#manageError")) $("#manageError").textContent = err.message;
        else showToast(`Caption could not be saved: ${err.message}`);
      } finally {
        if (btn.isConnected) {
          btn.disabled = false;
          btn.textContent = originalLabel;
          btn.removeAttribute("aria-busy");
        }
      }
    };
  });

  document.querySelectorAll("[data-delete-photo]").forEach((btn) => {
    let armed = false;
    const originalLabel = btn.textContent;
    const originalAriaLabel = btn.getAttribute("aria-label");
    btn.onclick = async () => {
      if (!armed) {
        armed = true;
        btn.textContent = "Confirm?";
        btn.setAttribute("aria-label", "Confirm removal of this photo");
        return;
      }
      if (btn.disabled) return;
      const pid = btn.dataset.deletePhoto;
      btn.disabled = true;
      btn.textContent = "Removing…";
      btn.setAttribute("aria-busy", "true");
      try {
        await api(`/api/photos/${encodeURIComponent(pid)}`, {
          method: "DELETE",
        });
        armed = false;
        const refreshManage = isSameEventWorkspaceVisible() ? manageEvent(eventId) : Promise.resolve(false);
        await Promise.all([loadDashboard(), refreshManage]);
        if ($("#manageDialog").open && currentEventId === eventId && $("#manageStatus")) {
          $("#manageStatus").textContent = "Photo removed.";
        } else {
          showToast("Photo removed.");
        }
      } catch (err) {
        if (isSameEventWorkspaceVisible() && $("#manageError")) $("#manageError").textContent = err.message;
        else showToast(`Photo could not be removed: ${err.message}`);
        armed = false;
      } finally {
        if (btn.isConnected) {
          btn.disabled = false;
          btn.textContent = armed ? "Confirm?" : originalLabel;
          if (originalAriaLabel) btn.setAttribute("aria-label", originalAriaLabel);
          else btn.removeAttribute("aria-label");
          btn.removeAttribute("aria-busy");
        }
      }
    };
  });

  if (canDeletePhoto && data.photos.length) {
    const checkboxes = [...document.querySelectorAll(".photo-select-cb")];
    const selectAllEl = $("#selectAllPhotos");
    const countEl = $("#selectedPhotosCount");
    const clearBtn = $("#clearSelectedPhotosBtn");
    const bulkBtn = $("#bulkDeletePhotosBtn");
    let bulkArmed = false;
    let bulkDeleteInProgress = false;

    function syncBulkSelectionUi() {
      bulkArmed = false;
      const selected = checkboxes.filter((cb) => cb.checked);
      const total = checkboxes.length;
      const count = selected.length;

      checkboxes.forEach((cb) => {
        const card = cb.closest("[data-photo-card]");
        if (card) card.classList.toggle("is-selected", cb.checked);
        cb.disabled = bulkDeleteInProgress;
      });

      selectAllEl.checked = count > 0 && count === total;
      selectAllEl.indeterminate = count > 0 && count < total;
      selectAllEl.disabled = bulkDeleteInProgress;
      clearBtn.disabled = bulkDeleteInProgress;
      countEl.textContent = `${count} selected`;
      clearBtn.classList.toggle("hidden", count === 0);
      bulkBtn.classList.toggle("hidden", count === 0);
      bulkBtn.disabled = bulkDeleteInProgress;
      bulkBtn.textContent = bulkDeleteInProgress ? "Deleting…" : `Delete selected (${count})`;
    }

    checkboxes.forEach((cb) => {
      cb.onchange = syncBulkSelectionUi;
    });

    selectAllEl.onchange = () => {
      checkboxes.forEach((cb) => {
        cb.checked = selectAllEl.checked;
      });
      syncBulkSelectionUi();
    };

    clearBtn.onclick = () => {
      checkboxes.forEach((cb) => {
        cb.checked = false;
      });
      syncBulkSelectionUi();
    };

    bulkBtn.onclick = async () => {
      const photoIds = checkboxes.filter((cb) => cb.checked).map((cb) => cb.dataset.selectPhoto);
      if (!photoIds.length) return;
      if (!bulkArmed) {
        bulkArmed = true;
        bulkBtn.textContent = `Confirm delete (${photoIds.length})?`;
        return;
      }
      if (bulkDeleteInProgress || bulkBtn.disabled) return;
      $("#manageError").textContent = "";
      bulkDeleteInProgress = true;
      bulkBtn.setAttribute("aria-busy", "true");
      syncBulkSelectionUi();
      try {
        const res = await api(`/api/events/${encodeURIComponent(eventId)}/photos/bulk-delete`, {
          method: "POST",
          body: JSON.stringify({ photo_ids: photoIds }),
        });
        bulkArmed = false;
        const refreshManage = isSameEventWorkspaceVisible() ? manageEvent(eventId) : Promise.resolve(false);
        await Promise.all([loadDashboard(), refreshManage]);
        if ($("#manageDialog").open && currentEventId === eventId && $("#manageStatus")) {
          $("#manageStatus").textContent = `Deleted ${res.deleted_count} photo(s).`;
        } else {
          showToast(`Deleted ${res.deleted_count} photo(s).`);
        }
      } catch (err) {
        if (isSameEventWorkspaceVisible() && $("#manageError")) $("#manageError").textContent = err.message;
        else showToast(`Selected photos could not be deleted: ${err.message}`);
        bulkArmed = false;
      } finally {
        bulkDeleteInProgress = false;
        if (bulkBtn.isConnected) {
          bulkBtn.removeAttribute("aria-busy");
          syncBulkSelectionUi();
        }
      }
    };
  }

  if (sameOpenEvent && previousManageFocusId) {
    const focusTarget = document.getElementById(previousManageFocusId);
    if (focusTarget && !focusTarget.disabled && !focusTarget.closest(".hidden")) {
      focusTarget.focus({ preventScroll: true });
    }
  }

  if (!options.suppressAutoIndex && e.ai_enabled && canAiIndex && unindexedOnOpen > 0) {
    runStudioFaceIndexing(eventId, data.photos, false);
  }
}

async function runStudioFaceIndexing(eventId, photos, forceReindex = false) {
  if (!window.faceapi || !window.SnapFindFace) {
    $("#manageError").textContent = "Self-hosted face-api library could not be loaded.";
    return;
  }

  const runId = ++indexingRunSequence;
  indexingAbort = false;
  const targets = forceReindex ? photos : photos.filter((p) => !p.face_indexed);
  $("#dynamicPanel").innerHTML = `
    <div class="panel-box">
      <h3>AI Face Indexing</h3>
      <p class="muted" id="indexProgress" role="status" aria-live="polite">Loading self-hosted face models…</p>
      <div class="manage-actions">
        <button class="btn sm ghost" id="cancelIndexBtn" type="button">Cancel</button>
        <button class="btn sm ghost" id="reindexAllBtn" type="button">Re-index all photos (${photos.length})</button>
        <button class="btn sm danger" id="clearIndexBtn" type="button">Clear AI index</button>
      </div>
    </div>
  `;

  $("#cancelIndexBtn").onclick = () => {
    if (runId !== indexingRunSequence || indexingAbort) return;
    indexingAbort = true;
    const button = $("#cancelIndexBtn");
    button.disabled = true;
    button.textContent = "Stopping…";
    button.setAttribute("aria-busy", "true");
    $("#indexProgress").textContent = "Stopping after any in-flight face operation…";
  };

  $("#reindexAllBtn").onclick = async () => {
    if (runId !== indexingRunSequence) return;
    indexingAbort = true;
    const resetRunId = ++indexingRunSequence;
    const controls = [$("#cancelIndexBtn"), $("#reindexAllBtn"), $("#clearIndexBtn")].filter(Boolean);
    controls.forEach((button) => {
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    });
    try {
      $("#indexProgress").textContent = "Waiting for the current save, then preparing a fresh scan…";
      if (indexingSavePromise) await indexingSavePromise.catch(() => {});
      if (resetRunId !== indexingRunSequence) return;
      await api(`/api/events/${encodeURIComponent(eventId)}/faces`, { method: "DELETE" });
      if (resetRunId !== indexingRunSequence) return;
      await runStudioFaceIndexing(eventId, photos.map((p) => ({ ...p, face_indexed: 0 })), true);
    } catch (err) {
      if (resetRunId === indexingRunSequence) {
        $("#manageError").textContent = err.message;
        $("#indexProgress").textContent = "Re-index could not start. Close and reopen this event before trying again.";
        controls.forEach((button) => {
          if (!button.isConnected) return;
          button.disabled = true;
          button.removeAttribute("aria-busy");
        });
      }
    }
  };

  $("#clearIndexBtn").onclick = async () => {
    if (runId !== indexingRunSequence) return;
    indexingAbort = true;
    const clearRunId = ++indexingRunSequence;
    const controls = [$("#cancelIndexBtn"), $("#reindexAllBtn"), $("#clearIndexBtn")].filter(Boolean);
    controls.forEach((button) => {
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    });
    try {
      $("#indexProgress").textContent = "Waiting for the current save, then clearing the AI index…";
      if (indexingSavePromise) await indexingSavePromise.catch(() => {});
      if (clearRunId !== indexingRunSequence) return;
      await api(`/api/events/${encodeURIComponent(eventId)}/faces`, { method: "DELETE" });
      if (clearRunId !== indexingRunSequence) return;
      await loadDashboard();
      if (clearRunId !== indexingRunSequence) return;
      await manageEvent(eventId, { suppressAutoIndex: true });
      if (clearRunId !== indexingRunSequence) return;
      $("#manageStatus").textContent = "AI face index cleared. It will stay cleared until you choose to re-index.";
    } catch (err) {
      if (clearRunId === indexingRunSequence) {
        $("#manageError").textContent = err.message;
        $("#indexProgress").textContent = "The index could not be cleared. Close and reopen this event before trying again.";
        controls.forEach((button) => {
          if (!button.isConnected) return;
          button.disabled = true;
          button.removeAttribute("aria-busy");
        });
      }
    }
  };

  if (!targets.length) {
    $("#cancelIndexBtn").disabled = true;
    $("#cancelIndexBtn").classList.add("hidden");
    $("#indexProgress").textContent = "All uploaded photos in this event are already indexed. Use Re-index all photos to refresh with multi-angle detection.";
    return;
  }

  try {
    if (indexingSavePromise) await indexingSavePromise.catch(() => {});
    if (indexingAbort || runId !== indexingRunSequence) return;
    await window.SnapFindFace.loadFaceModels();
    if (indexingAbort || runId !== indexingRunSequence) return;

    const batch = [];
    let totalFacesFound = 0;
    for (let i = 0; i < targets.length; i++) {
      if (indexingAbort || runId !== indexingRunSequence) return;
      const p = targets[i];
      $("#indexProgress").textContent = `Analysing faces in photo ${i + 1} of ${targets.length} (${p.original_name})…`;
      const result = await window.SnapFindFace.extractEventFaces(p.preview_url);
      if (indexingAbort || runId !== indexingRunSequence) return;
      totalFacesFound += result.faceCount;

      batch.push({
        photo_id: p.id,
        descriptors: result.descriptors,
      });

      if (batch.length >= 10 || i === targets.length - 1) {
        const entries = batch.splice(0, batch.length);
        const savePromise = api(`/api/events/${encodeURIComponent(eventId)}/faces`, {
          method: "POST",
          body: JSON.stringify({ entries }),
        });
        indexingSavePromise = savePromise;
        try {
          await savePromise;
        } finally {
          if (indexingSavePromise === savePromise) indexingSavePromise = null;
        }
        if (indexingAbort || runId !== indexingRunSequence) return;
      }
    }

    await loadDashboard();
    if (indexingAbort || runId !== indexingRunSequence) return;
    await manageEvent(eventId, { suppressAutoIndex: true });
    if (indexingAbort || runId !== indexingRunSequence) return;
    $("#manageStatus").textContent = `Face indexing complete (${totalFacesFound} faces detected across ${targets.length} photo(s)).`;
  } catch (err) {
    if (!indexingAbort && runId === indexingRunSequence) {
      $("#manageError").textContent = err.message || "Face indexing failed";
    }
  } finally {
    if (indexingAbort && runId === indexingRunSequence) {
      const progress = $("#indexProgress");
      if (progress) progress.textContent = "Indexing stopped. You can re-index whenever you're ready.";
      const cancelButton = $("#cancelIndexBtn");
      if (cancelButton) {
        cancelButton.disabled = true;
        cancelButton.textContent = "Stopped";
        cancelButton.removeAttribute("aria-busy");
      }
    }
  }
}

$("#manageDialog").addEventListener("close", () => {
  manageEventRequestSequence += 1;
  indexingRunSequence += 1;
  indexingAbort = true;
});

$("#newEvent").onclick = () => {
  $("#eventError").textContent = "";
  if ($("#evAiEnabled") && $("#evSelfieOnly")) {
    $("#evSelfieOnly").disabled = !$("#evAiEnabled").checked;
    if (!$("#evAiEnabled").checked) $("#evSelfieOnly").checked = false;
  }
  $("#eventDialog").showModal();
};

$("#eventClose").onclick = () => $("#eventDialog").close();

$("#eventForm").onsubmit = async (e) => {
  e.preventDefault();
  const submitButton = e.submitter || e.target.querySelector('button[type="submit"]');
  const originalLabel = submitButton?.textContent || "Create event";
  $("#eventError").textContent = "";
  if (submitButton) {
    submitButton.disabled = true;
    submitButton.textContent = "Creating event…";
    submitButton.setAttribute("aria-busy", "true");
  }
  const fd = new FormData(e.target);
  const payload = {
    title: fd.get("title"),
    description: fd.get("description"),
    event_date: fd.get("event_date"),
    venue: fd.get("venue"),
    pin: fd.get("pin"),
    is_public: fd.has("is_public"),
    ai_enabled: fd.has("ai_enabled"),
    selfie_only: fd.has("selfie_only"),
  };

  try {
    await api("/api/events", { method: "POST", body: JSON.stringify(payload) });
    $("#eventDialog").close();
    e.target.reset();
    await loadDashboard();
  } catch (err) {
    $("#eventError").textContent = err.message;
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = originalLabel;
      submitButton.removeAttribute("aria-busy");
    }
  }
};

$("#profileForm").onsubmit = async (e) => {
  e.preventDefault();
  setStatusMsg("#profileMsg", "", false);
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    await api("/api/profile", { method: "PATCH", body: JSON.stringify(payload) });
    setStatusMsg("#profileMsg", "Studio profile saved.", false);
  } catch (err) {
    setStatusMsg("#profileMsg", err.message, true);
  }
};

$("#passwordForm").onsubmit = async (e) => {
  e.preventDefault();
  setStatusMsg("#passwordMsg", "", false);
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    const res = await api("/api/auth/password", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res.csrfToken) csrfToken = res.csrfToken;
    e.target.reset();
    setStatusMsg("#passwordMsg", "Password updated cleanly.", false);
    await loadSelfSessions();
  } catch (err) {
    setStatusMsg("#passwordMsg", err.message, true);
  }
};

async function performDashLogout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    // ignore logout error during sign-out transition
  }
  location.href = "/";
}

$("#logout").onclick = performDashLogout;
$("#topLogout").onclick = performDashLogout;

// Consistent single-flight feedback for account and team forms.
function addDashboardPendingState(formId, pendingLabel) {
  const form = document.getElementById(formId);
  if (!form || typeof form.onsubmit !== "function") return;
  const originalHandler = form.onsubmit;
  form.onsubmit = async function (event) {
    if (form.dataset.submitting === "true") {
      event.preventDefault();
      return;
    }
    form.dataset.submitting = "true";
    const button = event.submitter || form.querySelector('button[type="submit"]');
    const originalLabel = button?.textContent;
    if (button) {
      button.disabled = true;
      button.textContent = pendingLabel;
      button.setAttribute("aria-busy", "true");
    }
    try {
      return await originalHandler.call(this, event);
    } finally {
      delete form.dataset.submitting;
      if (button) {
        button.disabled = false;
        button.textContent = originalLabel;
        button.removeAttribute("aria-busy");
      }
    }
  };
}

addDashboardPendingState("staffForm", "Adding team member…");
addDashboardPendingState("profileForm", "Saving profile…");
addDashboardPendingState("passwordForm", "Updating password…");
addDashboardPendingState("forcePwForm", "Updating password…");

init().catch(() => {
  location.href = "/";
});

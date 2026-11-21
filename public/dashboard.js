const $ = (selector) => document.querySelector(selector);

let csrfToken = null;
let currentUser = null;
let currentEventId = null;
let events = [];
let indexingAbort = false;

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

async function init() {
  const meData = await api("/api/auth/me");
  const me = meData.user;
  csrfToken = meData.csrfToken;
  currentUser = me;
  if (!me) {
    location.href = "/";
    return;
  }

  $("#welcomeName").textContent = me.name.split(" ")[0];
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
  const d = await api("/api/auth/sessions");
  $("#selfSessionsWrap").innerHTML = d.sessions.length
    ? `<table>
        <tr><th>Device / Browser</th><th>IP</th><th>Created</th><th>Last seen</th><th>Action</th></tr>
        ${d.sessions
          .map(
            (s) => `
          <tr>
            <td>${esc(s.device_label)} ${s.current ? '<span class="badge">current</span>' : ""}</td>
            <td>${esc(s.ip)}</td>
            <td>${esc(s.created_at)}</td>
            <td>${esc(s.last_seen_at)}</td>
            <td>${
              s.current
                ? '<span class="muted">This device</span>'
                : `<button class="btn sm danger" data-revoke-self-sid="${esc(s.sid)}" type="button">Sign out</button>`
            }</td>
          </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted">No active sessions recorded.</p>';

  document.querySelectorAll("[data-revoke-self-sid]").forEach((btn) => {
    btn.onclick = async () => {
      await api(`/api/auth/sessions/${encodeURIComponent(btn.dataset.revokeSelfSid)}`, {
        method: "DELETE",
      });
      await loadSelfSessions();
    };
  });
}

async function loadStaff() {
  const d = await api("/api/studio/staff");
  $("#staffListWrap").innerHTML = d.staff.length
    ? `<table>
        <tr><th>Name</th><th>Email</th><th>Permissions</th><th>Status</th><th>Action</th></tr>
        ${d.staff
          .map(
            (s) => `
          <tr>
            <td>${esc(s.name)}</td>
            <td>${esc(s.email)}</td>
            <td>${s.staff_permissions.map((p) => `<span class="badge neutral">${esc(p)}</span>`).join(" ") || '<span class="muted">None</span>'}</td>
            <td><span class="badge ${s.status === "suspended" ? "warn" : ""}">${esc(s.status)}</span></td>
            <td>
              <button class="btn sm ghost" data-toggle-staff="${esc(s.id)}" data-next-status="${s.status === "active" ? "suspended" : "active"}" type="button">
                ${s.status === "active" ? "Suspend" : "Activate"}
              </button>
              <button class="btn sm danger" data-del-staff="${esc(s.id)}" type="button">Remove</button>
            </td>
          </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted">No staff members added yet.</p>';

  document.querySelectorAll("[data-toggle-staff]").forEach((btn) => {
    btn.onclick = async () => {
      await api(`/api/studio/staff/${encodeURIComponent(btn.dataset.toggleStaff)}`, {
        method: "PATCH",
        body: JSON.stringify({ status: btn.dataset.nextStatus }),
      });
      await loadStaff();
    };
  });

  document.querySelectorAll("[data-del-staff]").forEach((btn) => {
    let armed = false;
    btn.onclick = async () => {
      if (!armed) {
        armed = true;
        btn.textContent = "Confirm?";
        return;
      }
      await api(`/api/studio/staff/${encodeURIComponent(btn.dataset.delStaff)}`, {
        method: "DELETE",
      });
      await loadStaff();
    };
  });
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

async function loadDashboard() {
  const data = await api("/api/dashboard");
  events = data.events;
  $("#statEvents").textContent = data.totals.events;
  $("#statPhotos").textContent = data.totals.photos;
  $("#statSelections").textContent = data.totals.selections;

  const used = data.storage?.used_bytes || 0;
  const limit = data.storage?.limit_bytes || 1;
  const pct = Math.min(100, Math.round((used / limit) * 100));
  $("#statStorage").textContent = formatMb(used);
  $("#statStorageLimit").textContent = `of ${Math.round(limit / (1024 * 1024))} MB limit`;
  $("#storageProgress").value = pct;

  $("#eventList").innerHTML = events.length
    ? events
        .map(
          (e) => `
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
        `
        )
        .join("")
    : '<div class="empty">No events yet. Create your first event to get started.</div>';

  document.querySelectorAll("[data-manage]").forEach((btn) => {
    btn.onclick = () => {
      manageEvent(btn.dataset.manage).catch((err) => {
        showToast(err.message);
      });
    };
  });
}

async function manageEvent(eventId) {
  currentEventId = eventId;
  indexingAbort = false;
  const data = await api(`/api/events/${encodeURIComponent(eventId)}`);
  const e = data.event;
  const canWrite = hasPerm("events:write");
  const canUpload = hasPerm("photos:upload");
  const canDeletePhoto = hasPerm("photos:delete");
  const canSelections = hasPerm("selections:read");
  const canAiIndex = hasPerm("ai:index");

  $("#manageContent").innerHTML = `
    <button class="close" id="manageClose" type="button" aria-label="Close">×</button>
    <p class="eyebrow">EVENT CONTROL</p>
    <h2>${esc(e.title)} <span class="badge ${esc(e.status)}">${esc(e.status)}</span></h2>
    <p class="muted">
      Access code: <b>${esc(e.access_code)}</b>
      · ${e.has_pin ? "PIN protected" : "No PIN"}
      · ${e.is_public ? "Publicly listed" : "Private link"}
      · AI Discovery: ${e.ai_enabled ? (e.selfie_only ? "Selfie-only delivery" : "Enabled (browse all)") : "Off"}
    </p>

    <div class="manage-actions">
      <button class="btn" id="qrBtn" type="button">Generate QR</button>
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
          ? `<button class="btn ghost" id="selectionBtn" type="button">Selections (${data.stats.selections})</button>`
          : ""
      }
      ${
        canWrite
          ? `<button class="btn ghost" id="editToggleBtn" type="button">Event settings</button>`
          : ""
      }
      ${
        e.ai_enabled && canAiIndex
          ? `<button class="btn ghost" id="indexFacesBtn" type="button">Index faces (${data.stats.indexed_faces})</button>`
          : ""
      }
      <a class="btn ghost" target="_blank" href="/gallery/${encodeURIComponent(e.access_code)}">Open gallery ↗</a>
    </div>

    <p id="manageStatus" class="muted" role="status" aria-live="polite"></p>
    <progress id="uploadProgress" class="upload-progress hidden" max="100" value="0" aria-label="Photo upload progress"></progress>
    <p id="manageError" class="error" role="alert"></p>
    <div id="dynamicPanel"></div>

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
          <label class="inline"><input type="checkbox" name="selfie_only" ${e.selfie_only ? "checked" : ""}> Private selfie-only delivery (guests only see photos matching their selfie)</label>
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
        <label class="inline"><input type="checkbox" id="selectAllPhotos"> Select all (${data.photos.length})</label>
        <span id="selectedPhotosCount" class="muted">0 selected</span>
        <div class="bulk-photo-actions">
          <button class="btn sm ghost hidden" id="clearSelectedPhotosBtn" type="button">Clear</button>
          <button class="btn sm danger hidden" id="bulkDeletePhotosBtn" type="button">Delete selected (0)</button>
        </div>
      </div>`
        : ""
    }

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
                <small class="muted">${esc(p.original_name)} ${p.face_indexed ? `· ${p.face_count} faces` : ""}</small>
                <input type="text" value="${esc(p.caption || "")}" placeholder="Add caption…" data-caption-input="${esc(p.id)}" ${canWrite ? "" : "disabled"}>
                <div class="row">
                  ${canWrite ? `<button class="btn sm ghost" data-save-caption="${esc(p.id)}" type="button">Save</button>` : ""}
                  ${canDeletePhoto ? `<button class="btn sm danger" data-delete-photo="${esc(p.id)}" type="button">Remove</button>` : ""}
                </div>
              </div>
            `
              )
              .join("")
          : '<div class="empty-card"><span>No photos uploaded yet.</span><small>Use "＋ Upload photos" above to add images.</small></div>'
      }
    </div>
  `;

  if (!$("#manageDialog").open) {
    $("#manageDialog").showModal();
  }

  const unindexedOnOpen = data.photos.filter((p) => !p.face_indexed).length;
  if (e.ai_enabled && e.selfie_only && unindexedOnOpen > 0 && canAiIndex) {
    $("#manageStatus").textContent = `Selfie-only mode is active (${unindexedOnOpen} unindexed photo(s)). Click Index faces (${data.stats.indexed_faces}) so guests can scan and unlock their photos.`;
  }

  $("#manageClose").onclick = () => {
    indexingAbort = true;
    $("#manageDialog").close();
  };

  if ($("#editToggleBtn")) {
    $("#editToggleBtn").onclick = () => {
      const box = $("#editEventBox");
      box.classList.toggle("hidden");
      if (!box.classList.contains("hidden")) {
        box.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    };
  }

  $("#qrBtn").onclick = async () => {
    $("#manageError").textContent = "";
    try {
      const q = await api(`/api/events/${encodeURIComponent(eventId)}/qr`, { method: "POST" });
      $("#dynamicPanel").innerHTML = `
        <div class="panel-box">
          <img class="qr-large" src="${q.qr}" alt="Event QR Code">
          <p class="muted">Share link: <a target="_blank" href="${esc(q.url)}">${esc(q.url)}</a></p>
          <a class="btn sm" href="${q.qr}" download="snapfind-${esc(e.access_code)}.png">Download QR PNG</a>
        </div>
      `;
    } catch (err) {
      $("#manageError").textContent = err.message;
    }
  };

  if ($("#photoUpload")) {
    $("#photoUpload").onchange = async (ev) => {
      const files = [...ev.target.files];
      if (!files.length) return;
      $("#manageError").textContent = "";
      const uploadProgress = $("#uploadProgress");
      uploadProgress.value = 65;
      uploadProgress.classList.remove("hidden");
      ev.target.value = "";

      const canIndexOnUpload = Boolean(e.ai_enabled && window.SnapFindFace);
      if (canIndexOnUpload) {
        $("#manageStatus").textContent = "Loading face models to auto-index uploads…";
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
              $("#manageStatus").textContent = `Scanning faces (${overallIdx}/${files.length}): ${f.name}…`;
              try {
                const extracted = await window.SnapFindFace.extractEventFaces(f);
                faceEntries.push({ indexed: true, descriptors: extracted.descriptors });
                uploadProgress.value = Math.round((overallIdx / files.length) * 65);
              } catch {
                faceEntries.push({ indexed: false, descriptors: [] });
              }
            }
          }

          if (canIndexOnUpload && faceEntries.length) {
            fd.append("face_entries", JSON.stringify(faceEntries));
          }

          uploadProgress.value = 65 + Math.round((processedOffset / files.length) * 35);
          $("#manageStatus").textContent = `Uploading & saving (${processedOffset + batch.length}/${files.length})…`;
          const result = await api(`/api/events/${encodeURIComponent(eventId)}/photos`, {
            method: "POST",
            body: fd,
          });
          uploadedCount += (result.photos || []).length;
          indexedFacesTotal += Number(result.faces_indexed_total || 0);
          if (result.rejected?.length) allRejected.push(...result.rejected);
          processedOffset += batch.length;
          uploadProgress.value = 65 + Math.round((processedOffset / files.length) * 35);
        }

        await Promise.all([loadDashboard(), manageEvent(eventId)]);
        if (allRejected.length) {
          $("#manageError").textContent = `Skipped ${allRejected.length} invalid file(s): ${allRejected.map((r) => r.name).join(", ")}`;
        }
        if (uploadedCount > 0) {
          $("#manageStatus").textContent = canIndexOnUpload
            ? `Uploaded ${uploadedCount} photo(s) and automatically indexed ${indexedFacesTotal} face(s).`
            : `Uploaded ${uploadedCount} photo(s) cleanly (EXIF stripped, WebP previews ready).`;
        }
      } catch (err) {
        $("#manageStatus").textContent = "";
        $("#manageError").textContent = err.message;
      }
    };
  }

  if ($("#selectionBtn")) {
    $("#selectionBtn").onclick = async () => {
      $("#manageError").textContent = "";
      try {
        const res = await api(`/api/events/${encodeURIComponent(eventId)}/selections`);
        $("#dynamicPanel").innerHTML = `
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
        $("#manageError").textContent = err.message;
      }
    };
  }

  if ($("#editEventForm")) {
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
        await loadDashboard();
        await manageEvent(eventId);
        $("#manageStatus").textContent = "Event settings updated.";
      } catch (err) {
        $("#manageError").textContent = err.message;
      }
    };

    let deleteArmed = false;
    $("#deleteEventBtn").onclick = async () => {
      if (!deleteArmed) {
        deleteArmed = true;
        $("#deleteEventBtn").textContent = "Click again to confirm delete";
        return;
      }
      try {
        await api(`/api/events/${encodeURIComponent(eventId)}`, { method: "DELETE" });
        $("#manageDialog").close();
        await loadDashboard();
      } catch (err) {
        $("#manageError").textContent = err.message;
      }
    };
  }

  if ($("#indexFacesBtn")) {
    $("#indexFacesBtn").onclick = () => runStudioFaceIndexing(eventId, data.photos);
  }

  document.querySelectorAll("[data-save-caption]").forEach((btn) => {
    btn.onclick = async () => {
      const pid = btn.dataset.saveCaption;
      const input = document.querySelector(`[data-caption-input="${CSS.escape(pid)}"]`);
      try {
        await api(`/api/photos/${encodeURIComponent(pid)}`, {
          method: "PATCH",
          body: JSON.stringify({ caption: input.value }),
        });
        $("#manageStatus").textContent = "Caption saved.";
      } catch (err) {
        $("#manageError").textContent = err.message;
      }
    };
  });

  document.querySelectorAll("[data-delete-photo]").forEach((btn) => {
    let armed = false;
    btn.onclick = async () => {
      if (!armed) {
        armed = true;
        btn.textContent = "Confirm?";
        return;
      }
      btn.disabled = true;
      btn.textContent = "…";
      try {
        await api(`/api/photos/${encodeURIComponent(btn.dataset.deletePhoto)}`, {
          method: "DELETE",
        });
        await Promise.all([loadDashboard(), manageEvent(eventId)]);
      } catch (err) {
        $("#manageError").textContent = err.message;
        btn.disabled = false;
        armed = false;
        btn.textContent = "Remove";
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

    function syncBulkSelectionUi() {
      bulkArmed = false;
      const selected = checkboxes.filter((cb) => cb.checked);
      const total = checkboxes.length;
      const count = selected.length;

      checkboxes.forEach((cb) => {
        const card = cb.closest("[data-photo-card]");
        if (card) card.classList.toggle("is-selected", cb.checked);
      });

      selectAllEl.checked = count > 0 && count === total;
      selectAllEl.indeterminate = count > 0 && count < total;
      countEl.textContent = `${count} selected`;
      clearBtn.classList.toggle("hidden", count === 0);
      bulkBtn.classList.toggle("hidden", count === 0);
      bulkBtn.disabled = false;
      bulkBtn.textContent = `Delete selected (${count})`;
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
      $("#manageError").textContent = "";
      bulkBtn.disabled = true;
      bulkBtn.textContent = "Deleting…";
      try {
        const res = await api(`/api/events/${encodeURIComponent(eventId)}/photos/bulk-delete`, {
          method: "POST",
          body: JSON.stringify({ photo_ids: photoIds }),
        });
        await Promise.all([loadDashboard(), manageEvent(eventId)]);
        $("#manageStatus").textContent = `Deleted ${res.deleted_count} photo(s).`;
      } catch (err) {
        $("#manageError").textContent = err.message;
        bulkBtn.disabled = false;
        bulkArmed = false;
        bulkBtn.textContent = `Delete selected (${photoIds.length})`;
      }
    };
  }

  if (e.ai_enabled && canAiIndex && unindexedOnOpen > 0) {
    runStudioFaceIndexing(eventId, data.photos, false);
  }
}

async function runStudioFaceIndexing(eventId, photos, forceReindex = false) {
  if (!window.faceapi || !window.SnapFindFace) {
    $("#manageError").textContent = "Self-hosted face-api library could not be loaded.";
    return;
  }

  indexingAbort = false;
  const targets = forceReindex ? photos : photos.filter((p) => !p.face_indexed);
  $("#dynamicPanel").innerHTML = `
    <div class="panel-box">
      <h3>AI Face Indexing</h3>
      <p class="muted" id="indexProgress">Loading self-hosted face models…</p>
      <div class="manage-actions">
        <button class="btn sm ghost" id="cancelIndexBtn" type="button">Cancel</button>
        <button class="btn sm ghost" id="reindexAllBtn" type="button">Re-index all photos (${photos.length})</button>
        <button class="btn sm danger" id="clearIndexBtn" type="button">Clear AI index</button>
      </div>
    </div>
  `;

  $("#cancelIndexBtn").onclick = () => {
    indexingAbort = true;
    $("#indexProgress").textContent = "Indexing cancelled.";
  };

  $("#reindexAllBtn").onclick = async () => {
    try {
      $("#indexProgress").textContent = "Resetting existing index and scanning all faces…";
      await api(`/api/events/${encodeURIComponent(eventId)}/faces`, { method: "DELETE" });
      await runStudioFaceIndexing(eventId, photos.map((p) => ({ ...p, face_indexed: 0 })), true);
    } catch (err) {
      $("#manageError").textContent = err.message;
    }
  };

  $("#clearIndexBtn").onclick = async () => {
    try {
      await api(`/api/events/${encodeURIComponent(eventId)}/faces`, { method: "DELETE" });
      await loadDashboard();
      await manageEvent(eventId);
    } catch (err) {
      $("#manageError").textContent = err.message;
    }
  };

  if (!targets.length) {
    $("#indexProgress").textContent = "All uploaded photos in this event are already indexed. Use Re-index all photos to refresh with multi-angle detection.";
    return;
  }

  try {
    await window.SnapFindFace.loadFaceModels();

    const batch = [];
    let totalFacesFound = 0;
    for (let i = 0; i < targets.length; i++) {
      if (indexingAbort) return;
      const p = targets[i];
      $("#indexProgress").textContent = `Analysing faces in photo ${i + 1} of ${targets.length} (${p.original_name})…`;
      const result = await window.SnapFindFace.extractEventFaces(p.preview_url);
      totalFacesFound += result.faceCount;

      batch.push({
        photo_id: p.id,
        descriptors: result.descriptors,
      });

      if (batch.length >= 10 || i === targets.length - 1) {
        const entries = batch.splice(0, batch.length);
        await api(`/api/events/${encodeURIComponent(eventId)}/faces`, {
          method: "POST",
          body: JSON.stringify({ entries }),
        });
      }
    }

    await Promise.all([loadDashboard(), manageEvent(eventId)]);
    $("#manageStatus").textContent = `Face indexing complete (${totalFacesFound} faces detected across ${targets.length} photo(s)).`;
  } catch (err) {
    $("#manageError").textContent = err.message || "Face indexing failed";
  }
}

$("#newEvent").onclick = () => {
  $("#eventError").textContent = "";
  $("#eventDialog").showModal();
};

$("#eventClose").onclick = () => $("#eventDialog").close();

$("#eventForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#eventError").textContent = "";
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

init().catch(() => {
  location.href = "/";
});

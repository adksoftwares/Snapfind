const $ = (selector) => document.querySelector(selector);
let mode = "login";
let csrfToken = null;
let inviteRequired = false;

function esc(value = "") {
  return String(value).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
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
    throw new Error(data.error || "Request failed");
  }
  return data;
}

let csrfRequest = null;
let authRequestPending = false;

async function ensureCsrfToken() {
  if (csrfToken) return csrfToken;
  if (!csrfRequest) {
    csrfRequest = api("/api/auth/csrf")
      .then((data) => {
        if (!data?.csrfToken) throw new Error("Could not prepare secure sign-in. Please try again.");
        csrfToken = data.csrfToken;
        return csrfToken;
      })
      .finally(() => {
        csrfRequest = null;
      });
  }
  return csrfRequest;
}

function openAuthDialog(nextMode) {
  if (authRequestPending && nextMode !== "mfa") return;
  mode = nextMode;
  const isRegister = nextMode === "register";
  const isMfa = nextMode === "mfa";

  $("#authTitle").textContent = isMfa
    ? "Two-factor verification"
    : isRegister
      ? "Create your studio account"
      : "Welcome back";
  $("#authEyebrow").textContent = isMfa
    ? "SECURITY CHECK"
    : isRegister
      ? "START YOUR STUDIO"
      : "YOUR WORKSPACE";

  $("#registerRow").classList.toggle("hidden", !isRegister);
  $("#inviteField").classList.toggle("hidden", !(isRegister && inviteRequired));
  $("#emailField").classList.toggle("hidden", isMfa);
  $("#passwordField").classList.toggle("hidden", isMfa);
  $("#mfaField").classList.toggle("hidden", !isMfa);
  $("#authForgot").classList.toggle("hidden", isRegister || isMfa);
  $("#authSwitch").classList.toggle("hidden", isMfa);

  $("#authForm").elements.name.required = isRegister;
  $("#authForm").elements.invite_code.required = isRegister && inviteRequired;
  $("#authForm").elements.email.required = !isMfa;
  $("#authForm").elements.password.required = !isMfa;
  $("#authForm").elements.mfa_code.required = isMfa;
  $("#authForm").elements.password.autocomplete = isRegister
    ? "new-password"
    : "current-password";
  $("#authSubmit").textContent = isMfa
    ? "Verify code"
    : isRegister
      ? "Create workspace"
      : "Sign in";
  $("#authSwitch").innerHTML = isRegister
    ? 'Already registered? <a href="#">Sign in</a>'
    : 'New to SnapFind? <a href="#">Create account</a>';
  $("#authError").textContent = "";
  if (!$("#authDialog").open) $("#authDialog").showModal();
  const focusTarget = isMfa ? $("#authMfaCode") : isRegister ? $("#authName") : $("#authEmail");
  focusTarget?.focus({ preventScroll: true });
  if (!csrfToken) ensureCsrfToken().catch(() => {});
}

$("#loginOpen").onclick = () => openAuthDialog("login");
$("#registerOpen").onclick = () => openAuthDialog("register");
$("#heroStart").onclick = () => openAuthDialog("register");
$("#authClose").onclick = () => $("#authDialog").close();

$("#authSwitch").onclick = (e) => {
  if (e.target.tagName === "A") {
    e.preventDefault();
    openAuthDialog(mode === "login" ? "register" : "login");
  }
};

$("#authForm").onsubmit = async (e) => {
  e.preventDefault();
  if (authRequestPending) return;

  const submitButton = $("#authSubmit");
  const originalLabel = submitButton.textContent;
  const submittingMode = mode;
  authRequestPending = true;
  submitButton.disabled = true;
  submitButton.textContent = submittingMode === "mfa"
    ? "Verifying…"
    : submittingMode === "register" ? "Creating workspace…" : "Signing in…";
  submitButton.setAttribute("aria-busy", "true");
  $("#authSwitch a")?.setAttribute("aria-disabled", "true");
  $("#authError").textContent = "";

  try {
    await ensureCsrfToken();
    const payload = Object.fromEntries(new FormData(e.target));

    if (submittingMode === "mfa") {
      const mfaRes = await api("/api/auth/mfa/verify", {
        method: "POST",
        body: JSON.stringify({ code: payload.mfa_code }),
      });
      location.href =
        mfaRes.user?.role === "super_admin" ? "/super-admin.html" : "/dashboard.html";
      return;
    }

    const res = await api(`/api/auth/${submittingMode === "login" ? "login" : "register"}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res.csrfToken) csrfToken = res.csrfToken;
    if (res.mfaRequired) {
      openAuthDialog("mfa");
      return;
    }
    location.href =
      res.user?.role === "super_admin" ? "/super-admin.html" : "/dashboard.html";
  } catch (err) {
    $("#authError").textContent = err.message || "Authentication could not be completed.";
  } finally {
    authRequestPending = false;
    submitButton.disabled = false;
    submitButton.removeAttribute("aria-busy");
    $("#authSwitch a")?.removeAttribute("aria-disabled");
    if (mode === submittingMode) submitButton.textContent = originalLabel;
  }
};

$("#codeJumpForm").onsubmit = (e) => {
  e.preventDefault();
  const code = $("#codeJumpInput").value.trim().toUpperCase();
  if (code) {
    location.href = `/gallery/${encodeURIComponent(code)}`;
  }
};

async function loadPublicEvents() {
  const container = $("#publicEventsGrid");
  container.setAttribute("aria-busy", "true");
  container.innerHTML = '<p class="muted" role="status" aria-live="polite">Loading public galleries…</p>';
  try {
    const data = await api("/api/public/events");
    container.setAttribute("aria-busy", "false");
    if (!data.events.length) {
      container.innerHTML =
        '<div class="empty-card" role="status"><span>No public galleries are currently listed.</span><small>Ask your photographer for a private event QR or access code.</small></div>';
      return;
    }
    container.innerHTML = data.events
      .map(
        (ev) => `
          <a class="public-card" href="/gallery/${encodeURIComponent(ev.access_code)}">
            <div class="public-cover">
              ${
                ev.cover_url
                  ? `<img src="${esc(ev.cover_url)}" alt="${esc(ev.title)}">`
                  : `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/></svg><span>${ev.has_pin ? "PIN-protected gallery" : "Gallery ready"}</span>`
              }
            </div>
            <div class="public-body">
              <h3>${esc(ev.title)}</h3>
              <p>${esc(ev.studio_name || "Studio")} · ${ev.photo_count} photos</p>
              <p>${esc([ev.event_date, ev.venue].filter(Boolean).join(" · ") || "Open gallery")}</p>
            </div>
          </a>
        `
      )
      .join("");
  } catch {
    container.setAttribute("aria-busy", "false");
    container.innerHTML = '<div class="empty-card" role="alert"><p class="muted">Could not load public galleries right now.</p><button class="btn sm ghost" type="button" data-retry-public-galleries>Try again</button></div>';
    const retry = container.querySelector("[data-retry-public-galleries]");
    if (retry) retry.onclick = () => loadPublicEvents();
  }
}

async function checkSession() {
  try {
    const me = await api("/api/auth/me");
    csrfToken = me.csrfToken || null;
    inviteRequired = Boolean(me.inviteRequired);
    if (me.pendingMfa) {
      openAuthDialog("mfa");
      return;
    }
    if (me.user) {
      $("#loginOpen").classList.add("hidden");
      $("#registerOpen").classList.add("hidden");
      $("#dashNavBtn").classList.remove("hidden");
      $("#homeLogoutBtn").classList.remove("hidden");
      if (me.user.role === "super_admin") {
        $("#dashNavBtn").href = "/super-admin.html";
        $("#dashNavBtn").textContent = "Super Admin Console";
      }
    }
  } catch {
    // ignore unauthenticated state
  }
}

$("#homeLogoutBtn").onclick = async () => {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } catch {
    // ignore logout error during sign-out transition
  }
  location.reload();
};

checkSession();
loadPublicEvents();

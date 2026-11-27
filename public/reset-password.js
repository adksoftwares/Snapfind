const $ = (s) => document.querySelector(s);
const params = new URLSearchParams(location.search);
const tokenFromUrl = params.get("token") || "";
let csrfToken = null;

function setMsg(text, isError = false) {
  const el = $("#resetMsg");
  el.textContent = text;
  el.className = isError ? "error" : "success-msg";
  el.setAttribute("role", isError ? "alert" : "status");
  el.setAttribute("aria-live", isError ? "assertive" : "polite");
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const r = await fetch(url, { ...options, method, headers });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "Request failed");
  return d;
}

async function init() {
  // Remove the one-time token from the address bar before any network request.
  if (tokenFromUrl) history.replaceState(null, "", "/reset-password.html");
  const c = await api("/api/auth/csrf").catch(() => null);
  if (c?.csrfToken) csrfToken = c.csrfToken;

  if (tokenFromUrl) {
    $("#confirmResetForm").classList.remove("hidden");
    $("#resetToken").value = tokenFromUrl;
  } else {
    $("#resetHeading").textContent = "Forgot password?";
    $("#requestResetForm").classList.remove("hidden");
  }
}

$("#confirmResetForm").onsubmit = async (e) => {
  e.preventDefault();
  setMsg("", false);
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    await api("/api/auth/password-reset/confirm", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setMsg("Password updated. You can now sign in with your new password.", false);
    e.target.reset();
    e.target.classList.add("hidden");
  } catch (err) {
    setMsg(err.message, true);
  }
};

$("#requestResetForm").onsubmit = async (e) => {
  e.preventDefault();
  setMsg("", false);
  const payload = Object.fromEntries(new FormData(e.target));
  try {
    const res = await api("/api/auth/password-reset/request", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setMsg(res.message, false);
  } catch (err) {
    setMsg(err.message, true);
  }
};


function addPendingSubmitState(formId, pendingLabel) {
  const form = $(formId);
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

addPendingSubmitState("#confirmResetForm", "Updating password…");
addPendingSubmitState("#requestResetForm", "Preparing reset link…");

init();

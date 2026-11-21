const $ = (s) => document.querySelector(s);
const params = new URLSearchParams(location.search);
const tokenFromUrl = params.get("token") || "";
let csrfToken = null;

function setMsg(text, isError = false) {
  const el = $("#resetMsg");
  el.textContent = text;
  el.className = isError ? "error" : "success-msg";
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

init();

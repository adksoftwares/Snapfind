const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");

const { createApp } = require("../src/app");
const { openDatabase } = require("../src/db");
const { computeHotp } = require("../src/security");

class CookieJar {
  constructor() {
    this.cookies = new Map();
  }
  capture(res) {
    const setCookies =
      typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    for (const raw of setCookies) {
      const pair = raw.split(";")[0];
      const idx = pair.indexOf("=");
      if (idx > 0) this.cookies.set(pair.slice(0, idx), pair.slice(idx + 1));
    }
  }
  header() {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }
}

async function reqJson(baseUrl, jar, urlPath, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const cookie = jar?.header();
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(`${baseUrl}${urlPath}`, { ...options, headers });
  jar?.capture(res);
  const data = await res.json().catch(() => ({}));
  return { res, data };
}

async function getCsrf(baseUrl, jar) {
  const { data } = await reqJson(baseUrl, jar, "/api/auth/csrf");
  return data.csrfToken;
}

function currentTotp(secret) {
  return computeHotp(secret, Math.floor(Date.now() / 1000 / 30));
}

describe("Super Admin Control System & Multi-Tenant RBAC", () => {
  let tmpDir;
  let instance;
  let baseUrl;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "snapfind-sa-"));
    instance = createApp({
      port: 0,
      uploadDir: path.join(tmpDir, "uploads"),
      dbPath: path.join(tmpDir, "sa.sqlite"),
      superAdminSetupToken: "setup-token-with-sufficient-entropy-987654",
      allowMultipleSuperAdmins: false,
      disableRateLimit: true,
      sessionSecret: "test-secret-with-more-than-thirty-two-characters-1234",
    });
    await new Promise((resolve) => instance.server.listen(0, "127.0.0.1", () => resolve()));
    baseUrl = `http://127.0.0.1:${instance.server.address().port}`;
  });

  after(async () => {
    await instance.close();
    fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it("blocks public Super Admin registration and enforces controlled initial setup with MFA", async () => {
    const anonJar = new CookieJar();
    const csrf = await getCsrf(baseUrl, anonJar);

    // Public registration cannot create super_admin
    const pubSa = await reqJson(baseUrl, anonJar, "/api/auth/register", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      body: JSON.stringify({
        name: "Attacker",
        email: "evil@example.com",
        password: "StrongPassword123!",
        role: "super_admin",
      }),
    });
    assert.equal(pubSa.res.status, 403);

    // Setup status shows needsSetup=true
    const status1 = await reqJson(baseUrl, anonJar, "/api/super-admin/setup/status");
    assert.equal(status1.data.needsSetup, true);

    // Wrong setup token rejected
    const badInit = await reqJson(baseUrl, anonJar, "/api/super-admin/setup/init", {
      method: "POST",
      headers: { "X-CSRF-Token": status1.data.csrfToken },
      body: JSON.stringify({
        setup_token: "wrong-token",
        name: "Root Admin",
        email: "root@snapfind.test",
        password: "SuperAdminPassword123!",
      }),
    });
    assert.equal(badInit.res.status, 403);

    // Correct setup token generates QR & secret
    const initRes = await reqJson(baseUrl, anonJar, "/api/super-admin/setup/init", {
      method: "POST",
      headers: { "X-CSRF-Token": status1.data.csrfToken },
      body: JSON.stringify({
        setup_token: "setup-token-with-sufficient-entropy-987654",
        name: "Root Admin",
        email: "root@snapfind.test",
        password: "SuperAdminPassword123!",
      }),
    });
    assert.equal(initRes.res.status, 200);
    assert.ok(initRes.data.secret);
    assert.match(initRes.data.qr, /^data:image\/png;base64,/);

    const saSecret = initRes.data.secret;
    const confirmRes = await reqJson(baseUrl, anonJar, "/api/super-admin/setup/confirm", {
      method: "POST",
      headers: { "X-CSRF-Token": status1.data.csrfToken },
      body: JSON.stringify({ code: currentTotp(saSecret) }),
    });
    assert.equal(confirmRes.res.status, 201);
    assert.equal(confirmRes.data.user.role, "super_admin");
    assert.equal(confirmRes.data.user.mfa_enabled, true);
    assert.equal(confirmRes.data.recoveryCodes.length, 8);
    let saCsrf = confirmRes.data.csrfToken;

    // Setup is permanently locked after completion
    const status2 = await reqJson(baseUrl, anonJar, "/api/super-admin/setup/status");
    assert.equal(status2.data.needsSetup, false);

    const reInit = await reqJson(baseUrl, anonJar, "/api/super-admin/setup/init", {
      method: "POST",
      headers: { "X-CSRF-Token": saCsrf },
      body: JSON.stringify({
        setup_token: "setup-token-with-sufficient-entropy-987654",
        name: "Second Admin",
        email: "root2@snapfind.test",
        password: "SuperAdminPassword123!",
      }),
    });
    assert.equal(reInit.res.status, 403);

    // Logout & verify Super Admin login requires MFA step
    await reqJson(baseUrl, anonJar, "/api/auth/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": saCsrf },
    });

    const loginCsrf = await getCsrf(baseUrl, anonJar);
    const loginStep1 = await reqJson(baseUrl, anonJar, "/api/auth/login", {
      method: "POST",
      headers: { "X-CSRF-Token": loginCsrf },
      body: JSON.stringify({
        email: "root@snapfind.test",
        password: "SuperAdminPassword123!",
      }),
    });
    assert.equal(loginStep1.res.status, 200);
    assert.equal(loginStep1.data.mfaRequired, true);

    // Cannot access Super Admin overview before MFA verification
    const preMfa = await reqJson(baseUrl, anonJar, "/api/super-admin/overview");
    assert.equal(preMfa.res.status, 401);

    // Verify with TOTP code
    const mfaRes = await reqJson(baseUrl, anonJar, "/api/auth/mfa/verify", {
      method: "POST",
      headers: { "X-CSRF-Token": loginStep1.data.csrfToken },
      body: JSON.stringify({ code: currentTotp(saSecret) }),
    });
    assert.equal(mfaRes.res.status, 200);
    saCsrf = mfaRes.data.csrfToken;

    // Register Studio A and Studio B
    const studioAJar = new CookieJar();
    const csrfA = await getCsrf(baseUrl, studioAJar);
    const regA = await reqJson(baseUrl, studioAJar, "/api/auth/register", {
      method: "POST",
      headers: { "X-CSRF-Token": csrfA },
      body: JSON.stringify({
        name: "Studio A Owner",
        email: "ownerA@example.com",
        password: "StudioAPassword123!",
        studio: "Alpha Studio",
      }),
    });
    assert.equal(regA.res.status, 201);
    const studioACsrf = regA.data.csrfToken;

    const evA = await reqJson(baseUrl, studioAJar, "/api/events", {
      method: "POST",
      headers: { "X-CSRF-Token": studioACsrf },
      body: JSON.stringify({ title: "Alpha Gala", is_public: true }),
    });
    assert.equal(evA.res.status, 201);
    const eventAId = evA.data.event.id;
    const eventACode = evA.data.event.access_code;

    const studioBJar = new CookieJar();
    const csrfB = await getCsrf(baseUrl, studioBJar);
    const regB = await reqJson(baseUrl, studioBJar, "/api/auth/register", {
      method: "POST",
      headers: { "X-CSRF-Token": csrfB },
      body: JSON.stringify({
        name: "Studio B Owner",
        email: "ownerB@example.com",
        password: "StudioBPassword123!",
        studio: "Beta Studio",
      }),
    });
    assert.equal(regB.res.status, 201);
    const studioBCsrf = regB.data.csrfToken;

    // Cross-tenant isolation: Studio B cannot access or mutate Studio A's event
    const crossGet = await reqJson(baseUrl, studioBJar, `/api/events/${eventAId}`);
    assert.equal(crossGet.res.status, 403);
    const crossDel = await reqJson(baseUrl, studioBJar, `/api/events/${eventAId}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": studioBCsrf },
    });
    assert.equal(crossDel.res.status, 403);

    // Studio A creates a Studio Staff member with limited permissions (events:read only)
    const addStaff = await reqJson(baseUrl, studioAJar, "/api/studio/staff", {
      method: "POST",
      headers: { "X-CSRF-Token": studioACsrf },
      body: JSON.stringify({
        name: "Staff Member",
        email: "staffA@example.com",
        password: "TempStaffPassword123!",
        staff_permissions: ["events:read"],
      }),
    });
    assert.equal(addStaff.res.status, 201);

    // Staff logs in -> blocked by must_change_password until password updated
    const staffJar = new CookieJar();
    const staffCsrf0 = await getCsrf(baseUrl, staffJar);
    const staffLogin = await reqJson(baseUrl, staffJar, "/api/auth/login", {
      method: "POST",
      headers: { "X-CSRF-Token": staffCsrf0 },
      body: JSON.stringify({
        email: "staffA@example.com",
        password: "TempStaffPassword123!",
      }),
    });
    assert.equal(staffLogin.data.mustChangePassword, true);
    let staffCsrf = staffLogin.data.csrfToken;

    const blockedBeforePw = await reqJson(baseUrl, staffJar, "/api/dashboard");
    assert.equal(blockedBeforePw.res.status, 403);
    assert.equal(blockedBeforePw.data.code, "PASSWORD_CHANGE_REQUIRED");

    const staffPwUpdate = await reqJson(baseUrl, staffJar, "/api/auth/password", {
      method: "POST",
      headers: { "X-CSRF-Token": staffCsrf },
      body: JSON.stringify({
        current_password: "TempStaffPassword123!",
        new_password: "NewStaffPassword456!",
      }),
    });
    assert.equal(staffPwUpdate.res.status, 200);
    staffCsrf = staffPwUpdate.data.csrfToken;

    // Staff can read Studio A's dashboard & event, but CANNOT create/edit events (missing events:write)
    const staffDash = await reqJson(baseUrl, staffJar, "/api/dashboard");
    assert.equal(staffDash.res.status, 200);
    assert.equal(staffDash.data.events.length, 1);

    const staffForbiddenCreate = await reqJson(baseUrl, staffJar, "/api/events", {
      method: "POST",
      headers: { "X-CSRF-Token": staffCsrf },
      body: JSON.stringify({ title: "Unauthorized Staff Event" }),
    });
    assert.equal(staffForbiddenCreate.res.status, 403);

    // Super Admin overview, account search/pagination, detail & session revocation
    const saOverview = await reqJson(baseUrl, anonJar, "/api/super-admin/overview");
    assert.equal(saOverview.res.status, 200);
    assert.ok(saOverview.data.accounts.total >= 4);
    assert.ok(saOverview.data.studios.total >= 2);
    assert.ok(saOverview.data.sessions.online_users >= 1);

    const accSearch = await reqJson(
      baseUrl,
      anonJar,
      "/api/super-admin/accounts?q=ownera&role=studio_owner&status=active"
    );
    assert.equal(accSearch.res.status, 200);
    assert.equal(accSearch.data.accounts.length, 1);
    const ownerAId = accSearch.data.accounts[0].id;
    const studioAId = accSearch.data.accounts[0].studio_id;
    assert.equal(accSearch.data.accounts[0].password_hash, undefined);

    // Super Admin cannot create second super_admin when policy disallows
    const policyBlock = await reqJson(baseUrl, anonJar, "/api/super-admin/accounts", {
      method: "POST",
      headers: { "X-CSRF-Token": saCsrf },
      body: JSON.stringify({
        name: "Extra SA",
        email: "extra-sa@example.com",
        password: "StrongPassword123!",
        role: "super_admin",
      }),
    });
    assert.equal(policyBlock.res.status, 403);

    // Super Admin suspends Studio A -> immediately blocks Studio A owner, Staff A, AND public gallery
    const suspendStudio = await reqJson(
      baseUrl,
      anonJar,
      `/api/super-admin/studios/${studioAId}/suspend`,
      {
        method: "POST",
        headers: { "X-CSRF-Token": saCsrf },
        body: JSON.stringify({ reason: "Policy review" }),
      }
    );
    assert.equal(suspendStudio.res.status, 200);

    const ownerAAfterSuspend = await reqJson(baseUrl, studioAJar, "/api/dashboard");
    assert.equal(ownerAAfterSuspend.res.status, 401); // sessions were revoked!

    const publicAfterSuspend = await reqJson(baseUrl, studioBJar, `/api/gallery/${eventACode}`);
    assert.equal(publicAfterSuspend.res.status, 404);

    // Reactivate Studio A -> gallery becomes accessible again
    const activateStudio = await reqJson(
      baseUrl,
      anonJar,
      `/api/super-admin/studios/${studioAId}/activate`,
      { method: "POST", headers: { "X-CSRF-Token": saCsrf } }
    );
    assert.equal(activateStudio.res.status, 200);

    const publicAfterActivate = await reqJson(baseUrl, studioBJar, `/api/gallery/${eventACode}`);
    assert.equal(publicAfterActivate.res.status, 200);

    // Super Admin initiates password reset for Owner A & Owner A completes reset
    const resetInit = await reqJson(
      baseUrl,
      anonJar,
      `/api/super-admin/accounts/${ownerAId}/reset-password`,
      {
        method: "POST",
        headers: { "X-CSRF-Token": saCsrf },
        body: JSON.stringify({ force_change_on_login: true, revoke_sessions: true }),
      }
    );
    assert.equal(resetInit.res.status, 200);
    assert.ok(resetInit.data.token);

    const resetCsrf = await getCsrf(baseUrl, studioAJar);
    const resetConfirm = await reqJson(baseUrl, studioAJar, "/api/auth/password-reset/confirm", {
      method: "POST",
      headers: { "X-CSRF-Token": resetCsrf },
      body: JSON.stringify({
        token: resetInit.data.token,
        new_password: "RecoveredOwnerPassword789!",
      }),
    });
    assert.equal(resetConfirm.res.status, 200);

    const ownerALoginNew = await reqJson(baseUrl, studioAJar, "/api/auth/login", {
      method: "POST",
      headers: { "X-CSRF-Token": resetCsrf },
      body: JSON.stringify({
        email: "ownerA@example.com",
        password: "RecoveredOwnerPassword789!",
      }),
    });
    assert.equal(ownerALoginNew.res.status, 200);

    // Super Admin permanently deletes Studio B owner (requires exact confirm_email)
    const ownerBId = regB.data.user.id;
    const badDel = await reqJson(baseUrl, anonJar, `/api/super-admin/accounts/${ownerBId}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": saCsrf },
      body: JSON.stringify({ confirm_email: "wrong@example.com" }),
    });
    assert.equal(badDel.res.status, 400);

    const goodDel = await reqJson(baseUrl, anonJar, `/api/super-admin/accounts/${ownerBId}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": saCsrf },
      body: JSON.stringify({ confirm_email: "ownerB@example.com" }),
    });
    assert.equal(goodDel.res.status, 200);

    // Security & Audit logs recorded all sensitive actions
    const secLogs = await reqJson(baseUrl, anonJar, "/api/super-admin/security");
    assert.equal(secLogs.res.status, 200);
    assert.ok(secLogs.data.events.some((e) => e.event_type === "studio.suspended"));
    assert.ok(secLogs.data.events.some((e) => e.event_type === "password.reset_completed"));

    const auditLogs = await reqJson(baseUrl, anonJar, "/api/super-admin/audit-logs");
    assert.equal(auditLogs.res.status, 200);
    assert.ok(auditLogs.data.logs.some((l) => l.action === "super_admin.account_deleted"));
  });

  it("migrates existing v1 SQLite database cleanly to v2 multi-tenant schema", () => {
    const migDir = fs.mkdtempSync(path.join(os.tmpdir(), "snapfind-mig-"));
    const dbPath = path.join(migDir, "v1.sqlite");
    try {
      const legacy = new DatabaseSync(dbPath);
      legacy.exec(`
        CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO schema_migrations (version, name) VALUES (1, 'initial_schema');
        CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'photographer' CHECK(role IN ('photographer', 'admin')), phone TEXT, studio TEXT, storage_used_bytes INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE events (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id), title TEXT NOT NULL, description TEXT, event_date TEXT, venue TEXT, access_code TEXT UNIQUE NOT NULL, pin_hash TEXT, is_public INTEGER DEFAULT 0, ai_enabled INTEGER DEFAULT 0, status TEXT DEFAULT 'active', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE photos (id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE, filename TEXT NOT NULL, thumb_filename TEXT NOT NULL, preview_filename TEXT NOT NULL, original_name TEXT, mime TEXT NOT NULL, size INTEGER DEFAULT 0, total_bytes INTEGER DEFAULT 0, width INTEGER DEFAULT 0, height INTEGER DEFAULT 0, caption TEXT DEFAULT '', face_indexed INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE photo_faces (id TEXT PRIMARY KEY, photo_id TEXT NOT NULL, event_id TEXT NOT NULL, descriptor_json TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE selections (id TEXT PRIMARY KEY, event_id TEXT NOT NULL, photo_id TEXT NOT NULL, guest_name TEXT, guest_email TEXT, guest_key TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE favourites (id TEXT PRIMARY KEY, photo_id TEXT NOT NULL, event_id TEXT NOT NULL, guest_key TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE audit_logs (id TEXT PRIMARY KEY, user_id TEXT, action TEXT NOT NULL, entity_type TEXT, entity_id TEXT, details TEXT, ip TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE sessions (sid TEXT PRIMARY KEY, sess TEXT NOT NULL, expired INTEGER NOT NULL);
        INSERT INTO users (id, name, email, password_hash, role, studio) VALUES ('u1', 'Legacy User', 'legacy@example.com', 'hash', 'admin', 'Legacy Studio');
        INSERT INTO events (id, owner_id, title, access_code) VALUES ('e1', 'u1', 'Legacy Event', 'LEGACY123456');
      `);
      legacy.close();

      const migrated = openDatabase(dbPath);
      const user = migrated.prepare("SELECT * FROM users WHERE id = 'u1'").get();
      const studio = migrated.prepare("SELECT * FROM studios WHERE id = ?").get(user.studio_id);
      const event = migrated.prepare("SELECT * FROM events WHERE id = 'e1'").get();
      // Legacy admin must NOT silently become super_admin without controlled MFA setup
      assert.equal(user.role, "studio_owner");
      assert.equal(studio.name, "Legacy Studio");
      assert.equal(event.studio_id, user.studio_id);
      migrated.close();
    } finally {
      fs.rmSync(migDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
});

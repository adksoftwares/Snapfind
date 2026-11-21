const crypto = require("node:crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const { v4: uuid } = require("uuid");
const { getPublicBaseUrl } = require("../config");
const {
  ALL_STAFF_PERMISSIONS,
  isValidEmail,
  escapeLike,
  parsePermissions,
  safeUser,
  ensureCsrf,
  requireAuth,
  requireSuperAdmin,
  auditLog,
} = require("../middleware");
const {
  generateTotpSecret,
  buildOtpAuthUri,
  verifyTotpCode,
  generateRecoveryCodes,
  hashRecoveryCodes,
  recordSecurityEvent,
  registerUserSession,
  revokeUserSessions,
  revokeSingleSession,
  createPasswordResetToken,
} = require("../security");
const { deleteEventMediaDir } = require("../media");
const { createUniqueSlug } = require("./auth");

const VALID_ROLES = new Set(["super_admin", "studio_owner", "studio_staff"]);
const VALID_PLANS = new Set(["free", "standard", "pro", "enterprise"]);
const VALID_EVENT_STATUSES = new Set(["active", "paused", "archived"]);

function timingSafeMatch(expected, provided) {
  const a = Buffer.from(String(expected || ""), "utf8");
  const b = Buffer.from(String(provided || ""), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function regenerateSession(req, patch = {}) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      Object.assign(req.session, patch);
      const csrfToken = ensureCsrf(req);
      req.session.save((saveErr) => {
        if (saveErr) return reject(saveErr);
        resolve(csrfToken);
      });
    });
  });
}

function sanitizeAccountRow(row, defaultLimitBytes) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    studio_id: row.studio_id || null,
    studio_name: row.studio_name || row.studio || "",
    studio_status: row.studio_status || null,
    studio_plan: row.studio_plan || null,
    staff_permissions: parsePermissions(row.staff_permissions),
    phone: row.phone || "",
    status: row.status,
    must_change_password: Boolean(row.must_change_password),
    mfa_enabled: Boolean(row.mfa_enabled),
    storage_used_bytes: Number(row.storage_used_bytes || 0),
    storage_limit_bytes: Number(row.studio_storage_limit || defaultLimitBytes),
    last_login_at: row.last_login_at || null,
    suspended_at: row.suspended_at || null,
    suspended_reason: row.suspended_reason || "",
    deleted_at: row.deleted_at || null,
    created_at: row.created_at,
  };
}

function createSuperAdminRouter({ db, config, limiters, eventStatusCache }) {
  const router = express.Router();
  const auth = requireAuth(db);

  // -------------------------------------------------------------------------
  // Controlled Initial Super Admin Setup (only when 0 super_admin accounts exist)
  // -------------------------------------------------------------------------
  router.get("/super-admin/setup/status", async (req, res, next) => {
    try {
      const row = await db.get(
        "SELECT COUNT(*) AS cnt FROM users WHERE role = 'super_admin' AND status <> 'deleted'"
      );
      const count = Number(row?.cnt || 0);
      const hadCsrf = Boolean(req.session?.csrfToken);
      const csrfToken = ensureCsrf(req);
      const payload = {
        needsSetup: count === 0,
        setupTokenConfigured: Boolean(
          config.superAdminSetupToken && config.superAdminSetupToken.length >= 16
        ),
        allowMultipleSuperAdmins: config.allowMultipleSuperAdmins,
        csrfToken,
      };
      if (hadCsrf) return res.json(payload);
      return req.session.save((err) => {
        if (err) return next(err);
        return res.json(payload);
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/setup/init", limiters.auth, async (req, res, next) => {
    try {
      const existingRow = await db.get(
        "SELECT COUNT(*) AS cnt FROM users WHERE role = 'super_admin' AND status <> 'deleted'"
      );
      if (Number(existingRow?.cnt || 0) > 0) {
        return res.status(403).json({ error: "Initial Super Admin setup is already completed" });
      }
      if (!config.superAdminSetupToken || config.superAdminSetupToken.length < 16) {
        return res.status(403).json({
          error: "SUPER_ADMIN_SETUP_TOKEN (16+ chars) must be configured in environment before web setup",
        });
      }

      const setupToken = String(req.body.setup_token || "").trim();
      if (!timingSafeMatch(config.superAdminSetupToken, setupToken)) {
        await auditLog(db, req, "super_admin.setup_rejected", "system", null, "invalid_setup_token");
        return res.status(403).json({ error: "Invalid setup token" });
      }

      const name = String(req.body.name || "").trim();
      const email = String(req.body.email || "").toLowerCase().trim();
      const password = String(req.body.password || "");

      if (!name || name.length > 100) {
        return res.status(400).json({ error: "Valid name (1–100 characters) required" });
      }
      if (!isValidEmail(email) || email.length > 160) {
        return res.status(400).json({ error: "Valid email address required" });
      }
      if (password.length < 6 || password.length > 128) {
        return res.status(400).json({ error: "Super Admin password must be 6–128 characters" });
      }
      if (await db.get("SELECT id FROM users WHERE email = ?", email)) {
        return res.status(409).json({ error: "Email already registered" });
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const mfaSecret = generateTotpSecret();
      const otpauthUrl = buildOtpAuthUri({ secret: mfaSecret, email, issuer: "SnapFind Super Admin" });
      const qr = await QRCode.toDataURL(otpauthUrl, { width: 320, margin: 2 });

      req.session.pendingSuperAdminSetup = {
        name,
        email,
        passwordHash,
        mfaSecret,
        expiresAt: Date.now() + 10 * 60 * 1000,
      };

      return req.session.save((err) => {
        if (err) return next(err);
        return res.json({ qr, secret: mfaSecret, otpauthUrl });
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/setup/confirm", limiters.auth, async (req, res, next) => {
    try {
      const existingRow = await db.get(
        "SELECT COUNT(*) AS cnt FROM users WHERE role = 'super_admin' AND status <> 'deleted'"
      );
      if (Number(existingRow?.cnt || 0) > 0) {
        return res.status(403).json({ error: "Initial Super Admin setup is already completed" });
      }

      const pending = req.session?.pendingSuperAdminSetup;
      if (!pending || pending.expiresAt <= Date.now()) {
        return res.status(400).json({ error: "Setup session expired. Please start again." });
      }

      const code = String(req.body.code || "").trim();
      if (!verifyTotpCode(pending.mfaSecret, code, 1)) {
        return res.status(400).json({ error: "Invalid 6-digit authenticator code" });
      }

      const uid = uuid();
      const recoveryCodes = generateRecoveryCodes(8);
      const recoveryHashes = hashRecoveryCodes(recoveryCodes);

      await db.run(
        `INSERT INTO users (
          id, name, email, password_hash, role, status, mfa_enabled, mfa_secret, mfa_recovery_codes, last_login_at
        ) VALUES (?, ?, ?, ?, 'super_admin', 'active', 1, ?, ?, CURRENT_TIMESTAMP)`,
        uid,
        pending.name,
        pending.email,
        pending.passwordHash,
        pending.mfaSecret,
        recoveryHashes
      );

      const csrfToken = await regenerateSession(req, {
        userId: uid,
        mfaVerified: true,
      });

      const user = await db.get("SELECT * FROM users WHERE id = ?", uid);
      await registerUserSession(db, req, user);
      await recordSecurityEvent(db, req, {
        userId: uid,
        email: pending.email,
        eventType: "login.success",
        success: true,
        details: "super_admin_initial_setup",
      });
      await auditLog(db, req, "super_admin.initialized", "user", uid, pending.email, uid);

      return res.status(201).json({
        user: safeUser(user, config.maxStorageBytesPerUser),
        recoveryCodes,
        csrfToken,
      });
    } catch (err) {
      return next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Protected Super Admin Endpoints (require role='super_admin' + MFA verified)
  // -------------------------------------------------------------------------
  router.use("/super-admin", auth, requireSuperAdmin);

  router.get("/super-admin/overview", async (req, res, next) => {
    try {
      const accountCounts = await db.get(
        `SELECT
           COUNT(*) AS total,
           SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
           SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) AS suspended,
           SUM(CASE WHEN status = 'deleted' THEN 1 ELSE 0 END) AS deleted,
           SUM(CASE WHEN role = 'super_admin' AND status <> 'deleted' THEN 1 ELSE 0 END) AS super_admins,
           SUM(CASE WHEN role = 'studio_owner' AND status <> 'deleted' THEN 1 ELSE 0 END) AS studio_owners,
           SUM(CASE WHEN role = 'studio_staff' AND status <> 'deleted' THEN 1 ELSE 0 END) AS studio_staff,
           SUM(CASE WHEN status <> 'deleted' AND created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) AS new_registrations_7d
         FROM users`
      );

      const onlineSessions = await db.get(
        `SELECT COUNT(DISTINCT user_id) AS users, COUNT(*) AS sessions
         FROM user_sessions
         WHERE revoked_at IS NULL
           AND last_seen_at >= datetime('now', '-30 minutes')`
      );

      const securityCounts = await db.get(
        `SELECT
           SUM(CASE WHEN event_type = 'login.success' THEN 1 ELSE 0 END) AS total_logins,
           SUM(CASE WHEN event_type = 'login.failed' THEN 1 ELSE 0 END) AS failed_logins,
           SUM(CASE WHEN suspicious = 1 THEN 1 ELSE 0 END) AS suspicious_events
         FROM security_events`
      );

      const studioStats = await db.get(
        `SELECT
           COUNT(*) AS total_studios,
           SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active_studios,
           SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) AS suspended_studios,
           (SELECT COUNT(*) FROM events) AS total_events,
           (SELECT COUNT(*) FROM photos) AS total_photos,
           (SELECT COALESCE(SUM(total_bytes), 0) FROM photos) AS total_storage_bytes
         FROM studios`
      );

      const lastRegistered = await db.all(
        `SELECT u.id, u.name, u.email, u.role, u.status, u.studio, u.created_at, s.name AS studio_name
         FROM users u
         LEFT JOIN studios s ON s.id = u.studio_id
         WHERE u.status <> 'deleted'
         ORDER BY u.created_at DESC
         LIMIT 8`
      );

      const recentLogins = await db.all(
        `SELECT se.*, u.name AS user_name
         FROM security_events se
         LEFT JOIN users u ON u.id = se.user_id
         WHERE se.event_type IN ('login.success', 'login.failed', 'login.suspicious', 'mfa.failed')
         ORDER BY se.created_at DESC
         LIMIT 12`
      );

      return res.json({
        policy: {
          allowMultipleSuperAdmins: config.allowMultipleSuperAdmins,
        },
        accounts: {
          total: Number(accountCounts?.total || 0),
          active: Number(accountCounts?.active || 0),
          suspended: Number(accountCounts?.suspended || 0),
          deleted: Number(accountCounts?.deleted || 0),
          super_admins: Number(accountCounts?.super_admins || 0),
          studio_owners: Number(accountCounts?.studio_owners || 0),
          studio_staff: Number(accountCounts?.studio_staff || 0),
          new_registrations_7d: Number(accountCounts?.new_registrations_7d || 0),
        },
        sessions: {
          online_users: Number(onlineSessions?.users || 0),
          active_sessions: Number(onlineSessions?.sessions || 0),
        },
        security: {
          total_logins: Number(securityCounts?.total_logins || 0),
          failed_logins: Number(securityCounts?.failed_logins || 0),
          suspicious_events: Number(securityCounts?.suspicious_events || 0),
        },
        studios: {
          total: Number(studioStats?.total_studios || 0),
          active: Number(studioStats?.active_studios || 0),
          suspended: Number(studioStats?.suspended_studios || 0),
          total_events: Number(studioStats?.total_events || 0),
          total_photos: Number(studioStats?.total_photos || 0),
          total_storage_bytes: Number(studioStats?.total_storage_bytes || 0),
        },
        last_registered: lastRegistered,
        recent_logins: recentLogins,
      });
    } catch (err) {
      return next(err);
    }
  });

  // Searchable, filterable, paginated accounts list
  router.get("/super-admin/accounts", async (req, res, next) => {
    try {
      const q = String(req.query.q || "").trim().toLowerCase();
      const role = String(req.query.role || "").trim();
      const status = String(req.query.status || "").trim();
      const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 20));
      const offset = (page - 1) * limit;

      const conditions = [];
      const params = [];

      if (role && VALID_ROLES.has(role)) {
        conditions.push("u.role = ?");
        params.push(role);
      }
      if (status && ["active", "suspended", "deleted"].includes(status)) {
        conditions.push("u.status = ?");
        params.push(status);
      }
      if (q) {
        const escQ = `%${escapeLike(q)}%`;
        conditions.push(
          "(LOWER(u.name) LIKE ? ESCAPE '\\' OR LOWER(u.email) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(s.name, u.studio, '')) LIKE ? ESCAPE '\\')"
        );
        params.push(escQ, escQ, escQ);
      }

      const whereSql = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

      const totalRow = await db.get(
        `SELECT COUNT(*) AS cnt
         FROM users u
         LEFT JOIN studios s ON s.id = u.studio_id
         ${whereSql}`,
        ...params
      );
      const total = Number(totalRow?.cnt || 0);

      const rows = (
        await db.all(
          `SELECT u.*, s.name AS studio_name, s.status AS studio_status, s.plan AS studio_plan,
                  s.storage_limit_bytes AS studio_storage_limit
           FROM users u
           LEFT JOIN studios s ON s.id = u.studio_id
           ${whereSql}
           ORDER BY u.created_at DESC
           LIMIT ? OFFSET ?`,
          ...params,
          limit,
          offset
        )
      ).map((r) => sanitizeAccountRow(r, config.maxStorageBytesPerUser));

      return res.json({
        accounts: rows,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/super-admin/accounts/:id", async (req, res, next) => {
    try {
      const row = await db.get(
        `SELECT u.*, s.name AS studio_name, s.status AS studio_status, s.plan AS studio_plan,
                s.storage_limit_bytes AS studio_storage_limit, s.slug AS studio_slug
         FROM users u
         LEFT JOIN studios s ON s.id = u.studio_id
         WHERE u.id = ?`,
        req.params.id
      );

      if (!row) return res.status(404).json({ error: "Account not found" });

      const loginStats = await db.get(
        `SELECT
           SUM(CASE WHEN event_type = 'login.success' THEN 1 ELSE 0 END) AS login_count,
           SUM(CASE WHEN event_type = 'login.failed' THEN 1 ELSE 0 END) AS failed_count
         FROM security_events WHERE user_id = ?`,
        row.id
      );

      const activeSessions = await db.all(
        `SELECT sid, ip, device_label, created_at, last_seen_at
         FROM user_sessions
         WHERE user_id = ? AND revoked_at IS NULL
         ORDER BY last_seen_at DESC`,
        row.id
      );

      const loginHistory = await db.all(
        `SELECT id, event_type, success, ip, device_label, suspicious, details, created_at
         FROM security_events
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 25`,
        row.id
      );

      const recentAudit = await db.all(
        `SELECT id, action, entity_type, entity_id, details, ip, created_at
         FROM audit_logs
         WHERE entity_id = ? OR user_id = ?
         ORDER BY created_at DESC
         LIMIT 25`,
        row.id,
        row.id
      );

      return res.json({
        account: sanitizeAccountRow(row, config.maxStorageBytesPerUser),
        studio: row.studio_id
          ? {
              id: row.studio_id,
              name: row.studio_name,
              slug: row.studio_slug,
              status: row.studio_status,
              plan: row.studio_plan,
              storage_limit_bytes: Number(row.studio_storage_limit || config.maxStorageBytesPerUser),
            }
          : null,
        stats: {
          login_count: Number(loginStats?.login_count || 0),
          failed_count: Number(loginStats?.failed_count || 0),
          active_sessions: activeSessions.length,
        },
        active_sessions: activeSessions,
        login_history: loginHistory,
        recent_audit: recentAudit,
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/accounts", async (req, res, next) => {
    try {
      const name = String(req.body.name || "").trim();
      const email = String(req.body.email || "").toLowerCase().trim();
      const password = String(req.body.password || "");
      const role = String(req.body.role || "studio_owner").trim();
      const phone = String(req.body.phone || "").trim().slice(0, 40);
      const studioNameInput = String(req.body.studio || "").trim().slice(0, 120);
      const studioIdInput = String(req.body.studio_id || "").trim();
      const mustChange = req.body.must_change_password !== false ? 1 : 0;
      const permissions = parsePermissions(req.body.staff_permissions);

      if (!name || name.length > 100) {
        return res.status(400).json({ error: "Valid name (1–100 characters) required" });
      }
      if (!isValidEmail(email) || email.length > 160) {
        return res.status(400).json({ error: "Valid email address required" });
      }
      if (password.length < 6 || password.length > 128) {
        return res.status(400).json({ error: "Password must be 6–128 characters" });
      }
      if (!VALID_ROLES.has(role)) {
        return res.status(400).json({ error: "Invalid account role" });
      }
      if (role === "super_admin" && !config.allowMultipleSuperAdmins) {
        return res.status(403).json({
          error: "Platform policy allows only one central Super Admin account (ALLOW_MULTIPLE_SUPER_ADMINS=false)",
        });
      }
      if (await db.get("SELECT id FROM users WHERE email = ?", email)) {
        return res.status(409).json({ error: "Email already registered" });
      }

      const uid = uuid();
      const passwordHash = await bcrypt.hash(password, 12);
      let assignedStudioId = null;
      let assignedStudioName = studioNameInput;
      let ownerStudioSlug = null;

      if (role === "studio_staff") {
        const targetStudio = await db.get("SELECT * FROM studios WHERE id = ?", studioIdInput);
        if (!targetStudio) {
          return res.status(400).json({ error: "Valid studio_id is required for Studio Staff" });
        }
        assignedStudioId = targetStudio.id;
        assignedStudioName = targetStudio.name;
      } else if (role === "studio_owner") {
        assignedStudioId = uuid();
        assignedStudioName = studioNameInput || `${name}'s Studio`;
        ownerStudioSlug = await createUniqueSlug(db, assignedStudioName);
      }

      await db.tx(async (tx) => {
        if (role === "studio_owner") {
          await tx.run(
            `INSERT INTO studios (id, name, slug, owner_id, plan, status, storage_limit_bytes)
             VALUES (?, ?, ?, ?, 'standard', 'active', ?)`,
            assignedStudioId,
            assignedStudioName,
            ownerStudioSlug,
            uid,
            config.maxStorageBytesPerUser
          );
        }

        await tx.run(
          `INSERT INTO users (
            id, name, email, password_hash, role, studio_id, staff_permissions,
            phone, studio, status, must_change_password
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
          uid,
          name,
          email,
          passwordHash,
          role,
          assignedStudioId,
          JSON.stringify(role === "studio_staff" ? permissions : []),
          phone,
          assignedStudioName,
          mustChange
        );
      });

      await auditLog(db, req, "super_admin.account_created", "user", uid, `${email} role=${role}`);
      const created = await db.get(
        `SELECT u.*, s.name AS studio_name, s.status AS studio_status, s.plan AS studio_plan,
                s.storage_limit_bytes AS studio_storage_limit
         FROM users u LEFT JOIN studios s ON s.id = u.studio_id WHERE u.id = ?`,
        uid
      );

      return res.status(201).json({
        account: sanitizeAccountRow(created, config.maxStorageBytesPerUser),
      });
    } catch (err) {
      return next(err);
    }
  });

  router.patch("/super-admin/accounts/:id", async (req, res, next) => {
    try {
      const target = await db.get("SELECT * FROM users WHERE id = ?", req.params.id);
      if (!target || target.status === "deleted") {
        return res.status(404).json({ error: "Account not found" });
      }

      const name =
        req.body.name !== undefined ? String(req.body.name).trim() : target.name;
      const email =
        req.body.email !== undefined
          ? String(req.body.email).toLowerCase().trim()
          : target.email;
      const phone =
        req.body.phone !== undefined
          ? String(req.body.phone).trim().slice(0, 40)
          : target.phone;
      const studioName =
        req.body.studio !== undefined
          ? String(req.body.studio).trim().slice(0, 120)
          : target.studio;
      const role = req.body.role !== undefined ? String(req.body.role) : target.role;
      const mustChangePassword =
        req.body.must_change_password !== undefined
          ? req.body.must_change_password
            ? 1
            : 0
          : target.must_change_password;
      const staffPermissions =
        req.body.staff_permissions !== undefined
          ? JSON.stringify(parsePermissions(req.body.staff_permissions))
          : target.staff_permissions;

      if (!name || name.length > 100) {
        return res.status(400).json({ error: "Valid name (1–100 characters) required" });
      }
      if (!isValidEmail(email)) {
        return res.status(400).json({ error: "Valid email required" });
      }
      if (!VALID_ROLES.has(role)) {
        return res.status(400).json({ error: "Invalid role" });
      }
      if (target.id === req.user.id && role !== "super_admin") {
        return res.status(400).json({ error: "You cannot demote your own Super Admin account" });
      }
      if (role === "super_admin" && target.role !== "super_admin" && !config.allowMultipleSuperAdmins) {
        return res.status(403).json({
          error: "Platform policy disallows additional Super Admin accounts",
        });
      }

      const emailConflict = await db.get(
        "SELECT id FROM users WHERE email = ? AND id <> ?",
        email,
        target.id
      );
      if (emailConflict) {
        return res.status(409).json({ error: "Email already in use by another account" });
      }

      await db.tx(async (tx) => {
        await tx.run(
          `UPDATE users
           SET name = ?, email = ?, phone = ?, studio = ?, role = ?,
               staff_permissions = ?, must_change_password = ?
           WHERE id = ?`,
          name,
          email,
          phone,
          studioName,
          role,
          staffPermissions,
          mustChangePassword,
          target.id
        );

        if (role === "studio_owner" && target.studio_id && studioName) {
          await tx.run("UPDATE studios SET name = ? WHERE id = ?", studioName, target.studio_id);
        }
      });

      await auditLog(db, req, "super_admin.account_updated", "user", target.id, `role=${role}`);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/accounts/:id/suspend", async (req, res, next) => {
    try {
      const target = await db.get("SELECT * FROM users WHERE id = ?", req.params.id);
      if (!target || target.status === "deleted") {
        return res.status(404).json({ error: "Account not found" });
      }
      if (target.id === req.user.id) {
        return res.status(400).json({ error: "You cannot suspend your own account" });
      }

      const reason = String(req.body.reason || "Suspended by Super Admin").trim().slice(0, 240);
      await db.run(
        "UPDATE users SET status = 'suspended', suspended_at = CURRENT_TIMESTAMP, suspended_reason = ? WHERE id = ?",
        reason,
        target.id
      );
      const revokedCount = await revokeUserSessions(db, target.id);

      await recordSecurityEvent(db, req, {
        userId: target.id,
        studioId: target.studio_id,
        email: target.email,
        eventType: "account.suspended",
        success: true,
        details: `${reason} (revoked_sessions=${revokedCount})`,
      });
      await auditLog(db, req, "super_admin.account_suspended", "user", target.id, reason);

      return res.json({ ok: true, revoked_sessions: revokedCount });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/accounts/:id/reactivate", async (req, res, next) => {
    try {
      const target = await db.get("SELECT * FROM users WHERE id = ?", req.params.id);
      if (!target || target.status === "deleted") {
        return res.status(404).json({ error: "Account not found" });
      }

      await db.run(
        "UPDATE users SET status = 'active', suspended_at = NULL, suspended_reason = '' WHERE id = ?",
        target.id
      );

      await recordSecurityEvent(db, req, {
        userId: target.id,
        studioId: target.studio_id,
        email: target.email,
        eventType: "account.reactivated",
        success: true,
      });
      await auditLog(db, req, "super_admin.account_reactivated", "user", target.id, target.email);

      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.delete("/super-admin/accounts/:id", async (req, res, next) => {
    try {
      const target = await db.get("SELECT * FROM users WHERE id = ?", req.params.id);
      if (!target || target.status === "deleted") {
        return res.status(404).json({ error: "Account not found" });
      }
      if (target.id === req.user.id) {
        return res.status(400).json({ error: "You cannot delete your own Super Admin account" });
      }

      const confirmEmail = String(req.body?.confirm_email || "").toLowerCase().trim();
      if (confirmEmail !== target.email.toLowerCase()) {
        return res.status(400).json({
          error: "Confirmation failed: provide exact confirm_email matching the target account",
        });
      }

      const ownedEvents = await db.all(
        "SELECT id FROM events WHERE owner_id = ?",
        target.id
      );

      await revokeUserSessions(db, target.id);
      const originalEmail = target.email;

      let studioDeleted = false;
      await db.tx(async (tx) => {
        for (const ev of ownedEvents) {
          await tx.run("DELETE FROM events WHERE id = ?", ev.id);
          eventStatusCache.invalidate(ev.id);
        }
        if (target.role === "studio_owner" && target.studio_id) {
          const remRow = await tx.get(
            "SELECT COUNT(*) AS cnt FROM users WHERE studio_id = ? AND id <> ? AND status <> 'deleted'",
            target.studio_id,
            target.id
          );
          if (Number(remRow?.cnt || 0) === 0) {
            await tx.run("DELETE FROM studios WHERE id = ?", target.studio_id);
            studioDeleted = true;
          } else {
            await tx.run(
              "UPDATE studios SET status = 'suspended', owner_id = NULL WHERE id = ?",
              target.studio_id
            );
          }
          await eventStatusCache.invalidateStudio(target.studio_id);
        }
        await tx.run(
          `UPDATE users
           SET status = 'deleted',
               deleted_at = CURRENT_TIMESTAMP,
               email = ?,
               name = 'Deleted Account',
               phone = '',
               password_hash = '!deleted!',
               mfa_enabled = 0,
               mfa_secret = NULL,
               mfa_recovery_codes = NULL,
               storage_used_bytes = 0
           WHERE id = ?`,
          `deleted-${target.id}@deleted.local`,
          target.id
        );
      });

      for (const ev of ownedEvents) {
        await deleteEventMediaDir(config, ev.id);
      }

      await recordSecurityEvent(db, req, {
        userId: target.id,
        studioId: studioDeleted ? null : target.studio_id,
        email: originalEmail,
        eventType: "account.deleted",
        success: true,
        details: `deleted_events=${ownedEvents.length}`,
      });
      await auditLog(db, req, "super_admin.account_deleted", "user", target.id, originalEmail);

      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/accounts/:id/reset-password", async (req, res, next) => {
    try {
      const target = await db.get("SELECT * FROM users WHERE id = ?", req.params.id);
      if (!target || target.status === "deleted") {
        return res.status(404).json({ error: "Account not found" });
      }

      const forceChange = req.body.force_change_on_login !== false;
      const { rawToken, expiresAt } = await createPasswordResetToken(
        db,
        target.id,
        req.user.id,
        60
      );

      if (forceChange) {
        await db.run("UPDATE users SET must_change_password = 1 WHERE id = ?", target.id);
      }
      if (req.body.revoke_sessions) {
        await revokeUserSessions(db, target.id);
      }

      await recordSecurityEvent(db, req, {
        userId: target.id,
        studioId: target.studio_id,
        email: target.email,
        eventType: "password.reset_requested",
        success: true,
        details: `initiated_by=${req.user.email}`,
      });
      await auditLog(db, req, "super_admin.password_reset_initiated", "user", target.id, target.email);

      const origin = getPublicBaseUrl(req, config);
      const resetUrl = `${origin}/reset-password.html?token=${rawToken}`;
      return res.json({
        ok: true,
        resetUrl,
        token: rawToken,
        expiresAt,
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/accounts/:id/force-password-change", async (req, res, next) => {
    try {
      const target = await db.get("SELECT * FROM users WHERE id = ?", req.params.id);
      if (!target || target.status === "deleted") {
        return res.status(404).json({ error: "Account not found" });
      }

      await db.run("UPDATE users SET must_change_password = 1 WHERE id = ?", target.id);
      await auditLog(db, req, "super_admin.force_password_change", "user", target.id, target.email);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/accounts/:id/revoke-sessions", async (req, res, next) => {
    try {
      const target = await db.get("SELECT * FROM users WHERE id = ?", req.params.id);
      if (!target) return res.status(404).json({ error: "Account not found" });

      const count = await revokeUserSessions(
        db,
        target.id,
        target.id === req.user.id ? req.sessionID : null
      );
      await recordSecurityEvent(db, req, {
        userId: target.id,
        studioId: target.studio_id,
        email: target.email,
        eventType: "session.revoked",
        success: true,
        details: `super_admin_revoked_count=${count}`,
      });
      await auditLog(
        db,
        req,
        "super_admin.sessions_revoked",
        "user",
        target.id,
        `count=${count}`
      );

      return res.json({ ok: true, revoked_count: count });
    } catch (err) {
      return next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Security Monitoring & Active Sessions
  // -------------------------------------------------------------------------
  router.get("/super-admin/security", async (req, res, next) => {
    try {
      const q = String(req.query.q || "").trim().toLowerCase();
      const eventType = String(req.query.event_type || "").trim();
      const suspiciousOnly = req.query.suspicious === "1" || req.query.suspicious === "true";
      const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 30));
      const offset = (page - 1) * limit;

      const conditions = [];
      const params = [];
      if (eventType) {
        conditions.push("se.event_type = ?");
        params.push(eventType);
      }
      if (suspiciousOnly) {
        conditions.push("se.suspicious = 1");
      }
      if (q) {
        const escQ = `%${escapeLike(q)}%`;
        conditions.push(
          "(LOWER(se.email) LIKE ? ESCAPE '\\' OR LOWER(se.ip) LIKE ? ESCAPE '\\' OR LOWER(se.device_label) LIKE ? ESCAPE '\\' OR LOWER(se.details) LIKE ? ESCAPE '\\')"
        );
        params.push(escQ, escQ, escQ, escQ);
      }

      const whereSql = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
      const totalRow = await db.get(
        `SELECT COUNT(*) AS cnt FROM security_events se ${whereSql}`,
        ...params
      );
      const total = Number(totalRow?.cnt || 0);

      const events = await db.all(
        `SELECT se.*, u.name AS user_name, u.role AS user_role
         FROM security_events se
         LEFT JOIN users u ON u.id = se.user_id
         ${whereSql}
         ORDER BY se.created_at DESC
         LIMIT ? OFFSET ?`,
        ...params,
        limit,
        offset
      );

      return res.json({
        events,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/super-admin/sessions", async (req, res, next) => {
    try {
      const activeOnly = req.query.active_only !== "0";
      const userId = String(req.query.user_id || "").trim();

      const conditions = [];
      const params = [];
      if (activeOnly) {
        conditions.push("us.revoked_at IS NULL");
      }
      if (userId) {
        conditions.push("us.user_id = ?");
        params.push(userId);
      }
      const whereSql = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

      const rows = await db.all(
        `SELECT us.*, u.name AS user_name, u.email AS user_email, u.role AS user_role,
                s.name AS studio_name
         FROM user_sessions us
         JOIN users u ON u.id = us.user_id
         LEFT JOIN studios s ON s.id = us.studio_id
         ${whereSql}
         ORDER BY us.last_seen_at DESC
         LIMIT 200`,
        ...params
      );

      const sessions = rows.map((s) => ({
        ...s,
        current: s.sid === req.sessionID,
      }));

      return res.json({ sessions });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/sessions/:sid/revoke", async (req, res, next) => {
    try {
      const row = await db.get(
        "SELECT us.*, u.email FROM user_sessions us JOIN users u ON u.id = us.user_id WHERE us.sid = ?",
        req.params.sid
      );
      if (!row) return res.status(404).json({ error: "Session not found" });
      if (row.sid === req.sessionID) {
        return res.status(400).json({ error: "Use Sign out to close your current Super Admin session" });
      }

      await revokeSingleSession(db, row.sid);
      await recordSecurityEvent(db, req, {
        userId: row.user_id,
        studioId: row.studio_id,
        email: row.email,
        eventType: "session.revoked",
        success: true,
        sessionId: row.sid,
        details: `revoked_by=${req.user.email}`,
      });
      await auditLog(db, req, "super_admin.session_revoked", "session", row.sid, row.email);

      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/super-admin/audit-logs", async (req, res, next) => {
    try {
      const q = String(req.query.q || "").trim().toLowerCase();
      const action = String(req.query.action || "").trim();
      const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 30));
      const offset = (page - 1) * limit;

      const conditions = [];
      const params = [];
      if (action) {
        conditions.push("l.action = ?");
        params.push(action);
      }
      if (q) {
        const escQ = `%${escapeLike(q)}%`;
        conditions.push(
          "(LOWER(l.action) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(u.email, '')) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(l.details, '')) LIKE ? ESCAPE '\\')"
        );
        params.push(escQ, escQ, escQ);
      }

      const whereSql = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
      const totalRow = await db.get(
        `SELECT COUNT(*) AS cnt FROM audit_logs l LEFT JOIN users u ON u.id = l.user_id ${whereSql}`,
        ...params
      );
      const total = Number(totalRow?.cnt || 0);

      const logs = await db.all(
        `SELECT l.*, u.email AS actor_email, u.name AS actor_name, u.role AS actor_role
         FROM audit_logs l
         LEFT JOIN users u ON u.id = l.user_id
         ${whereSql}
         ORDER BY l.created_at DESC
         LIMIT ? OFFSET ?`,
        ...params,
        limit,
        offset
      );

      return res.json({
        logs,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  // -------------------------------------------------------------------------
  // Business / Studio Management
  // -------------------------------------------------------------------------
  router.get("/super-admin/studios", async (req, res, next) => {
    try {
      const q = String(req.query.q || "").trim().toLowerCase();
      const status = String(req.query.status || "").trim();
      const plan = String(req.query.plan || "").trim();
      const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 20));
      const offset = (page - 1) * limit;

      const conditions = [];
      const params = [];
      if (status && ["active", "suspended"].includes(status)) {
        conditions.push("s.status = ?");
        params.push(status);
      }
      if (plan && VALID_PLANS.has(plan)) {
        conditions.push("s.plan = ?");
        params.push(plan);
      }
      if (q) {
        const escQ = `%${escapeLike(q)}%`;
        conditions.push(
          "(LOWER(s.name) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(u.email, '')) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(u.name, '')) LIKE ? ESCAPE '\\')"
        );
        params.push(escQ, escQ, escQ);
      }

      const whereSql = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
      const totalRow = await db.get(
        `SELECT COUNT(*) AS cnt FROM studios s LEFT JOIN users u ON u.id = s.owner_id ${whereSql}`,
        ...params
      );
      const total = Number(totalRow?.cnt || 0);

      const studios = (
        await db.all(
          `SELECT s.*,
                  u.name AS owner_name, u.email AS owner_email, u.status AS owner_status,
                  (SELECT COUNT(*) FROM users m WHERE m.studio_id = s.id AND m.role = 'studio_staff' AND m.status <> 'deleted') AS staff_count,
                  (SELECT COUNT(*) FROM events e WHERE e.studio_id = s.id) AS event_count,
                  (SELECT COUNT(*) FROM photos p JOIN events e ON e.id = p.event_id WHERE e.studio_id = s.id) AS photo_count,
                  (SELECT COALESCE(SUM(m.storage_used_bytes), 0) FROM users m WHERE m.studio_id = s.id) AS storage_used_bytes
           FROM studios s
           LEFT JOIN users u ON u.id = s.owner_id
           ${whereSql}
           ORDER BY s.created_at DESC
           LIMIT ? OFFSET ?`,
          ...params,
          limit,
          offset
        )
      ).map((s) => ({
        ...s,
        storage_limit_bytes: Number(s.storage_limit_bytes || config.maxStorageBytesPerUser),
        staff_count: Number(s.staff_count || 0),
        event_count: Number(s.event_count || 0),
        photo_count: Number(s.photo_count || 0),
        storage_used_bytes: Number(s.storage_used_bytes || 0),
      }));

      return res.json({
        studios,
        pagination: {
          page,
          limit,
          total,
          total_pages: Math.ceil(total / limit),
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/super-admin/studios/:id", async (req, res, next) => {
    try {
      const studio = await db.get(
        `SELECT s.*, u.name AS owner_name, u.email AS owner_email, u.phone AS owner_phone, u.status AS owner_status
         FROM studios s
         LEFT JOIN users u ON u.id = s.owner_id
         WHERE s.id = ?`,
        req.params.id
      );
      if (!studio) return res.status(404).json({ error: "Studio not found" });

      const members = (
        await db.all(
          `SELECT id, name, email, role, status, staff_permissions, last_login_at, created_at
           FROM users
           WHERE studio_id = ? AND status <> 'deleted'
           ORDER BY role ASC, created_at DESC`,
          studio.id
        )
      ).map((m) => ({ ...m, staff_permissions: parsePermissions(m.staff_permissions) }));

      const events = (
        await db.all(
          `SELECT e.id, e.title, e.access_code, e.status, e.is_public, e.ai_enabled, e.created_at,
                  (SELECT COUNT(*) FROM photos p WHERE p.event_id = e.id) AS photo_count,
                  (SELECT COUNT(*) FROM selections sel WHERE sel.event_id = e.id) AS selection_count
           FROM events e
           WHERE e.studio_id = ?
           ORDER BY e.created_at DESC
           LIMIT 50`,
          studio.id
        )
      ).map((ev) => ({
        ...ev,
        photo_count: Number(ev.photo_count || 0),
        selection_count: Number(ev.selection_count || 0),
      }));

      const activity = await db.all(
        `SELECT id, email, event_type, success, ip, device_label, suspicious, details, created_at
         FROM security_events
         WHERE studio_id = ?
         ORDER BY created_at DESC
         LIMIT 25`,
        studio.id
      );

      return res.json({
        studio: {
          ...studio,
          storage_limit_bytes: Number(studio.storage_limit_bytes || config.maxStorageBytesPerUser),
        },
        members,
        events,
        activity,
        available_permissions: ALL_STAFF_PERMISSIONS,
      });
    } catch (err) {
      return next(err);
    }
  });

  router.patch("/super-admin/studios/:id", async (req, res, next) => {
    try {
      const studio = await db.get("SELECT * FROM studios WHERE id = ?", req.params.id);
      if (!studio) return res.status(404).json({ error: "Studio not found" });

      const name =
        req.body.name !== undefined ? String(req.body.name).trim().slice(0, 120) : studio.name;
      const plan = req.body.plan !== undefined ? String(req.body.plan) : studio.plan;
      const storageLimitBytes =
        req.body.storage_limit_mb !== undefined
          ? Math.max(10, Number(req.body.storage_limit_mb)) * 1024 * 1024
          : Number(studio.storage_limit_bytes);
      const notes =
        req.body.notes !== undefined ? String(req.body.notes).trim().slice(0, 1000) : studio.notes;

      if (!name) return res.status(400).json({ error: "Studio name required" });
      if (!VALID_PLANS.has(plan)) return res.status(400).json({ error: "Invalid plan" });

      await db.run(
        "UPDATE studios SET name = ?, plan = ?, storage_limit_bytes = ?, notes = ? WHERE id = ?",
        name,
        plan,
        storageLimitBytes,
        notes,
        studio.id
      );

      await auditLog(db, req, "super_admin.studio_updated", "studio", studio.id, `plan=${plan}`);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/studios/:id/suspend", async (req, res, next) => {
    try {
      const studio = await db.get("SELECT * FROM studios WHERE id = ?", req.params.id);
      if (!studio) return res.status(404).json({ error: "Studio not found" });

      const reason = String(req.body.reason || "Studio suspended by Super Admin").trim().slice(0, 240);
      await db.run("UPDATE studios SET status = 'suspended' WHERE id = ?", studio.id);
      await eventStatusCache.invalidateStudio(studio.id);

      const members = await db.all(
        "SELECT id, email FROM users WHERE studio_id = ?",
        studio.id
      );
      let revoked = 0;
      for (const m of members) {
        revoked += await revokeUserSessions(db, m.id);
      }

      await recordSecurityEvent(db, req, {
        studioId: studio.id,
        email: studio.name,
        eventType: "studio.suspended",
        success: true,
        details: `${reason} (revoked_sessions=${revoked})`,
      });
      await auditLog(db, req, "super_admin.studio_suspended", "studio", studio.id, reason);

      return res.json({ ok: true, revoked_sessions: revoked });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/super-admin/studios/:id/activate", async (req, res, next) => {
    try {
      const studio = await db.get("SELECT * FROM studios WHERE id = ?", req.params.id);
      if (!studio) return res.status(404).json({ error: "Studio not found" });

      await db.run("UPDATE studios SET status = 'active' WHERE id = ?", studio.id);
      await eventStatusCache.invalidateStudio(studio.id);

      await recordSecurityEvent(db, req, {
        studioId: studio.id,
        email: studio.name,
        eventType: "studio.activated",
        success: true,
      });
      await auditLog(db, req, "super_admin.studio_activated", "studio", studio.id, studio.name);

      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.patch("/super-admin/events/:id/status", async (req, res, next) => {
    try {
      const nextStatus = String(req.body.status || "");
      if (!VALID_EVENT_STATUSES.has(nextStatus)) {
        return res.status(400).json({ error: "Invalid event status" });
      }
      const event = await db.get(
        "SELECT id, title, status FROM events WHERE id = ?",
        req.params.id
      );
      if (!event) return res.status(404).json({ error: "Event not found" });

      await db.run("UPDATE events SET status = ? WHERE id = ?", nextStatus, event.id);
      eventStatusCache.invalidate(event.id);
      await auditLog(
        db,
        req,
        "super_admin.event_moderated",
        "event",
        event.id,
        `${event.status} -> ${nextStatus}`
      );
      return res.json({ ok: true, status: nextStatus });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}

module.exports = { createSuperAdminRouter };

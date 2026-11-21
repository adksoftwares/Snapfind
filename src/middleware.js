const crypto = require("node:crypto");
const rateLimit = require("express-rate-limit");
const { v4: uuid } = require("uuid");

const ACCESS_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const ALL_STAFF_PERMISSIONS = [
  "events:read",
  "events:write",
  "photos:upload",
  "photos:delete",
  "selections:read",
  "ai:index",
];

function normalizeIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "unknown").replace(/^::ffff:/, "");
}

function generateAccessCode(length = 12) {
  const bytes = crypto.randomBytes(length);
  let code = "";
  for (let i = 0; i < length; i++) {
    code += ACCESS_ALPHABET[bytes[i] % ACCESS_ALPHABET.length];
  }
  return code;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || "").trim());
}

function escapeLike(value) {
  return String(value || "").replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

function parsePermissions(raw) {
  if (Array.isArray(raw)) return raw.filter((p) => ALL_STAFF_PERMISSIONS.includes(p));
  try {
    const parsed = JSON.parse(raw || "[]");
    return Array.isArray(parsed)
      ? parsed.filter((p) => ALL_STAFF_PERMISSIONS.includes(p))
      : [];
  } catch {
    return [];
  }
}

function safeUser(u, defaultMaxStorageBytes = 0, studio = null) {
  if (!u) return null;
  const effectiveLimit = Number(studio?.storage_limit_bytes || defaultMaxStorageBytes);
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    studio_id: u.studio_id || null,
    staff_permissions: parsePermissions(u.staff_permissions),
    phone: u.phone || "",
    studio: studio?.name || u.studio || "",
    studio_status: studio?.status || null,
    studio_plan: studio?.plan || null,
    status: u.status || "active",
    must_change_password: Boolean(u.must_change_password),
    mfa_enabled: Boolean(u.mfa_enabled),
    last_login_at: u.last_login_at || null,
    storage_used_bytes: Number(u.storage_used_bytes || 0),
    storage_limit_bytes: effectiveLimit,
    created_at: u.created_at,
  };
}

function ensureCsrf(req) {
  if (!req.session) return null;
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString("hex");
  }
  return req.session.csrfToken;
}

function requiresCsrf(req) {
  // All state-changing API requests require the session-bound token, including
  // guest actions on public galleries (not only PIN-unlocked/authenticated flows).
  return !["GET", "HEAD", "OPTIONS"].includes(req.method);
}

function verifyCsrf(req, res, next) {
  if (!requiresCsrf(req)) return next();

  const expected = req.session?.csrfToken;
  const provided = req.get("x-csrf-token") || "";
  if (!expected || !provided) {
    return res.status(403).json({ error: "Missing CSRF token" });
  }
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(provided, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }
  return next();
}

async function loadSessionContext(db, req) {
  if (!req.session?.userId) return null;
  const user = await db.get("SELECT * FROM users WHERE id = ?", req.session.userId);
  if (!user) return null;

  if (req.sessionID) {
    const sessRow = await db.get(
      "SELECT revoked_at FROM user_sessions WHERE sid = ?",
      req.sessionID
    );
    if (sessRow && sessRow.revoked_at) {
      return { user, studio: null, revoked: true };
    }
  }

  const studio = user.studio_id
    ? (await db.get("SELECT * FROM studios WHERE id = ?", user.studio_id)) || null
    : null;

  return { user, studio, revoked: false };
}

async function getSessionUser(db, req) {
  const ctx = await loadSessionContext(db, req);
  if (!ctx || ctx.revoked) return null;
  if (ctx.user.status !== "active") return null;
  if (ctx.user.role !== "super_admin" && ctx.studio && ctx.studio.status !== "active") {
    return null;
  }
  return ctx.user;
}

function requireAuth(db, opts = {}) {
  return async (req, res, next) => {
    try {
      const ctx = await loadSessionContext(db, req);
      if (!ctx || ctx.revoked) {
        if (ctx?.revoked && req.session) {
          req.session.destroy(() => {});
        }
        return res.status(401).json({ error: "Sign in required" });
      }

      const { user, studio } = ctx;
      if (user.status === "suspended") {
        return res.status(403).json({
          error: "Your account has been suspended. Contact the platform administrator.",
          code: "ACCOUNT_SUSPENDED",
        });
      }
      if (user.status === "deleted") {
        return res.status(401).json({ error: "Sign in required" });
      }
      if (user.role !== "super_admin" && studio && studio.status === "suspended") {
        return res.status(403).json({
          error: "This studio account is currently suspended.",
          code: "STUDIO_SUSPENDED",
        });
      }

      if (user.must_change_password && !opts.allowPasswordChangeOnly) {
        return res.status(403).json({
          error: "You must change your password before continuing.",
          code: "PASSWORD_CHANGE_REQUIRED",
        });
      }

      if (req.sessionID) {
        try {
          await db.run(
            `UPDATE user_sessions SET last_seen_at = CURRENT_TIMESTAMP
             WHERE sid = ? AND last_seen_at < datetime('now', '-30 seconds')`,
            req.sessionID
          );
        } catch {
          // ignore non-critical timestamp update
        }
      }

      req.user = user;
      req.studio = studio;
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

function requireSuperAdmin(req, res, next) {
  if (req.user?.role !== "super_admin") {
    return res.status(403).json({ error: "Super Admin access required" });
  }
  if (req.user.mfa_enabled && !req.session?.mfaVerified) {
    return res.status(403).json({ error: "Multi-factor authentication required", code: "MFA_REQUIRED" });
  }
  return next();
}

function requireStudioOwner(req, res, next) {
  if (req.user?.role !== "studio_owner") {
    return res.status(403).json({ error: "Studio Owner access required" });
  }
  return next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Sign in required" });
    if (req.user.role === "super_admin" || req.user.role === "studio_owner") {
      return next();
    }
    if (req.user.role === "studio_staff") {
      const perms = parsePermissions(req.user.staff_permissions);
      if (perms.includes(permission)) return next();
    }
    return res.status(403).json({ error: `Missing permission: ${permission}` });
  };
}

function requireOwnEvent(db) {
  return async (req, res, next) => {
    try {
      const event = await db.get("SELECT * FROM events WHERE id = ?", req.params.id);
      if (!event) return res.status(404).json({ error: "Event not found" });
      if (req.user.role === "super_admin") {
        req.event = event;
        return next();
      }
      if (!req.user.studio_id || event.studio_id !== req.user.studio_id) {
        return res.status(403).json({ error: "Not your studio's event" });
      }
      req.event = event;
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

async function auditLog(db, req, action, entityType = null, entityId = null, details = "", userIdOverride = null) {
  try {
    const userId = userIdOverride ?? req.user?.id ?? null;
    const ip = normalizeIp(req).slice(0, 64);
    await db.run(
      `INSERT INTO audit_logs (id, user_id, action, entity_type, entity_id, details, ip)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      uuid(),
      userId,
      String(action),
      entityType ? String(entityType) : null,
      entityId ? String(entityId) : null,
      String(details || "").slice(0, 500),
      ip
    );
  } catch (err) {
    console.error("[SnapFind] Failed to write audit log:", err);
  }
}

function createEventStatusCache(db) {
  const cache = new Map();
  const TTL_MS = 30_000;

  return {
    async isActive(eventId) {
      const entry = cache.get(eventId);
      const now = Date.now();
      if (entry && entry.expiresAt > now) {
        return entry.active;
      }
      const row = await db.get(
        `SELECT e.status AS event_status, COALESCE(s.status, 'active') AS studio_status
         FROM events e
         LEFT JOIN studios s ON s.id = e.studio_id
         WHERE e.id = ?`,
        eventId
      );
      const active = Boolean(
        row && row.event_status === "active" && row.studio_status === "active"
      );
      cache.set(eventId, { active, expiresAt: now + TTL_MS });
      return active;
    },
    invalidate(eventId) {
      if (eventId) cache.delete(eventId);
    },
    async invalidateStudio(studioId) {
      if (!studioId) return;
      const rows = await db.all("SELECT id FROM events WHERE studio_id = ?", studioId);
      for (const r of rows) cache.delete(r.id);
    },
  };
}

function createLimiters(options = {}) {
  const skip = options.disableRateLimit ? () => true : undefined;
  return {
    api: rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 2000,
      standardHeaders: true,
      legacyHeaders: false,
      skip,
    }),
    auth: rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 20,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: "Too many authentication attempts. Try again in 15 minutes." },
      skip,
    }),
    register: rateLimit({
      windowMs: 60 * 60 * 1000,
      limit: 10,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: "Registration limit reached. Try again later." },
      skip,
    }),
    pinUnlock: rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 15,
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => `${normalizeIp(req)}:${req.params.code || ""}`,
      message: { error: "Too many PIN attempts. Please wait 15 minutes." },
      skip,
    }),
    galleryLookup: rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 180,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: "Too many gallery requests. Please slow down." },
      skip,
    }),
    guestAction: rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 120,
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => `${normalizeIp(req)}:${req.params.code || ""}`,
      message: { error: "Too many requests from this device. Please slow down." },
      skip,
    }),
  };
}

module.exports = {
  ALL_STAFF_PERMISSIONS,
  normalizeIp,
  generateAccessCode,
  isValidEmail,
  escapeLike,
  parsePermissions,
  safeUser,
  ensureCsrf,
  verifyCsrf,
  loadSessionContext,
  getSessionUser,
  requireAuth,
  requireSuperAdmin,
  requireStudioOwner,
  requirePermission,
  requireOwnEvent,
  auditLog,
  createEventStatusCache,
  createLimiters,
};

const crypto = require("node:crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const { v4: uuid } = require("uuid");
const {
  isValidEmail,
  safeUser,
  ensureCsrf,
  loadSessionContext,
  requireAuth,
  auditLog,
} = require("../middleware");
const {
  generateTotpSecret,
  buildOtpAuthUri,
  verifyTotpCode,
  generateRecoveryCodes,
  hashRecoveryCodes,
  consumeRecoveryCode,
  recordSecurityEvent,
  detectSuspiciousLogin,
  registerUserSession,
  revokeUserSessions,
  revokeSingleSession,
  createPasswordResetToken,
  consumePasswordResetToken,
} = require("../security");

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

function timingSafeMatch(expected, provided) {
  const a = Buffer.from(String(expected || ""), "utf8");
  const b = Buffer.from(String(provided || ""), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function createUniqueSlug(db, baseText) {
  const clean =
    String(baseText || "studio")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 32) || "studio";
  let slug = `${clean}-${crypto.randomBytes(3).toString("hex")}`;
  while (await db.get("SELECT id FROM studios WHERE slug = ?", slug)) {
    slug = `${clean}-${crypto.randomBytes(3).toString("hex")}`;
  }
  return slug;
}

function createAuthRouter({ db, config, limiters }) {
  const router = express.Router();
  const auth = requireAuth(db);
  const authAllowPwChange = requireAuth(db, { allowPasswordChangeOnly: true });

  router.post("/auth/register", limiters.register, async (req, res, next) => {
    try {
      // Never allow public Super Admin or Staff registration
      if (req.body.role && req.body.role !== "studio_owner" && req.body.role !== "photographer") {
        return res.status(403).json({ error: "Public registration is only available for Studio Owners" });
      }

      if (config.registrationInviteCode) {
        const invite = String(req.body.invite_code || "").trim();
        if (!invite || !timingSafeMatch(config.registrationInviteCode, invite)) {
          await auditLog(db, req, "auth.register.rejected", "user", null, "invalid_invite_code");
          return res.status(403).json({ error: "Valid studio invite code required" });
        }
      }

      const name = String(req.body.name || "").trim();
      const email = String(req.body.email || "").toLowerCase().trim();
      const password = String(req.body.password || "");
      const phone = String(req.body.phone || "").trim().slice(0, 40);
      const studioNameInput = String(req.body.studio || "").trim().slice(0, 120);

      if (!name || name.length > 100) {
        return res.status(400).json({ error: "Valid name (1–100 characters) required" });
      }
      if (!isValidEmail(email) || email.length > 160) {
        return res.status(400).json({ error: "Valid email address required" });
      }
      if (password.length < 6 || password.length > 128) {
        return res.status(400).json({ error: "Password must be between 6 and 128 characters" });
      }

      const existing = await db.get("SELECT id FROM users WHERE email = ?", email);
      if (existing) {
        return res.status(409).json({ error: "Email already registered" });
      }

      const uid = uuid();
      const studioId = uuid();
      const finalStudioName = studioNameInput || `${name}'s Studio`;
      const slug = await createUniqueSlug(db, finalStudioName);
      const passwordHash = await bcrypt.hash(password, 12);

      await db.tx(async (tx) => {
        await tx.run(
          `INSERT INTO studios (id, name, slug, owner_id, plan, status, storage_limit_bytes)
           VALUES (?, ?, ?, ?, 'standard', 'active', ?)`,
          studioId,
          finalStudioName,
          slug,
          uid,
          config.maxStorageBytesPerUser
        );

        await tx.run(
          `INSERT INTO users (
            id, name, email, password_hash, role, studio_id, phone, studio, status, last_login_at
          ) VALUES (?, ?, ?, ?, 'studio_owner', ?, ?, ?, 'active', CURRENT_TIMESTAMP)`,
          uid,
          name,
          email,
          passwordHash,
          studioId,
          phone,
          finalStudioName
        );
      });

      const csrfToken = await regenerateSession(req, { userId: uid });
      const user = await db.get("SELECT * FROM users WHERE id = ?", uid);
      const studio = await db.get("SELECT * FROM studios WHERE id = ?", studioId);

      await registerUserSession(db, req, user);
      await recordSecurityEvent(db, req, {
        userId: uid,
        studioId,
        email,
        eventType: "login.success",
        success: true,
        details: "initial_registration",
      });
      await auditLog(db, req, "auth.register", "user", uid, email, uid);

      return res.status(201).json({
        user: safeUser(user, config.maxStorageBytesPerUser, studio),
        csrfToken,
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/auth/login", limiters.auth, async (req, res, next) => {
    try {
      const email = String(req.body.email || "").toLowerCase().trim();
      const password = String(req.body.password || "");
      const user = await db.get("SELECT * FROM users WHERE email = ?", email);

      if (!user || user.status === "deleted" || !(await bcrypt.compare(password, user.password_hash))) {
        const susp = await detectSuspiciousLogin(db, req, user, false);
        await recordSecurityEvent(db, req, {
          userId: user?.id || null,
          studioId: user?.studio_id || null,
          email,
          eventType: "login.failed",
          success: false,
          suspicious: susp.suspicious,
          details: susp.reasons.join(",") || "invalid_credentials",
        });
        await auditLog(db, req, "auth.login.failed", "user", user?.id || null, email);
        return res.status(401).json({ error: "Incorrect email or password" });
      }

      if (user.status === "suspended") {
        await recordSecurityEvent(db, req, {
          userId: user.id,
          studioId: user.studio_id,
          email,
          eventType: "login.failed",
          success: false,
          suspicious: true,
          details: "account_suspended",
        });
        return res.status(403).json({
          error: "Your account has been suspended. Contact the platform administrator.",
          code: "ACCOUNT_SUSPENDED",
        });
      }

      const studio = user.studio_id
        ? (await db.get("SELECT * FROM studios WHERE id = ?", user.studio_id)) || null
        : null;

      if (user.role !== "super_admin" && studio && studio.status === "suspended") {
        await recordSecurityEvent(db, req, {
          userId: user.id,
          studioId: studio.id,
          email,
          eventType: "login.failed",
          success: false,
          suspicious: true,
          details: "studio_suspended",
        });
        return res.status(403).json({
          error: "This studio account is currently suspended.",
          code: "STUDIO_SUSPENDED",
        });
      }

      // Require MFA step if enabled (mandatory for super_admin)
      if (user.mfa_enabled) {
        const csrfToken = await regenerateSession(req, {
          pendingMfaUserId: user.id,
          pendingMfaExpires: Date.now() + 5 * 60 * 1000,
        });
        return res.json({
          mfaRequired: true,
          role: user.role,
          csrfToken,
        });
      }

      const susp = await detectSuspiciousLogin(db, req, user, true);
      const csrfToken = await regenerateSession(req, {
        userId: user.id,
        mfaVerified: false,
      });

      await db.run("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", user.id);
      await registerUserSession(db, req, user);
      await recordSecurityEvent(db, req, {
        userId: user.id,
        studioId: user.studio_id,
        email,
        eventType: susp.suspicious ? "login.suspicious" : "login.success",
        success: true,
        suspicious: susp.suspicious,
        details: susp.reasons.join(","),
      });
      if (susp.suspicious) {
        await recordSecurityEvent(db, req, {
          userId: user.id,
          studioId: user.studio_id,
          email,
          eventType: "login.success",
          success: true,
          suspicious: true,
          details: susp.reasons.join(","),
        });
      }
      await auditLog(db, req, "auth.login.success", "user", user.id, email, user.id);

      const updatedUser = await db.get("SELECT * FROM users WHERE id = ?", user.id);
      return res.json({
        user: safeUser(updatedUser, config.maxStorageBytesPerUser, studio),
        csrfToken,
        mustChangePassword: Boolean(updatedUser.must_change_password),
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/auth/mfa/verify", limiters.auth, async (req, res, next) => {
    try {
      const pendingId = req.session?.pendingMfaUserId;
      const pendingExp = req.session?.pendingMfaExpires || 0;
      if (!pendingId || pendingExp <= Date.now()) {
        return res.status(401).json({ error: "MFA session expired. Please sign in again." });
      }

      const user = await db.get("SELECT * FROM users WHERE id = ?", pendingId);
      if (!user || user.status !== "active" || !user.mfa_enabled || !user.mfa_secret) {
        return res.status(401).json({ error: "MFA verification unavailable" });
      }

      const code = String(req.body.code || "").trim();
      let valid = verifyTotpCode(user.mfa_secret, code, 1);
      let usedRecovery = false;

      if (!valid && code) {
        const rec = consumeRecoveryCode(user.mfa_recovery_codes, code);
        if (rec.valid) {
          valid = true;
          usedRecovery = true;
          await db.run(
            "UPDATE users SET mfa_recovery_codes = ? WHERE id = ?",
            rec.nextJson,
            user.id
          );
        }
      }

      if (!valid) {
        await recordSecurityEvent(db, req, {
          userId: user.id,
          studioId: user.studio_id,
          email: user.email,
          eventType: "mfa.failed",
          success: false,
          suspicious: true,
          details: "invalid_totp_or_recovery_code",
        });
        return res.status(401).json({ error: "Invalid verification code" });
      }

      const studio = user.studio_id
        ? (await db.get("SELECT * FROM studios WHERE id = ?", user.studio_id)) || null
        : null;
      const susp = await detectSuspiciousLogin(db, req, user, true);

      const csrfToken = await regenerateSession(req, {
        userId: user.id,
        mfaVerified: true,
      });

      await db.run("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", user.id);
      await registerUserSession(db, req, user);
      await recordSecurityEvent(db, req, {
        userId: user.id,
        studioId: user.studio_id,
        email: user.email,
        eventType: "mfa.verified",
        success: true,
        suspicious: susp.suspicious,
        details: usedRecovery ? "recovery_code" : "totp",
      });
      await recordSecurityEvent(db, req, {
        userId: user.id,
        studioId: user.studio_id,
        email: user.email,
        eventType: "login.success",
        success: true,
        suspicious: susp.suspicious,
        details: susp.reasons.join(","),
      });
      await auditLog(db, req, "auth.login.mfa_success", "user", user.id, user.email, user.id);

      const updatedUser = await db.get("SELECT * FROM users WHERE id = ?", user.id);
      return res.json({
        user: safeUser(updatedUser, config.maxStorageBytesPerUser, studio),
        csrfToken,
        usedRecovery,
        mustChangePassword: Boolean(updatedUser.must_change_password),
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/auth/logout", async (req, res, next) => {
    try {
      const uid = req.session?.userId || null;
      const sid = req.sessionID;
      if (uid) {
        const user = await db.get("SELECT email, studio_id FROM users WHERE id = ?", uid);
        if (sid) await revokeSingleSession(db, sid);
        await recordSecurityEvent(db, req, {
          userId: uid,
          studioId: user?.studio_id || null,
          email: user?.email || "",
          eventType: "logout",
          success: true,
          sessionId: sid,
        });
        await auditLog(db, req, "auth.logout", "user", uid, "", uid);
      }
      req.session.destroy(() => {
        res.clearCookie("connect.sid");
        res.json({ ok: true });
      });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/auth/me", async (req, res, next) => {
    try {
      const ctx = await loadSessionContext(db, req);
      let user = null;
      let studio = null;
      if (ctx && !ctx.revoked && ctx.user.status === "active") {
        if (ctx.user.role === "super_admin" || !ctx.studio || ctx.studio.status === "active") {
          user = ctx.user;
          studio = ctx.studio;
        }
      }

      const hadCsrf = Boolean(req.session?.csrfToken);
      const csrfToken = ensureCsrf(req);
      const payload = {
        user: safeUser(user, config.maxStorageBytesPerUser, studio),
        csrfToken,
        inviteRequired: Boolean(config.registrationInviteCode),
        pendingMfa: Boolean(
          req.session?.pendingMfaUserId && (req.session?.pendingMfaExpires || 0) > Date.now()
        ),
        mustChangePassword: Boolean(user?.must_change_password),
      };

      if (hadCsrf) {
        return res.json(payload);
      }
      return req.session.save((err) => {
        if (err) return next(err);
        return res.json(payload);
      });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/auth/csrf", (req, res, next) => {
    const hadCsrf = Boolean(req.session?.csrfToken);
    const csrfToken = ensureCsrf(req);
    if (hadCsrf) {
      return res.json({ csrfToken });
    }
    return req.session.save((err) => {
      if (err) return next(err);
      return res.json({ csrfToken });
    });
  });

  router.patch("/profile", auth, async (req, res, next) => {
    try {
      const name = String(req.body.name || "").trim();
      const phone = String(req.body.phone || "").trim().slice(0, 40);
      const studioName = String(req.body.studio || "").trim().slice(0, 120);

      if (!name || name.length > 100) {
        return res.status(400).json({ error: "Valid name (1–100 characters) required" });
      }

      await db.tx(async (tx) => {
        await tx.run(
          "UPDATE users SET name = ?, phone = ?, studio = ? WHERE id = ?",
          name,
          phone,
          studioName,
          req.user.id
        );
        if (req.user.role === "studio_owner" && req.user.studio_id && studioName) {
          await tx.run("UPDATE studios SET name = ? WHERE id = ?", studioName, req.user.studio_id);
        }
      });

      await auditLog(db, req, "profile.updated", "user", req.user.id);
      const updated = await db.get("SELECT * FROM users WHERE id = ?", req.user.id);
      const studio = updated.studio_id
        ? (await db.get("SELECT * FROM studios WHERE id = ?", updated.studio_id)) || null
        : null;
      return res.json({ user: safeUser(updated, config.maxStorageBytesPerUser, studio) });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/auth/password", authAllowPwChange, limiters.auth, async (req, res, next) => {
    try {
      const currentPassword = String(req.body.current_password || "");
      const newPassword = String(req.body.new_password || "");

      if (!currentPassword || !(await bcrypt.compare(currentPassword, req.user.password_hash))) {
        return res.status(401).json({ error: "Current password is incorrect" });
      }
      if (newPassword.length < 6 || newPassword.length > 128) {
        return res.status(400).json({ error: "New password must be between 6 and 128 characters" });
      }

      const nextHash = await bcrypt.hash(newPassword, 12);
      const wasMfaVerified = Boolean(req.session?.mfaVerified);
      const oldSid = req.sessionID;

      await db.run(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        nextHash,
        req.user.id
      );

      const csrfToken = await regenerateSession(req, {
        userId: req.user.id,
        mfaVerified: wasMfaVerified,
      });

      await revokeUserSessions(db, req.user.id, oldSid);
      if (oldSid) await revokeSingleSession(db, oldSid);
      await registerUserSession(db, req, req.user);

      await recordSecurityEvent(db, req, {
        userId: req.user.id,
        studioId: req.user.studio_id,
        email: req.user.email,
        eventType: "password.changed",
        success: true,
      });
      await auditLog(db, req, "auth.password_changed", "user", req.user.id);

      return res.json({ ok: true, csrfToken });
    } catch (err) {
      return next(err);
    }
  });

  // Self-service password reset request & token completion
  router.post("/auth/password-reset/request", limiters.auth, async (req, res, next) => {
    try {
      const email = String(req.body.email || "").toLowerCase().trim();
      const user = email && email.length <= 160 ? await db.get("SELECT * FROM users WHERE email = ?", email) : null;
      // Keep responses indistinguishable for valid/invalid accounts to prevent enumeration.
      if (user && user.status === "active" && config.resetEmailConfigured) {
        try {
          const { rawToken } = await createPasswordResetToken(db, user.id, "self", 30);
          const resetUrl = new URL("/reset-password.html", config.baseUrl);
          resetUrl.searchParams.set("token", rawToken);
          const { sendPasswordResetEmail } = require("../email");
          await sendPasswordResetEmail(config, user.email, resetUrl.toString());
          await recordSecurityEvent(db, req, {
            userId: user.id, studioId: user.studio_id, email: user.email,
            eventType: "password.reset_requested", success: true, details: "self_service_email_sent",
          });
          await auditLog(db, req, "auth.password_reset_email_sent", "user", user.id, user.email, user.id);
        } catch (mailErr) {
          // Never log reset tokens, links, request bodies, or provider response bodies.
          console.error("[SnapFind] Password reset delivery failed:", String(mailErr?.message || "mail delivery error").slice(0, 180));
          await recordSecurityEvent(db, req, {
            userId: user.id, studioId: user.studio_id, email: user.email,
            eventType: "password.reset_delivery_failed", success: false, details: "provider_delivery_error",
          });
        }
      } else if (user && user.status === "active") {
        await recordSecurityEvent(db, req, {
          userId: user.id, studioId: user.studio_id, email: user.email,
          eventType: "password.reset_requested", success: false, details: "email_provider_not_configured",
        });
      }
      return res.json({
        ok: true,
        message: "If an active account matches that email, a password-reset link will be sent when email delivery is configured.",
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/auth/password-reset/confirm", limiters.auth, async (req, res, next) => {
    try {
      const token = String(req.body.token || "").trim();
      const newPassword = String(req.body.new_password || "");

      if (!token) {
        return res.status(400).json({ error: "Reset token is required" });
      }
      if (newPassword.length < 6 || newPassword.length > 128) {
        return res.status(400).json({ error: "New password must be between 6 and 128 characters" });
      }

      const resetRow = await consumePasswordResetToken(db, token);
      if (!resetRow) {
        return res.status(400).json({ error: "Reset link is invalid or has expired" });
      }

      const user = await db.get("SELECT * FROM users WHERE id = ?", resetRow.user_id);
      if (!user || user.status === "deleted") {
        return res.status(400).json({ error: "Account unavailable" });
      }

      const nextHash = await bcrypt.hash(newPassword, 12);
      await db.tx(async (tx) => {
        await tx.run(
          "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
          nextHash,
          user.id
        );
        // A successful reset invalidates every other outstanding reset link.
        await tx.run(
          "DELETE FROM password_resets WHERE user_id = ? AND id <> ? AND used_at IS NULL",
          user.id,
          resetRow.id
        );
      });

      await revokeUserSessions(db, user.id);
      await recordSecurityEvent(db, req, {
        userId: user.id,
        studioId: user.studio_id,
        email: user.email,
        eventType: "password.reset_completed",
        success: true,
        details: `initiated_by=${resetRow.initiated_by}`,
      });
      await auditLog(db, req, "auth.password_reset_completed", "user", user.id, user.email, user.id);

      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  // MFA management for authenticated user
  router.post("/auth/mfa/setup", auth, async (req, res, next) => {
    try {
      const secret = generateTotpSecret();
      const otpauthUrl = buildOtpAuthUri({ secret, email: req.user.email });
      const qr = await QRCode.toDataURL(otpauthUrl, { width: 320, margin: 2 });
      req.session.pendingMfaSetupSecret = secret;
      return req.session.save((err) => {
        if (err) return next(err);
        return res.json({ secret, otpauthUrl, qr });
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/auth/mfa/enable", auth, async (req, res, next) => {
    try {
      const secret = req.session?.pendingMfaSetupSecret;
      const code = String(req.body.code || "").trim();
      if (!secret) {
        return res.status(400).json({ error: "Start MFA setup first" });
      }
      if (!verifyTotpCode(secret, code, 1)) {
        return res.status(400).json({ error: "Invalid 6-digit authenticator code" });
      }

      const recoveryCodes = generateRecoveryCodes(8);
      const hashed = hashRecoveryCodes(recoveryCodes);

      await db.run(
        "UPDATE users SET mfa_enabled = 1, mfa_secret = ?, mfa_recovery_codes = ? WHERE id = ?",
        secret,
        hashed,
        req.user.id
      );

      delete req.session.pendingMfaSetupSecret;
      req.session.mfaVerified = true;

      await recordSecurityEvent(db, req, {
        userId: req.user.id,
        studioId: req.user.studio_id,
        email: req.user.email,
        eventType: "mfa.enabled",
        success: true,
      });
      await auditLog(db, req, "auth.mfa_enabled", "user", req.user.id);

      return req.session.save((err) => {
        if (err) return next(err);
        return res.json({ ok: true, recoveryCodes });
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/auth/mfa/disable", auth, async (req, res, next) => {
    try {
      if (req.user.role === "super_admin") {
        return res.status(403).json({ error: "MFA cannot be disabled on Super Admin accounts" });
      }
      const password = String(req.body.password || "");
      if (!password || !(await bcrypt.compare(password, req.user.password_hash))) {
        return res.status(401).json({ error: "Incorrect password" });
      }

      await db.run(
        "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_recovery_codes = NULL WHERE id = ?",
        req.user.id
      );

      await recordSecurityEvent(db, req, {
        userId: req.user.id,
        studioId: req.user.studio_id,
        email: req.user.email,
        eventType: "mfa.disabled",
        success: true,
      });
      await auditLog(db, req, "auth.mfa_disabled", "user", req.user.id);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  // Self-service active sessions management
  router.get("/auth/sessions", auth, async (req, res, next) => {
    try {
      const rows = await db.all(
        `SELECT sid, ip, device_label, created_at, last_seen_at
         FROM user_sessions
         WHERE user_id = ? AND revoked_at IS NULL
         ORDER BY last_seen_at DESC`,
        req.user.id
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

  router.delete("/auth/sessions/:sid", auth, async (req, res, next) => {
    try {
      const target = await db.get(
        "SELECT sid, user_id FROM user_sessions WHERE sid = ?",
        req.params.sid
      );
      if (!target || target.user_id !== req.user.id) {
        return res.status(404).json({ error: "Session not found" });
      }
      await revokeSingleSession(db, target.sid);
      await recordSecurityEvent(db, req, {
        userId: req.user.id,
        studioId: req.user.studio_id,
        email: req.user.email,
        eventType: "session.revoked",
        success: true,
        details: "self_revoke",
      });
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}

module.exports = { createAuthRouter, createUniqueSlug };

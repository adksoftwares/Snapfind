const crypto = require("node:crypto");
const { v4: uuid } = require("uuid");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str) {
  const clean = String(str || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function buildOtpAuthUri({ secret, email, issuer = "SnapFind AI" }) {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function computeHotp(secret, counter) {
  const key = base32Decode(secret);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

function verifyTotpCode(secret, token, windowSteps = 1, nowMs = Date.now()) {
  const clean = String(token || "").trim();
  if (!secret || !/^\d{6}$/.test(clean)) return false;
  const currentStep = Math.floor(nowMs / 1000 / 30);
  for (let delta = -windowSteps; delta <= windowSteps; delta++) {
    const expected = computeHotp(secret, currentStep + delta);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(clean))) {
      return true;
    }
  }
  return false;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString("hex").toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

function hashRecoveryCodes(codes) {
  return JSON.stringify(codes.map((c) => sha256Hex(c.replace(/-/g, "").toUpperCase())));
}

function consumeRecoveryCode(storedJson, providedCode) {
  if (!storedJson) return { valid: false, nextJson: storedJson };
  let hashes;
  try {
    hashes = JSON.parse(storedJson);
  } catch {
    return { valid: false, nextJson: storedJson };
  }
  if (!Array.isArray(hashes)) return { valid: false, nextJson: storedJson };
  const target = sha256Hex(String(providedCode || "").replace(/[-\s]/g, "").toUpperCase());
  const idx = hashes.findIndex(
    (h) =>
      typeof h === "string" &&
      h.length === target.length &&
      crypto.timingSafeEqual(Buffer.from(h), Buffer.from(target))
  );
  if (idx === -1) return { valid: false, nextJson: storedJson };
  hashes.splice(idx, 1);
  return { valid: true, nextJson: JSON.stringify(hashes) };
}

function parseDeviceLabel(userAgent) {
  const ua = String(userAgent || "");
  if (!ua) return "Unknown device";
  let browser = "Browser";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/Chrome\//i.test(ua)) browser = "Chrome";
  else if (/Firefox\//i.test(ua)) browser = "Firefox";
  else if (/Safari\//i.test(ua)) browser = "Safari";
  else if (/node|undici|curl/i.test(ua)) browser = "API Client";

  let os = "Unknown OS";
  if (/Windows/i.test(ua)) os = "Windows";
  else if (/iPhone|iPad|iOS/i.test(ua)) os = "iOS";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/Mac OS X|Macintosh/i.test(ua)) os = "macOS";
  else if (/Linux/i.test(ua)) os = "Linux";

  return `${browser} on ${os}`;
}

function getClientMeta(req) {
  const ip = String(req.ip || req.socket?.remoteAddress || "")
    .replace(/^::ffff:/, "")
    .slice(0, 64);
  const userAgent = String(req.get?.("user-agent") || req.headers?.["user-agent"] || "").slice(0, 300);
  const deviceLabel = parseDeviceLabel(userAgent);
  return { ip, userAgent, deviceLabel };
}

async function recordSecurityEvent(db, req, opts) {
  try {
    const meta = getClientMeta(req);
    await db.run(
      `INSERT INTO security_events (
        id, user_id, studio_id, email, event_type, success,
        ip, user_agent, device_label, session_id, suspicious, details
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      uuid(),
      opts.userId ?? null,
      opts.studioId ?? null,
      String(opts.email || "").slice(0, 160),
      String(opts.eventType),
      opts.success === false ? 0 : 1,
      meta.ip,
      meta.userAgent,
      meta.deviceLabel,
      String(opts.sessionId || req.sessionID || "").slice(0, 128),
      opts.suspicious ? 1 : 0,
      String(opts.details || "").slice(0, 500)
    );
  } catch (err) {
    console.error("[SnapFind] Failed to write security event:", err);
  }
}

async function detectSuspiciousLogin(db, req, user, success) {
  const meta = getClientMeta(req);
  const reasons = [];

  const failRow = await db.get(
    `SELECT COUNT(*) AS cnt FROM security_events
     WHERE event_type = 'login.failed'
       AND ip = ?
       AND created_at >= datetime('now', '-15 minutes')`,
    meta.ip
  );
  const recentFailsFromIp = Number(failRow?.cnt || 0);

  if (recentFailsFromIp >= 3) {
    reasons.push("multiple_failed_attempts_ip");
  }

  if (user) {
    if (user.status !== "active") {
      reasons.push(`login_on_${user.status}_account`);
    }
    if (success) {
      const priorRow = await db.get(
        `SELECT COUNT(*) AS cnt FROM security_events
         WHERE user_id = ? AND event_type = 'login.success'`,
        user.id
      );
      const priorLogins = Number(priorRow?.cnt || 0);
      if (priorLogins > 0) {
        const knownIp = await db.get(
          `SELECT id FROM security_events
           WHERE user_id = ? AND event_type = 'login.success' AND ip = ? LIMIT 1`,
          user.id,
          meta.ip
        );
        if (!knownIp) {
          reasons.push("new_ip_address");
        }
      }
    }
  }

  return {
    suspicious: reasons.length > 0,
    reasons,
  };
}

async function registerUserSession(db, req, user) {
  const meta = getClientMeta(req);
  await db.run(
    `INSERT INTO user_sessions (sid, user_id, studio_id, ip, user_agent, device_label)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(sid) DO UPDATE SET
       last_seen_at = CURRENT_TIMESTAMP,
       revoked_at = NULL`,
    req.sessionID,
    user.id,
    user.studio_id ?? null,
    meta.ip,
    meta.userAgent,
    meta.deviceLabel
  );
}

async function revokeUserSessions(db, userId, exceptSid = null) {
  const rows = exceptSid
    ? await db.all(
        "SELECT sid FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL AND sid <> ?",
        userId,
        exceptSid
      )
    : await db.all(
        "SELECT sid FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL",
        userId
      );

  await db.tx(async (tx) => {
    if (exceptSid) {
      await tx.run(
        "UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL AND sid <> ?",
        userId,
        exceptSid
      );
    } else {
      await tx.run(
        "UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL",
        userId
      );
    }
    for (const r of rows) {
      await tx.run("DELETE FROM sessions WHERE sid = ?", r.sid);
    }
  });
  return rows.length;
}

async function revokeSingleSession(db, sid) {
  await db.tx(async (tx) => {
    await tx.run(
      "UPDATE user_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE sid = ? AND revoked_at IS NULL",
      sid
    );
    await tx.run("DELETE FROM sessions WHERE sid = ?", sid);
  });
}

async function createPasswordResetToken(db, userId, initiatedBy = "self", ttlMinutes = 60) {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = sha256Hex(rawToken);
  const expiresAt = Date.now() + ttlMinutes * 60 * 1000;
  await db.run(
    `INSERT INTO password_resets (id, user_id, token_hash, initiated_by, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
    uuid(),
    userId,
    tokenHash,
    String(initiatedBy),
    expiresAt
  );
  return { rawToken, expiresAt };
}

async function consumePasswordResetToken(db, rawToken, nowMs = Date.now()) {
  const tokenHash = sha256Hex(String(rawToken || "").trim());
  return db.tx(async (tx) => {
    const row = await tx.get("SELECT * FROM password_resets WHERE token_hash = ?", tokenHash);
    if (!row || row.used_at || Number(row.expires_at) <= nowMs) {
      return null;
    }
    const result = await tx.run(
      "UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL AND expires_at > ?",
      row.id,
      nowMs
    );
    if (!Number(result?.changes || 0)) return null;
    return row;
  });
}

module.exports = {
  generateTotpSecret,
  buildOtpAuthUri,
  verifyTotpCode,
  computeHotp,
  generateRecoveryCodes,
  hashRecoveryCodes,
  consumeRecoveryCode,
  parseDeviceLabel,
  getClientMeta,
  recordSecurityEvent,
  detectSuspiciousLogin,
  registerUserSession,
  revokeUserSessions,
  revokeSingleSession,
  createPasswordResetToken,
  consumePasswordResetToken,
};

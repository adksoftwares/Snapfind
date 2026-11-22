const fs = require("node:fs");
const { Readable } = require("node:stream");
const express = require("express");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");
const {
  isValidEmail,
  escapeLike,
  ensureCsrf,
  getSessionUser,
} = require("../middleware");
const {
  resolveMediaPath,
  buildBlobPathname,
  fetchPrivateMediaBlob,
  signMediaUrl,
  verifyMediaSignature,
  encodeContentDisposition,
} = require("../media");
const { mapPhotoUrls } = require("./events");
const { decryptFaceDescriptor } = require("../biometric");

async function isEventUnlocked(db, req, event) {
  if (!event.pin_hash) return true;
  if (req.session?.unlockedEvents?.[event.id]) return true;
  const user = await getSessionUser(db, req);
  if (
    user &&
    (user.role === "super_admin" ||
      (user.studio_id && user.studio_id === event.studio_id) ||
      user.id === event.owner_id)
  ) {
    return true;
  }
  return false;
}

async function getActiveEventByCode(db, code) {
  return (
    (await db.get(
      `SELECT e.*
       FROM events e
       LEFT JOIN studios s ON s.id = e.studio_id
       WHERE e.access_code = ?
         AND e.status = 'active'
         AND COALESCE(s.status, 'active') = 'active'`,
      code
    )) || null
  );
}

function euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < 128; i++) {
    const diff = a[i] - b[i];
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

function createGalleryRouter({ db, config, io, limiters }) {
  const router = express.Router();

  router.get("/public/events", async (req, res, next) => {
    try {
      const rows = await db.all(
        `SELECT e.id, e.title, e.description, e.event_date, e.venue, e.access_code,
                e.pin_hash, e.ai_enabled, e.selfie_only, e.created_at,
                COALESCE(NULLIF(s.name, ''), u.studio, u.name) AS studio_name,
                u.name AS photographer_name,
                (SELECT COUNT(*) FROM photos p WHERE p.event_id = e.id) AS photo_count,
                (SELECT thumb_filename FROM photos WHERE event_id = e.id ORDER BY created_at DESC LIMIT 1) AS cover_thumb
         FROM events e
         JOIN users u ON u.id = e.owner_id
         LEFT JOIN studios s ON s.id = e.studio_id
         WHERE e.is_public = 1
           AND e.pin_hash IS NULL
           AND e.status = 'active'
           AND COALESCE(s.status, 'active') = 'active'
         ORDER BY e.created_at DESC
         LIMIT 50`
      );

      const events = rows.map((e) => {
        const selfieOnly = Boolean(e.ai_enabled && e.selfie_only);
        return {
          id: e.id,
          title: e.title,
          description: e.description,
          event_date: e.event_date,
          venue: e.venue,
          access_code: e.access_code,
          has_pin: Boolean(e.pin_hash),
          ai_enabled: Boolean(e.ai_enabled),
          selfie_only: selfieOnly,
          studio_name: e.studio_name || e.photographer_name,
          photo_count: Number(e.photo_count || 0),
          cover_url:
            !e.pin_hash && !selfieOnly && e.cover_thumb
              ? signMediaUrl(config, {
                  variant: "thumbs",
                  eventId: e.id,
                  filename: e.cover_thumb,
                  originalName: "cover.webp",
                  isPublic: true,
                })
              : null,
        };
      });

      return res.json({ events });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/gallery/:code", limiters.galleryLookup, async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const event = await getActiveEventByCode(db, code);

      if (!event) {
        return res.status(404).json({ error: "Gallery unavailable" });
      }

      const hadCsrf = Boolean(req.session?.csrfToken);
      const csrfToken = ensureCsrf(req);
      const unlocked = await isEventUnlocked(db, req, event);
      const selfieOnly = Boolean(event.ai_enabled && event.selfie_only);
      const eventInfo = {
        id: event.id,
        title: event.title,
        description: event.description,
        event_date: event.event_date,
        venue: event.venue,
        access_code: event.access_code,
        is_public: Boolean(event.is_public),
        has_pin: Boolean(event.pin_hash),
        ai_enabled: Boolean(event.ai_enabled),
        selfie_only: selfieOnly,
        face_match_consent: Number(req.session?.faceMatchConsent?.[event.id] || 0) === Number(event.ai_consent_version || 1),
        status: event.status,
      };

      const respond = (payload) => {
        if (hadCsrf) {
          return res.json({ ...payload, csrfToken });
        }
        return req.session.save((err) => {
          if (err) return next(err);
          return res.json({ ...payload, csrfToken });
        });
      };

      if (!unlocked) {
        return respond({
          locked: true,
          event: eventInfo,
          photos: [],
          pagination: { page: 1, limit: 48, total: 0, total_pages: 0 },
        });
      }

      const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 48));
      const offset = (page - 1) * limit;
      const q = String(req.query.q || "").trim().toLowerCase();
      const guestKey = String(req.query.guest_key || "").trim().slice(0, 80);
      const idsParam = String(req.query.ids || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 100);

      const sessionMatches = selfieOnly && Array.isArray(req.session?.matchedPhotos?.[event.id])
        ? req.session.matchedPhotos[event.id]
        : null;
      const totalEventRow = await db.get(
        "SELECT COUNT(*) AS cnt FROM photos WHERE event_id = ?",
        event.id
      );
      const totalEventPhotos = Number(totalEventRow?.cnt || 0);

      let total = 0;
      let photos = [];

      if (!selfieOnly || (sessionMatches && sessionMatches.length > 0)) {
        let whereSql = "WHERE event_id = ?";
        const params = [event.id];

        if (selfieOnly && sessionMatches) {
          const allowedSet = new Set(sessionMatches);
          const effectiveIds =
            idsParam.length > 0
              ? idsParam.filter((id) => allowedSet.has(id))
              : sessionMatches.slice(0, 100);
          if (effectiveIds.length > 0) {
            const placeholders = effectiveIds.map(() => "?").join(",");
            whereSql += ` AND id IN (${placeholders})`;
            params.push(...effectiveIds);
          } else {
            whereSql += " AND 1 = 0";
          }
        } else if (idsParam.length > 0) {
          const placeholders = idsParam.map(() => "?").join(",");
          whereSql += ` AND id IN (${placeholders})`;
          params.push(...idsParam);
        }

        if (q) {
          const escaped = escapeLike(q);
          whereSql +=
            " AND (LOWER(caption) LIKE ? ESCAPE '\\' OR LOWER(original_name) LIKE ? ESCAPE '\\')";
          params.push(`%${escaped}%`, `%${escaped}%`);
        }

        const totalRow = await db.get(`SELECT COUNT(*) AS cnt FROM photos ${whereSql}`, ...params);
        total = Number(totalRow?.cnt || 0);

        const photoRows = await db.all(
          `SELECT * FROM photos ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
          ...params,
          limit,
          offset
        );
        photos = photoRows.map((p) => mapPhotoUrls(config, p, event));
      }

      const facesRow = await db.get(
        "SELECT COUNT(*) AS cnt FROM photo_faces WHERE event_id = ?",
        event.id
      );
      const indexedFaces = Number(facesRow?.cnt || 0);

      let favouritedIds = [];
      let selectedIds = [];
      if (guestKey) {
        favouritedIds = (
          await db.all(
            "SELECT photo_id FROM favourites WHERE event_id = ? AND guest_key = ?",
            event.id,
            guestKey
          )
        ).map((r) => r.photo_id);
        selectedIds = (
          await db.all(
            "SELECT DISTINCT photo_id FROM selections WHERE event_id = ? AND guest_key = ?",
            event.id,
            guestKey
          )
        ).map((r) => r.photo_id);
      }

      return respond({
        locked: false,
        event: eventInfo,
        photos,
        total_event_photos: totalEventPhotos,
        selfie_scanned: Boolean(sessionMatches && sessionMatches.length > 0),
        indexed_faces: indexedFaces,
        favourited_ids: favouritedIds,
        selected_ids: selectedIds,
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

  router.post("/gallery/:code/unlock", limiters.pinUnlock, async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const pin = String(req.body.pin || "").trim();
      const event = await getActiveEventByCode(db, code);

      if (!event) {
        return res.status(404).json({ error: "Gallery unavailable" });
      }
      if (!event.pin_hash) {
        return res.json({ ok: true });
      }
      if (!pin || !(await bcrypt.compare(pin, event.pin_hash))) {
        return res.status(401).json({ error: "Incorrect event PIN" });
      }

      if (!req.session.unlockedEvents) {
        req.session.unlockedEvents = {};
      }
      req.session.unlockedEvents[event.id] = true;
      const csrfToken = ensureCsrf(req);
      return req.session.save((err) => {
        if (err) return next(err);
        return res.json({ ok: true, csrfToken });
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/gallery/:code/match/consent", limiters.guestAction, async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const event = await getActiveEventByCode(db, code);
      if (!event) return res.status(404).json({ error: "Gallery unavailable" });
      if (!(await isEventUnlocked(db, req, event))) {
        return res.status(403).json({ error: "Gallery PIN required" });
      }
      if (!event.ai_enabled) {
        return res.status(403).json({ error: "AI face discovery is disabled for this event" });
      }
      if (!req.session.faceMatchConsent) req.session.faceMatchConsent = {};
      req.session.faceMatchConsent[event.id] = Number(event.ai_consent_version || 1);
      return req.session.save((err) => {
        if (err) return next(err);
        return res.json({ ok: true, consented: true });
      });
    } catch (err) {
      return next(err);
    }
  });

  // Ephemeral server-side face matching: client sends ONLY its own selfie vector, never receives others'
  router.post("/gallery/:code/match", limiters.guestAction, async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const event = await getActiveEventByCode(db, code);

      if (!event) {
        return res.status(404).json({ error: "Gallery unavailable" });
      }
      if (!(await isEventUnlocked(db, req, event))) {
        return res.status(403).json({ error: "Gallery PIN required" });
      }
      if (!event.ai_enabled) {
        return res.status(403).json({ error: "AI face discovery is disabled for this event" });
      }
      if (Number(req.session?.faceMatchConsent?.[event.id] || 0) !== Number(event.ai_consent_version || 1)) {
        return res.status(403).json({ error: "Guest face-discovery consent is required" });
      }

      const rawList = Array.isArray(req.body?.descriptors)
        ? req.body.descriptors.slice(0, 6)
        : req.body?.descriptor
          ? [req.body.descriptor]
          : [];

      const queryDescriptors = rawList.filter(
        (d) =>
          Array.isArray(d) &&
          d.length === 128 &&
          d.every((n) => typeof n === "number" && Number.isFinite(n) && n >= -2 && n <= 2)
      );

      if (!queryDescriptors.length) {
        return res.status(400).json({ error: "Valid 128-dimension face descriptor required" });
      }

      const rows = await db.all(
        "SELECT photo_id, descriptor_json FROM photo_faces WHERE event_id = ?",
        event.id
      );

      const bestByPhoto = new Map();
      for (const r of rows) {
        try {
          const stored = decryptFaceDescriptor(config, r.descriptor_json);
          if (!Array.isArray(stored) || stored.length !== 128 || !stored.every((n) => typeof n === "number" && Number.isFinite(n) && n >= -2 && n <= 2)) continue;
          let dist = 1;
          for (const q of queryDescriptors) {
            const d = euclideanDistance(q, stored);
            if (d < dist) dist = d;
          }
          const prev = bestByPhoto.get(r.photo_id);
          if (prev === undefined || dist < prev) {
            bestByPhoto.set(r.photo_id, dist);
          }
        } catch {
          // skip invalid descriptor
        }
      }

      // Keep face matching conservative and server-controlled. Client-adjustable
      // thresholds can increase false positives and expose unrelated guests' photos.
      const threshold = 0.58;
      const matches = [];
      for (const [photo_id, distance] of bestByPhoto.entries()) {
        if (distance < threshold) {
          const confidence = Math.max(1, Math.min(99, Math.round((1 - distance / 0.85) * 100)));
          matches.push({
            photo_id,
            distance: Number(distance.toFixed(4)),
            confidence,
          });
        }
      }
      matches.sort((a, b) => a.distance - b.distance);

      const matchedIds = matches.map((m) => m.photo_id).slice(0, 100);
      if (!req.session.matchedPhotos) {
        req.session.matchedPhotos = {};
      }
      req.session.matchedPhotos[event.id] = matchedIds;

      let matchedPhotos = [];
      if (matchedIds.length > 0) {
        const placeholders = matchedIds.map(() => "?").join(",");
        const photoRows = await db.all(
          `SELECT * FROM photos WHERE event_id = ? AND id IN (${placeholders})`,
          event.id,
          ...matchedIds
        );
        const byId = new Map(photoRows.map((p) => [p.id, mapPhotoUrls(config, p, event)]));
        matchedPhotos = matches
          .map((m) => {
            const item = byId.get(m.photo_id);
            return item ? { ...item, distance: m.distance, confidence: m.confidence } : null;
          })
          .filter(Boolean);
      }

      const scannedRow = await db.get(
        "SELECT COUNT(*) AS cnt FROM photos WHERE event_id = ? AND face_indexed = 1",
        event.id
      );

      return req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        return res.json({
          indexed_count: bestByPhoto.size,
          scanned_photos_count: Number(scannedRow?.cnt || 0),
          selfie_only: Boolean(event.selfie_only),
          matches,
          photos: matchedPhotos,
        });
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/gallery/:code/match/clear", limiters.guestAction, async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const event = await getActiveEventByCode(db, code);
      if (!event) return res.status(404).json({ error: "Gallery unavailable" });

      if (req.session?.matchedPhotos?.[event.id]) {
        delete req.session.matchedPhotos[event.id];
      }
      if (req.session?.faceMatchConsent?.[event.id]) {
        delete req.session.faceMatchConsent[event.id];
      }
      return req.session.save((err) => {
        if (err) return next(err);
        return res.json({ ok: true });
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/gallery/:code/select", limiters.guestAction, async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const event = await getActiveEventByCode(db, code);

      if (!event) return res.status(404).json({ error: "Gallery unavailable" });
      if (!(await isEventUnlocked(db, req, event))) {
        return res.status(403).json({ error: "Gallery PIN required" });
      }

      const photoId = String(req.body.photo_id || "").trim();
      const guestName = String(req.body.guest_name || "").trim().slice(0, 100);
      const guestEmail = String(req.body.guest_email || "").trim().slice(0, 160);
      const guestKey = String(req.body.guest_key || "").trim().slice(0, 80);

      if (!guestKey || guestKey.length < 8) {
        return res.status(400).json({ error: "Valid guest key required" });
      }
      if (guestEmail && !isValidEmail(guestEmail)) {
        return res.status(400).json({ error: "Please enter a valid email address" });
      }

      const photo = await db.get(
        "SELECT id, original_name FROM photos WHERE id = ? AND event_id = ?",
        photoId,
        event.id
      );
      if (!photo) {
        return res.status(400).json({ error: "Invalid photo" });
      }

      const existing = await db.get(
        "SELECT id FROM selections WHERE photo_id = ? AND guest_key = ?",
        photo.id,
        guestKey
      );
      if (existing) {
        return res.json({ ok: true, duplicate: true });
      }

      await db.run(
        `INSERT INTO selections (id, event_id, photo_id, guest_name, guest_email, guest_key)
         VALUES (?, ?, ?, ?, ?, ?)`,
        uuid(),
        event.id,
        photo.id,
        guestName,
        guestEmail,
        guestKey
      );

      io.to(`studio:${event.studio_id || event.owner_id}`).emit("selection:new", {
        event_id: event.id,
        photo_id: photo.id,
        guest_name: guestName || "Guest",
      });

      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/gallery/:code/favourite", limiters.guestAction, async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const event = await getActiveEventByCode(db, code);

      if (!event) return res.status(404).json({ error: "Gallery unavailable" });
      if (!(await isEventUnlocked(db, req, event))) {
        return res.status(403).json({ error: "Gallery PIN required" });
      }

      const photoId = String(req.body.photo_id || "").trim();
      const guestKey = String(req.body.guest_key || "").trim().slice(0, 80);
      if (!guestKey || guestKey.length < 8) {
        return res.status(400).json({ error: "Valid guest key required" });
      }

      const photo = await db.get(
        "SELECT id FROM photos WHERE id = ? AND event_id = ?",
        photoId,
        event.id
      );
      if (!photo) {
        return res.status(400).json({ error: "Invalid photo" });
      }

      const existing = await db.get(
        "SELECT id FROM favourites WHERE photo_id = ? AND guest_key = ?",
        photo.id,
        guestKey
      );

      if (existing) {
        await db.run("DELETE FROM favourites WHERE id = ?", existing.id);
        return res.json({ ok: true, favourited: false });
      }

      await db.run(
        "INSERT INTO favourites (id, photo_id, event_id, guest_key) VALUES (?, ?, ?, ?)",
        uuid(),
        photo.id,
        event.id,
        guestKey
      );

      return res.json({ ok: true, favourited: true });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}

async function sendMediaFile(res, { config, variant, eventId, filename, targetPath, isPublic, downloadName }) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
  res.setHeader("Cache-Control", isPublic ? "public, max-age=3600" : "private, max-age=900");

  if (downloadName) {
    res.setHeader("Content-Disposition", encodeContentDisposition(downloadName));
  }

  if (config.useBlob) {
    const blobResult = await fetchPrivateMediaBlob(variant, eventId, filename);
    if (!blobResult) {
      return res.status(404).json({ error: "Media not found" });
    }
    if (blobResult.blob?.contentType) {
      res.setHeader("Content-Type", blobResult.blob.contentType);
    }
    const readable = Readable.fromWeb(blobResult.stream);
    readable.on("error", () => {
      if (!res.headersSent) res.status(500).end();
      else res.end();
    });
    return readable.pipe(res);
  }

  return res.sendFile(targetPath, (err) => {
    if (err && !res.headersSent) {
      res.status(err.statusCode || 404).json({ error: "Media not found" });
    }
  });
}

function createFastSignedMediaHandler({ config, eventStatusCache }) {
  return async (req, res, next) => {
    try {
      const { variant, eventId, filename } = req.params;
      const { exp, pub, name, sig } = req.query;

      if (!sig) return next();

      const validTarget = config.useBlob
        ? buildBlobPathname(variant, eventId, filename)
        : resolveMediaPath(config.uploadDir, variant, eventId, filename);
      if (!validTarget) {
        return res.status(400).json({ error: "Invalid media path" });
      }

      if (
        !verifyMediaSignature(config, {
          variant,
          eventId,
          filename,
          exp,
          pub,
          name,
          sig,
        })
      ) {
        return res.status(403).json({ error: "Invalid or expired media token" });
      }

      // O(1) memory check: ensures paused/archived/deleted events stop serving immediately
      if (!(await eventStatusCache.isActive(eventId))) {
        return res.status(403).json({ error: "Media access denied" });
      }

      return await sendMediaFile(res, {
        config,
        variant,
        eventId,
        filename,
        targetPath: validTarget,
        isPublic: pub === "1",
        downloadName: req.query.download === "1" ? String(name || filename) : null,
      });
    } catch (err) {
      return next(err);
    }
  };
}

function createSessionMediaHandler({ db, config }) {
  return async (req, res, next) => {
    try {
      const { variant, eventId, filename } = req.params;
      const targetPath = config.useBlob
        ? buildBlobPathname(variant, eventId, filename)
        : resolveMediaPath(config.uploadDir, variant, eventId, filename);
      if (!targetPath) {
        return res.status(400).json({ error: "Invalid media path" });
      }

      const event = await db.get(
        `SELECT e.*, COALESCE(s.status, 'active') AS studio_status
         FROM events e
         LEFT JOIN studios s ON s.id = e.studio_id
         WHERE e.id = ?`,
        eventId
      );
      if (!event) {
        return res.status(404).json({ error: "Media not found" });
      }

      const user = await getSessionUser(db, req);
      const isOwnerOrAdmin =
        user &&
        (user.role === "super_admin" ||
          (user.studio_id && user.studio_id === event.studio_id) ||
          user.id === event.owner_id);

      if (!isOwnerOrAdmin) {
        if (
          event.status !== "active" ||
          event.studio_status !== "active" ||
          !(await isEventUnlocked(db, req, event))
        ) {
          return res.status(403).json({ error: "Media access denied" });
        }
      }

      const column =
        variant === "originals"
          ? "filename"
          : variant === "previews"
            ? "preview_filename"
            : "thumb_filename";

      const photo = await db.get(
        `SELECT id, original_name FROM photos WHERE event_id = ? AND ${column} = ?`,
        eventId,
        filename
      );

      if (!photo || (!config.useBlob && !fs.existsSync(targetPath))) {
        return res.status(404).json({ error: "Media not found" });
      }
      if (!isOwnerOrAdmin && event.ai_enabled && event.selfie_only) {
        const matched = Array.isArray(req.session?.matchedPhotos?.[event.id])
          ? req.session.matchedPhotos[event.id]
          : [];
        if (!matched.includes(photo.id)) {
          return res.status(403).json({ error: "Media access denied" });
        }
      }

      return await sendMediaFile(res, {
        config,
        variant,
        eventId,
        filename,
        targetPath,
        isPublic: Boolean(event.is_public && !event.pin_hash),
        downloadName: req.query.download === "1" ? photo.original_name || filename : null,
      });
    } catch (err) {
      return next(err);
    }
  };
}

module.exports = {
  createGalleryRouter,
  createFastSignedMediaHandler,
  createSessionMediaHandler,
  isEventUnlocked,
};

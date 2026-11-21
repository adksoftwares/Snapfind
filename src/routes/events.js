const fs = require("node:fs");
const fsp = require("node:fs/promises");
const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const QRCode = require("qrcode");
const { v4: uuid } = require("uuid");
const { getPublicBaseUrl } = require("../config");
const {
  ALL_STAFF_PERMISSIONS,
  generateAccessCode,
  isValidEmail,
  parsePermissions,
  requireAuth,
  requireStudioOwner,
  requirePermission,
  requireOwnEvent,
  auditLog,
} = require("../middleware");
const {
  processUploadedImage,
  signMediaUrl,
  deletePhotoFiles,
  deleteManyPhotoFiles,
  deleteEventMediaDir,
} = require("../media");
const { revokeUserSessions } = require("../security");

const VALID_STATUSES = new Set(["active", "paused", "archived"]);

function isValidFaceDescriptor(value) {
  return Array.isArray(value) &&
    value.length === 128 &&
    value.every((n) => typeof n === "number" && Number.isFinite(n) && n >= -2 && n <= 2);
}

function sanitizeEvent(e) {
  if (!e) return null;
  const { pin_hash, ...rest } = e;
  return {
    ...rest,
    has_pin: Boolean(pin_hash),
    is_public: Boolean(e.is_public),
    ai_enabled: Boolean(e.ai_enabled),
    selfie_only: Boolean(e.selfie_only),
  };
}

function mapPhotoUrls(config, p, event) {
  const isPublic = Boolean(
    event && event.is_public && !event.pin_hash && !(event.ai_enabled && event.selfie_only)
  );
  return {
    id: p.id,
    event_id: p.event_id,
    filename: p.filename,
    original_name: p.original_name,
    mime: p.mime,
    size: Number(p.size || 0),
    width: Number(p.width || 0),
    height: Number(p.height || 0),
    caption: p.caption || "",
    face_indexed: Boolean(p.face_indexed),
    face_count: Number(p.face_count || 0),
    created_at: p.created_at,
    thumb_url: signMediaUrl(config, {
      variant: "thumbs",
      eventId: p.event_id,
      filename: p.thumb_filename,
      originalName: p.original_name,
      isPublic,
    }),
    preview_url: signMediaUrl(config, {
      variant: "previews",
      eventId: p.event_id,
      filename: p.preview_filename,
      originalName: p.original_name,
      isPublic,
    }),
    url: signMediaUrl(config, {
      variant: "originals",
      eventId: p.event_id,
      filename: p.filename,
      originalName: p.original_name,
      isPublic,
    }),
  };
}

async function cleanupTempFiles(files = []) {
  await Promise.all(
    files.map(async (f) => {
      if (!f?.path) return;
      try {
        await fsp.unlink(f.path);
      } catch {
        // ignore missing temp file
      }
    })
  );
}

async function getStudioStorage(db, config, studioId, fallbackOwnerId) {
  const studio = studioId
    ? await db.get("SELECT storage_limit_bytes, storage_used_bytes FROM studios WHERE id = ?", studioId)
    : null;
  const limitBytes = Number(studio?.storage_limit_bytes || config.maxStorageBytesPerUser);
  const usedBytes = studioId
    ? Number(studio?.storage_used_bytes || 0)
    : Number((await db.get("SELECT storage_used_bytes FROM users WHERE id = ?", fallbackOwnerId))?.storage_used_bytes || 0);
  return { usedBytes, limitBytes };
}

function createEventsRouter({ db, config, io, eventStatusCache }) {
  const router = express.Router();
  const auth = requireAuth(db);
  const ownEvent = requireOwnEvent(db);

  fs.mkdirSync(config.tmpUploadDir, { recursive: true });

  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        try {
          fs.mkdirSync(config.tmpUploadDir, { recursive: true });
          cb(null, config.tmpUploadDir);
        } catch (err) {
          cb(err);
        }
      },
      filename: (req, file, cb) => cb(null, `${uuid()}.tmp`),
    }),
    defParamCharset: "utf8",
    limits: {
      fileSize: config.maxFileSizeBytes,
      files: config.maxFilesPerUpload,
    },
  });

  function checkUploadRequestSize(req, res, next) {
    const contentLength = Number(req.headers["content-length"] || 0);
    if (contentLength > config.maxUploadBatchBytes) {
      return res.status(413).json({
        error: `Upload request exceeds ${Math.round(config.maxUploadBatchBytes / (1024 * 1024))} MB batch limit`,
      });
    }
    return next();
  }

  async function checkQuotaBeforeUpload(req, res, next) {
    try {
      const { usedBytes, limitBytes } = await getStudioStorage(
        db,
        config,
        req.event.studio_id || req.user.studio_id,
        req.event.owner_id
      );
      const contentLength = Number(req.headers["content-length"] || 0);

      if (usedBytes >= limitBytes) {
        return res.status(413).json({
          error: `Storage quota exceeded (${Math.round(limitBytes / (1024 * 1024))} MB limit per studio)`,
        });
      }
      if (contentLength > 0 && usedBytes + contentLength > limitBytes * 1.15) {
        return res.status(413).json({
          error: `Upload exceeds remaining studio storage quota (${Math.round(limitBytes / (1024 * 1024))} MB limit)`,
        });
      }
      req.studioStorageUsed = usedBytes;
      req.studioStorageLimit = limitBytes;
      return next();
    } catch (err) {
      return next(err);
    }
  }

  router.get("/dashboard", auth, requirePermission("events:read"), async (req, res, next) => {
    try {
      const studioId = req.user.studio_id;
      const whereClause = studioId ? "e.studio_id = ?" : "e.owner_id = ?";
      const whereArg = studioId || req.user.id;

      const events = await db.all(
        `SELECT e.*,
                COALESCE(p.cnt, 0) AS photos,
                COALESCE(s.cnt, 0) AS selections,
                COALESCE(f.cnt, 0) AS indexed_faces
         FROM events e
         LEFT JOIN (
           SELECT event_id, COUNT(*) AS cnt FROM photos GROUP BY event_id
         ) p ON p.event_id = e.id
         LEFT JOIN (
           SELECT event_id, COUNT(*) AS cnt FROM selections GROUP BY event_id
         ) s ON s.event_id = e.id
         LEFT JOIN (
           SELECT event_id, COUNT(*) AS cnt FROM photo_faces GROUP BY event_id
         ) f ON f.event_id = e.id
         WHERE ${whereClause}
         ORDER BY e.created_at DESC`,
        whereArg
      );

      const totals = events.reduce(
        (acc, e) => {
          acc.events += 1;
          acc.photos += Number(e.photos || 0);
          acc.selections += Number(e.selections || 0);
          return acc;
        },
        { events: 0, photos: 0, selections: 0 }
      );

      const { usedBytes, limitBytes } = await getStudioStorage(db, config, studioId, req.user.id);

      return res.json({
        events: events.map((e) => ({
          ...sanitizeEvent(e),
          photos: Number(e.photos || 0),
          selections: Number(e.selections || 0),
          indexed_faces: Number(e.indexed_faces || 0),
        })),
        totals,
        storage: {
          used_bytes: usedBytes,
          limit_bytes: limitBytes,
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/events", auth, requirePermission("events:write"), async (req, res, next) => {
    try {
      if (!req.user.studio_id && req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Account is not assigned to a studio tenant" });
      }

      const title = String(req.body.title || "").trim();
      const description = String(req.body.description || "").trim().slice(0, 2000);
      const eventDate = req.body.event_date ? String(req.body.event_date).slice(0, 32) : null;
      const venue = String(req.body.venue || "").trim().slice(0, 200);
      const isPublic = req.body.is_public ? 1 : 0;
      const aiEnabled = req.body.ai_enabled ? 1 : 0;
      const selfieOnly = req.body.selfie_only ? 1 : 0;
      const rawPin = String(req.body.pin || "").trim();

      if (!title || title.length > 140) {
        return res.status(400).json({ error: "Event title (1–140 characters) required" });
      }
      if (rawPin && (rawPin.length < 4 || rawPin.length > 16)) {
        return res.status(400).json({ error: "Guest PIN must be 4–16 characters" });
      }

      const pinHash = rawPin ? await bcrypt.hash(rawPin, 10) : null;
      const eid = uuid();
      let code = generateAccessCode(12);
      while (await db.get("SELECT id FROM events WHERE access_code = ?", code)) {
        code = generateAccessCode(12);
      }

      await db.run(
        `INSERT INTO events (
          id, owner_id, studio_id, title, description, event_date, venue,
          access_code, pin_hash, is_public, ai_enabled, selfie_only
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        eid,
        req.user.id,
        req.user.studio_id || null,
        title,
        description,
        eventDate,
        venue,
        code,
        pinHash,
        isPublic,
        aiEnabled,
        selfieOnly
      );

      await auditLog(db, req, "event.created", "event", eid, title);
      const created = await db.get("SELECT * FROM events WHERE id = ?", eid);
      return res.status(201).json({ event: sanitizeEvent(created) });
    } catch (err) {
      return next(err);
    }
  });

  router.get("/events/:id", auth, requirePermission("events:read"), ownEvent, async (req, res, next) => {
    try {
      const photoRows = await db.all(
        `SELECT p.*, COALESCE(fc.cnt, 0) AS face_count
         FROM photos p
         LEFT JOIN (
           SELECT photo_id, COUNT(*) AS cnt FROM photo_faces GROUP BY photo_id
         ) fc ON fc.photo_id = p.id
         WHERE p.event_id = ?
         ORDER BY p.created_at DESC`,
        req.event.id
      );
      const photos = photoRows.map((p) => mapPhotoUrls(config, p, req.event));

      const stats = await db.get(
        `SELECT
           (SELECT COUNT(*) FROM photos WHERE event_id = ?) AS photos,
           (SELECT COUNT(*) FROM selections WHERE event_id = ?) AS selections,
           (SELECT COUNT(*) FROM favourites WHERE event_id = ?) AS favourites,
           (SELECT COUNT(*) FROM photo_faces WHERE event_id = ?) AS indexed_faces`,
        req.event.id,
        req.event.id,
        req.event.id,
        req.event.id
      );

      return res.json({
        event: sanitizeEvent(req.event),
        photos,
        stats: {
          photos: Number(stats?.photos || 0),
          selections: Number(stats?.selections || 0),
          favourites: Number(stats?.favourites || 0),
          indexed_faces: Number(stats?.indexed_faces || 0),
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  router.patch("/events/:id", auth, requirePermission("events:write"), ownEvent, async (req, res, next) => {
    try {
      const e = req.event;
      const title =
        req.body.title !== undefined ? String(req.body.title).trim() : e.title;
      if (!title || title.length > 140) {
        return res.status(400).json({ error: "Event title (1–140 characters) required" });
      }

      const description =
        req.body.description !== undefined
          ? String(req.body.description).trim().slice(0, 2000)
          : e.description;
      const eventDate =
        req.body.event_date !== undefined
          ? req.body.event_date
            ? String(req.body.event_date).slice(0, 32)
            : null
          : e.event_date;
      const venue =
        req.body.venue !== undefined ? String(req.body.venue).trim().slice(0, 200) : e.venue;
      const isPublic =
        req.body.is_public !== undefined ? (req.body.is_public ? 1 : 0) : e.is_public;
      const aiEnabled =
        req.body.ai_enabled !== undefined ? (req.body.ai_enabled ? 1 : 0) : e.ai_enabled;
      const selfieOnly =
        req.body.selfie_only !== undefined ? (req.body.selfie_only ? 1 : 0) : e.selfie_only;
      const status = req.body.status !== undefined ? String(req.body.status) : e.status;
      const aiConsentVersion = Number(e.ai_consent_version || 1) +
        (Boolean(e.ai_enabled) !== Boolean(aiEnabled) ? 1 : 0);

      if (!VALID_STATUSES.has(status)) {
        return res.status(400).json({ error: "Invalid event status" });
      }

      let pinHash = e.pin_hash;
      if (req.body.clear_pin) {
        pinHash = null;
      } else if (req.body.pin !== undefined && String(req.body.pin).trim() !== "") {
        const rawPin = String(req.body.pin).trim();
        if (rawPin.length < 4 || rawPin.length > 16) {
          return res.status(400).json({ error: "Guest PIN must be 4–16 characters" });
        }
        pinHash = await bcrypt.hash(rawPin, 10);
      }

      await db.tx(async (tx) => {
        await tx.run(
          `UPDATE events
           SET title = ?, description = ?, event_date = ?, venue = ?,
               pin_hash = ?, is_public = ?, ai_enabled = ?, selfie_only = ?, ai_consent_version = ?, status = ?
           WHERE id = ?`,
          title,
          description,
          eventDate,
          venue,
          pinHash,
          isPublic,
          aiEnabled,
          selfieOnly,
          aiConsentVersion,
          status,
          e.id
        );

        if (e.ai_enabled && !aiEnabled) {
          await tx.run("DELETE FROM photo_faces WHERE event_id = ?", e.id);
          await tx.run("UPDATE photos SET face_indexed = 0 WHERE event_id = ?", e.id);
        }
      });

      eventStatusCache.invalidate(e.id);
      await auditLog(db, req, "event.updated", "event", e.id, `status=${status}`);
      const updated = await db.get("SELECT * FROM events WHERE id = ?", e.id);
      return res.json({ event: sanitizeEvent(updated) });
    } catch (err) {
      return next(err);
    }
  });

  router.delete("/events/:id", auth, requirePermission("events:write"), ownEvent, async (req, res, next) => {
    try {
      const e = req.event;
      const sumRow = await db.get(
        "SELECT COALESCE(SUM(total_bytes), 0) AS total FROM photos WHERE event_id = ?",
        e.id
      );
      const byteSum = Number(sumRow?.total || 0);

      await db.tx(async (tx) => {
        await tx.run("DELETE FROM events WHERE id = ?", e.id);
        await tx.run(
          "UPDATE users SET storage_used_bytes = MAX(0, storage_used_bytes - ?) WHERE id = ?",
          byteSum,
          e.owner_id
        );
        if (e.studio_id) {
          await tx.run(
            "UPDATE studios SET storage_used_bytes = MAX(0, storage_used_bytes - ?) WHERE id = ?",
            byteSum,
            e.studio_id
          );
        }
      });

      eventStatusCache.invalidate(e.id);
      await deleteEventMediaDir(config, e.id);
      await auditLog(db, req, "event.deleted", "event", e.id, e.title);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/events/:id/qr", auth, requirePermission("events:read"), ownEvent, async (req, res, next) => {
    try {
      const origin = getPublicBaseUrl(req, config);
      const url = `${origin}/gallery/${req.event.access_code}`;
      const qr = await QRCode.toDataURL(url, { width: 900, margin: 2 });
      return res.json({ url, qr });
    } catch (err) {
      return next(err);
    }
  });

  router.post(
    "/events/:id/photos",
    auth,
    requirePermission("photos:upload"),
    ownEvent,
    checkQuotaBeforeUpload,
    checkUploadRequestSize,
    upload.array("photos", config.maxFilesPerUpload),
    async (req, res, next) => {
      const savedPhotos = [];
      const files = req.files || [];
      try {
        if (!files.length) {
          return res.status(400).json({ error: "No image files provided" });
        }

        const currentUsed = req.studioStorageUsed ?? 0;
        const limitBytes = req.studioStorageLimit ?? config.maxStorageBytesPerUser;
        const incomingRawBytes = files.reduce((sum, f) => sum + (f.size || 0), 0);

        if (currentUsed + incomingRawBytes > limitBytes) {
          return res.status(413).json({
            error: `Storage quota exceeded (${Math.round(limitBytes / (1024 * 1024))} MB limit per studio)`,
          });
        }

        let parsedFaceEntries = null;
        if (req.event.ai_enabled && req.body?.face_entries) {
          try {
            const rawEntries = JSON.parse(String(req.body.face_entries));
            if (Array.isArray(rawEntries)) parsedFaceEntries = rawEntries;
          } catch {
            parsedFaceEntries = null;
          }
        }

        const rejected = [];
        for (let idx = 0; idx < files.length; idx++) {
          const file = files[idx];
          try {
            const processed = await processUploadedImage(
              config,
              req.event.id,
              file.path,
              file.originalname
            );
            const fe = parsedFaceEntries?.[idx];
            if (fe && fe.indexed === true && Array.isArray(fe.descriptors)) {
              processed.faceIndexed = 1;
              processed.faceDescriptors = fe.descriptors
                .filter(isValidFaceDescriptor)
                .slice(0, 100);
            } else {
              processed.faceIndexed = 0;
              processed.faceDescriptors = [];
            }
            savedPhotos.push(processed);
          } catch (err) {
            rejected.push({
              name: file.originalname,
              reason: err.message || "Invalid image",
            });
          }
        }

        if (!savedPhotos.length) {
          return res.status(400).json({
            error: rejected[0]?.reason || "No valid image files could be processed",
            rejected,
          });
        }

        const addedBytes = savedPhotos.reduce((sum, p) => sum + p.totalBytes, 0);
        let facesIndexedTotal = 0;

        await db.tx(async (tx) => {
          if (req.event.studio_id) {
            const quotaResult = await tx.run(
              "UPDATE studios SET storage_used_bytes = storage_used_bytes + ? WHERE id = ? AND storage_used_bytes + ? <= storage_limit_bytes",
              addedBytes,
              req.event.studio_id,
              addedBytes
            );
            if (!Number(quotaResult?.changes || 0)) {
              const quotaError = new Error("Storage quota exceeded after image processing");
              quotaError.status = 413;
              throw quotaError;
            }
          } else {
            const quotaResult = await tx.run(
              "UPDATE users SET storage_used_bytes = storage_used_bytes + ? WHERE id = ? AND storage_used_bytes + ? <= ?",
              addedBytes,
              req.event.owner_id,
              addedBytes,
              limitBytes
            );
            if (!Number(quotaResult?.changes || 0)) {
              const quotaError = new Error("Storage quota exceeded after image processing");
              quotaError.status = 413;
              throw quotaError;
            }
          }
          for (const p of savedPhotos) {
            await tx.run(
              `INSERT INTO photos (
                 id, event_id, filename, thumb_filename, preview_filename,
                 original_name, mime, size, total_bytes, width, height, face_indexed
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              p.id,
              req.event.id,
              p.filename,
              p.thumbFilename,
              p.previewFilename,
              p.originalName,
              p.mime,
              p.size,
              p.totalBytes,
              p.width,
              p.height,
              p.faceIndexed
            );
            for (const desc of p.faceDescriptors) {
              await tx.run(
                "INSERT INTO photo_faces (id, photo_id, event_id, descriptor_json) VALUES (?, ?, ?, ?)",
                uuid(),
                p.id,
                req.event.id,
                JSON.stringify(desc)
              );
              facesIndexedTotal += 1;
            }
          }
          if (req.event.studio_id) {
            await tx.run(
              "UPDATE users SET storage_used_bytes = storage_used_bytes + ? WHERE id = ?",
              addedBytes,
              req.event.owner_id
            );
          }
        });

        await auditLog(
          db,
          req,
          "photo.uploaded",
          "event",
          req.event.id,
          `count=${savedPhotos.length}${facesIndexedTotal ? `,faces=${facesIndexedTotal}` : ""}`
        );

        io.to(`event:${req.event.id}`).emit("photos:added", {
          count: savedPhotos.length,
        });
        io.to(`studio:${req.event.studio_id || req.event.owner_id}`).emit("event:updated", {
          event_id: req.event.id,
        });

        const responseRows = savedPhotos.map((p) =>
          mapPhotoUrls(
            config,
            {
              id: p.id,
              event_id: req.event.id,
              filename: p.filename,
              thumb_filename: p.thumbFilename,
              preview_filename: p.previewFilename,
              original_name: p.originalName,
              mime: p.mime,
              size: p.size,
              width: p.width,
              height: p.height,
              caption: "",
              face_indexed: p.faceIndexed,
              face_count: p.faceDescriptors.length,
              created_at: new Date().toISOString(),
            },
            req.event
          )
        );

        return res.status(201).json({
          photos: responseRows,
          rejected,
          faces_indexed_total: facesIndexedTotal,
        });
      } catch (err) {
        for (const p of savedPhotos) {
          await deletePhotoFiles(config, {
            event_id: req.event.id,
            filename: p.filename,
            thumb_filename: p.thumbFilename,
            preview_filename: p.previewFilename,
          });
        }
        return next(err);
      } finally {
        await cleanupTempFiles(files);
      }
    }
  );

  router.patch("/photos/:id", auth, requirePermission("events:write"), async (req, res, next) => {
    try {
      const photo = await db.get(
        `SELECT p.*, e.owner_id, e.studio_id, e.is_public, e.pin_hash
         FROM photos p
         JOIN events e ON e.id = p.event_id
         WHERE p.id = ?`,
        req.params.id
      );
      if (!photo) return res.status(404).json({ error: "Photo not found" });
      if (
        req.user.role !== "super_admin" &&
        (!req.user.studio_id || photo.studio_id !== req.user.studio_id)
      ) {
        return res.status(403).json({ error: "Not your studio's photo" });
      }

      const caption = String(req.body.caption || "").trim().slice(0, 300);
      await db.run("UPDATE photos SET caption = ? WHERE id = ?", caption, photo.id);
      await auditLog(db, req, "photo.updated", "photo", photo.id, "caption");

      const updated = await db.get("SELECT * FROM photos WHERE id = ?", photo.id);
      return res.json({ photo: mapPhotoUrls(config, updated, photo) });
    } catch (err) {
      return next(err);
    }
  });

  async function deletePhotosAndUpdateStorage(photos) {
    if (!photos.length) return;
    const placeholders = photos.map(() => "?").join(",");
    const bytesByOwner = new Map();
    const bytesByStudio = new Map();
    for (const p of photos) {
      bytesByOwner.set(
        p.owner_id,
        (bytesByOwner.get(p.owner_id) || 0) + Number(p.total_bytes || 0)
      );
      if (p.studio_id) {
        bytesByStudio.set(
          p.studio_id,
          (bytesByStudio.get(p.studio_id) || 0) + Number(p.total_bytes || 0)
        );
      }
    }

    await db.tx(async (tx) => {
      await tx.run(
        `DELETE FROM photos WHERE id IN (${placeholders})`,
        ...photos.map((p) => p.id)
      );
      for (const [ownerId, freedBytes] of bytesByOwner.entries()) {
        await tx.run(
          "UPDATE users SET storage_used_bytes = MAX(0, storage_used_bytes - ?) WHERE id = ?",
          freedBytes,
          ownerId
        );
      }
      for (const [studioId, freedBytes] of bytesByStudio.entries()) {
        await tx.run(
          "UPDATE studios SET storage_used_bytes = MAX(0, storage_used_bytes - ?) WHERE id = ?",
          freedBytes,
          studioId
        );
      }
    });

    await deleteManyPhotoFiles(config, photos);
  }

  router.delete("/photos/:id", auth, requirePermission("photos:delete"), async (req, res, next) => {
    try {
      const photo = await db.get(
        `SELECT p.*, e.owner_id, e.studio_id
         FROM photos p
         JOIN events e ON e.id = p.event_id
         WHERE p.id = ?`,
        req.params.id
      );
      if (!photo) return res.status(404).json({ error: "Photo not found" });
      if (
        req.user.role !== "super_admin" &&
        (!req.user.studio_id || photo.studio_id !== req.user.studio_id)
      ) {
        return res.status(403).json({ error: "Not your studio's photo" });
      }

      await deletePhotosAndUpdateStorage([photo]);
      await auditLog(db, req, "photo.deleted", "photo", photo.id, photo.original_name);
      io.to(`event:${photo.event_id}`).emit("photos:removed", { photo_id: photo.id });

      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.post(
    "/events/:id/photos/bulk-delete",
    auth,
    requirePermission("photos:delete"),
    ownEvent,
    async (req, res, next) => {
      try {
        const rawIds = Array.isArray(req.body?.photo_ids) ? req.body.photo_ids : [];
        const uniqueIds = [...new Set(rawIds.map((id) => String(id || "").trim()).filter(Boolean))];
        if (!uniqueIds.length || uniqueIds.length > 200) {
          return res
            .status(400)
            .json({ error: "Select between 1 and 200 photos to delete" });
        }

        const placeholders = uniqueIds.map(() => "?").join(",");
        const photos = (
          await db.all(
            `SELECT p.*
             FROM photos p
             WHERE p.event_id = ? AND p.id IN (${placeholders})`,
            req.event.id,
            ...uniqueIds
          )
        ).map((p) => ({ ...p, owner_id: req.event.owner_id, studio_id: req.event.studio_id }));

        if (!photos.length) {
          return res.status(404).json({ error: "No matching photos found in this event" });
        }

        await deletePhotosAndUpdateStorage(photos);
        const deletedIds = photos.map((p) => p.id);
        await auditLog(
          db,
          req,
          "photo.bulk_deleted",
          "event",
          req.event.id,
          `deleted=${deletedIds.length}`
        );
        io.to(`event:${req.event.id}`).emit("photos:removed", { photo_ids: deletedIds });

        return res.json({
          ok: true,
          deleted_count: deletedIds.length,
          deleted_ids: deletedIds,
        });
      } catch (err) {
        return next(err);
      }
    }
  );

  router.get("/events/:id/selections", auth, requirePermission("selections:read"), ownEvent, async (req, res, next) => {
    try {
      const rows = await db.all(
        `SELECT s.*, p.filename, p.thumb_filename, p.original_name, p.caption
         FROM selections s
         JOIN photos p ON p.id = s.photo_id
         WHERE s.event_id = ?
         ORDER BY s.created_at DESC`,
        req.event.id
      );
      const selections = rows.map((s) => ({
        ...s,
        thumb_url: signMediaUrl(config, {
          variant: "thumbs",
          eventId: req.event.id,
          filename: s.thumb_filename,
          originalName: s.original_name,
          isPublic: false,
        }),
        url: signMediaUrl(config, {
          variant: "originals",
          eventId: req.event.id,
          filename: s.filename,
          originalName: s.original_name,
          isPublic: false,
        }),
      }));

      return res.json({ selections });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/events/:id/faces", auth, requirePermission("ai:index"), ownEvent, async (req, res, next) => {
    try {
      if (!req.event.ai_enabled) {
        return res.status(400).json({ error: "Enable AI face discovery on this event first" });
      }

      const entries = Array.isArray(req.body.entries) ? req.body.entries : [];
      if (!entries.length || entries.length > 200) {
        return res.status(400).json({ error: "Provide 1–200 photo face descriptor entries" });
      }

      const validPhotoIds = new Set(
        (await db.all("SELECT id FROM photos WHERE event_id = ?", req.event.id)).map((r) => r.id)
      );

      const totalDescriptorCount = entries.reduce(
        (sum, entry) => sum + (Array.isArray(entry?.descriptors) ? entry.descriptors.length : 0),
        0
      );
      if (totalDescriptorCount > 5000) {
        return res.status(413).json({ error: "Face indexing batch is too large (5,000 descriptors maximum)" });
      }

      let savedDescriptors = 0;
      await db.tx(async (tx) => {
        for (const entry of entries) {
          if (!entry || !validPhotoIds.has(entry.photo_id)) continue;
          const descriptors = Array.isArray(entry.descriptors) ? entry.descriptors.slice(0, 100) : [];
          await tx.run(
            "DELETE FROM photo_faces WHERE photo_id = ? AND event_id = ?",
            entry.photo_id,
            req.event.id
          );
          for (const desc of descriptors) {
            if (
              isValidFaceDescriptor(desc)
            ) {
              await tx.run(
                "INSERT INTO photo_faces (id, photo_id, event_id, descriptor_json) VALUES (?, ?, ?, ?)",
                uuid(),
                entry.photo_id,
                req.event.id,
                JSON.stringify(desc)
              );
              savedDescriptors += 1;
            }
          }
          await tx.run(
            "UPDATE photos SET face_indexed = 1 WHERE id = ? AND event_id = ?",
            entry.photo_id,
            req.event.id
          );
        }
      });

      await auditLog(
        db,
        req,
        "event.faces_indexed",
        "event",
        req.event.id,
        `descriptors=${savedDescriptors}`
      );

      return res.json({ ok: true, saved_descriptors: savedDescriptors });
    } catch (err) {
      return next(err);
    }
  });

  router.delete("/events/:id/faces", auth, requirePermission("ai:index"), ownEvent, async (req, res, next) => {
    try {
      await db.tx(async (tx) => {
        await tx.run("DELETE FROM photo_faces WHERE event_id = ?", req.event.id);
        await tx.run("UPDATE photos SET face_indexed = 0 WHERE event_id = ?", req.event.id);
      });
      await auditLog(db, req, "event.faces_cleared", "event", req.event.id);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  // Studio Staff Management (Studio Owner only, strictly scoped to own studio_id)
  router.get("/studio/staff", auth, requireStudioOwner, async (req, res, next) => {
    try {
      const rows = await db.all(
        `SELECT id, name, email, role, staff_permissions, status, last_login_at, created_at
         FROM users
         WHERE studio_id = ? AND role = 'studio_staff' AND status <> 'deleted'
         ORDER BY created_at DESC`,
        req.user.studio_id
      );
      const staff = rows.map((s) => ({
        ...s,
        staff_permissions: parsePermissions(s.staff_permissions),
      }));

      return res.json({ staff, available_permissions: ALL_STAFF_PERMISSIONS });
    } catch (err) {
      return next(err);
    }
  });

  router.post("/studio/staff", auth, requireStudioOwner, async (req, res, next) => {
    try {
      const name = String(req.body.name || "").trim();
      const email = String(req.body.email || "").toLowerCase().trim();
      const password = String(req.body.password || "");
      const permissions = parsePermissions(req.body.staff_permissions);

      if (!name || name.length > 100) {
        return res.status(400).json({ error: "Valid staff name (1–100 characters) required" });
      }
      if (!isValidEmail(email) || email.length > 160) {
        return res.status(400).json({ error: "Valid email address required" });
      }
      if (password.length < 6 || password.length > 128) {
        return res.status(400).json({ error: "Temporary password must be 6–128 characters" });
      }
      if (await db.get("SELECT id FROM users WHERE email = ?", email)) {
        return res.status(409).json({ error: "Email already registered" });
      }

      const staffId = uuid();
      const passwordHash = await bcrypt.hash(password, 12);
      await db.run(
        `INSERT INTO users (
          id, name, email, password_hash, role, studio_id, staff_permissions,
          studio, status, must_change_password
        ) VALUES (?, ?, ?, ?, 'studio_staff', ?, ?, ?, 'active', 1)`,
        staffId,
        name,
        email,
        passwordHash,
        req.user.studio_id,
        JSON.stringify(permissions),
        req.studio?.name || req.user.studio || ""
      );

      await auditLog(
        db,
        req,
        "studio.staff_created",
        "user",
        staffId,
        `${email} perms=${permissions.join(",")}`
      );
      return res.status(201).json({
        staff: {
          id: staffId,
          name,
          email,
          role: "studio_staff",
          staff_permissions: permissions,
          status: "active",
        },
      });
    } catch (err) {
      return next(err);
    }
  });

  router.patch("/studio/staff/:id", auth, requireStudioOwner, async (req, res, next) => {
    try {
      const target = await db.get(
        "SELECT * FROM users WHERE id = ? AND studio_id = ? AND role = 'studio_staff'",
        req.params.id,
        req.user.studio_id
      );
      if (!target) {
        return res.status(404).json({ error: "Staff member not found in your studio" });
      }

      const permissions =
        req.body.staff_permissions !== undefined
          ? parsePermissions(req.body.staff_permissions)
          : parsePermissions(target.staff_permissions);
      const status =
        req.body.status !== undefined && ["active", "suspended"].includes(req.body.status)
          ? req.body.status
          : target.status;

      await db.run(
        "UPDATE users SET staff_permissions = ?, status = ? WHERE id = ?",
        JSON.stringify(permissions),
        status,
        target.id
      );
      if (status === "suspended") {
        await revokeUserSessions(db, target.id);
      }
      await auditLog(db, req, "studio.staff_updated", "user", target.id, `status=${status}`);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  router.delete("/studio/staff/:id", auth, requireStudioOwner, async (req, res, next) => {
    try {
      const target = await db.get(
        "SELECT * FROM users WHERE id = ? AND studio_id = ? AND role = 'studio_staff'",
        req.params.id,
        req.user.studio_id
      );
      if (!target) {
        return res.status(404).json({ error: "Staff member not found in your studio" });
      }
      await revokeUserSessions(db, target.id);
      await db.run(
        "UPDATE users SET status = 'deleted', deleted_at = CURRENT_TIMESTAMP, email = ? WHERE id = ?",
        `deleted-${target.id}@deleted.local`,
        target.id
      );
      await auditLog(db, req, "studio.staff_deleted", "user", target.id, target.email);
      return res.json({ ok: true });
    } catch (err) {
      return next(err);
    }
  });

  return router;
}

module.exports = { createEventsRouter, sanitizeEvent, mapPhotoUrls };

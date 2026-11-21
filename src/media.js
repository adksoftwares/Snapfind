const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { v4: uuid } = require("uuid");
const sharp = require("sharp");
const { put, get: getBlob, del: delBlobs, list: listBlobs } = require("@vercel/blob");

sharp.cache(false);

const ALLOWED_FORMATS = {
  jpeg: { ext: ".jpg", mime: "image/jpeg" },
  png: { ext: ".png", mime: "image/png" },
  webp: { ext: ".webp", mime: "image/webp" },
  gif: { ext: ".gif", mime: "image/gif" },
};

const VALID_VARIANTS = new Set(["originals", "previews", "thumbs"]);
const SAFE_SEGMENT_RE = /^[a-zA-Z0-9_-]+(?:\.[a-z0-9]+)?$/;

function normalizeStorageOpts(uploadDirOrConfig) {
  if (typeof uploadDirOrConfig === "string") {
    return { uploadDir: uploadDirOrConfig, useBlob: false };
  }
  return {
    uploadDir: uploadDirOrConfig?.uploadDir || "",
    useBlob: Boolean(uploadDirOrConfig?.useBlob),
  };
}

function buildBlobPathname(variant, eventId, filename) {
  if (
    !VALID_VARIANTS.has(variant) ||
    !SAFE_SEGMENT_RE.test(eventId) ||
    !SAFE_SEGMENT_RE.test(filename)
  ) {
    return null;
  }
  return `events/${eventId}/${variant}/${filename}`;
}

function detectMagicFormat(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpeg";
  if (
    buf[0] === 0x89 &&
    buf[1] === 0x50 &&
    buf[2] === 0x4e &&
    buf[3] === 0x47 &&
    buf[4] === 0x0d &&
    buf[5] === 0x0a &&
    buf[6] === 0x1a &&
    buf[7] === 0x0a
  ) {
    return "png";
  }
  const head6 = buf.subarray(0, 6).toString("ascii");
  if (head6 === "GIF87a" || head6 === "GIF89a") return "gif";
  if (
    buf.subarray(0, 4).toString("ascii") === "RIFF" &&
    buf.subarray(8, 12).toString("ascii") === "WEBP"
  ) {
    return "webp";
  }
  return null;
}

async function detectMagicFormatFromFile(filePath) {
  const fh = await fsp.open(filePath, "r");
  try {
    const header = Buffer.alloc(16);
    const { bytesRead } = await fh.read(header, 0, 16, 0);
    return detectMagicFormat(header.subarray(0, bytesRead));
  } finally {
    await fh.close();
  }
}

function sanitizeOriginalName(name) {
  const base = path
    .basename(String(name || "photo"))
    .replace(/[\r\n\t\0"/\\<>:|?*]+/g, "_")
    .trim();
  return (base || "photo").slice(0, 120);
}

function encodeContentDisposition(filename) {
  const clean = sanitizeOriginalName(filename);
  const asciiFallback = clean.replace(/[^\x20-\x7e]/g, "_").replace(/"/g, "");
  const utf8Encoded = encodeURIComponent(clean);
  return `attachment; filename="${asciiFallback || "photo"}"; filename*=UTF-8''${utf8Encoded}`;
}

async function ensureEventMediaDirs(uploadDir, eventId) {
  const dirs = ["originals", "previews", "thumbs"].map((v) =>
    path.join(uploadDir, eventId, v)
  );
  await Promise.all(dirs.map((d) => fsp.mkdir(d, { recursive: true })));
}

async function processUploadedImage(uploadDirOrConfig, eventId, filePath, originalname) {
  const storage = normalizeStorageOpts(uploadDirOrConfig);
  const magic = await detectMagicFormatFromFile(filePath);
  if (!magic) {
    const err = new Error("Unsupported or invalid image file");
    err.status = 400;
    throw err;
  }

  let metadata;
  try {
    metadata = await sharp(filePath, { limitInputPixels: 100_000_000 }).metadata();
  } catch {
    const err = new Error("Corrupted or unreadable image file");
    err.status = 400;
    throw err;
  }

  const formatInfo = ALLOWED_FORMATS[metadata.format];
  if (!formatInfo || metadata.format !== magic) {
    const err = new Error("Image format verification failed");
    err.status = 400;
    throw err;
  }

  const id = uuid();
  const origName = `${id}${formatInfo.ext}`;
  const webpName = `${id}.webp`;

  let basePipeline = sharp(filePath, {
    limitInputPixels: 100_000_000,
    animated: metadata.format === "gif" || metadata.format === "webp",
  }).rotate();

  if (metadata.format === "jpeg") {
    basePipeline = basePipeline.jpeg({ quality: 92, mozjpeg: true });
  } else if (metadata.format === "png") {
    basePipeline = basePipeline.png({ compressionLevel: 9 });
  } else if (metadata.format === "webp") {
    basePipeline = basePipeline.webp({ quality: 90 });
  } else if (metadata.format === "gif") {
    basePipeline = basePipeline.gif();
  }

  if (storage.useBlob) {
    const origOut = await basePipeline.toBuffer({ resolveWithObject: true });
    const previewOut = await sharp(origOut.data, { limitInputPixels: 100_000_000 })
      .resize({ width: 1200, height: 1200, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 82 })
      .toBuffer({ resolveWithObject: true });
    const thumbOut = await sharp(previewOut.data)
      .resize({ width: 480, height: 480, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 76 })
      .toBuffer({ resolveWithObject: true });

    const blobPaths = [
      buildBlobPathname("originals", eventId, origName),
      buildBlobPathname("previews", eventId, webpName),
      buildBlobPathname("thumbs", eventId, webpName),
    ];
    try {
      await Promise.all([
        put(blobPaths[0], origOut.data, {
          access: "private",
          contentType: formatInfo.mime,
          addRandomSuffix: false,
          allowOverwrite: true,
        }),
        put(blobPaths[1], previewOut.data, {
          access: "private",
          contentType: "image/webp",
          addRandomSuffix: false,
          allowOverwrite: true,
        }),
        put(blobPaths[2], thumbOut.data, {
          access: "private",
          contentType: "image/webp",
          addRandomSuffix: false,
          allowOverwrite: true,
        }),
      ]);
    } catch (err) {
      // A partial parallel upload can leave one or two variants behind.
      await delBlobs(blobPaths).catch((cleanupErr) => {
        console.error("[SnapFind] Partial blob upload cleanup failed", {
          errorName: String(cleanupErr?.name || "Error").slice(0, 80),
        });
      });
      throw err;
    }

    const totalBytes = origOut.info.size + previewOut.info.size + thumbOut.info.size;
    return {
      id,
      filename: origName,
      thumbFilename: webpName,
      previewFilename: webpName,
      originalName: sanitizeOriginalName(originalname),
      mime: formatInfo.mime,
      size: origOut.info.size,
      totalBytes,
      width: origOut.info.width || metadata.width || 0,
      height: origOut.info.height || metadata.height || 0,
    };
  }

  await ensureEventMediaDirs(storage.uploadDir, eventId);

  const origPath = path.join(storage.uploadDir, eventId, "originals", origName);
  const previewPath = path.join(storage.uploadDir, eventId, "previews", webpName);
  const thumbPath = path.join(storage.uploadDir, eventId, "thumbs", webpName);

  let origInfo, previewInfo, thumbInfo;
  try {
    origInfo = await basePipeline.toFile(origPath);
    previewInfo = await sharp(origPath, { limitInputPixels: 100_000_000 })
      .resize({ width: 1200, height: 1200, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 82 })
      .toFile(previewPath);
    thumbInfo = await sharp(previewPath)
      .resize({ width: 480, height: 480, fit: "inside", withoutEnlargement: true })
      .webp({ quality: 76 })
      .toFile(thumbPath);
  } catch (err) {
    // Keep failed conversions from accumulating incomplete local media variants.
    const cleanupResults = await Promise.all(
      [origPath, previewPath, thumbPath].map((p) => fsp.unlink(p).catch((cleanupErr) => cleanupErr))
    );
    if (cleanupResults.some((cleanupErr) => cleanupErr && cleanupErr.code !== "ENOENT")) {
      console.error("[SnapFind] Partial local image cleanup failed", {
        errorName: String(err?.name || "Error").slice(0, 80),
      });
    }
    throw err;
  }

  const totalBytes = origInfo.size + previewInfo.size + thumbInfo.size;

  return {
    id,
    filename: origName,
    thumbFilename: webpName,
    previewFilename: webpName,
    originalName: sanitizeOriginalName(originalname),
    mime: formatInfo.mime,
    size: origInfo.size,
    totalBytes,
    width: origInfo.width || metadata.width || 0,
    height: origInfo.height || metadata.height || 0,
  };
}

function buildMediaSignPayload({ variant, eventId, filename, exp, pub, name }) {
  return `${variant}:${eventId}:${filename}:${exp}:${pub}:${name}`;
}

function signMediaUrl(config, { variant, eventId, filename, originalName = "", isPublic = false }) {
  const exp = Math.floor(Date.now() / 1000) + config.mediaTokenTtlSeconds;
  const pub = isPublic ? "1" : "0";
  const cleanName = sanitizeOriginalName(originalName || filename);
  const payload = buildMediaSignPayload({
    variant,
    eventId,
    filename,
    exp,
    pub,
    name: cleanName,
  });
  const sig = crypto
    .createHmac("sha256", config.mediaSigningSecret)
    .update(payload)
    .digest("hex");

  const params = new URLSearchParams({
    exp: String(exp),
    pub,
    name: cleanName,
    sig,
  });
  return `/media/${variant}/${eventId}/${filename}?${params.toString()}`;
}

function verifyMediaSignature(config, { variant, eventId, filename, exp, pub, name, sig }) {
  const expNum = Number(exp);
  if (!Number.isFinite(expNum) || expNum <= Math.floor(Date.now() / 1000)) {
    return false;
  }
  if (!sig || typeof sig !== "string") return false;
  const payload = buildMediaSignPayload({
    variant,
    eventId,
    filename,
    exp: String(expNum),
    pub: pub === "1" ? "1" : "0",
    name: String(name || ""),
  });
  const expected = crypto
    .createHmac("sha256", config.mediaSigningSecret)
    .update(payload)
    .digest("hex");

  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(sig, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function resolveMediaPath(uploadDir, variant, eventId, filename) {
  if (
    !VALID_VARIANTS.has(variant) ||
    !SAFE_SEGMENT_RE.test(eventId) ||
    !SAFE_SEGMENT_RE.test(filename)
  ) {
    return null;
  }
  const base = path.resolve(uploadDir);
  const target = path.resolve(base, eventId, variant, filename);
  if (!target.startsWith(base + path.sep)) {
    return null;
  }
  return target;
}

async function fetchPrivateMediaBlob(variant, eventId, filename) {
  const pathname = buildBlobPathname(variant, eventId, filename);
  if (!pathname) return null;
  try {
    const result = await getBlob(pathname, { access: "private" });
    if (!result || result.statusCode !== 200) return null;
    return result;
  } catch (err) {
    if (err?.name === "BlobNotFoundError") return null;
    throw err;
  }
}

async function deleteManyPhotoFiles(uploadDirOrConfig, photos) {
  const list = Array.isArray(photos) ? photos : [];
  if (!list.length) return;
  const storage = normalizeStorageOpts(uploadDirOrConfig);

  if (storage.useBlob) {
    const pathnames = [
      ...new Set(
        list.flatMap((photo) => [
          buildBlobPathname("originals", photo.event_id, photo.filename),
          buildBlobPathname("previews", photo.event_id, photo.preview_filename),
          buildBlobPathname("thumbs", photo.event_id, photo.thumb_filename),
        ]).filter(Boolean)
      ),
    ];
    const CHUNK = 100;
    const tasks = [];
    for (let i = 0; i < pathnames.length; i += CHUNK) {
      tasks.push(
        delBlobs(pathnames.slice(i, i + CHUNK)).catch((cleanupErr) => {
          console.error("[SnapFind] Blob photo deletion failed", {
            variantCount: Math.min(CHUNK, pathnames.length - i),
            errorName: String(cleanupErr?.name || "Error").slice(0, 80),
          });
        })
      );
    }
    await Promise.all(tasks);
    return;
  }

  const paths = [
    ...new Set(
      list.flatMap((photo) => [
        resolveMediaPath(storage.uploadDir, "originals", photo.event_id, photo.filename),
        resolveMediaPath(storage.uploadDir, "previews", photo.event_id, photo.preview_filename),
        resolveMediaPath(storage.uploadDir, "thumbs", photo.event_id, photo.thumb_filename),
      ]).filter(Boolean)
    ),
  ];

  await Promise.all(
    paths.map(async (p) => {
      try {
        await fsp.unlink(p);
      } catch (cleanupErr) {
        if (cleanupErr?.code !== "ENOENT") {
          console.error("[SnapFind] Local photo deletion failed", {
            errorName: String(cleanupErr?.name || "Error").slice(0, 80),
          });
        }
      }
    })
  );
}

async function deletePhotoFiles(uploadDirOrConfig, photo) {
  if (!photo) return;
  await deleteManyPhotoFiles(uploadDirOrConfig, [photo]);
}

async function deleteEventMediaDir(uploadDirOrConfig, eventId) {
  if (!SAFE_SEGMENT_RE.test(eventId)) return;
  const storage = normalizeStorageOpts(uploadDirOrConfig);
  if (storage.useBlob) {
    try {
      let cursor;
      do {
        const res = await listBlobs({ prefix: `events/${eventId}/`, cursor });
        if (res.blobs.length) {
          await delBlobs(res.blobs.map((b) => b.url));
        }
        cursor = res.hasMore ? res.cursor : undefined;
      } while (cursor);
    } catch (cleanupErr) {
      console.error("[SnapFind] Event media cleanup failed", {
        eventId,
        errorName: String(cleanupErr?.name || "Error").slice(0, 80),
      });
    }
    return;
  }

  const base = path.resolve(storage.uploadDir);
  const target = path.resolve(base, eventId);
  if (!target.startsWith(base + path.sep)) return;
  if (fs.existsSync(target)) {
    try {
      await fsp.rm(target, { recursive: true, force: true });
    } catch (cleanupErr) {
      console.error("[SnapFind] Local event media cleanup failed", {
        eventId,
        errorName: String(cleanupErr?.name || "Error").slice(0, 80),
      });
    }
  }
}

module.exports = {
  detectMagicFormat,
  detectMagicFormatFromFile,
  sanitizeOriginalName,
  encodeContentDisposition,
  processUploadedImage,
  signMediaUrl,
  verifyMediaSignature,
  resolveMediaPath,
  buildBlobPathname,
  fetchPrivateMediaBlob,
  deletePhotoFiles,
  deleteManyPhotoFiles,
  deleteEventMediaDir,
};

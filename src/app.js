const fs = require("node:fs");
const http = require("node:http");
const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const compression = require("compression");
const multer = require("multer");
const { Server } = require("socket.io");

const pkg = require("../package.json");
const { loadConfig } = require("./config");
const { migrateLegacyFaceDescriptors } = require("./biometric");
const { openDatabase } = require("./db");
const { DatabaseSessionStore } = require("./session-store");
const {
  verifyCsrf,
  createLimiters,
  createEventStatusCache,
  getSessionUser,
} = require("./middleware");
const { createAuthRouter } = require("./routes/auth");
const { createEventsRouter } = require("./routes/events");
const {
  createGalleryRouter,
  createFastSignedMediaHandler,
  createSessionMediaHandler,
  isEventUnlocked,
} = require("./routes/gallery");
const { createSuperAdminRouter } = require("./routes/super-admin");

function createApp(options = {}) {
  const config = loadConfig(options);
  if (!config.useBlob) {
    fs.mkdirSync(config.uploadDir, { recursive: true });
  }
  fs.mkdirSync(config.tmpUploadDir, { recursive: true });

  const db = openDatabase({
    dbPath: config.dbPath,
    databaseUrl: config.databaseUrl,
  });
  // Encrypt any historical plaintext biometric vectors before serving API routes.
  const startupReady = db.ensureReady().then(() => migrateLegacyFaceDescriptors(db, config));
  const sessionStore = new DatabaseSessionStore(db);
  const eventStatusCache = createEventStatusCache(db);
  const limiters = createLimiters({ disableRateLimit: Boolean(options.disableRateLimit) });

  const app = express();
  const server = http.createServer(app);
  const io = new Server(server);

  app.use((req, res, next) => {
    const requestId = crypto.randomUUID();
    req.requestId = requestId;
    res.setHeader("X-Request-ID", requestId);
    next();
  });

  app.set("trust proxy", 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:", "blob:"],
          connectSrc: ["'self'", "ws:", "wss:"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: config.secureCookies ? [] : null,
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use(compression());

  // Minimal readiness endpoint for external uptime checks; never expose database details.
  app.get("/healthz", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try {
      await startupReady;
      await db.get("SELECT 1");
      return res.status(200).json({ status: "ok", checks: { database: "ok" } });
    } catch (err) {
      console.error("[SnapFind] Readiness check failed", {
        requestId: req.requestId || "unknown",
        errorName: String(err?.name || "Error").slice(0, 80),
      });
      return res.status(503).json({ status: "unavailable", request_id: req.requestId || "unknown" });
    }
  });

  // Ensure Postgres schema/migrations or SQLite DB ready before serving any route
  app.use(async (req, res, next) => {
    try {
      await startupReady;
      next();
    } catch (err) {
      next(err);
    }
  });

  // Fast-path HMAC-signed media delivery BEFORE sessionMiddleware
  app.get(
    "/media/:variant/:eventId/:filename",
    createFastSignedMediaHandler({ config, eventStatusCache })
  );

  app.use(express.json({ limit: "8mb" }));
  app.use(express.urlencoded({ extended: false }));

  const sessionMiddleware = session({
    store: sessionStore,
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: config.secureCookies,
      maxAge: 7 * 86400 * 1000,
    },
  });

  app.use(sessionMiddleware);
  io.engine.use((req, res, next) => {
    // Only parse session on initial Engine.IO handshake, never wrapping long-poll responses
    if (!req._query?.sid) {
      return sessionMiddleware(req, res, next);
    }
    return next();
  });

  // Static public assets & self-hosted face-api models/bundle (served from CDN on Vercel, disk locally)
  app.use(express.static(path.join(config.rootDir, "public")));
  const faceApiRoot = path.join(
    config.rootDir,
    "node_modules",
    "@vladmandic",
    "face-api"
  );
  if (fs.existsSync(faceApiRoot)) {
    app.use(
      "/vendor/face-api/model",
      express.static(path.join(faceApiRoot, "model"), { maxAge: "7d" })
    );
    app.use(
      "/vendor/face-api",
      express.static(path.join(faceApiRoot, "dist"), { maxAge: "7d" })
    );
  }

  // Fallback stub for Socket.IO client script on serverless deployments
  if (config.isVercel) {
    app.get("/socket.io/socket.io.js", (req, res) => {
      res.type("application/javascript").send("/* Socket.IO disabled in serverless mode */");
    });
  }

  // Fallback session-checked media delivery for unsigned/owner/admin requests
  app.get(
    "/media/:variant/:eventId/:filename",
    createSessionMediaHandler({ db, config })
  );

  app.use("/api", (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });
  app.use("/api", limiters.api);
  app.use("/api", verifyCsrf);

  app.get("/api/health", (req, res) => {
    res.json({
      ok: true,
      service: "SnapFind AI",
      version: pkg.version,
      storage: config.useBlob ? "vercel-blob" : "local",
      database: db.dialect,
    });
  });

  app.use("/api", createAuthRouter({ db, config, limiters }));
  app.use("/api", createEventsRouter({ db, config, io, eventStatusCache }));
  app.use("/api", createGalleryRouter({ db, config, io, limiters }));
  app.use("/api", createSuperAdminRouter({ db, config, limiters, eventStatusCache }));

  app.get("/", (req, res) => {
    res.sendFile(path.join(config.rootDir, "public", "index.html"));
  });

  app.get("/super-admin", (req, res) => {
    res.sendFile(path.join(config.rootDir, "public", "super-admin.html"));
  });

  app.get("/reset-password", (req, res) => {
    res.sendFile(path.join(config.rootDir, "public", "reset-password.html"));
  });

  app.get("/gallery/:code", (req, res) => {
    res.sendFile(path.join(config.rootDir, "public", "gallery.html"));
  });

  io.on("connection", async (socket) => {
    try {
      const req = socket.request;
      const user = await getSessionUser(db, req);
      if (user) {
        socket.join(`studio:${user.studio_id || user.id}`);
      }

      socket.on("gallery:join", async (code) => {
        try {
          const cleanCode = String(code || "").trim().toUpperCase();
          if (!cleanCode) return;
          const event = await db.get(
            `SELECT e.* FROM events e
             LEFT JOIN studios s ON s.id = e.studio_id
             WHERE e.access_code = ? AND e.status = 'active' AND COALESCE(s.status, 'active') = 'active'`,
            cleanCode
          );
          if (event && (await isEventUnlocked(db, req, event))) {
            socket.join(`event:${event.id}`);
          }
        } catch {
          // ignore invalid socket join
        }
      });
    } catch {
      // ignore socket auth error
    }
  });

  app.use((err, req, res, next) => {
    const requestId = req.requestId || "unknown";
    if (err instanceof multer.MulterError) {
      const status = ["LIMIT_FILE_SIZE", "LIMIT_FILE_COUNT", "LIMIT_FIELD_COUNT", "LIMIT_PART_COUNT"].includes(err.code) ? 413 : 400;
      const message = err.code === "LIMIT_FILE_SIZE"
        ? `Image exceeds ${config.maxFileSizeMb} MB upload limit`
        : status === 413
          ? "Upload request exceeds configured limits"
          : "Upload request could not be processed";
      return res.status(status).json({ error: message, request_id: requestId });
    }
    if (err?.type === "entity.parse.failed") {
      return res.status(400).json({ error: "Invalid JSON payload", request_id: requestId });
    }
    if (err?.status && err.status < 500) {
      return res.status(err.status).json({ error: err.message, request_id: requestId });
    }
    console.error("[SnapFind] Unexpected server error", {
      requestId,
      errorName: String(err?.name || "Error").slice(0, 80),
    });
    return res.status(500).json({ error: "Unexpected server error", request_id: requestId });
  });

  async function close() {
    sessionStore.stopCleanup();
    await new Promise((resolve) => io.close(() => resolve()));
    if (server.listening) {
      await new Promise((resolve) => server.close(() => resolve()));
    }
    await db.close();
  }

  return { app, server, io, db, config, close };
}

module.exports = { createApp };

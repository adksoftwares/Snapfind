const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");

const PLACEHOLDER_SECRETS = new Set([
  "",
  "replace-with-a-long-random-secret",
  "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT_123456",
]);

function positiveNumber(value, fallback, minimum = 1) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= minimum ? parsed : fallback;
}

function resolveSessionSecret(env) {
  const raw = (env.SESSION_SECRET || "").trim();
  if (!PLACEHOLDER_SECRETS.has(raw) && raw.length >= 32) {
    return raw;
  }
  if (env.NODE_ENV === "production") {
    throw new Error(
      "SESSION_SECRET must be set to a strong random value of at least 32 characters in production."
    );
  }
  if (!resolveSessionSecret._warned) {
    resolveSessionSecret._warned = true;
    console.warn(
      "[SnapFind] Warning: SESSION_SECRET is missing or weak; using an ephemeral random secret for this process."
    );
  }
  return crypto.randomBytes(32).toString("hex");
}

function loadConfig(overrides = {}) {
  const rootDir = overrides.rootDir || path.resolve(__dirname, "..");
  const env = { ...process.env, ...(overrides.env || {}) };
  const isVercel = Boolean(env.VERCEL || env.VERCEL_ENV);
  const isProduction = env.NODE_ENV === "production";
  const port = Number(overrides.port ?? env.PORT ?? 4100);
  const vercelHost = (env.VERCEL_PROJECT_PRODUCTION_URL || env.VERCEL_URL || "").trim();
  const fallbackBaseUrl = vercelHost ? `https://${vercelHost}` : `http://localhost:${port}`;
  const baseUrlInput = (overrides.baseUrl || env.BASE_URL || fallbackBaseUrl).trim();
  let parsedBaseUrl;
  try {
    parsedBaseUrl = new URL(baseUrlInput);
    if (!["http:", "https:"].includes(parsedBaseUrl.protocol) || parsedBaseUrl.username || parsedBaseUrl.password || parsedBaseUrl.search || parsedBaseUrl.hash) {
      throw new Error("BASE_URL must be an HTTP(S) URL without credentials, query, or fragment.");
    }
    if (isProduction && parsedBaseUrl.protocol !== "https:") {
      throw new Error("BASE_URL must use HTTPS in production.");
    }
  } catch (err) {
    throw new Error(err.message || "BASE_URL must be a valid HTTP(S) URL.");
  }
  const baseUrl = parsedBaseUrl.toString().replace(/\/+$/, "");

  const defaultUploadDir = isVercel
    ? path.join(os.tmpdir(), "snapfind-uploads")
    : path.join(rootDir, "storage", "uploads");
  const uploadDir = overrides.uploadDir
    ? path.resolve(rootDir, overrides.uploadDir)
    : env.UPLOAD_DIR
      ? path.resolve(rootDir, env.UPLOAD_DIR)
      : defaultUploadDir;
  const tmpUploadDir = path.join(uploadDir, "_tmp");

  const defaultDbPath = isVercel
    ? path.join(os.tmpdir(), "snapfind.sqlite")
    : path.join(rootDir, "storage", "snapfind.sqlite");
  const dbPath = overrides.dbPath
    ? path.resolve(rootDir, overrides.dbPath)
    : env.DB_PATH
      ? path.resolve(rootDir, env.DB_PATH)
      : defaultDbPath;

  // Explicit dbPath in tests/local overrides skips external DATABASE_URL unless databaseUrl is also passed
  const databaseUrl =
    overrides.databaseUrl !== undefined
      ? String(overrides.databaseUrl || "").trim()
      : overrides.dbPath
        ? ""
        : String(env.DATABASE_URL || env.POSTGRES_URL || "").trim();

  const useBlob =
    overrides.useBlob !== undefined
      ? Boolean(overrides.useBlob)
      : !overrides.uploadDir &&
        Boolean(
          (env.BLOB_READ_WRITE_TOKEN || "").trim() ||
            ((env.BLOB_STORE_ID || "").trim() && (env.VERCEL_OIDC_TOKEN || "").trim())
        );

  const maxFileSizeMb = positiveNumber(
    overrides.maxFileSizeMb ?? env.MAX_FILE_SIZE_MB ?? (isVercel ? 4 : 20),
    isVercel ? 4 : 20
  );
  const maxFilesPerUpload = Math.floor(positiveNumber(
    overrides.maxFilesPerUpload ?? env.MAX_FILES_PER_UPLOAD ?? 3,
    3
  ));
  const maxUploadBatchMb = positiveNumber(
    overrides.maxUploadBatchMb ?? env.MAX_UPLOAD_BATCH_MB ?? (isVercel ? 4 : 60),
    isVercel ? 4 : 60
  );
  const maxStorageMbPerUser = positiveNumber(
    overrides.maxStorageMbPerUser ?? env.MAX_STORAGE_MB_PER_USER ?? 500,
    500,
    10
  );
  const sessionSecret = overrides.sessionSecret || resolveSessionSecret(env);
  const rawFaceDescriptorEncryptionKey = String(env.FACE_DESCRIPTOR_ENCRYPTION_KEY || "").trim();
  if (isProduction && rawFaceDescriptorEncryptionKey.length < 32) {
    throw new Error("FACE_DESCRIPTOR_ENCRYPTION_KEY must be set to a stable secret of at least 32 characters in production.");
  }
  // Derive a fixed-size AES key. A dedicated key is strongly recommended in development
  // and mandatory in production; the fallback keeps local development functional.
  const faceDescriptorEncryptionKey = crypto.createHash("sha256")
    .update(rawFaceDescriptorEncryptionKey || sessionSecret)
    .digest();
  const mediaSigningSecret =
    (overrides.mediaSigningSecret || env.MEDIA_SIGNING_SECRET || "").trim() ||
    crypto.createHmac("sha256", sessionSecret).update("snapfind-media-signing").digest("hex");
  const mediaTokenTtlSeconds = Math.max(
    60,
    Number(overrides.mediaTokenTtlSeconds ?? env.MEDIA_TOKEN_TTL_SECONDS ?? 900)
  );
  const registrationInviteCode = String(
    overrides.registrationInviteCode ?? env.REGISTRATION_INVITE_CODE ?? ""
  ).trim();
  const superAdminSetupToken = String(
    overrides.superAdminSetupToken ?? env.SUPER_ADMIN_SETUP_TOKEN ?? ""
  ).trim();
  const allowMultipleSuperAdmins = Boolean(
    overrides.allowMultipleSuperAdmins ?? env.ALLOW_MULTIPLE_SUPER_ADMINS === "true"
  );
  const resetEmailProvider = String(env.RESET_EMAIL_PROVIDER || "").trim().toLowerCase();
  const resetEmailConfigured = resetEmailProvider === "resend" && Boolean((env.RESEND_API_KEY || "").trim()) && Boolean((env.RESET_EMAIL_FROM || "").trim());
  const resetEmailProviderConfig = {
    provider: resetEmailProvider,
    resendApiKey: String(env.RESEND_API_KEY || "").trim(),
    from: String(env.RESET_EMAIL_FROM || "").trim(),
  };
  const isProductionVercel = isProduction && isVercel;
  if (isProductionVercel && !databaseUrl) {
    throw new Error("DATABASE_URL (managed PostgreSQL) is required for production Vercel deployments; local SQLite is ephemeral.");
  }
  if (isProductionVercel && !useBlob) {
    throw new Error("Vercel Blob storage is required for production Vercel deployments; local filesystem uploads are ephemeral.");
  }
  const secureCookies =
    env.FORCE_HTTPS_COOKIES === "true" ||
    isProduction ||
    (isVercel && baseUrl.startsWith("https://"));

  return {
    rootDir,
    isVercel,
    isProductionVercel,
    resetEmailConfigured,
    resetEmailProviderConfig,
    port,
    baseUrl,
    uploadDir,
    tmpUploadDir,
    dbPath,
    databaseUrl,
    useBlob,
    maxFileSizeMb,
    maxFileSizeBytes: maxFileSizeMb * 1024 * 1024,
    maxFilesPerUpload,
    maxUploadBatchBytes: maxUploadBatchMb * 1024 * 1024,
    maxStorageMbPerUser,
    maxStorageBytesPerUser: overrides.maxStorageBytesPerUser ?? maxStorageMbPerUser * 1024 * 1024,
    sessionSecret,
    faceDescriptorEncryptionKey,
    mediaSigningSecret,
    mediaTokenTtlSeconds,
    registrationInviteCode,
    superAdminSetupToken,
    allowMultipleSuperAdmins,
    isProduction,
    secureCookies,
  };
}

function getPublicBaseUrl(_req, config) {
  // Use the configured canonical origin; request Host/Forwarded headers are untrusted
  // and must not be used to construct share links or QR destinations.
  return config.baseUrl;
}

module.exports = { loadConfig, getPublicBaseUrl };

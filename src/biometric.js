const crypto = require("node:crypto");

const ENCRYPTED_PREFIX = "enc:v1:";

function isValidFaceDescriptor(value) {
  return Array.isArray(value) &&
    value.length === 128 &&
    value.every((n) => typeof n === "number" && Number.isFinite(n) && n >= -2 && n <= 2);
}

function encryptFaceDescriptor(config, descriptor) {
  if (!isValidFaceDescriptor(descriptor)) {
    throw new TypeError("Invalid face descriptor");
  }
  const key = config.faceDescriptorEncryptionKey;
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error("Face descriptor encryption is not configured");
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(descriptor), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return `${ENCRYPTED_PREFIX}${iv.toString("base64url")}:${tag.toString("base64url")}:${ciphertext.toString("base64url")}`;
}

function decryptFaceDescriptor(config, storedValue) {
  if (typeof storedValue !== "string") return null;
  if (!storedValue.startsWith(ENCRYPTED_PREFIX)) {
    try {
      return JSON.parse(storedValue); // legacy plaintext row; migration converts on startup
    } catch {
      return null;
    }
  }
  const parts = storedValue.slice(ENCRYPTED_PREFIX.length).split(":");
  if (parts.length !== 3) return null;
  try {
    const [ivText, tagText, ciphertextText] = parts;
    const iv = Buffer.from(ivText, "base64url");
    const tag = Buffer.from(tagText, "base64url");
    const ciphertext = Buffer.from(ciphertextText, "base64url");
    if (iv.length !== 12 || tag.length !== 16 || !ciphertext.length) return null;
    const decipher = crypto.createDecipheriv("aes-256-gcm", config.faceDescriptorEncryptionKey, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8"));
  } catch {
    return null;
  }
}

async function migrateLegacyFaceDescriptors(db, config, batchSize = 500) {
  let totalMigrated = 0;
  while (true) {
    const rows = await db.all(
      "SELECT id, descriptor_json FROM photo_faces WHERE descriptor_json NOT LIKE ? LIMIT ?",
      `${ENCRYPTED_PREFIX}%`,
      batchSize
    );
    if (!rows.length) break;
    let batchMigrated = 0;
    await db.tx(async (tx) => {
      for (const row of rows) {
        let descriptor;
        try {
          descriptor = JSON.parse(row.descriptor_json);
        } catch {
          continue;
        }
        if (!isValidFaceDescriptor(descriptor)) continue;
        const encrypted = encryptFaceDescriptor(config, descriptor);
        const result = await tx.run(
          "UPDATE photo_faces SET descriptor_json = ? WHERE id = ? AND descriptor_json = ?",
          encrypted,
          row.id,
          row.descriptor_json
        );
        batchMigrated += Number(result?.changes || 0);
      }
    });
    totalMigrated += batchMigrated;
    if (!batchMigrated) break; // malformed legacy rows or concurrent conversion
  }
  return totalMigrated;
}

module.exports = {
  isValidFaceDescriptor,
  encryptFaceDescriptor,
  decryptFaceDescriptor,
  migrateLegacyFaceDescriptors,
};

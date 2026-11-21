const dotenv = require("dotenv");
dotenv.config({ path: ".env.local", override: false });
dotenv.config();

const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");

const { loadConfig } = require("../src/config");
const { openDatabase } = require("../src/db");
const { isValidEmail } = require("../src/middleware");
const {
  generateTotpSecret,
  buildOtpAuthUri,
  generateRecoveryCodes,
  hashRecoveryCodes,
} = require("../src/security");

async function main() {
  const config = loadConfig();
  const db = openDatabase({
    dbPath: config.dbPath,
    databaseUrl: config.databaseUrl,
  });

  try {
    await db.ensureReady();
    const existingRow = await db.get(
      "SELECT COUNT(*) AS cnt FROM users WHERE role = 'super_admin' AND status <> 'deleted'"
    );
    const existing = Number(existingRow?.cnt || 0);

    if (existing > 0 && !config.allowMultipleSuperAdmins) {
      console.error(
        "A Super Admin account already exists and ALLOW_MULTIPLE_SUPER_ADMINS is not true."
      );
      process.exitCode = 1;
      return;
    }

    let name = (process.env.SUPER_ADMIN_NAME || "").trim();
    let email = (process.env.SUPER_ADMIN_EMAIL || "").toLowerCase().trim();
    let password = process.env.SUPER_ADMIN_PASSWORD || "";

    if (!name || !email || !password) {
      const rl = readline.createInterface({ input: stdin, output: stdout });
      try {
        if (!name) name = (await rl.question("Super Admin full name: ")).trim();
        if (!email) email = (await rl.question("Super Admin email: ")).toLowerCase().trim();
        if (!password) password = await rl.question("Super Admin password (6+ chars): ");
      } finally {
        rl.close();
      }
    }

    if (!name || name.length > 100) {
      throw new Error("Valid name (1–100 characters) required");
    }
    if (!isValidEmail(email)) {
      throw new Error("Valid email address required");
    }
    if (password.length < 6 || password.length > 128) {
      throw new Error("Super Admin password must be 6–128 characters");
    }
    if (await db.get("SELECT id FROM users WHERE email = ?", email)) {
      throw new Error(`An account with email ${email} already exists`);
    }

    const uid = uuid();
    const passwordHash = await bcrypt.hash(password, 12);
    const mfaSecret = generateTotpSecret();
    const otpauthUrl = buildOtpAuthUri({
      secret: mfaSecret,
      email,
      issuer: "SnapFind Super Admin",
    });
    const recoveryCodes = generateRecoveryCodes(8);
    const recoveryHashes = hashRecoveryCodes(recoveryCodes);

    await db.run(
      `INSERT INTO users (
        id, name, email, password_hash, role, status, mfa_enabled, mfa_secret, mfa_recovery_codes
      ) VALUES (?, ?, ?, ?, 'super_admin', 'active', 1, ?, ?)`,
      uid,
      name,
      email,
      passwordHash,
      mfaSecret,
      recoveryHashes
    );

    await db.run(
      `INSERT INTO audit_logs (id, user_id, action, entity_type, entity_id, details, ip)
       VALUES (?, ?, 'super_admin.cli_created', 'user', ?, ?, 'cli')`,
      uuid(),
      uid,
      uid,
      email
    );

    console.log("\nSuper Admin account created successfully.");
    console.log(`Database backend: ${db.dialect}`);
    console.log(`Email: ${email}`);
    console.log(`TOTP Secret (add to Authenticator app): ${mfaSecret}`);
    console.log(`OTPAuth URI: ${otpauthUrl}`);
    console.log("One-time Recovery Codes (store securely offline):");
    recoveryCodes.forEach((c) => console.log(`  - ${c}`));
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error("Failed:", err.message);
  process.exit(1);
});

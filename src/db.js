const fs = require("node:fs");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { Pool, types } = require("@neondatabase/serverless");

// Parse Postgres BIGINT (OID 20) & NUMERIC (OID 1700 from SUM(BIGINT)) as JS numbers
types.setTypeParser(20, (val) => (val === null ? null : Number(val)));
types.setTypeParser(1700, (val) => (val === null ? null : Number(val)));

function formatPgTimestamp(val) {
  if (!val) return null;
  const d = new Date(val);
  if (Number.isNaN(d.getTime())) return String(val);
  return d.toISOString().replace("T", " ").slice(0, 19);
}

types.setTypeParser(1114, formatPgTimestamp);
types.setTypeParser(1184, formatPgTimestamp);

const SQLITE_MIGRATIONS = [
  {
    version: 1,
    name: "initial_schema",
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'photographer' CHECK(role IN ('photographer', 'admin')),
        phone TEXT DEFAULT '',
        studio TEXT DEFAULT '',
        storage_used_bytes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL REFERENCES users(id),
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        event_date TEXT,
        venue TEXT DEFAULT '',
        access_code TEXT UNIQUE NOT NULL,
        pin_hash TEXT,
        is_public INTEGER NOT NULL DEFAULT 0,
        ai_enabled INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'paused', 'archived')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS photos (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        filename TEXT NOT NULL,
        thumb_filename TEXT NOT NULL,
        preview_filename TEXT NOT NULL,
        original_name TEXT DEFAULT '',
        mime TEXT NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        total_bytes INTEGER NOT NULL DEFAULT 0,
        width INTEGER DEFAULT 0,
        height INTEGER DEFAULT 0,
        caption TEXT DEFAULT '',
        face_indexed INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS photo_faces (
        id TEXT PRIMARY KEY,
        photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
        event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        descriptor_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS selections (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
        guest_name TEXT DEFAULT '',
        guest_email TEXT DEFAULT '',
        guest_key TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS favourites (
        id TEXT PRIMARY KEY,
        photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
        event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
        guest_key TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(photo_id, guest_key)
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        action TEXT NOT NULL,
        entity_type TEXT,
        entity_id TEXT,
        details TEXT DEFAULT '',
        ip TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        sess TEXT NOT NULL,
        expired INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_events_owner ON events(owner_id);
      CREATE INDEX IF NOT EXISTS idx_events_public_status ON events(is_public, status);
      CREATE INDEX IF NOT EXISTS idx_photos_event ON photos(event_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_photo_faces_event ON photo_faces(event_id);
      CREATE INDEX IF NOT EXISTS idx_photo_faces_photo ON photo_faces(photo_id);
      CREATE INDEX IF NOT EXISTS idx_selections_event ON selections(event_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_favourites_event_guest ON favourites(event_id, guest_key);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired);
    `,
  },
  {
    version: 2,
    name: "super_admin_and_multi_tenant",
    disableFk: true,
    sql: `
      CREATE TABLE IF NOT EXISTS studios (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        owner_id TEXT,
        plan TEXT NOT NULL DEFAULT 'standard' CHECK(plan IN ('free', 'standard', 'pro', 'enterprise')),
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended')),
        storage_limit_bytes INTEGER NOT NULL DEFAULT 524288000,
        notes TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE users_v2 (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'studio_owner' CHECK(role IN ('super_admin', 'studio_owner', 'studio_staff')),
        studio_id TEXT REFERENCES studios(id) ON DELETE SET NULL,
        staff_permissions TEXT NOT NULL DEFAULT '[]',
        phone TEXT DEFAULT '',
        studio TEXT DEFAULT '',
        storage_used_bytes INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted')),
        must_change_password INTEGER NOT NULL DEFAULT 0,
        mfa_enabled INTEGER NOT NULL DEFAULT 0,
        mfa_secret TEXT,
        mfa_recovery_codes TEXT,
        last_login_at TEXT,
        deleted_at TEXT,
        suspended_at TEXT,
        suspended_reason TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      INSERT INTO users_v2 (
        id, name, email, password_hash, role, studio_id, phone, studio, storage_used_bytes, created_at
      )
      SELECT
        id,
        name,
        email,
        password_hash,
        'studio_owner',
        'studio-' || id,
        COALESCE(phone, ''),
        COALESCE(studio, ''),
        COALESCE(storage_used_bytes, 0),
        created_at
      FROM users;

      INSERT OR IGNORE INTO studios (id, name, slug, owner_id, status, created_at)
      SELECT
        'studio-' || id,
        CASE WHEN TRIM(COALESCE(studio, '')) <> '' THEN studio ELSE name || ' Studio' END,
        'studio-' || LOWER(SUBSTR(id, 1, 12)),
        id,
        'active',
        created_at
      FROM users;

      DROP TABLE users;
      ALTER TABLE users_v2 RENAME TO users;

      ALTER TABLE events ADD COLUMN studio_id TEXT REFERENCES studios(id) ON DELETE CASCADE;
      UPDATE events
      SET studio_id = (SELECT studio_id FROM users WHERE users.id = events.owner_id)
      WHERE studio_id IS NULL;

      CREATE TABLE IF NOT EXISTS user_sessions (
        sid TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        studio_id TEXT,
        ip TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        device_label TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        revoked_at TEXT
      );

      CREATE TABLE IF NOT EXISTS security_events (
        id TEXT PRIMARY KEY,
        user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        studio_id TEXT REFERENCES studios(id) ON DELETE SET NULL,
        email TEXT DEFAULT '',
        event_type TEXT NOT NULL,
        success INTEGER NOT NULL DEFAULT 1,
        ip TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        device_label TEXT DEFAULT '',
        session_id TEXT DEFAULT '',
        suspicious INTEGER NOT NULL DEFAULT 0,
        details TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS password_resets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT UNIQUE NOT NULL,
        initiated_by TEXT DEFAULT 'self',
        expires_at INTEGER NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_users_role_status ON users(role, status);
      CREATE INDEX IF NOT EXISTS idx_users_studio ON users(studio_id);
      CREATE INDEX IF NOT EXISTS idx_studios_status ON studios(status);
      CREATE INDEX IF NOT EXISTS idx_events_studio ON events(studio_id);
      CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, revoked_at);
      CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type, suspicious);
      CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
    `,
  },
  {
    version: 3,
    name: "selfie_only_gallery",
    sql: `ALTER TABLE events ADD COLUMN selfie_only INTEGER NOT NULL DEFAULT 0;`,
  },
  {
    version: 4,
    name: "studio_storage_usage_counter",
    sql: `
      ALTER TABLE studios ADD COLUMN storage_used_bytes INTEGER NOT NULL DEFAULT 0;
      UPDATE studios SET storage_used_bytes = COALESCE((
        SELECT SUM(p.total_bytes) FROM photos p JOIN events e ON e.id = p.event_id
        WHERE e.studio_id = studios.id
      ), 0);
    `,
  },
  {
    version: 5,
    name: "reconcile_user_storage_usage",
    sql: `
      UPDATE users SET storage_used_bytes = COALESCE((
        SELECT SUM(p.total_bytes) FROM photos p JOIN events e ON e.id = p.event_id
        WHERE e.owner_id = users.id
      ), 0);
    `,
  },
  {
    version: 6,
    name: "face_discovery_consent_version",
    sql: `ALTER TABLE events ADD COLUMN ai_consent_version INTEGER NOT NULL DEFAULT 1;`,
  },
];

const PG_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS studios (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    owner_id TEXT,
    plan TEXT NOT NULL DEFAULT 'standard' CHECK(plan IN ('free', 'standard', 'pro', 'enterprise')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended')),
    storage_limit_bytes BIGINT NOT NULL DEFAULT 524288000,
    storage_used_bytes BIGINT NOT NULL DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'studio_owner' CHECK(role IN ('super_admin', 'studio_owner', 'studio_staff')),
    studio_id TEXT REFERENCES studios(id) ON DELETE SET NULL,
    staff_permissions TEXT NOT NULL DEFAULT '[]',
    phone TEXT DEFAULT '',
    studio TEXT DEFAULT '',
    storage_used_bytes BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret TEXT,
    mfa_recovery_codes TEXT,
    last_login_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    suspended_at TIMESTAMPTZ,
    suspended_reason TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    studio_id TEXT REFERENCES studios(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    event_date TEXT,
    venue TEXT DEFAULT '',
    access_code TEXT UNIQUE NOT NULL,
    pin_hash TEXT,
    is_public INTEGER NOT NULL DEFAULT 0,
    ai_enabled INTEGER NOT NULL DEFAULT 0,
    selfie_only INTEGER NOT NULL DEFAULT 0,
    ai_consent_version INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'paused', 'archived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS photos (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    thumb_filename TEXT NOT NULL,
    preview_filename TEXT NOT NULL,
    original_name TEXT DEFAULT '',
    mime TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    total_bytes BIGINT NOT NULL DEFAULT 0,
    width INTEGER DEFAULT 0,
    height INTEGER DEFAULT 0,
    caption TEXT DEFAULT '',
    face_indexed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS photo_faces (
    id TEXT PRIMARY KEY,
    photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    descriptor_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS selections (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
    guest_name TEXT DEFAULT '',
    guest_email TEXT DEFAULT '',
    guest_key TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS favourites (
    id TEXT PRIMARY KEY,
    photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    guest_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(photo_id, guest_key)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    details TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expired BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS user_sessions (
    sid TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    studio_id TEXT,
    ip TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    device_label TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
  );

  CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    studio_id TEXT REFERENCES studios(id) ON DELETE SET NULL,
    email TEXT DEFAULT '',
    event_type TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 1,
    ip TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    device_label TEXT DEFAULT '',
    session_id TEXT DEFAULT '',
    suspicious INTEGER NOT NULL DEFAULT 0,
    details TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    initiated_by TEXT DEFAULT 'self',
    expires_at BIGINT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE INDEX IF NOT EXISTS idx_events_owner ON events(owner_id);
  CREATE INDEX IF NOT EXISTS idx_events_public_status ON events(is_public, status);
  CREATE INDEX IF NOT EXISTS idx_photos_event ON photos(event_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_photo_faces_event ON photo_faces(event_id);
  CREATE INDEX IF NOT EXISTS idx_photo_faces_photo ON photo_faces(photo_id);
  CREATE INDEX IF NOT EXISTS idx_selections_event ON selections(event_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_favourites_event_guest ON favourites(event_id, guest_key);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired);
  CREATE INDEX IF NOT EXISTS idx_users_role_status ON users(role, status);
  CREATE INDEX IF NOT EXISTS idx_users_studio ON users(studio_id);
  CREATE INDEX IF NOT EXISTS idx_studios_status ON studios(status);
  CREATE INDEX IF NOT EXISTS idx_events_studio ON events(studio_id);
  CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, revoked_at);
  CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type, suspicious);
  CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
`;

function translateSqlToPostgres(sql) {
  let out = String(sql)
    .replace(/\bMAX\s*\(\s*0\s*,/gi, "GREATEST(0,")
    .replace(/datetime\('now',\s*'-7 days'\)/gi, "(NOW() - INTERVAL '7 days')")
    .replace(/datetime\('now',\s*'-15 minutes'\)/gi, "(NOW() - INTERVAL '15 minutes')")
    .replace(/datetime\('now',\s*'-30 minutes'\)/gi, "(NOW() - INTERVAL '30 minutes')")
    .replace(/datetime\('now',\s*'-30 seconds'\)/gi, "(NOW() - INTERVAL '30 seconds')");

  // Replace '?' placeholders outside single-quoted literals with $1, $2, ...
  let idx = 0;
  let result = "";
  let inSingleQuote = false;
  for (let i = 0; i < out.length; i++) {
    const ch = out[i];
    if (ch === "'") {
      result += ch;
      if (inSingleQuote && out[i + 1] === "'") {
        result += "'";
        i++;
      } else {
        inSingleQuote = !inSingleQuote;
      }
    } else if (ch === "?" && !inSingleQuote) {
      idx += 1;
      result += `$${idx}`;
    } else {
      result += ch;
    }
  }
  return result;
}

function openSqliteDatabase(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const raw = new DatabaseSync(dbPath);
  raw.exec("PRAGMA journal_mode = WAL;");
  raw.exec("PRAGMA foreign_keys = ON;");
  raw.exec("PRAGMA busy_timeout = 5000;");

  raw.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const applied = new Set(
    raw.prepare("SELECT version FROM schema_migrations").all().map((r) => r.version)
  );

  for (const m of SQLITE_MIGRATIONS) {
    if (applied.has(m.version)) continue;
    if (m.disableFk) {
      raw.exec("PRAGMA foreign_keys = OFF;");
    }
    raw.exec("BEGIN IMMEDIATE;");
    try {
      raw.exec(m.sql);
      raw
        .prepare("INSERT INTO schema_migrations (version, name) VALUES (?, ?)")
        .run(m.version, m.name);
      raw.exec("COMMIT;");
    } catch (err) {
      raw.exec("ROLLBACK;");
      throw err;
    } finally {
      if (m.disableFk) {
        raw.exec("PRAGMA foreign_keys = ON;");
      }
    }
  }

  let closed = false;
  let txChain = Promise.resolve();

  const adapter = {
    dialect: "sqlite",
    prepare(sql) {
      return raw.prepare(sql);
    },
    async ensureReady() {},
    async get(sql, ...params) {
      return raw.prepare(sql).get(...params);
    },
    async all(sql, ...params) {
      return raw.prepare(sql).all(...params);
    },
    async run(sql, ...params) {
      return raw.prepare(sql).run(...params);
    },
    async exec(sql) {
      return raw.exec(sql);
    },
    tx(fn) {
      const runTx = async () => {
        raw.exec("BEGIN IMMEDIATE;");
        try {
          const result = await fn(adapter);
          raw.exec("COMMIT;");
          return result;
        } catch (err) {
          try {
            raw.exec("ROLLBACK;");
          } catch {
            // ignore rollback error if transaction already closed
          }
          throw err;
        }
      };
      const next = txChain.then(runTx, runTx);
      txChain = next.catch(() => {});
      return next;
    },
    close() {
      if (!closed) {
        closed = true;
        raw.close();
      }
    },
  };

  return adapter;
}

function openPostgresDatabase(databaseUrl) {
  let pool = null;
  let readyPromise = null;

  function getPool() {
    if (!pool) {
      pool = new Pool({
        connectionString: databaseUrl,
        max: process.env.VERCEL ? 5 : 10,
        idleTimeoutMillis: 10000,
        connectionTimeoutMillis: 10000,
        statement_timeout: 25000,
      });
      pool.on("error", () => {
        // ignore idle pool socket disconnects in serverless environments
      });
    }
    return pool;
  }

  function makeExecutor(clientOrPool) {
    return {
      dialect: "postgres",
      async get(sql, ...params) {
        const res = await clientOrPool.query(translateSqlToPostgres(sql), params);
        return res.rows[0];
      },
      async all(sql, ...params) {
        const res = await clientOrPool.query(translateSqlToPostgres(sql), params);
        return res.rows;
      },
      async run(sql, ...params) {
        const res = await clientOrPool.query(translateSqlToPostgres(sql), params);
        return { changes: res.rowCount || 0 };
      },
      async exec(sql) {
        return clientOrPool.query(sql);
      },
    };
  }

  async function ensureReady() {
    if (!readyPromise) {
      readyPromise = (async () => {
        try {
          const check = await getPool().query(
            "SELECT 1 FROM schema_migrations WHERE version = 6 LIMIT 1"
          );
          if (check.rowCount > 0) return;
        } catch {
          // Table does not exist yet — run initial schema bootstrap below
        }

        const client = await getPool().connect();
        try {
          await client.query("BEGIN");
          await client.query("SET LOCAL lock_timeout = '10s'");
          await client.query("SELECT pg_advisory_xact_lock(84729103)");
          await client.query(PG_SCHEMA_SQL);
          await client.query(
            "ALTER TABLE events ADD COLUMN IF NOT EXISTS selfie_only INTEGER NOT NULL DEFAULT 0"
          );
          await client.query(
            "ALTER TABLE studios ADD COLUMN IF NOT EXISTS storage_used_bytes BIGINT NOT NULL DEFAULT 0"
          );
          await client.query(
            "ALTER TABLE events ADD COLUMN IF NOT EXISTS ai_consent_version INTEGER NOT NULL DEFAULT 1"
          );
          await client.query(
            `UPDATE studios s SET storage_used_bytes = COALESCE((
              SELECT SUM(p.total_bytes) FROM photos p JOIN events e ON e.id = p.event_id
              WHERE e.studio_id = s.id
            ), 0)`
          );
          await client.query(
            `UPDATE users u SET storage_used_bytes = COALESCE((
              SELECT SUM(p.total_bytes) FROM photos p JOIN events e ON e.id = p.event_id
              WHERE e.owner_id = u.id
            ), 0)`
          );
          await client.query(
            `INSERT INTO schema_migrations (version, name)
             VALUES
               (1, 'initial_schema'),
               (2, 'super_admin_and_multi_tenant'),
               (3, 'selfie_only_gallery'),
               (4, 'studio_storage_usage_counter'),
               (5, 'reconcile_user_storage_usage'),
               (6, 'face_discovery_consent_version')
             ON CONFLICT (version) DO NOTHING`
          );
          await client.query("COMMIT");
        } catch (err) {
          try {
            await client.query("ROLLBACK");
          } catch {
            // ignore rollback failure
          }
          throw err;
        } finally {
          client.release();
        }
      })().catch((err) => {
        readyPromise = null;
        throw err;
      });
    }
    return readyPromise;
  }

  return {
    dialect: "postgres",
    ensureReady,
    async get(sql, ...params) {
      await ensureReady();
      return makeExecutor(getPool()).get(sql, ...params);
    },
    async all(sql, ...params) {
      await ensureReady();
      return makeExecutor(getPool()).all(sql, ...params);
    },
    async run(sql, ...params) {
      await ensureReady();
      return makeExecutor(getPool()).run(sql, ...params);
    },
    async exec(sql) {
      await ensureReady();
      return getPool().query(sql);
    },
    async tx(fn) {
      await ensureReady();
      const client = await getPool().connect();
      const txExec = makeExecutor(client);
      txExec.tx = (nestedFn) => nestedFn(txExec);
      try {
        await client.query("BEGIN");
        const result = await fn(txExec);
        await client.query("COMMIT");
        return result;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // ignore rollback error
        }
        throw err;
      } finally {
        client.release();
      }
    },
    async close() {
      if (pool) {
        const p = pool;
        pool = null;
        await p.end();
      }
    },
  };
}

function openDatabase(targetOrOptions) {
  if (typeof targetOrOptions === "string") {
    return openSqliteDatabase(targetOrOptions);
  }
  const opts = targetOrOptions || {};
  if (opts.databaseUrl && !opts.forceSqlite) {
    return openPostgresDatabase(opts.databaseUrl);
  }
  return openSqliteDatabase(opts.dbPath);
}

module.exports = { openDatabase, translateSqlToPostgres };

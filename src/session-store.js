const session = require("express-session");

class DatabaseSessionStore extends session.Store {
  constructor(db, options = {}) {
    super();
    this.db = db;
    this.ttlMs = options.ttlMs || 7 * 86400 * 1000;
    if (!options.disableCleanupInterval && !process.env.VERCEL) {
      this.cleanupInterval = setInterval(() => {
        this.prune().catch(() => {
          // ignore cleanup errors if DB is closing
        });
      }, options.cleanupIntervalMs || 15 * 60 * 1000);
      if (this.cleanupInterval.unref) {
        this.cleanupInterval.unref();
      }
    } else {
      this.cleanupInterval = null;
    }
  }

  async prune() {
    await this.db.run("DELETE FROM sessions WHERE expired <= ?", Date.now());
  }

  stopCleanup() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  _getExpireMs(sess) {
    const maxAge = sess?.cookie?.maxAge;
    return Date.now() + (typeof maxAge === "number" ? maxAge : this.ttlMs);
  }

  get(sid, cb) {
    this.db
      .get("SELECT sess, expired FROM sessions WHERE sid = ?", sid)
      .then((row) => {
        if (!row) return cb(null, null);
        if (Number(row.expired) <= Date.now()) {
          return this.db
            .run("DELETE FROM sessions WHERE sid = ?", sid)
            .then(() => cb(null, null))
            .catch((err) => cb(err));
        }
        return cb(null, JSON.parse(row.sess));
      })
      .catch((err) => cb(err));
  }

  set(sid, sess, cb) {
    const expired = this._getExpireMs(sess);
    const serialized = JSON.stringify(sess);
    this.db
      .run(
        `INSERT INTO sessions (sid, sess, expired) VALUES (?, ?, ?)
         ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expired = excluded.expired`,
        sid,
        serialized,
        expired
      )
      .then(() => cb?.(null))
      .catch((err) => cb?.(err));
  }

  destroy(sid, cb) {
    this.db
      .run("DELETE FROM sessions WHERE sid = ?", sid)
      .then(() => cb?.(null))
      .catch((err) => cb?.(err));
  }

  touch(sid, sess, cb) {
    const expired = this._getExpireMs(sess);
    this.db
      .run("UPDATE sessions SET expired = ? WHERE sid = ?", expired, sid)
      .then(() => cb?.(null))
      .catch((err) => cb?.(err));
  }
}

module.exports = {
  DatabaseSessionStore,
  SQLiteSessionStore: DatabaseSessionStore,
};

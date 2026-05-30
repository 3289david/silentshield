/**
 * better-sqlite3-compatible synchronous API wrapper around sql.js (WASM SQLite).
 * No native compilation needed — works on Windows, Mac, Linux without build tools.
 */
const fs = require('fs');

class Statement {
  constructor(sqliteDb, sql, wrapper) {
    this._sqliteDb = sqliteDb;
    this._sql = sql;
    this._wrapper = wrapper;
  }

  _normalizeParams(args) {
    if (args.length === 0) return [];
    if (args.length === 1 && Array.isArray(args[0])) return args[0];
    if (args.length === 1 && args[0] !== null && typeof args[0] === 'object' && !Array.isArray(args[0])) {
      // Named params: {name: val} → convert to positional array won't work cleanly,
      // so pass as-is — sql.js accepts objects for named param SQL ($name style)
      return args[0];
    }
    return args;
  }

  run(...args) {
    const params = this._normalizeParams(args);
    const stmt = this._sqliteDb.prepare(this._sql);
    try {
      if (Array.isArray(params)) stmt.bind(params);
      else stmt.bind(params);
      stmt.step();
      const changes = this._sqliteDb.getRowsModified();
      this._wrapper._markDirty();
      return { changes, lastInsertRowid: 0 };
    } finally {
      stmt.free();
    }
  }

  get(...args) {
    const params = this._normalizeParams(args);
    const stmt = this._sqliteDb.prepare(this._sql);
    try {
      if (params.length > 0 || (typeof params === 'object' && !Array.isArray(params))) {
        stmt.bind(params);
      }
      if (stmt.step()) return stmt.getAsObject(null);
      return undefined;
    } finally {
      stmt.free();
    }
  }

  all(...args) {
    const params = this._normalizeParams(args);
    const rows = [];
    const stmt = this._sqliteDb.prepare(this._sql);
    try {
      if (params.length > 0 || (typeof params === 'object' && !Array.isArray(params))) {
        stmt.bind(params);
      }
      while (stmt.step()) rows.push(stmt.getAsObject(null));
    } finally {
      stmt.free();
    }
    return rows;
  }
}

class DbWrapper {
  constructor(sqliteDb, dbPath) {
    this._db = sqliteDb;
    this._path = dbPath;
    this._dirty = false;
    // Persist to disk every 2 seconds if there are writes
    this._saveTimer = setInterval(() => this._persist(), 2000);
  }

  pragma(str) {
    this._db.run('PRAGMA ' + str + ';');
  }

  exec(sql) {
    this._db.run(sql);
    this._markDirty();
    return this;
  }

  prepare(sql) {
    return new Statement(this._db, sql, this);
  }

  transaction(fn) {
    return (...args) => {
      this._db.run('BEGIN;');
      try {
        const result = fn(...args);
        this._db.run('COMMIT;');
        return result;
      } catch (e) {
        try { this._db.run('ROLLBACK;'); } catch (_) {}
        throw e;
      }
    };
  }

  _markDirty() {
    this._dirty = true;
  }

  _persist() {
    if (!this._dirty || !this._path) return;
    try {
      const data = this._db.export();
      fs.writeFileSync(this._path, Buffer.from(data));
      this._dirty = false;
    } catch (e) {
      console.error('[DB] Save error:', e.message);
    }
  }

  close() {
    clearInterval(this._saveTimer);
    this._persist();
    this._db.close();
  }
}

module.exports = { DbWrapper };

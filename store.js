// Storage layer. Uses Postgres when DATABASE_URL is set (production),
// otherwise a local JSON file (development only, not persistent on Render).
const fs = require('fs');
const path = require('path');

function makeFileStore() {
  const file = process.env.DATA_FILE || path.join(__dirname, 'data.json');
  let data = {};
  try { data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { data = {}; }
  const save = () => fs.writeFileSync(file, JSON.stringify(data));
  return {
    kind: 'file',
    async init() {},
    async all() { return Object.values(data); },
    async get(key) { return data[key] || null; },
    async insertMany(recs) {
      for (const r of recs) data[r.key] = r;
      save();
    },
    // fn(rec) returns { rec, result }; rec may be null to delete
    async mutate(key, fn) {
      const out = fn(data[key] || null);
      if (out.rec === null) delete data[key];
      else if (out.rec) data[key] = out.rec;
      if (out.rec !== undefined) save();
      return out.result;
    },
  };
}

function makePgStore() {
  const { Pool } = require('pg');
  const url = process.env.DATABASE_URL;
  const ssl = process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false };
  const pool = new Pool({ connectionString: url, ssl, max: 5 });
  return {
    kind: 'postgres',
    async init() {
      await pool.query(
        'CREATE TABLE IF NOT EXISTS license_keys (key TEXT PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMPTZ DEFAULT now())'
      );
    },
    async all() {
      const r = await pool.query('SELECT data FROM license_keys ORDER BY created_at DESC');
      return r.rows.map((x) => x.data);
    },
    async get(key) {
      const r = await pool.query('SELECT data FROM license_keys WHERE key=$1', [key]);
      return r.rows[0] ? r.rows[0].data : null;
    },
    async insertMany(recs) {
      const c = await pool.connect();
      try {
        await c.query('BEGIN');
        for (const rec of recs) {
          await c.query('INSERT INTO license_keys (key, data) VALUES ($1,$2)', [rec.key, JSON.stringify(rec)]);
        }
        await c.query('COMMIT');
      } catch (e) {
        await c.query('ROLLBACK');
        throw e;
      } finally {
        c.release();
      }
    },
    async mutate(key, fn) {
      const c = await pool.connect();
      try {
        await c.query('BEGIN');
        const r = await c.query('SELECT data FROM license_keys WHERE key=$1 FOR UPDATE', [key]);
        const out = fn(r.rows[0] ? r.rows[0].data : null);
        if (out.rec === null) await c.query('DELETE FROM license_keys WHERE key=$1', [key]);
        else if (out.rec) await c.query('UPDATE license_keys SET data=$2 WHERE key=$1', [key, JSON.stringify(out.rec)]);
        await c.query('COMMIT');
        return out.result;
      } catch (e) {
        await c.query('ROLLBACK');
        throw e;
      } finally {
        c.release();
      }
    },
  };
}

module.exports = process.env.DATABASE_URL ? makePgStore() : makeFileStore();

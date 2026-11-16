"""SQLite persistence (plain sqlite3; SQL kept portable so PostgreSQL can replace it later)."""
import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, target TEXT, config TEXT, status TEXT,
  stage TEXT, progress REAL DEFAULT 0, vantage TEXT, checkpoint TEXT DEFAULT '{}',
  created REAL, finished REAL, error TEXT, cooldown_until REAL);
CREATE TABLE IF NOT EXISTS hosts(
  scan_id INTEGER, address TEXT, family INTEGER, hostname TEXT, os TEXT, status TEXT,
  PRIMARY KEY(scan_id, address));
CREATE TABLE IF NOT EXISTS ports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, host TEXT, proto TEXT, port INTEGER,
  state TEXT, reason TEXT, service TEXT, product TEXT, version TEXT, banner TEXT,
  verdict TEXT, confidence REAL, fingerprint TEXT, UNIQUE(scan_id, host, proto, port));
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ts REAL, level TEXT, kind TEXT, message TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS investigations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, host TEXT, proto TEXT, port INTEGER,
  investigator TEXT, reason TEXT, result TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, host TEXT, proto TEXT, port INTEGER,
  kind TEXT, category TEXT, severity TEXT, title TEXT, evidence TEXT);
CREATE TABLE IF NOT EXISTS raw_output(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, host TEXT, label TEXT, content TEXT, ts REAL);
"""


class Storage:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def execute(self, sql, args=()):
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute(sql, args)
                c.commit()
                return cur.lastrowid
            finally:
                c.close()

    def query(self, sql, args=()):
        c = self._conn()
        try:
            return [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()

    def one(self, sql, args=()):
        r = self.query(sql, args)
        return r[0] if r else None

    # ---- scans
    def create_scan(self, name, target, cfg):
        return self.execute(
            "INSERT INTO scans(name,target,config,status,stage,vantage,created) VALUES(?,?,?,?,?,?,?)",
            (name, target, json.dumps(cfg), "queued", "queued", cfg.get("vantage", "default"), time.time()))

    def update_scan(self, scan_id, **kw):
        if not kw:
            return
        cols = ",".join(f"{k}=?" for k in kw)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in kw.values()]
        self.execute(f"UPDATE scans SET {cols} WHERE id=?", (*vals, scan_id))

    def get_scan(self, scan_id):
        s = self.one("SELECT * FROM scans WHERE id=?", (scan_id,))
        if s:
            s["config"] = json.loads(s["config"] or "{}")
            s["checkpoint"] = json.loads(s["checkpoint"] or "{}")
        return s

    def list_scans(self, limit=100):
        return self.query("SELECT id,name,target,status,stage,progress,vantage,created,finished FROM scans ORDER BY id DESC LIMIT ?", (limit,))

    # ---- results
    def upsert_host(self, scan_id, address, family, hostname="", os_="", status="up"):
        self.execute(
            "INSERT INTO hosts VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id,address) DO UPDATE SET "
            "hostname=excluded.hostname, os=CASE WHEN excluded.os!='' THEN excluded.os ELSE os END, "
            "status=CASE WHEN status='done' THEN status ELSE excluded.status END",
            (scan_id, address, family, hostname, os_, status))

    def set_host_status(self, scan_id, address, status):
        self.execute("UPDATE hosts SET status=? WHERE scan_id=? AND address=?", (status, scan_id, address))

    def upsert_port(self, scan_id, host, proto, port, state, reason="", service="", product="", version=""):
        self.execute(
            "INSERT INTO ports(scan_id,host,proto,port,state,reason,service,product,version) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(scan_id,host,proto,port) DO UPDATE SET state=excluded.state, reason=excluded.reason, "
            "service=CASE WHEN excluded.service!='' THEN excluded.service ELSE service END, "
            "product=CASE WHEN excluded.product!='' THEN excluded.product ELSE product END, "
            "version=CASE WHEN excluded.version!='' THEN excluded.version ELSE version END",
            (scan_id, host, proto, port, state, reason, service, product, version))

    def update_port_fp(self, scan_id, host, proto, port, banner, verdict, confidence, fingerprint):
        self.execute(
            "UPDATE ports SET banner=?, verdict=?, confidence=?, fingerprint=? WHERE scan_id=? AND host=? AND proto=? AND port=?",
            (banner, verdict, confidence, json.dumps(fingerprint), scan_id, host, proto, port))

    def add_event(self, scan_id, level, kind, message, data=None):
        self.execute("INSERT INTO events(scan_id,ts,level,kind,message,data) VALUES(?,?,?,?,?,?)",
                     (scan_id, time.time(), level, kind, message, json.dumps(data or {})))

    def add_investigation(self, scan_id, host, proto, port, investigator, reason, result):
        self.execute("INSERT INTO investigations(scan_id,host,proto,port,investigator,reason,result,ts) VALUES(?,?,?,?,?,?,?,?)",
                     (scan_id, host, proto, port, investigator, reason, json.dumps(result, default=str), time.time()))

    def add_finding(self, scan_id, host, proto, port, kind, category, severity, title, evidence):
        self.execute("INSERT INTO findings(scan_id,host,proto,port,kind,category,severity,title,evidence) VALUES(?,?,?,?,?,?,?,?,?)",
                     (scan_id, host, proto, port, kind, category, severity, title, json.dumps(evidence, default=str)))

    def add_raw(self, scan_id, host, label, content):
        self.execute("INSERT INTO raw_output(scan_id,host,label,content,ts) VALUES(?,?,?,?,?)",
                     (scan_id, host, label, content, time.time()))

    def ports(self, scan_id, host=None):
        q, a = "SELECT * FROM ports WHERE scan_id=?", [scan_id]
        if host:
            q += " AND host=?"
            a.append(host)
        rows = self.query(q + " ORDER BY host, proto, port", a)
        for r in rows:
            r["fingerprint"] = json.loads(r["fingerprint"]) if r["fingerprint"] else {}
        return rows

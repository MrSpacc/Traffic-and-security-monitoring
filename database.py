from contextlib import contextmanager
import sqlite3
import threading

class MetricsDatabase:
    def __init__(self, path):
        self.path = str(path)
        self.write_lock = threading.RLock()
        self.initialize()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA busy_timeout=30000")
            db.execute("PRAGMA synchronous=NORMAL")
            with db:
                yield db
        finally:
            db.close()

    def initialize(self):
        with self.write_lock, self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL,
                    occurred_at TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
                    protocol TEXT NOT NULL, status INTEGER NOT NULL, size INTEGER NOT NULL,
                    referer TEXT NOT NULL, user_agent TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at);
                CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
                CREATE TABLE IF NOT EXISTS ip_stats (
                    ip TEXT PRIMARY KEY, requests INTEGER NOT NULL DEFAULT 0,
                    errors_403 INTEGER NOT NULL DEFAULT 0, bytes_sent INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    last_status INTEGER NOT NULL, last_method TEXT NOT NULL,
                    last_path TEXT NOT NULL, banned INTEGER NOT NULL DEFAULT 0, banned_at TEXT);
                CREATE TABLE IF NOT EXISTS checkpoints (
                    file_path TEXT PRIMARY KEY, inode INTEGER NOT NULL, offset INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
                    ip TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
                    message TEXT NOT NULL, action TEXT NOT NULL DEFAULT 'detected');
                CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(occurred_at);
                CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
                CREATE TABLE IF NOT EXISTS auth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
                    ip TEXT NOT NULL, username TEXT NOT NULL, service TEXT NOT NULL);
            """)

    def add_event(self, event):
        return self.add_events([event])[0]

    def add_events(self, events, checkpoint=None):
        """Commit a bounded batch and its file position atomically."""
        stats = []
        with self.write_lock, self.connect() as db:
            for event in events:
                db.execute("""INSERT INTO events
                    (ip, occurred_at, method, path, protocol, status, size, referer, user_agent)
                    VALUES (:ip,:occurred_at,:method,:path,:protocol,:status,:size,:referer,:user_agent)""", event)
                db.execute("""INSERT INTO ip_stats
                    (ip,requests,errors_403,bytes_sent,first_seen,last_seen,last_status,last_method,last_path)
                    VALUES (:ip,1,CASE WHEN :status=403 THEN 1 ELSE 0 END,:size,
                            :occurred_at,:occurred_at,:status,:method,:path)
                    ON CONFLICT(ip) DO UPDATE SET
                        requests=requests+1,
                        errors_403=errors_403+CASE WHEN excluded.last_status=403 THEN 1 ELSE 0 END,
                        bytes_sent=bytes_sent+excluded.bytes_sent, last_seen=excluded.last_seen,
                        last_status=excluded.last_status,last_method=excluded.last_method,last_path=excluded.last_path""", event)
                stats.append(dict(db.execute(
                    "SELECT * FROM ip_stats WHERE ip=?", (event["ip"],)).fetchone()))
            if checkpoint is not None:
                file_path, inode, offset = checkpoint
                db.execute("""INSERT INTO checkpoints(file_path,inode,offset) VALUES(?,?,?)
                    ON CONFLICT(file_path) DO UPDATE SET inode=excluded.inode,offset=excluded.offset""",
                    (str(file_path), inode, offset))
        return stats

    def get_checkpoint(self, file_path):
        with self.connect() as db:
            row = db.execute("SELECT inode,offset FROM checkpoints WHERE file_path=?", (str(file_path),)).fetchone()
        return dict(row) if row else None

    def save_checkpoint(self, file_path, inode, offset):
        with self.write_lock, self.connect() as db:
            db.execute("""INSERT INTO checkpoints(file_path,inode,offset) VALUES(?,?,?)
                ON CONFLICT(file_path) DO UPDATE SET inode=excluded.inode,offset=excluded.offset""",
                (str(file_path), inode, offset))

    def get_ip(self, ip):
        with self.connect() as db:
            row = db.execute("SELECT * FROM ip_stats WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    def mark_banned(self, ip, banned_at):
        with self.write_lock, self.connect() as db:
            db.execute("""INSERT INTO ip_stats
                (ip,requests,errors_403,bytes_sent,first_seen,last_seen,last_status,last_method,last_path,banned,banned_at)
                VALUES(?,0,0,0,?,?,0,'SSH','-',1,?) ON CONFLICT(ip) DO NOTHING""",
                (ip, banned_at, banned_at, banned_at))
            db.execute("UPDATE ip_stats SET banned=1,banned_at=? WHERE ip=?", (banned_at, ip))

    def mark_unbanned(self, ip):
        with self.write_lock, self.connect() as db:
            db.execute("UPDATE ip_stats SET banned=0,banned_at=NULL WHERE ip=?", (ip,))

    def add_alert(self, occurred_at, ip, kind, severity, message, action="detected"):
        with self.write_lock, self.connect() as db:
            cursor = db.execute("""INSERT INTO alerts(occurred_at,ip,kind,severity,message,action)
                VALUES(?,?,?,?,?,?)""", (occurred_at, ip, kind, severity, message, action))
            return cursor.lastrowid

    def set_alert_action(self, alert_id, action):
        with self.write_lock, self.connect() as db:
            db.execute("UPDATE alerts SET action=? WHERE id=?", (action, alert_id))

    def add_auth_failure(self, occurred_at, ip, username, service="ssh"):
        with self.write_lock, self.connect() as db:
            db.execute("INSERT INTO auth_events(occurred_at,ip,username,service) VALUES(?,?,?,?)",
                       (occurred_at, ip, username, service))

    def recent_alerts(self, limit=100):
        with self.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]

    def summary(self):
        with self.connect() as db:
            data = dict(db.execute("""SELECT COUNT(*) requests,COUNT(DISTINCT ip) unique_ips,
                COALESCE(SUM(status=403),0) errors_403,COALESCE(SUM(size),0) bytes_sent FROM events""").fetchone())
            data["banned"] = db.execute("SELECT COUNT(*) FROM ip_stats WHERE banned=1").fetchone()[0]
            data["alerts"] = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            data["auth_failures"] = db.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]
            data["statuses"] = [dict(r) for r in db.execute("SELECT status,COUNT(*) count FROM events GROUP BY status ORDER BY count DESC")]
            data["methods"] = [dict(r) for r in db.execute("SELECT method,COUNT(*) count FROM events GROUP BY method ORDER BY count DESC")]
            data["timeline"] = [dict(r) for r in db.execute("""SELECT substr(occurred_at,1,13)||':00' hour,COUNT(*) count
                FROM events GROUP BY hour ORDER BY hour DESC LIMIT 24""")][::-1]
            data["top_paths"] = [dict(r) for r in db.execute("SELECT path,COUNT(*) count FROM events GROUP BY path ORDER BY count DESC LIMIT 10")]
        return data

    def list_ips(self, limit=200, query=""):
        with self.connect() as db:
            rows = [dict(r) for r in db.execute("""SELECT s.*,
                (SELECT COUNT(*) FROM alerts a WHERE a.ip=s.ip) alert_count,
                (SELECT COUNT(*) FROM auth_events e WHERE e.ip=s.ip) auth_failures
                FROM ip_stats s WHERE ip LIKE ? ORDER BY requests DESC,last_seen DESC LIMIT ?""",
                (f"%{query}%",limit))]
        for row in rows:
            row["risk"] = min(100, row["errors_403"] * 2 + row["alert_count"] * 25 +
                              row["auth_failures"] * 5 + (40 if row["banned"] else 0))
        return rows

    def list_banned(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute("""SELECT ip,requests,errors_403,
                first_seen,last_seen,banned_at FROM ip_stats WHERE banned=1
                ORDER BY banned_at DESC""")]

    def ip_details(self, ip):
        data = self.get_ip(ip)
        if not data:
            return None
        with self.connect() as db:
            data["statuses"] = [dict(r) for r in db.execute("SELECT status,COUNT(*) count FROM events WHERE ip=? GROUP BY status ORDER BY count DESC",(ip,))]
            data["methods"] = [dict(r) for r in db.execute("SELECT method,COUNT(*) count FROM events WHERE ip=? GROUP BY method ORDER BY count DESC",(ip,))]
            data["recent"] = [dict(r) for r in db.execute("""SELECT occurred_at,method,path,status,size,user_agent
                FROM events WHERE ip=? ORDER BY id DESC LIMIT 50""",(ip,))]
            data["alerts"] = [dict(r) for r in db.execute(
                "SELECT occurred_at,kind,severity,message,action FROM alerts WHERE ip=? ORDER BY id DESC LIMIT 30",(ip,))]
            data["auth_failures"] = db.execute("SELECT COUNT(*) FROM auth_events WHERE ip=?",(ip,)).fetchone()[0]
        return data

    def recent_events(self, limit=30):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT occurred_at,ip,method,path,status,size FROM events ORDER BY id DESC LIMIT ?",(limit,))]

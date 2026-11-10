#!/usr/bin/env python3
"""omanet: LAN presence tracker with a cyberpunk dashboard.

Scans the local network with arp-scan every SCAN_INTERVAL seconds, keeps
devices and presence sessions in SQLite, serves the dashboard + JSON API.
"""

import base64
import hmac
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = os.environ.get("DB_PATH", "/data/omanet.db")
PORT = int(os.environ.get("PORT", "20211"))
BIND = os.environ.get("BIND", "127.0.0.1")
TOKEN = os.environ.get("OMANET_TOKEN", "").strip()
IFACE = os.environ.get("IFACE", "")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "60"))
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SEED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "names.json")
DAY = 86400
BUCKET = 900  # 15 min


def load_seed():
    try:
        return {k.lower(): v for k, v in json.load(open(SEED, encoding="utf-8")).items()}
    except Exception:
        return {}


SEED_NAMES = load_seed()

_lock = threading.Lock()


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.executescript(
            """
            create table if not exists devices(
              mac text primary key,
              name text,
              vendor text,
              first_seen integer not null,
              last_seen integer not null,
              last_ip text,
              online integer not null default 0,
              miss integer not null default 0,
              name_source text not null default 'AUTO'
            );
            create table if not exists sessions(
              id integer primary key autoincrement,
              mac text not null,
              ip text,
              start_ts integer not null,
              end_ts integer
            );
            create index if not exists idx_sessions_mac on sessions(mac);
            create index if not exists idx_sessions_end on sessions(end_ts);
            create table if not exists meta(key text primary key, value text);
            """
        )
        if os.path.exists(SEED):
            seed = json.load(open(SEED, encoding="utf-8"))
            for mac, name in seed.items():
                con.execute(
                    "update devices set name=?, name_source='SEED' "
                    "where lower(mac)=lower(?) and (name is null or name_source='AUTO')",
                    (name, mac),
                )


def detect_iface():
    if IFACE:
        return IFACE
    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True,
                             text=True, timeout=5).stdout
        m = re.search(r"dev (\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "eth0"


def arp_scan():
    iface = detect_iface()
    cmd = ["arp-scan", f"--interface={iface}", "--localnet", "--ignoredups",
           "--retry=2", "--timeout=200"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as exc:
        return None, str(exc)
    if out.returncode not in (0, 1):
        return None, (out.stderr or "arp-scan failed").strip()[:300]
    found = {}
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0].strip()):
            continue
        if "DUP" in line:
            continue
        ip = parts[0].strip()
        mac = parts[1].strip().lower()
        if len(mac) != 17:
            continue
        vendor = parts[2].strip() if len(parts) > 2 else ""
        found[mac] = (ip, vendor)
    return found, None


def set_meta(con, key, value):
    con.execute("insert into meta(key,value) values(?,?) "
                "on conflict(key) do update set value=excluded.value", (key, str(value)))


def get_meta(con, key, default=None):
    row = con.execute("select value from meta where key=?", (key,)).fetchone()
    return row["value"] if row else default


def do_scan():
    if not _lock.acquire(blocking=False):
        return False
    try:
        found, error = arp_scan()
        now = int(time.time())
        with db() as con:
            if found is None:
                set_meta(con, "last_scan_error", error or "scan failed")
                set_meta(con, "last_scan_ts", now)
                return False
            set_meta(con, "last_scan_error", "")
            for mac, (ip, vendor) in found.items():
                row = con.execute("select mac, vendor from devices where mac=?", (mac,)).fetchone()
                if row is None:
                    con.execute(
                        "insert into devices(mac,name,vendor,first_seen,last_seen,last_ip,online,miss) "
                        "values(?,?,?,?,?,?,1,0)",
                        (mac, SEED_NAMES.get(mac), vendor, now, now, ip))
                else:
                    con.execute(
                        "update devices set last_seen=?, last_ip=?, online=1, miss=0, "
                        "vendor=case when (vendor is null or vendor='') then ? else vendor end "
                        "where mac=?", (now, ip, vendor, mac))
                open_s = con.execute(
                    "select id from sessions where mac=? and end_ts is null order by id desc limit 1",
                    (mac,)).fetchone()
                if open_s is None:
                    con.execute("insert into sessions(mac,ip,start_ts) values(?,?,?)", (mac, ip, now))
            for mac, name in SEED_NAMES.items():
                con.execute(
                    "update devices set name=?, name_source='SEED' where mac=? "
                    "and (name is null or name_source='AUTO')", (name, mac))
            macs = set(found)
            for row in con.execute("select mac, miss from devices where online=1").fetchall():
                if row["mac"] in macs:
                    continue
                miss = row["miss"] + 1
                if miss >= 3:
                    con.execute("update devices set online=0, miss=? where mac=?", (miss, row["mac"]))
                    con.execute("update sessions set end_ts=? where mac=? and end_ts is null",
                                (now, row["mac"]))
                else:
                    con.execute("update devices set miss=? where mac=?", (miss, row["mac"]))
            set_meta(con, "last_scan_ts", now)
            set_meta(con, "last_scan_count", len(found))
        return True
    finally:
        _lock.release()


def scan_loop():
    while True:
        try:
            do_scan()
        except Exception as exc:
            print("scan error:", exc, flush=True)
        time.sleep(SCAN_INTERVAL)


def buckets_for(intervals, day_start, now):
    b = [0.0] * 96
    for s, e in intervals:
        a, z = max(s, day_start), min(e, now)
        while a < z:
            idx = int((a - day_start) // BUCKET)
            if idx >= 96:
                break
            edge = day_start + (idx + 1) * BUCKET
            seg = min(z, edge)
            b[idx] += (seg - a) / BUCKET
            a = seg
    return [round(min(1.0, x), 2) for x in b]


def state():
    now = int(time.time())
    day_start = now - DAY
    with db() as con:
        devices = con.execute(
            "select mac,name,vendor,first_seen,last_seen,last_ip,online,name_source "
            "from devices order by online desc, lower(coalesce(name,vendor,mac))"
        ).fetchall()
        sessions = con.execute(
            "select mac,start_ts,end_ts from sessions where end_ts is null or end_ts>?",
            (day_start,)).fetchall()
        last_scan = int(get_meta(con, "last_scan_ts", 0) or 0)
        last_count = int(get_meta(con, "last_scan_count", 0) or 0)
        scan_error = get_meta(con, "last_scan_error", "") or ""
        new_24h = con.execute("select count(*) c from devices where first_seen>=?",
                              (day_start,)).fetchone()["c"]
        sess_24h = con.execute(
            "select count(*) c from sessions where start_ts>=? or end_ts is null",
            (day_start,)).fetchone()["c"]

    by_mac = {}
    for s in sessions:
        end = s["end_ts"] if s["end_ts"] is not None else now
        by_mac.setdefault(s["mac"], []).append((s["start_ts"], end))

    out = []
    for d in devices:
        iv = by_mac.get(d["mac"], [])
        total = sum(max(0, min(e, now) - max(s, day_start)) for s, e in iv)
        current = 0
        for s, e in iv:
            if e == now and s <= now:
                current = max(current, now - s)
        out.append({
            "mac": d["mac"], "name": d["name"], "vendor": d["vendor"],
            "ip": d["last_ip"], "online": bool(d["online"]),
            "first_seen": d["first_seen"], "last_seen": d["last_seen"],
            "name_source": d["name_source"],
            "current_session": current,
            "total_24h": total,
            "sessions_24h": len(iv),
            "timeline": buckets_for(iv, day_start, now),
        })
    return {
        "now": now, "last_scan": last_scan, "last_scan_count": last_count,
        "scan_error": scan_error, "interval": SCAN_INTERVAL,
        "stats": {
            "online": sum(1 for d in out if d["online"]),
            "known": len(out),
            "sessions_24h": sess_24h,
            "new_24h": new_24h,
        },
        "devices": out,
    }


def device_detail(mac):
    now = int(time.time())
    day_start = now - DAY
    with db() as con:
        d = con.execute("select * from devices where mac=?", (mac,)).fetchone()
        if d is None:
            return None
        rows = con.execute(
            "select start_ts,end_ts,ip from sessions where mac=? order by start_ts desc limit 30",
            (mac,)).fetchall()
        total = con.execute(
            "select coalesce(sum(coalesce(end_ts,?)-start_ts),0) s from sessions where mac=?",
            (now, mac)).fetchone()["s"]
        sess = [{"start": r["start_ts"], "end": r["end_ts"], "ip": r["ip"]} for r in rows]
        open_s = con.execute(
            "select start_ts from sessions where mac=? and end_ts is null order by id desc limit 1",
            (mac,)).fetchone()
    return {
        "mac": d["mac"], "name": d["name"], "vendor": d["vendor"], "ip": d["last_ip"],
        "online": bool(d["online"]), "first_seen": d["first_seen"],
        "last_seen": d["last_seen"], "name_source": d["name_source"],
        "total_seconds": int(total),
        "current_session": (now - open_s["start_ts"]) if open_s else 0,
        "sessions": sess,
    }


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC, **kwargs)

    def log_message(self, fmt, *args):
        pass

    def authorized(self):
        if not TOKEN:
            return True
        header = self.headers.get("Authorization") or ""
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        except Exception:
            return False
        _, _, given = decoded.partition(":")
        return hmac.compare_digest(given, TOKEN)

    def require_auth(self):
        if self.authorized():
            return True
        body = b"autenticacao necessaria\n"
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="omanet", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.require_auth():
            return
        path = urlparse(self.path).path
        if path == "/api/state":
            self.json(state())
            return
        if path == "/api/device":
            mac = (parse_qs(urlparse(self.path).query).get("mac") or [""])[0]
            data = device_detail(mac)
            if data is None:
                self.json({"error": "not found"}, 404)
            else:
                self.json(data)
            return
        if path == "/health":
            self.json({"ok": True})
            return
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        if not self.require_auth():
            return
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self.json({"error": "bad json"}, 400)
            return
        if path == "/api/name":
            mac = str(payload.get("mac", "")).strip().lower()
            name = str(payload.get("name", "")).strip()[:40]
            if not mac or not name:
                self.json({"error": "mac and name required"}, 400)
                return
            with db() as con:
                cur = con.execute(
                    "update devices set name=?, name_source='USER' where mac=?", (name, mac))
            self.json({"ok": cur.rowcount == 1})
            return
        if path == "/api/scan":
            threading.Thread(target=do_scan, daemon=True).start()
            self.json({"ok": True})
            return
        self.json({"error": "not found"}, 404)


def main():
    if not TOKEN and BIND not in ("127.0.0.1", "::1", "localhost"):
        raise SystemExit(
            f"recusando escutar em {BIND}:{PORT} sem OMANET_TOKEN; "
            "defina BIND=127.0.0.1 ou um token")
    init_db()
    threading.Thread(target=scan_loop, daemon=True).start()
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    auth = "on" if TOKEN else "off (loopback only)"
    print(f"omanet on {BIND}:{PORT}, db {DB_PATH}, auth {auth}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

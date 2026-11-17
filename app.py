#!/usr/bin/env python3
"""omanet: LAN presence tracker with a cyberpunk dashboard.

Scans the local network with arp-scan every SCAN_INTERVAL seconds, keeps
devices and presence sessions in SQLite, serves the dashboard + JSON API.
"""

import base64
import hmac
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = os.environ.get("DB_PATH", "/data/omanet.db")
PORT = int(os.environ.get("PORT", "20211"))
BIND = os.environ.get("BIND", "127.0.0.1")
TOKEN = os.environ.get("OMANET_TOKEN", "").strip()
# LAN-only gate: comma-separated CIDRs allowed to use the app without a token.
# Anything outside them gets 403, including Tailscale/VPN and WAN clients.
ALLOW = os.environ.get("OMANET_ALLOW", "").strip()
NETS = []
for _cidr in filter(None, (x.strip() for x in ALLOW.split(","))):
    try:
        NETS.append(ipaddress.ip_network(_cidr, strict=False))
    except ValueError:
        raise SystemExit(f"OMANET_ALLOW invalido: {_cidr!r}")
IFACE = os.environ.get("IFACE", "")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "60"))
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SEED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "names.json")
DAY = 86400
BUCKET = 900  # 15 min

# Portas de servico comuns (TCP connect, sem root, so na LAN). 45 portas.
PORT_MAP = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 631: "IPP", 993: "IMAPS", 1883: "MQTT", 3000: "DEV",
    3306: "MYSQL", 3389: "RDP", 5000: "NAS", 5357: "WSD", 5900: "VNC",
    8000: "HTTP-ALT", 8008: "HTTP-ALT", 8080: "HTTP-ALT", 8081: "HTTP-ALT",
    8082: "HTTP-ALT", 8083: "HTTP-ALT", 8090: "APP", 8095: "APP",
    8096: "JELLYFIN", 8097: "APP", 8098: "APP", 8099: "APP", 8443: "HTTPS-ALT",
    8554: "RTSP-ALT", 8888: "HTTP-ALT", 9090: "APP", 9100: "PRINT", 1985: "DASH",
    20211: "OMANET", 32400: "PLEX", 50000: "APP", 5432: "PGSQL", 6379: "REDIS",
    27017: "MONGO",
}
PORTS = sorted(PORT_MAP)
PORT_TIMEOUT = float(os.environ.get("PORT_TIMEOUT", "0.35"))
PORT_THREADS = int(os.environ.get("PORT_THREADS", "40"))
PORT_INTERVAL = int(os.environ.get("PORT_INTERVAL", "900"))   # 15 min
PORT_TTL = 600                                                # cache do /api/ports
_port_cache = {}
_port_lock = threading.Lock()          # protege o cache
_ports_scan_lock = threading.Lock()    # uma varredura por vez (como o arp)
_net_cache = {"ts": 0.0, "net": None}


def lan_network():
    """A /24 configurada (OMANET_ALLOW) ou a do proprio host. Nunca varre fora dela."""
    if NETS:
        return NETS[0]
    now = time.time()
    if _net_cache["net"] and now - _net_cache["ts"] < 300:
        return _net_cache["net"]
    net = None
    try:
        iface = detect_iface()
        out = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", iface],
                             capture_output=True, text=True, timeout=3).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if m:
            net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
    except Exception:
        net = None
    _net_cache.update(ts=now, net=net)
    return net


def in_lan(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not addr.is_private or addr.is_loopback:
        return False
    net = lan_network()
    return bool(net) and addr in net and str(addr) != str(net.network_address)


def probe_ip(ip):
    """TCP connect nas 45 portas; devolve a lista ordenada das que aceitaram."""
    def one(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PORT_TIMEOUT)
        try:
            return port if s.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=min(PORT_THREADS, len(PORTS))) as ex:
        return sorted(p for p in ex.map(one, PORTS) if p)


def scan_ports(ip):
    """Probe com cache de 10 min (usado pelo /api/ports do dossie)."""
    now = time.time()
    with _port_lock:
        hit = _port_cache.get(ip)
        if hit and now - hit[0] < PORT_TTL:
            return hit[1], hit[0], True
    if not in_lan(ip):
        return [], now, False
    abertas = probe_ip(ip)
    found = [{"port": p, "name": PORT_MAP.get(p, "?")} for p in abertas]
    with _port_lock:
        _port_cache[ip] = (now, found)
    return found, now, False


def online_ips():
    """IPs que o arp-scan viu agora e que estao dentro da /24 permitida."""
    with db() as con:
        rows = con.execute(
            "select distinct last_ip ip from devices "
            "where online=1 and last_ip is not null and last_ip<>''").fetchall()
    return sorted(r["ip"] for r in rows if in_lan(r["ip"]))


def scan_ports_all():
    """Varre as portas dos IPs online, grava em `ports` e fecha o que sumiu.

    Lock nao bloqueante: se outra varredura estiver rodando, devolve False sem
    tocar em nada (mesmo padrao do arp-scan). Falha nao derruba o servidor:
    registra o erro no meta e o ultimo resultado continua valendo.
    """
    if not _ports_scan_lock.acquire(blocking=False):
        return False
    try:
        now = int(time.time())
        ips = online_ips()
        found = {ip: probe_ip(ip) for ip in ips}
        with db() as con:
            for ip, abertas in found.items():
                atual = set(abertas)
                for port in abertas:
                    row = con.execute(
                        "select first_seen from ports where ip=? and port=?", (ip, port)).fetchone()
                    if row is None:
                        con.execute(
                            "insert into ports(ip,port,first_seen,last_seen,state) "
                            "values(?,?,?,?,'open')", (ip, port, now, now))
                    else:
                        con.execute(
                            "update ports set last_seen=?, state='open' where ip=? and port=?",
                            (now, ip, port))
                for row in con.execute(
                        "select port from ports where ip=? and state='open'", (ip,)).fetchall():
                    if row["port"] not in atual:
                        con.execute("update ports set state='closed' where ip=? and port=?",
                                    (ip, row["port"]))
            set_meta(con, "ports_scanned_at", now)
            set_meta(con, "ports_scan_hosts", len(ips))
            set_meta(con, "ports_scan_open", sum(len(v) for v in found.values()))
            set_meta(con, "ports_scan_error", "")
            try:
                evaluate_threats(now, con)
            except Exception as exc:
                print("threats:", exc, flush=True)
                set_meta(con, "threats_error", f"{type(exc).__name__}: {exc}"[:200])
        return True
    except Exception as exc:                     # noqa: BLE001 - nada pode derrubar o app
        print("ports scan error:", exc, flush=True)
        try:
            with db() as con:
                set_meta(con, "ports_scan_error", f"{type(exc).__name__}: {exc}"[:300])
        except Exception:
            pass
        return False
    finally:
        _ports_scan_lock.release()


def ports_loop():
    """Primeira varredura logo apos o boot, depois a cada PORT_INTERVAL (15 min)."""
    time.sleep(8)
    while True:
        try:
            scan_ports_all()
        except Exception as exc:
            print("ports loop:", exc, flush=True)
        time.sleep(PORT_INTERVAL)


_special = {"ts": 0.0, "ips": set()}


def lan_special():
    """IPs que rodam servico mas nao aparecem no arp-scan: o proprio host e o gateway."""
    now = time.time()
    if now - _special["ts"] < 300 and _special["ips"]:
        return _special["ips"]
    ips = set()
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                             text=True, timeout=3).stdout
        ips.update(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out))
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True,
                             text=True, timeout=3).stdout
        ips.update(re.findall(r"via (\d+\.\d+\.\d+\.\d+)", out))
    except Exception:
        pass
    ips.discard("127.0.0.1")
    _special.update(ts=now, ips=ips)
    return ips


def known_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not addr.is_private or addr.is_loopback:
        return False
    if NETS and not any(addr in net for net in NETS):
        return False
    with db() as con:
        row = con.execute("select 1 from devices where last_ip=? limit 1", (ip,)).fetchone()
    if row is not None:
        return True
    return ip in lan_special()


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
            create table if not exists ports(
              ip text not null,
              port integer not null,
              first_seen integer not null,
              last_seen integer not null,
              state text not null default 'open',
              primary key(ip, port)
            );
            create index if not exists idx_ports_ip on ports(ip);
            create table if not exists findings(
              key text primary key,
              rule text not null,
              severity text not null,
              ip text,
              mac text,
              port integer,
              first_ts integer not null,
              last_ts integer not null,
              count integer not null default 1,
              state text not null default 'open',
              detail text
            );
            create index if not exists idx_findings_state on findings(state, severity);
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


# --- deteccao leve de ameaca -----------------------------------------------
# Regras sobre o que o app ja coleta (ARP + portas). Nao e IDS: nao ve pacote,
# nao ve conteudo, nao detecta exploracao. E superficie e anomalia de presenca.
RISKY_PORTS = {
    21: ("FTP", 2), 23: ("TELNET", 2), 3389: ("RDP", 2), 5900: ("VNC", 2),
    445: ("SMB", 2), 6379: ("REDIS", 2), 27017: ("MONGO", 2), 139: ("NETBIOS", 1),
    3306: ("MYSQL", 1), 5432: ("PGSQL", 1), 1883: ("MQTT", 1), 110: ("POP3", 1),
    25: ("SMTP", 1),
}
SEV_ORDER = {"critical": 0, "warn": 1, "notice": 2, "info": 3}
_gw_cache = {"ts": 0.0, "ip": ""}


def gateway_ip():
    """IP do gateway pela rota default (cache 5 min)."""
    now = time.time()
    if now - _gw_cache["ts"] < 300:
        return _gw_cache["ip"]
    ip = ""
    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True,
                             text=True, timeout=3).stdout
        m = re.search(r"\bvia (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            ip = m.group(1)
    except Exception:
        ip = ""
    _gw_cache.update(ts=now, ip=ip)
    return ip


def _sem_identidade(dev):
    vendor = (dev["vendor"] or "").lower()
    return (not dev["name"]) and (not vendor or "unknown" in vendor)


def evaluate_threats(now=None, con=None):
    """Roda as regras, grava/atualiza `findings` e fecha o que deixou de valer."""
    now = int(now or time.time())
    fechar = con is None
    if con is None:
        con = db()
    try:
        devs = con.execute(
            "select mac,name,vendor,first_seen,last_seen,last_ip,online,name_source "
            "from devices").fetchall()
        abertas = con.execute(
            "select ip, port, first_seen from ports where state='open'").fetchall()
        flap = con.execute(
            "select mac, count(*) c from sessions where start_ts>=? group by mac",
            (now - 3600,)).fetchall()
        erro = (get_meta(con, "last_scan_error", "") or "") + \
               (get_meta(con, "ports_scan_error", "") or "")
        gw = gateway_ip()
        base_gw = get_meta(con, f"gw_mac:{gw}", "") if gw else ""

        online = [d for d in devs if d["online"]]
        por_ip = {}
        for d in online:
            if d["last_ip"]:
                por_ip.setdefault(d["last_ip"], []).append(d)
        atual = {}

        def marcar(key, rule, sev, ip=None, mac=None, port=None, detail=""):
            atual[key] = (rule, sev, ip, mac, port, detail)

        # R1 gateway trocou de MAC (clássico de ARP spoofing / troca de roteador)
        if gw and gw in por_ip:
            mac_agora = por_ip[gw][0]["mac"]
            if not base_gw:
                set_meta(con, f"gw_mac:{gw}", mac_agora)
            elif base_gw != mac_agora:
                marcar(f"gw_mac:{gw}:{mac_agora}", "gateway_mac_changed", "critical", gw, mac_agora,
                       None, f"MAC do gateway era {base_gw} e agora e {mac_agora}")

        # R2 dois MACs online no mesmo IP
        for ip, ds in por_ip.items():
            if len(ds) > 1:
                marcar(f"ip_conflict:{ip}", "ip_conflict", "warn", ip, None, None,
                       f"{len(ds)} MACs online no mesmo IP: " + ", ".join(d["mac"] for d in ds[:4]))

        # R3 aparelho novo sem identificacao
        for d in online:
            if d["first_seen"] >= now - 3600 and _sem_identidade(d):
                marcar(f"new_device:{d['mac']}", "new_device", "notice", d["last_ip"], d["mac"],
                       None, "primeira vez na rede, sem nome e sem fabricante")

        # R4 MAC aleatorio (privacidade); suspeito quando o aparelho se diz servidor
        for d in online:
            if "locally administered" in (d["vendor"] or "").lower():
                marcar(f"random_mac:{d['mac']}", "random_mac", "info", d["last_ip"], d["mac"],
                       None, "MAC aleatorio (privacidade)")

        # R5 servico arriscado exposto na LAN
        dono = {d["last_ip"]: d for d in online if d["last_ip"]}
        for row in abertas:
            port = row["port"]
            if port not in RISKY_PORTS:
                continue
            nome, peso = RISKY_PORTS[port]
            d = dono.get(row["ip"])
            if not d:
                continue
            sev = "warn" if peso >= 2 else "notice"
            extra = ""
            if peso >= 2 and _sem_identidade(d):
                extra = " em aparelho sem identificacao"
            marcar(f"risky_port:{row['ip']}:{port}", "risky_service", sev, row["ip"], d["mac"],
                   port, f"{nome} ({port}) aberto{extra}")

        # R6 porta arriscada que apareceu agora
        corte = int(get_meta(con, "ports_scanned_at", 0) or 0) - 1
        for row in abertas:
            if row["port"] in RISKY_PORTS and corte > 0 and row["first_seen"] >= corte:
                d = dono.get(row["ip"])
                marcar(f"new_port:{row['ip']}:{row['port']}", "service_appeared", "notice",
                       row["ip"], d["mac"] if d else None, row["port"],
                       f"porta {row['port']} abriu agora")

        # R7 aparelho piscando na rede (privacidade de celular ou instabilidade)
        for row in flap:
            if row["c"] >= 5:
                marcar(f"flap:{row['mac']}", "flapping", "info", None, row["mac"], None,
                       f"{row['c']} entradas na ultima hora")

        # R8 sensor cego (arp ou portas falhando)
        if erro.strip():
            marcar("sensor_blind", "sensor_blind", "notice", None, None, None, erro.strip()[:140])

        for key, (rule, sev, ip, mac, port, detail) in atual.items():
            row = con.execute("select count from findings where key=?", (key,)).fetchone()
            if row is None:
                con.execute(
                    "insert into findings(key,rule,severity,ip,mac,port,first_ts,last_ts,count,state,detail) "
                    "values(?,?,?,?,?,?,?,?,1,'open',?)",
                    (key, rule, sev, ip, mac, port, now, now, detail))
            else:
                con.execute(
                    "update findings set severity=?, last_ts=?, count=count+1, state='open', detail=? "
                    "where key=?", (sev, now, detail, key))
        for row in con.execute("select key from findings where state='open'").fetchall():
            if row["key"] not in atual:
                con.execute("update findings set state='closed' where key=?", (row["key"],))
        set_meta(con, "threats_evaluated_at", now)
        set_meta(con, "threats_error", "")
        return len(atual)
    finally:
        if fechar:
            con.commit()          # conexao aberta aqui, nao num `with`
            con.close()


def threats_summary(limit=6):
    with db() as con:
        rows = con.execute(
            "select key,rule,severity,ip,mac,port,first_ts,last_ts,count,detail "
            "from findings where state='open'").fetchall()
        at = int(get_meta(con, "threats_evaluated_at", 0) or 0)
        err = get_meta(con, "threats_error", "") or ""
    itens = [{"key": r["key"], "rule": r["rule"], "severity": r["severity"], "ip": r["ip"],
              "mac": r["mac"], "port": r["port"], "first_ts": r["first_ts"],
              "last_ts": r["last_ts"], "count": r["count"], "detail": r["detail"]}
             for r in rows]
    itens.sort(key=lambda i: (SEV_ORDER.get(i["severity"], 9), -i["last_ts"]))
    contagem = {"critical": 0, "warn": 0, "notice": 0, "info": 0}
    for i in itens:
        contagem[i["severity"]] = contagem.get(i["severity"], 0) + 1
    return {"total": len(itens), "by_severity": contagem, "evaluated_at": at,
            "error": err, "items": itens, "top": itens[:limit]}


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
            try:
                evaluate_threats(now, con)
            except Exception as exc:                 # a deteccao nunca derruba o scan
                print("threats:", exc, flush=True)
                set_meta(con, "threats_error", f"{type(exc).__name__}: {exc}"[:200])
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


def ports_open_map(ips):
    """{ip: [portas abertas]} para os IPs pedidos, lido da tabela (sem sonda)."""
    ips = [ip for ip in ips if ip]
    if not ips:
        return {}
    marks = ",".join("?" * len(ips))
    with db() as con:
        rows = con.execute(
            f"select ip, port from ports where state='open' and ip in ({marks}) "
            "order by ip, port", tuple(ips)).fetchall()
    out = {ip: [] for ip in ips}
    for row in rows:
        out.setdefault(row["ip"], []).append(row["port"])
    return out


def ports_all():
    """Ultimo resultado gravado, no formato do /api/ports/all (com nome de servico)."""
    with db() as con:
        rows = con.execute(
            "select ip, port, last_seen from ports where state='open' "
            "order by ip, port").fetchall()
        scanned = int(get_meta(con, "ports_scanned_at", 0) or 0)
    out = {}
    for row in rows:
        item = out.setdefault(row["ip"], {"ports": [], "ts": row["last_seen"], "cached": True})
        item["ports"].append({"port": row["port"], "name": PORT_MAP.get(row["port"], "?")})
    return {"ips": out, "scanned_at": scanned, "probes": len(PORTS),
            "ttl": PORT_INTERVAL, "now": int(time.time())}


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
        ports_at = int(get_meta(con, "ports_scanned_at", 0) or 0)
        ports_error = get_meta(con, "ports_scan_error", "") or ""

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
    # porta e do IP e so vale para quem esta online agora (MAC antigo nao herda lua)
    online_now = [row["last_ip"] for row in devices if row["online"] and row["last_ip"]]
    return {
        "now": now, "last_scan": last_scan, "last_scan_count": last_count,
        "scan_error": scan_error, "interval": SCAN_INTERVAL,
        "ports": ports_open_map(online_now),
        "ports_scanned_at": ports_at,
        "ports_scan_error": ports_error,
        "ports_probes": len(PORTS),
        "ports_interval": PORT_INTERVAL,
        "threats": threats_summary(),
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


def events_since(since, limit=60):
    """Entradas e saidas (join/leave) a partir das sessoes, mais recentes primeiro."""
    now = int(time.time())
    with db() as con:
        rows = con.execute(
            "select mac, ip, start_ts, end_ts from sessions "
            "where start_ts>=? or (end_ts is not null and end_ts>=?) "
            "order by coalesce(end_ts, start_ts) desc limit ?",
            (since, since, limit * 2)).fetchall()
    ev = []
    for r in rows:
        if r["start_ts"] >= since:
            ev.append({"mac": r["mac"], "ip": r["ip"], "ts": r["start_ts"], "kind": "in"})
        if r["end_ts"] is not None and r["end_ts"] >= since:
            ev.append({"mac": r["mac"], "ip": r["ip"], "ts": r["end_ts"], "kind": "out"})
    ev.sort(key=lambda e: e["ts"], reverse=True)
    return {"now": now, "since": since, "events": ev[:limit]}


def presence_since(hours):
    """Sessoes exatas (nao bucketizadas) para replay quadro a quadro."""
    now = int(time.time())
    since = now - hours * 3600
    with db() as con:
        rows = con.execute(
            "select mac, ip, start_ts, end_ts from sessions "
            "where end_ts is null or end_ts>? order by start_ts", (since,)).fetchall()
    by_mac = {}
    for r in rows:
        by_mac.setdefault(r["mac"], []).append(
            [max(r["start_ts"], since), r["end_ts"] or 0, r["ip"] or ""])
    return {"now": now, "since": since, "hours": hours, "devices": by_mac}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC, **kwargs)

    def log_message(self, fmt, *args):
        pass

    def client_allowed(self):
        if not NETS:
            return True
        try:
            addr = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        if addr.is_loopback:
            return True
        return any(addr in net for net in NETS)

    def deny_offlan(self):
        body = b"fora da LAN\n"
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

    def serve_index(self):
        """Serve a raiz injetando o painel SENTINELA (o index.html e do Viselino).

        A injecao fica aqui, nao no arquivo: qualquer troca do index.html continua
        ganhando o painel, e se ele ja trouxer o <script> nao duplica.
        """
        try:
            with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as fh:
                html = fh.read()
        except OSError:
            self.send_error(404)
            return
        # se a propria pagina ja mostra ameacas, nao injeta (nada de painel duplicado)
        ja_tem = "sentinel.js" in html or "api/threats" in html
        if not ja_tem:
            tag = '<script src="/sentinel.js" defer></script>\n'
            html = html.replace("</body>", tag + "</body>", 1) if "</body>" in html else html + tag
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.client_allowed():
            self.deny_offlan()
            return
        if not self.require_auth():
            return
        path = urlparse(self.path).path
        if path == "/ameacas.html":
            # a deteccao vive na raiz; a pagina antiga so redireciona
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/api/state":
            self.json(state())
            return
        if path == "/api/ports":
            ip = (parse_qs(urlparse(self.path).query).get("ip") or [""])[0]
            if not known_ip(ip):
                self.json({"error": "ip desconhecido"}, 404)
                return
            ports, ts, cached = scan_ports(ip)
            self.json({"ip": ip, "ports": ports, "ts": ts, "cached": cached,
                       "probed": len(PORTS)})
            return
        if path == "/api/ports/all":
            self.json(ports_all())
            return
        if path == "/api/threats":
            qs = parse_qs(urlparse(self.path).query)
            sev = (qs.get("severity") or [""])[0]
            dados = threats_summary(limit=200)
            if sev:
                dados["items"] = [i for i in dados["items"] if i["severity"] == sev]
                dados["total"] = len(dados["items"])
            self.json(dados)
            return
        if path == "/api/events":
            qs = parse_qs(urlparse(self.path).query)
            try:
                since = int(qs.get("since", ["0"])[0] or 0)
                limit = int(qs.get("limit", ["60"])[0] or 60)
            except ValueError:
                self.json({"error": "since/limit invalidos"}, 400)
                return
            if since <= 0:
                since = int(time.time()) - DAY
            self.json(events_since(since, max(1, min(200, limit))))
            return
        if path == "/api/presence":
            qs = parse_qs(urlparse(self.path).query)
            try:
                hours = int(qs.get("hours", ["24"])[0] or 24)
            except ValueError:
                self.json({"error": "hours invalido"}, 400)
                return
            self.json(presence_since(max(1, min(168, hours))))
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
        if path in ("/", "/index.html"):
            self.serve_index()
            return
        return super().do_GET()

    def do_POST(self):
        if not self.client_allowed():
            self.deny_offlan()
            return
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
        if path == "/api/threats/scan":
            try:
                n = evaluate_threats()
                self.json({"ok": True, "findings": n})
            except Exception as exc:
                self.json({"ok": False, "error": str(exc)[:200]}, 500)
            return
        if path in ("/api/ports/scan", "/api/portscan"):
            if _ports_scan_lock.locked():
                self.json({"ok": False, "error": "varredura de portas ja em andamento"}, 409)
                return
            threading.Thread(target=scan_ports_all, daemon=True).start()
            self.json({"ok": True, "probes": len(PORTS), "interval": PORT_INTERVAL})
            return
        self.json({"error": "not found"}, 404)


def main():
    loopback = BIND in ("127.0.0.1", "::1", "localhost")
    if not TOKEN and not loopback and not NETS:
        raise SystemExit(
            f"recusando escutar em {BIND}:{PORT} sem OMANET_TOKEN e sem OMANET_ALLOW; "
            "defina BIND=127.0.0.1, um OMANET_ALLOW com a sub-rede da LAN, ou um token")
    init_db()
    threading.Thread(target=scan_loop, daemon=True).start()
    threading.Thread(target=ports_loop, daemon=True).start()
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    auth = "on" if TOKEN else "off"
    gate = f"LAN only {ALLOW}" if NETS else "sem gate de rede"
    print(f"omanet on {BIND}:{PORT}, db {DB_PATH}, auth {auth}, {gate}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

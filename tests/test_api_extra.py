"""Endpoints novos: portas em lote, eventos e presenca (sem rede, banco temporario).

Run: python3 -m unittest discover -s tests -v
"""
import importlib
import os
import sys
import tempfile
import time
import unittest

os.environ.setdefault("DB_PATH", "/tmp/omanet-test-extra.db")
os.environ["OMANET_ALLOW"] = "192.168.5.0/24"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
app = importlib.import_module("app")


class ApiExtra(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.DB_PATH = tempfile.mktemp(suffix="-omanet.db")
        app.init_db()

    def setUp(self):
        with app.db() as con:
            con.execute("delete from sessions")
            con.execute("delete from devices")
        app._port_cache.clear()
        app._special.update(ts=0.0, ips=set())

    # --- eventos ---------------------------------------------------------
    def test_eventos_entrada_e_saida_em_ordem(self):
        now = int(time.time())
        with app.db() as con:
            con.execute("insert into sessions(mac,ip,start_ts,end_ts) values(?,?,?,?)",
                        ("aa:aa:aa:aa:aa:aa", "192.168.5.50", now - 100, now - 50))
            con.execute("insert into sessions(mac,ip,start_ts,end_ts) values(?,?,?,?)",
                        ("bb:bb:bb:bb:bb:bb", "192.168.5.51", now - 40, None))
        out = app.events_since(now - 200)
        ev = out["events"]
        self.assertEqual(ev[0]["kind"], "in")           # mais recente primeiro
        self.assertEqual(ev[0]["mac"], "bb:bb:bb:bb:bb:bb")
        self.assertEqual([e["kind"] for e in ev[1:3]], ["out", "in"])
        self.assertTrue(all(e["ts"] >= now - 200 for e in ev))

    def test_eventos_ignoram_sessao_antiga(self):
        now = int(time.time())
        with app.db() as con:
            con.execute("insert into sessions(mac,ip,start_ts,end_ts) values(?,?,?,?)",
                        ("cc:cc:cc:cc:cc:cc", "192.168.5.52", now - 9000, now - 8000))
        self.assertEqual(app.events_since(now - 600)["events"], [])

    # --- presenca --------------------------------------------------------
    def test_presenca_traz_sessao_aberta_e_fecha_janela(self):
        now = int(time.time())
        with app.db() as con:
            con.execute("insert into sessions(mac,ip,start_ts,end_ts) values(?,?,?,?)",
                        ("dd:dd:dd:dd:dd:dd", "192.168.5.53", now - 300, now - 120))
            con.execute("insert into sessions(mac,ip,start_ts,end_ts) values(?,?,?,?)",
                        ("ee:ee:ee:ee:ee:ee", "192.168.5.54", now - 60, None))
        out = app.presence_since(24)
        self.assertEqual(out["hours"], 24)
        self.assertEqual(len(out["devices"]["dd:dd:dd:dd:dd:dd"]), 1)
        start, end, ip = out["devices"]["ee:ee:ee:ee:ee:ee"][0]
        self.assertEqual((end, ip), (0, "192.168.5.54"))   # 0 = aberta agora
        self.assertGreaterEqual(start, out["since"])

    # --- portas ----------------------------------------------------------
    def test_init_db_cria_tabela_ports_idempotente(self):
        app.init_db()
        app.init_db()                     # migracao roda duas vezes sem erro
        with app.db() as con:
            cols = [r["name"] for r in con.execute("pragma table_info(ports)")]
        self.assertEqual(cols, ["ip", "port", "first_seen", "last_seen", "state"])

    def test_varredura_grava_abertas_e_fecha_que_sumiu(self):
        now = int(time.time())
        with app.db() as con:
            for ip in ("192.168.5.10", "192.168.5.11"):
                con.execute(
                    "insert into devices(mac,name,vendor,first_seen,last_seen,last_ip,online,miss) "
                    "values(?,?,?,?,?,?,1,0)", ("m" + ip[-2:], None, "v", now, now, ip))
            # porta aberta numa rodada anterior que nao responde mais
            con.execute("insert into ports(ip,port,first_seen,last_seen,state) "
                        "values('192.168.5.10',9999,1,1,'open')")
        chamadas = []
        self._probe = app.probe_ip
        app.probe_ip = lambda ip: (chamadas.append(ip) or
                                   ([22, 80] if ip.endswith(".10") else [443]))
        self.assertTrue(app.scan_ports_all())
        app.probe_ip = self._probe
        with app.db() as con:
            linhas = {r["port"]: r["state"] for r in con.execute(
                "select port,state from ports where ip='192.168.5.10'")}
            at = int(con.execute(
                "select value from meta where key='ports_scanned_at'").fetchone()["value"])
        self.assertEqual(linhas, {22: "open", 80: "open", 9999: "closed"})
        self.assertGreaterEqual(at, now - 1)
        self.assertEqual(sorted(chamadas), ["192.168.5.10", "192.168.5.11"])

    def test_varredura_nao_roda_em_paralelo(self):
        import threading
        now = int(time.time())
        with app.db() as con:
            con.execute(
                "insert into devices(mac,name,vendor,first_seen,last_seen,last_ip,online,miss) "
                "values('mm',?,'v',?,?,'192.168.5.20',1,0)", (None, now, now))
        entrou, solta = threading.Event(), threading.Event()

        def lento(ip):
            entrou.set()
            solta.wait(3)
            return []

        self._probe = app.probe_ip
        app.probe_ip = lento
        t = threading.Thread(target=app.scan_ports_all)
        t.start()
        try:
            self.assertTrue(entrou.wait(2))
            self.assertFalse(app.scan_ports_all())     # segunda e recusada pelo lock
        finally:
            solta.set()
            t.join(4)
            app.probe_ip = self._probe

    def test_state_traz_portas_so_dos_online(self):
        now = int(time.time())
        with app.db() as con:
            con.execute(
                "insert into devices(mac,name,vendor,first_seen,last_seen,last_ip,online,miss) "
                "values('on',?,'v',?,?,'192.168.5.30',1,0)", (None, now, now))
            con.execute(
                "insert into devices(mac,name,vendor,first_seen,last_seen,last_ip,online,miss) "
                "values('off',?,'v',?,?,'192.168.5.31',0,3)", (None, now, now))
            for ip, port in (("192.168.5.30", 22), ("192.168.5.30", 80), ("192.168.5.31", 22)):
                con.execute("insert into ports(ip,port,first_seen,last_seen,state) "
                            "values(?,?,?,?,'open')", (ip, port, now, now))
            con.execute("insert into meta(key,value) values('ports_scanned_at',?) "
                        "on conflict(key) do update set value=excluded.value", (str(now),))
        st = app.state()
        self.assertEqual(st["ports"], {"192.168.5.30": [22, 80]})   # .31 offline nao herda
        self.assertEqual(st["ports_scanned_at"], now)
        self.assertEqual(st["ports_probes"], 45)
        self.assertEqual(st["ports_interval"], 900)

    def test_varredura_so_na_lan(self):
        app._net_cache.update(ts=0.0, net=None)
        self.assertTrue(app.in_lan("192.168.5.10"))
        self.assertEqual(set(app.PORTS), set(app.PORT_MAP))
        self.assertEqual(len(app.PORTS), 45)
        for fora in ("8.8.8.8", "10.9.9.9", "127.0.0.1", "192.168.5.0", "nada"):
            self.assertFalse(app.in_lan(fora), fora)

    def test_porta_de_ip_desconhecido_nao_passam(self):
        self.assertFalse(app.known_ip("192.168.5.99"))              # fora do arp-scan
        self.assertFalse(app.known_ip("8.8.8.8"))                   # internet
        self.assertFalse(app.known_ip("10.9.9.9"))                  # privado, fora da ALLOW
        self.assertFalse(app.known_ip("127.0.0.1"))

    def test_gateway_e_proprio_host_entram(self):
        app._special.update(ts=time.time(), ips={"192.168.5.1", "192.168.5.245"})
        self.assertTrue(app.known_ip("192.168.5.1"))
        self.assertTrue(app.known_ip("192.168.5.245"))


if __name__ == "__main__":
    unittest.main()

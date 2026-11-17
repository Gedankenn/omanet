"""Deteccao leve de ameaca: regras sobre ARP + portas (banco temporario, sem rede).

Run: python3 -m unittest discover -s tests -v
"""
import importlib
import os
import sys
import tempfile
import time
import unittest

os.environ.setdefault("DB_PATH", "/tmp/omanet-test-threats.db")
os.environ["OMANET_ALLOW"] = "192.168.5.0/24"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
app = importlib.import_module("app")


class Threats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.DB_PATH = tempfile.mktemp(suffix="-omanet-threats.db")
        app.init_db()

    def setUp(self):
        self._gw = app.gateway_ip
        app.gateway_ip = lambda: "192.168.5.1"
        with app.db() as con:
            for t in ("devices", "sessions", "ports", "findings", "meta"):
                con.execute(f"delete from {t}")

    def tearDown(self):
        app.gateway_ip = self._gw

    # --- helpers ---------------------------------------------------------
    def dev(self, mac, ip, name=None, vendor="Acme", online=1, first_seen=None):
        now = int(time.time())
        with app.db() as con:
            con.execute(
                "insert into devices(mac,name,vendor,first_seen,last_seen,last_ip,online,miss) "
                "values(?,?,?,?,?,?,?,0)",
                (mac, name, vendor, first_seen or now - 86400, now, ip, online))

    def porta(self, ip, port, first_seen=None):
        now = int(time.time())
        with app.db() as con:
            con.execute("insert into ports(ip,port,first_seen,last_seen,state) values(?,?,?,?,'open')",
                        (ip, port, first_seen or now - 60, now))

    def achados(self, rule=None):
        with app.db() as con:
            rows = con.execute("select * from findings where state='open'").fetchall()
        return [r for r in rows if rule is None or r["rule"] == rule]

    # --- regras ----------------------------------------------------------
    def test_primeira_leitura_aprende_o_mac_do_gateway(self):
        self.dev("aa:aa:aa:aa:aa:01", "192.168.5.1", name="Roteador")
        self.assertEqual(app.evaluate_threats(), 0)
        with app.db() as con:
            base = con.execute("select value from meta where key='gw_mac:192.168.5.1'").fetchone()
        self.assertEqual(base["value"], "aa:aa:aa:aa:aa:01")

    def test_gateway_trocou_de_mac_e_critico(self):
        self.dev("aa:aa:aa:aa:aa:01", "192.168.5.1", name="Roteador")
        app.evaluate_threats()                                  # aprende a base
        with app.db() as con:
            con.execute("update devices set online=0 where mac='aa:aa:aa:aa:aa:01'")
        self.dev("bb:bb:bb:bb:bb:02", "192.168.5.1", name="Roteador")
        app.evaluate_threats()
        f = self.achados("gateway_mac_changed")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "critical")
        self.assertIn("bb:bb:bb:bb:bb:02", f[0]["detail"])

    def test_dois_macs_no_mesmo_ip(self):
        self.dev("aa:aa:aa:aa:aa:03", "192.168.5.50")
        self.dev("bb:bb:bb:bb:bb:04", "192.168.5.50")
        app.evaluate_threats()
        f = self.achados("ip_conflict")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "warn")

    def test_servico_arriscado_exposto(self):
        self.dev("aa:aa:aa:aa:aa:05", "192.168.5.60", name="Servidor", vendor="Dell")
        self.porta("192.168.5.60", 23)          # telnet
        self.porta("192.168.5.60", 1883)        # mqtt
        self.porta("192.168.5.60", 80)          # http comum: nao entra
        app.evaluate_threats()
        f = {r["port"]: r for r in self.achados("risky_service")}
        self.assertEqual(set(f), {23, 1883})
        self.assertEqual(f[23]["severity"], "warn")
        self.assertEqual(f[1883]["severity"], "notice")
        self.assertIn("TELNET", f[23]["detail"])

    def test_servico_em_aparelho_sem_identidade_ganha_peso(self):
        self.dev("cc:cc:cc:cc:cc:06", "192.168.5.61", vendor="(Unknown: locally administered)")
        self.porta("192.168.5.61", 6379)        # redis
        app.evaluate_threats()
        f = self.achados("risky_service")
        self.assertEqual(f[0]["severity"], "warn")
        self.assertIn("sem identificacao", f[0]["detail"])

    def test_mac_aleatorio_e_info(self):
        self.dev("de:ad:be:ef:00:07", "192.168.5.62", vendor="(Unknown: locally administered)")
        app.evaluate_threats()
        f = self.achados("random_mac")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "info")

    def test_aparelho_novo_sem_identidade(self):
        agora = int(time.time())
        self.dev("ee:ee:ee:ee:ee:08", "192.168.5.63", vendor="(Unknown)", first_seen=agora - 60)
        app.evaluate_threats()
        self.assertEqual(len(self.achados("new_device")), 1)

    def test_sensor_cego_quando_o_scan_falha(self):
        with app.db() as con:
            con.execute("insert into meta(key,value) values('last_scan_error','arp-scan failed') "
                        "on conflict(key) do update set value=excluded.value")
        app.evaluate_threats()
        self.assertEqual(len(self.achados("sensor_blind")), 1)

    def test_deduplica_e_fecha(self):
        self.dev("aa:aa:aa:aa:aa:09", "192.168.5.64")
        self.porta("192.168.5.64", 445)
        app.evaluate_threats()
        app.evaluate_threats()
        with app.db() as con:
            rows = con.execute("select count(*) c, max(count) n from findings").fetchone()
        self.assertEqual(rows["c"], 1)                     # uma linha, nao duas
        self.assertEqual(rows["n"], 2)                     # com contador
        with app.db() as con:
            con.execute("update ports set state='closed'")
        app.evaluate_threats()
        self.assertEqual(self.achados(), [])               # fechou ao sumir a condicao
        with app.db() as con:
            st = con.execute("select state from findings").fetchone()["state"]
        self.assertEqual(st, "closed")

    def test_resumo_ordena_por_severidade(self):
        self.dev("aa:aa:aa:aa:aa:10", "192.168.5.65")
        self.dev("bb:bb:bb:bb:bb:11", "192.168.5.65")       # conflito (warn)
        self.porta("192.168.5.65", 23)                      # telnet (warn)
        app.evaluate_threats()
        s = app.threats_summary()
        self.assertGreaterEqual(s["total"], 2)
        self.assertEqual(s["by_severity"]["warn"], 2)
        self.assertEqual(s["items"][0]["severity"], "warn")
        self.assertEqual(len(s["top"]), 2)
        self.assertGreater(s["evaluated_at"], 0)


if __name__ == "__main__":
    unittest.main()

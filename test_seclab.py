#!/usr/bin/env python3
"""Testes do seclab.py (biblioteca padrao). Rode antes da apresentacao:
    python3 -m unittest -v
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest

import seclab as sl

HERE = os.path.dirname(os.path.abspath(__file__))


def run_all(app, funcs=None):
    for fn in funcs or sl.ALL_FUNCS:
        for ev in fn(app):
            app.emit(ev)
    return "\n".join(t for _, _, t in app.log)


class Regras(unittest.TestCase):
    def setUp(self):
        self.n = sl.Net()

    def test_visitante_espelha_o_pfsense_real(self):
        # slide 7: ICMP do visitante para .10.5, .10.20 e .50.1 bloqueado por "Bloqueia rede interna"
        for dst in ("proxmox", "ad-dc", "pfsense-vis"):
            ok, rule = self.n.check("visitante", dst, 0)
            self.assertFalse(ok, dst)
            self.assertEqual(rule, "Bloqueia rede interna")
        self.assertTrue(self.n.check("visitante", "internet", 443)[0])
        self.assertFalse(self.n.check("visitante", "internet", 22)[0])
        self.assertFalse(self.n.check("visitante", "site", 443)[0])   # DMZ tambem e rede interna

    def test_projeto_iot_e_tablet(self):
        self.assertTrue(self.n.check("tablet-01", "autoatendimento", 443)[0])
        self.assertFalse(self.n.check("tablet-01", "proxmox", 8006)[0])
        self.assertFalse(self.n.check("camera-01", "internet", 443)[0])
        self.assertTrue(self.n.check("camera-01", "monitor", 10051)[0])

    def test_kerberos_e_porta_88(self):
        self.assertIn(88, sl.HOSTS["ad-dc"][2])
        self.assertTrue(self.n.check("ws-01", "ad-dc", 88)[0])
        self.assertFalse(self.n.check("ws-01", "ad-dc", 89)[0])

    def test_quarentena(self):
        self.n.quar.add("autoatendimento")
        self.assertFalse(self.n.check("tablet-01", "autoatendimento", 443)[0])


class Honestidade(unittest.TestCase):
    """O simulador nao pode afirmar o que o projeto nao executou."""

    def setUp(self):
        self.app = sl.App(tempfile.gettempdir())
        self.txt = run_all(self.app)

    def test_todos_os_fluxos_simulados_passam(self):
        self.assertTrue(all(self.app.checks.values()), self.app.checks)

    def test_rto_rpo_nao_sao_apresentados_como_medidos(self):
        self.assertNotRegex(self.txt, r"(?i)(RTO|RPO) medido")
        self.assertNotRegex(self.txt, r"(?i)\d+h\d+")           # nenhum tempo inventado
        self.assertIn("NÃO MEDIDO", self.txt)
        self.assertNotIn("op_rto", self.app.checks)

    def test_nao_ha_claim_de_restauracao_real_nem_zabbix_rodando(self):
        self.assertNotRegex(self.txt, r"(?i)restaurado com sucesso")
        self.assertNotRegex(self.txt, r"(?i)Zabbix\s*(->|:)\s*(alerta|respons)")
        self.assertIn("proposta", self.txt.lower())

    def test_todo_cenario_simulado_se_declara(self):
        for fn in sl.ALL_FUNCS[1:-1]:                    # 2..7
            first = next(fn(sl.App(tempfile.gettempdir())))
            self.assertEqual(first.lvl, "step")
            self.assertIn("SIMULADO", first.txt, fn.__name__)

    def test_resumo_separa_lab_de_simulacao(self):
        self.assertIn("NO LABORATÓRIO (real, slide 7)", self.txt)
        self.assertIn("SIMULADO (proposta)", self.txt)

    def test_relatorio(self):
        with tempfile.TemporaryDirectory() as d:
            self.app.outdir = d
            path = self.app.export()
            with open(path, encoding="utf-8") as f:
                body = f.read()
        self.assertIn("Não é evidência do laboratório", body)
        self.assertIn("[-] " + sl.RTO_LINE, body)


class Tela(unittest.TestCase):
    SIZES = [(30, 110), (24, 80), (20, 70), (45, 160), (28, 104), (19, 69), (10, 30), (3, 5)]

    def setUp(self):
        self.app = sl.App(tempfile.gettempdir())
        run_all(self.app, [sl.sc5])

    def test_renderiza_em_qualquer_tamanho(self):
        for h, w in self.SIZES:
            for asc in (False, True):
                cv = sl.render(self.app, h, w, asc)
                self.assertEqual(len(cv.cells), h)
                self.assertTrue(all(len(r) == w for r in cv.cells), (h, w))
                if asc:
                    self.assertTrue(all(ord(c) < 128 for r in cv.cells for c, _ in r), (h, w))

    def test_modos(self):
        self.assertEqual(sl.mode_for(30, 110), "full")
        self.assertEqual(sl.mode_for(24, 80), "compact")
        self.assertEqual(sl.mode_for(20, 70), "compact")
        self.assertEqual(sl.mode_for(19, 70), "tiny")

    def test_aviso_zabbix_visivel_nos_tamanhos_de_projetor(self):
        for h, w in [(30, 110), (24, 80), (45, 160)]:
            top = sl.render(self.app, h, w).lines()[0]
            self.assertIn("Zabbix planejado, não implantado", top, (h, w))

    def test_menor_tamanho_mostra_aviso_em_vez_de_quebrar(self):
        self.assertIn("Terminal pequeno", "\n".join(sl.render(self.app, 10, 40).lines()))


class Cli(unittest.TestCase):
    def sh(self, *args, env=None):
        e = dict(os.environ, **(env or {}))
        return subprocess.run([sys.executable, os.path.join(HERE, "seclab.py"), *args],
                              capture_output=True, text=True, timeout=60, env=e)

    def test_plain_sem_tty(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.sh("--plain", "--out", d)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("NÃO MEDIDO", r.stdout)
            self.assertTrue(any(f.startswith("relatorio_simulacao_") for f in os.listdir(d)))

    def test_sem_tty_cai_em_modo_texto(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.sh("--out", d)               # stdout/stdin nao sao terminal
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("usando modo texto", r.stderr)

    def test_locale_c_nao_quebra(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.sh("--plain", "--ascii", "--out", d, env={"LC_ALL": "C", "LANG": "C"})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(all(ord(c) < 128 for c in r.stdout))

    def test_snapshot_e_cenario_invalido(self):
        r = self.sh("--snapshot", "80x24", "--scenario", "5")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(r.stdout.rstrip("\n").split("\n")), 24)
        self.assertNotEqual(self.sh("--scenario", "9").returncode, 0)

    def test_duracao_do_autopilot(self):
        self.assertLess(sl.duration(sl.ALL_FUNCS), 100)


if __name__ == "__main__":
    unittest.main(verbosity=2)

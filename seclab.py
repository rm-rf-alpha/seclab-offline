#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SECLAB COWORKING - demo ao vivo de seguranca de rede (TUI 100% offline)

* So usa a biblioteca padrao do Python 3 (curses). Nada para instalar.
* Os ataques/defesas sao SIMULADOS em memoria (nao tocam em nenhuma rede).
* O cenario 8 usa trafego REAL apenas na interface loopback (127.0.0.1).

Uso:   python3 seclab.py            (interface TUI)
       python3 seclab.py --plain    (sem TUI: imprime tudo e gera o relatorio)
"""
import argparse
import curses
import datetime
import hashlib
import locale
import shutil
import socket
import subprocess
import textwrap
import threading
import time
from collections import namedtuple

# --------------------------------------------------------------------------
# Modelo da rede do coworking (mesmo plano de enderecamento dos slides)
# --------------------------------------------------------------------------
VLANS = {10: "TI/Gerência", 20: "Workspace", 30: "Privativa",
         40: "IoT", 50: "Visitantes", 60: "DMZ"}

# nome: (vlan, ip, portas realmente abertas no servico)
HOSTS = {
    "admin-pc":        (10, "192.168.10.10", [22]),
    "proxmox":         (10, "192.168.10.5", [22, 8006]),
    "ad-dc":           (10, "192.168.10.20", [88, 389, 445]),
    "zabbix":          (10, "192.168.10.30", [80, 10051]),
    "grafana":         (10, "192.168.10.31", [3000]),
    "ws-01":           (20, "192.168.20.15", []),
    "sala-03":         (30, "192.168.30.12", []),
    "camera-01":       (40, "192.168.40.21", [554]),
    "biometria-01":    (40, "192.168.40.22", []),
    "tablet-01":       (40, "192.168.40.31", []),
    "visitante":       (50, "192.168.50.77", []),
    "site":            (60, "192.168.60.10", [80, 443]),
    "autoatendimento": (60, "192.168.60.20", [443]),
    "internet":        (0, "203.0.113.10", [80, 443]),
}

# Regras do pfSense, avaliadas em ordem. Padrao final: NEGAR.
RULES = [
    ("vlan:10", "any", None, "allow", "TI administra a infraestrutura"),
    ("vlan:60", "vlan:10", None, "deny", "DMZ nunca acessa a rede interna"),
    ("tablet-01", "autoatendimento", {443}, "allow", "tablet só no autoatendimento:443"),
    ("vlan:40", "zabbix", {10051}, "allow", "IoT só fala com o monitoramento"),
    ("vlan:20", "ad-dc", {53, 88, 389, 445}, "allow", "estações -> Active Directory"),
    ("vlan:20", "vlan:60", {80, 443}, "allow", "workspace -> site/autoatendimento"),
    ("vlan:30", "vlan:60", {80, 443}, "allow", "privativa -> site/autoatendimento"),
    ("vlan:20", "internet", {53, 80, 443}, "allow", "workspace -> Internet"),
    ("vlan:30", "internet", {53, 80, 443}, "allow", "privativa -> Internet"),
    ("vlan:50", "internet", {53, 80, 443}, "allow", "visitantes -> somente Internet"),
    ("internet", "site", {80, 443}, "allow", "site publicado na DMZ"),
]

CHECKS = [  # (id, texto da evidencia)  - espelham o slide "Testes de validacao"
    ("seg_visit", "Visitante isolado das redes internas"),
    ("seg_iot", "IoT só fala com destinos autorizados"),
    ("seg_tablet", "Tablets sem acesso administrativo"),
    ("seg_scan", "Port scan bloqueado e alertado"),
    ("svc_dhcp", "DHCP correto; DHCP falso barrado"),
    ("svc_site", "Site só nas portas permitidas"),
    ("svc_mfa", "Força bruta barrada; MFA exigido"),
    ("op_alert", "Alertas chegam aos responsáveis"),
    ("op_backup", "Backup restaurado com sucesso"),
    ("op_rto", "RTO/RPO dentro das metas"),
    ("op_logs", "Logs e plano de incidente ok"),
]

Ev = namedtuple("Ev", "lvl txt delay prog", defaults=(0.5, False))


class Net:
    def __init__(self):
        self.quar = set()
        self.stat = {v: [0, 0] for v in VLANS}  # [permitidos, bloqueados]

    @staticmethod
    def match(pat, host):
        if pat == "any":
            return True
        if pat.startswith("vlan:"):
            return HOSTS[host][0] == int(pat[5:])
        return pat == host

    def check(self, src, dst, port):
        if src in self.quar or dst in self.quar:
            res = (False, "host em quarentena")
        else:
            res = (False, "negar por padrão")
            for rs, rd, rp, act, lab in RULES:
                if (self.match(rs, src) and self.match(rd, dst)
                        and (rp is None or port in rp)):
                    res = (act == "allow", lab)
                    break
        vlan = HOSTS[src][0] or HOSTS[dst][0]
        if vlan in self.stat:
            self.stat[vlan][0 if res[0] else 1] += 1
        return res

    def scan(self, src, dst, ports):
        out = {}
        for p in ports:
            ok, _ = self.check(src, dst, p)
            if not ok:
                out[p] = "filtrada"
            else:
                out[p] = "aberta" if p in HOSTS[dst][2] else "fechada"
        return out


# --------------------------------------------------------------------------
# Cenarios (geradores: cada yield e um passo da apresentacao)
# --------------------------------------------------------------------------
def ip(h):
    return HOSTS[h][1]


def sc1(a):
    yield Ev("step", "TESTE 1 · SEGMENTAÇÃO — pfSense com \"negar por padrão\"", 0.9)
    groups = [
        ("seg_visit", "Visitantes (VLAN 50)", [
            ("visitante", "internet", 443, True),
            ("visitante", "ad-dc", 445, False),
            ("visitante", "proxmox", 8006, False)]),
        ("seg_iot", "IoT (VLAN 40)", [
            ("camera-01", "zabbix", 10051, True),
            ("camera-01", "ad-dc", 445, False),
            ("camera-01", "internet", 443, False),
            ("biometria-01", "proxmox", 22, False)]),
        ("seg_tablet", "Tablets (VLAN 40)", [
            ("tablet-01", "autoatendimento", 443, True),
            ("tablet-01", "proxmox", 8006, False),
            ("tablet-01", "admin-pc", 22, False)]),
    ]
    for key, name, tests in groups:
        yield Ev("info", "-- " + name, 0.5)
        allok = True
        for src, dst, port, expect in tests:
            ok, rule = a.net.check(src, dst, port)
            good = (ok == expect)
            allok &= good
            tag = "PERMITIDO" if ok else "BLOQUEADO"
            lvl = ("ok" if ok else "block") if good else "warn"
            extra = "" if good else "  <-- INESPERADO"
            yield Ev(lvl, f"[{tag}] {src} -> {dst}:{port}  ({rule}){extra}", 0.55)
        a.mark(key, allok)
        yield Ev("ok" if allok else "warn",
                 f"   Resultado: {name} " + ("conforme a política" if allok else "FORA da política"), 0.6)
    yield Ev("info", "Todos os bloqueios ficam no log do pfSense para revisão periódica.", 0.5)


def sc2(a):
    yield Ev("step", "TESTE 2 · VARREDURA DE PORTAS — atacante na VLAN de visitantes", 0.9)
    ports = [22, 80, 443, 445, 3389, 8006]
    yield Ev("cmd", f"$ nmap -sS -p {','.join(map(str, ports))} 192.168.10.0/24   (origem {ip('visitante')})", 0.8)
    for h in ("proxmox", "ad-dc", "zabbix"):
        res = a.net.scan("visitante", h, ports)
        filt = sum(1 for v in res.values() if v == "filtrada")
        yield Ev("block", f"   {ip(h):<14} ({h}): {filt}/{len(ports)} portas FILTRADAS — sem resposta", 0.6)
    yield Ev("info", "Nenhum serviço interno ficou visível para o visitante.", 0.5)
    yield Ev("alert", "IDS (Suricata): \"SCAN nmap SYN\" detectado vindo de " + ip("visitante"), 0.7)
    a.alert("ALTA", f"Varredura de portas vinda da VLAN 50 ({ip('visitante')})")
    yield Ev("ok", "pfSense: origem bloqueada por 1 h e evento enviado ao Zabbix.", 0.7)
    a.mark("seg_scan", True)
    yield Ev("info", "-- Agora um usuário legítimo confere o site na DMZ", 0.6)
    ports2 = [22, 80, 443, 3306, 8080]
    yield Ev("cmd", f"$ nmap -p {','.join(map(str, ports2))} {ip('site')}   (origem ws-01)", 0.7)
    res = a.net.scan("ws-01", "site", ports2)
    for p, st in res.items():
        yield Ev("ok" if st == "aberta" else "block", f"   {p}/tcp  {st}", 0.35)
    abertas = {p for p, s in res.items() if s == "aberta"}
    good = abertas == {80, 443}
    a.mark("svc_site", good)
    yield Ev("ok" if good else "warn", "Site responde apenas nas portas permitidas (80 e 443).", 0.6)


def sc3(a):
    yield Ev("step", "TESTE 3 · FORÇA BRUTA CONTRA O ACTIVE DIRECTORY + MFA", 0.9)
    ok, rule = a.net.check("ws-01", "ad-dc", 389)
    yield Ev("info", f"Origem: ws-01 (estação comprometida) -> AD:389  [{'permitido' if ok else 'bloqueado'}: {rule}]", 0.7)
    yield Ev("cmd", f"$ hydra -l admin.ti -P senhas.txt ldap://{ip('ad-dc')}", 0.8)
    for i, pw in enumerate(["123456", "admin", "coworking", "Senha@123", "Welcome1"], 1):
        yield Ev("block", f"   tentativa {i}/5  senha \"{pw}\"  -> FALHOU", 0.45)
    yield Ev("warn", "AD: política de bloqueio atingida (5 tentativas) -> conta admin.ti BLOQUEADA 15 min", 0.8)
    a.alert("ALTA", "Força bruta contra admin.ti vindo de ws-01 (conta bloqueada)")
    yield Ev("alert", "Zabbix + syslog: múltiplas falhas de login -> responsável notificado", 0.7)
    yield Ev("info", "-- Cenário pior: a senha vazou e o atacante acertou", 0.7)
    yield Ev("warn", "   login admin.ti / senha correta  -> senha OK, mas...", 0.7)
    yield Ev("info", "   MFA: desafio enviado ao celular do administrador", 0.7)
    for i in range(1, 4):
        yield Ev("block", f"   código MFA informado pelo atacante ({i}/3)  -> INVÁLIDO", 0.5)
    yield Ev("ok", "Acesso NEGADO: senha roubada sozinha não basta (MFA + privilégio mínimo).", 0.7)
    a.mark("svc_mfa", True)


def sc4(a):
    yield Ev("step", "TESTE 4 · DHCP/DNS CORRETOS E DHCP FALSO (ROGUE)", 0.9)
    yield Ev("info", "Novo notebook entra na VLAN 20 (Workspace) e pede endereço:", 0.6)
    yield Ev("cmd", "DHCPDISCOVER (broadcast) ...", 0.5)
    yield Ev("ok", "DHCPOFFER de 192.168.20.1 (pfSense): IP 192.168.20.101/24  gw 192.168.20.1  dns 192.168.20.1", 0.8)
    yield Ev("ok", "Cliente configurado: escopo da VLAN 20, gateway e DNS corretos.", 0.6)
    yield Ev("ok", "nslookup site.coworking.local -> 192.168.60.10 (DNS interno respondeu)", 0.6)
    yield Ev("info", "-- Alguém liga um roteador doméstico na tomada da sala:", 0.7)
    yield Ev("warn", "   DHCPOFFER de 192.168.20.99 (roteador falso): gw 192.168.20.99  dns 8.8.8.8", 0.8)
    yield Ev("block", "[DESCARTADO] Switch: DHCP snooping — porta Gi0/7 não é confiável para ofertas DHCP", 0.8)
    a.alert("MÉDIA", "DHCP falso detectado e descartado na porta Gi0/7 (VLAN 20)")
    yield Ev("alert", "Alerta registrado: possível dispositivo não autorizado na VLAN 20", 0.6)
    a.mark("svc_dhcp", True)
    yield Ev("ok", "Clientes continuam recebendo configuração apenas do pfSense.", 0.5)


def sc5(a):
    yield Ev("step", "TESTE 5 · INCIDENTE — CÂMERA IoT COMPROMETIDA (plano de resposta)", 0.9)
    yield Ev("info", "1) DETECTAR E REGISTRAR", 0.5)
    yield Ev("warn", "   camera-01 enviando 4 GB/h para 198.51.100.23 (padrão anormal)", 0.8)
    a.alert("ALTA", "camera-01 com tráfego anômalo para IP externo")
    ok, rule = a.net.check("camera-01", "internet", 443)
    yield Ev("block", f"   a política já barra IoT -> Internet ({rule}); o tráfego foi só tentativa", 0.8)
    yield Ev("info", "2) CONTER", 0.5)
    a.net.quar.add("camera-01")
    yield Ev("ok", "   camera-01 isolada em quarentena (porta desativada no switch).", 0.7)
    ok1, _ = a.net.check("camera-01", "zabbix", 10051)
    ok2, _ = a.net.check("biometria-01", "zabbix", 10051)
    yield Ev("block" if not ok1 else "warn", f"   camera-01 -> zabbix: {'PERMITIDO' if ok1 else 'BLOQUEADO'}", 0.5)
    yield Ev("ok" if ok2 else "warn", f"   biometria-01 -> zabbix: {'PERMITIDO' if ok2 else 'BLOQUEADO'} (sem dano colateral)", 0.6)
    yield Ev("info", "3) INVESTIGAR", 0.5)
    h = hashlib.sha256("\n".join(t for _, _, t in a.log).encode()).hexdigest()[:16]
    yield Ev("ok", f"   logs preservados (sha256 {h}...) e origem identificada: senha padrão", 0.8)
    yield Ev("info", "4) ERRADICAR E RECUPERAR", 0.5)
    yield Ev("ok", "   firmware regravado, senha padrão trocada, acesso remoto do fabricante desativado", 0.8)
    a.net.quar.discard("camera-01")
    ok3, _ = a.net.check("camera-01", "zabbix", 10051)
    yield Ev("ok" if ok3 else "warn", "   validação: camera-01 volta a falar só com o monitoramento", 0.6)
    yield Ev("info", "5) DOCUMENTAR", 0.5)
    yield Ev("ok", "   INC-0001 registrado: linha do tempo, causa, ação e lição aprendida", 0.6)
    yield Ev("info", "   Lição: trocar senhas padrão antes de ligar o dispositivo.", 0.5)
    a.mark("op_logs", True)


def _bar(pct):
    n = pct // 5
    return "[" + "#" * n + "." * (20 - n) + f"] {pct:3d}%"


def sc6(a):
    yield Ev("step", "TESTE 6 · RANSOMWARE + RESTAURAÇÃO DE BACKUP (RTO/RPO)", 0.9)
    yield Ev("info", "Política: backup a cada 4 h no Proxmox Backup Server (cópia imutável).", 0.7)
    yield Ev("info", "Último backup válido: 08:00     Agora (tempo simulado): 09:47", 0.7)
    yield Ev("warn", "autoatendimento: arquivos sendo renomeados em massa (.locked)", 0.9)
    a.alert("ALTA", "Possível ransomware na VM autoatendimento")
    yield Ev("alert", "Zabbix: escrita em disco anormal -> responsável notificado", 0.7)
    a.net.quar.add("autoatendimento")
    yield Ev("ok", "CONTER: VM isolada no pfSense; demais serviços continuam normais.", 0.8)
    ok, _ = a.net.check("tablet-01", "autoatendimento", 443)
    yield Ev("block", "   tablet-01 -> autoatendimento: BLOQUEADO (VM em quarentena)", 0.6)
    yield Ev("info", "O malware tenta apagar os backups a partir da VM infectada...", 0.8)
    yield Ev("block", "[NEGADO] PBS: a conta da VM não tem permissão de exclusão (backup imutável)", 0.9)
    yield Ev("cmd", "$ restaurar VM autoatendimento a partir do backup das 08:00", 0.7)
    for pct in range(0, 101, 10):
        yield Ev("info", "   restaurando " + _bar(pct), 0.3, True)
    a.net.quar.discard("autoatendimento")
    ok, _ = a.net.check("tablet-01", "autoatendimento", 443)
    yield Ev("ok" if ok else "warn", "   validação: tablet-01 -> autoatendimento:443 voltou a funcionar", 0.7)
    yield Ev("ok", "Backup restaurado em ambiente isolado e serviço validado.", 0.6)
    a.mark("op_backup", True)
    rpo, rto = 107, 41  # minutos (simulados): 09:47-08:00 e 09:47 -> 10:28
    r1 = rpo <= 240
    r2 = rto <= 240
    yield Ev("ok" if r1 else "warn", f"RPO medido: 1h47 (meta 4h)  -> {'OK' if r1 else 'FORA DA META'}", 0.7)
    yield Ev("ok" if r2 else "warn", f"RTO medido: 0h41 (meta 4h)  -> {'OK' if r2 else 'FORA DA META'}", 0.7)
    a.mark("op_rto", r1 and r2)
    yield Ev("dim", "(tempos simulados para a demonstração; metas do slide de backups)", 0.4)


def sc7(a):
    yield Ev("step", "TESTE 7 · MONITORAMENTO — QUEM AVISA QUANDO O PRÓPRIO HOST CAI?", 0.9)
    yield Ev("warn", "proxmox: CPU em 93% há 5 min", 0.7)
    a.alert("MÉDIA", "proxmox com CPU em 93% há 5 minutos")
    yield Ev("alert", "Zabbix -> alerta enviado ao responsável de plantão (canal definido)", 0.8)
    yield Ev("info", "-- Pior caso: queda de energia no servidor único", 0.8)
    yield Ev("block", "ping proxmox ... sem resposta (1/3)", 0.4)
    yield Ev("block", "ping proxmox ... sem resposta (2/3)", 0.4)
    yield Ev("warn", "pfSense, AD, Zabbix, Grafana e Site ficaram offline juntos.", 0.8)
    yield Ev("warn", "O Zabbix (VM) caiu junto: nenhum alerta interno será enviado!", 0.9)
    yield Ev("info", "Mitigação proposta: monitor externo (mini-PC) fora do host.", 0.7)
    yield Ev("block", "monitor externo: ping proxmox ... sem resposta (3/3)", 0.5)
    a.alert("ALTA", "Host Proxmox INDISPONÍVEL (detectado pelo monitor externo)")
    yield Ev("alert", "Monitor externo -> e-mail/mensagem ao TI de plantão (simulado)", 0.8)
    yield Ev("ok", "Alerta chegou ao responsável mesmo com o Zabbix fora do ar.", 0.7)
    yield Ev("info", "-- Energia volta: VMs sobem em ordem de dependência", 0.7)
    for vm in ("pfSense", "AD", "Zabbix", "Grafana", "Site"):
        yield Ev("ok", f"   {vm} iniciado", 0.5)
    yield Ev("ok", "Serviços normalizados; incidente registrado.", 0.6)
    yield Ev("info", "Lição: segundo nó (HA) e monitoramento externo reduzem o risco.", 0.6)
    a.mark("op_alert", True)


def sc8(a):
    yield Ev("step", "BÔNUS · SCAN REAL na interface loopback (127.0.0.1), sem rede externa", 0.9)
    stop = threading.Event()
    servers, threads = [], []

    def serve(s):
        try:
            s.settimeout(0.2)
        except OSError:
            return
        while not stop.is_set():
            try:
                c, _ = s.accept()
                c.close()
            except socket.timeout:
                continue
            except OSError:
                break

    try:
        for p in (18080, 18443):
            try:
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", p))
                s.listen(5)
                t = threading.Thread(target=serve, args=(s,), daemon=True)
                t.start()
                servers.append(s)
                threads.append(t)
            except OSError as e:
                yield Ev("warn", f"   não foi possível abrir {p}: {e}", 0.4)
        yield Ev("ok", "Serviços de teste ligados: 18080 (site) e 18443 (autoatendimento)", 0.7)
        portas = list(range(18070, 18101)) + list(range(18430, 18451))
        yield Ev("cmd", "$ scan TCP 127.0.0.1  portas 18070-18100 e 18430-18450", 0.7)
        t0 = time.time()
        abertas = []
        for p in portas:
            c = socket.socket()
            c.settimeout(0.15)
            if c.connect_ex(("127.0.0.1", p)) == 0:
                abertas.append(p)
            c.close()
        dt = time.time() - t0
        yield Ev("ok", f"   {len(portas)} portas testadas em {dt:.2f}s  ->  abertas: {abertas or 'nenhuma'}", 0.8)
        if shutil.which("nmap"):
            yield Ev("cmd", "$ nmap -Pn -sT -p 22,80,443,8006,18080,18443 127.0.0.1", 0.6)
            try:
                r = subprocess.run(["nmap", "-Pn", "-sT", "-p", "22,80,443,8006,18080,18443", "127.0.0.1"],
                                   capture_output=True, text=True, timeout=20)
                for line in r.stdout.splitlines():
                    if line.strip() and not line.startswith(("Starting", "Nmap done")):
                        yield Ev("info", "   " + line, 0.2)
            except Exception as e:  # noqa
                yield Ev("warn", f"   nmap falhou: {e}", 0.4)
        else:
            yield Ev("dim", "   (nmap não encontrado: usado o scanner embutido)", 0.4)
        yield Ev("ok", "Tráfego real, 100% local: só as portas com serviço respondem.", 0.6)
    finally:
        stop.set()
        for s in servers:
            try:
                s.close()
            except OSError:
                pass


def sc_resumo(a):
    ok = sum(1 for v in a.checks.values() if v)
    yield Ev("step", f"RESUMO · {ok}/{len(CHECKS)} evidências validadas", 0.8)
    for key, txt in CHECKS:
        v = a.checks[key]
        yield Ev("ok" if v else "warn", f"   [{'x' if v else ' '}] {txt}", 0.2)
    path = a.export()
    yield Ev("ok", f"Relatório de evidências salvo em: {path}", 0.5)


SCENARIOS = [
    ("1", "Segmentação (VLANs/ACLs)", sc1),
    ("2", "Varredura de portas", sc2),
    ("3", "Força bruta + MFA", sc3),
    ("4", "DHCP falso (rogue)", sc4),
    ("5", "Incidente IoT (resposta)", sc5),
    ("6", "Ransomware + backup", sc6),
    ("7", "Queda do host + alertas", sc7),
    ("8", "Bônus: scan real (loopback)", sc8),
]


# --------------------------------------------------------------------------
# Estado da aplicacao
# --------------------------------------------------------------------------
class App:
    def __init__(self):
        self.net = Net()
        self.log = []      # (ts, lvl, txt)
        self.prog = False  # ultima linha e barra de progresso?
        self.alerts = []   # (ts, sev, txt)
        self.checks = {k: None for k, _ in CHECKS}
        self.gen = None
        self.queue = []
        self.speed = 1.0
        self.paused = False
        self.next_at = 0.0
        self.sel = 0
        self.running = ""

    @staticmethod
    def ts():
        return datetime.datetime.now().strftime("%H:%M:%S")

    def emit(self, ev):
        entry = (self.ts(), ev.lvl, ev.txt)
        if ev.prog and self.prog and self.log:
            self.log[-1] = entry
        else:
            self.log.append(entry)
        self.prog = ev.prog

    def alert(self, sev, txt):
        self.alerts.append((self.ts(), sev, txt))

    def mark(self, key, ok):
        self.checks[key] = bool(ok)

    def start(self, funcs, label=""):
        if self.gen is not None:
            return
        self.queue = list(funcs)
        self.running = label
        self.gen = None
        self._advance()

    def _advance(self):
        if self.queue:
            fn = self.queue.pop(0)
            self.gen = fn(self)
            self.next_at = 0.0
        else:
            self.gen = None
            self.running = ""

    def tick(self, now):
        if self.gen is None or self.paused or now < self.next_at:
            return
        try:
            ev = next(self.gen)
            self.emit(ev)
            self.next_at = now + ev.delay / self.speed
        except StopIteration:
            self._advance()
            self.next_at = time.time() + 0.8 / self.speed

    def reset(self):
        if self.gen is not None:
            self.gen.close()
        self.__init__()

    def export(self):
        name = datetime.datetime.now().strftime("evidencias_coworking_%Y%m%d_%H%M%S.txt")
        ok = sum(1 for v in self.checks.values() if v)
        lines = ["RELATÓRIO DE EVIDÊNCIAS - SEGURANÇA DA REDE DE UM COWORKING",
                 "Gerado em " + datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                 "Ambiente: simulação offline (cenário 8 usa loopback real)", "",
                 f"EVIDÊNCIAS: {ok}/{len(CHECKS)} validadas"]
        for key, txt in CHECKS:
            v = self.checks[key]
            lines.append(f"  [{'x' if v else ' '}] {txt}" + ("" if v is not None else "  (não executado)"))
        lines += ["", "ALERTAS GERADOS"]
        lines += [f"  {t} [{s}] {x}" for t, s, x in self.alerts] or ["  (nenhum)"]
        lines += ["", "LOG COMPLETO"]
        lines += [f"  {t} {x}" for t, _, x in self.log]
        try:
            with open(name, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            return "(não foi possível gravar)"
        return name


# --------------------------------------------------------------------------
# Interface curses
# --------------------------------------------------------------------------
LVL_COLOR = {"step": (4, True), "cmd": (7, True), "ok": (1, False), "block": (2, True),
             "warn": (3, True), "alert": (5, True), "info": (0, False), "dim": (0, False)}
SEV_COLOR = {"ALTA": (2, True), "MÉDIA": (3, True), "INFO": (4, False)}
MIN_H, MIN_W = 30, 110


def attr_for(color, bold):
    a = curses.color_pair(color) if color else curses.A_NORMAL
    return a | (curses.A_BOLD if bold else 0)


def put(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w - 1:
        return
    try:
        win.addnstr(y, x, text, max(0, w - x - 1), attr)
    except curses.error:
        pass


def panel(win, title, color=6):
    win.erase()
    win.attrset(curses.color_pair(color))
    win.box()
    win.attrset(curses.A_NORMAL)
    put(win, 0, 2, f" {title} ", curses.color_pair(color) | curses.A_BOLD)


def draw(scr, app):
    scr.erase()
    H, W = scr.getmaxyx()
    if H < MIN_H or W < MIN_W:
        put(scr, 1, 2, f"Terminal pequeno ({W}x{H}). Aumente para pelo menos {MIN_W}x{MIN_H}", curses.A_BOLD)
        put(scr, 3, 2, "(ou rode com --plain)   Q = sair")
        scr.refresh()
        return
    # cabecalho
    head = " SEGURANÇA DA REDE DE UM COWORKING · demo ao vivo "
    tag = " SIMULAÇÃO OFFLINE "
    put(scr, 0, 0, head.ljust(W), curses.color_pair(8) | curses.A_BOLD)
    put(scr, 0, W - len(tag) - 2, tag, curses.color_pair(8) | curses.A_BOLD)
    vel = f" vel {app.speed:.1f}x "
    put(scr, 0, W - len(tag) - len(vel) - 3, vel, curses.color_pair(8))
    keys = " 1-8 cenário · A autopilot · ESPAÇO acelera · P pausa · +/- vel · E relatório · R zerar · Q sair "
    put(scr, H - 1, 0, keys.ljust(W), curses.color_pair(8))
    scr.noutrefresh()
    body = H - 2
    LW = 46
    RW = W - LW
    # --- menu
    menu_h = len(SCENARIOS) + 4
    m = curses.newwin(menu_h, LW, 1, 0)
    panel(m, "CENÁRIOS")
    for i, (k, title, _) in enumerate(SCENARIOS):
        sel = (i == app.sel)
        line = f" {k}  {title}"
        put(m, 1 + i, 1, line.ljust(LW - 3), curses.A_REVERSE if sel else curses.A_NORMAL)
    put(m, 1 + len(SCENARIOS), 1, " A  AUTOPILOT (todos + relatório)", curses.color_pair(4) | curses.A_BOLD)
    m.noutrefresh()
    # --- evidencias
    ev_h = body - menu_h
    e = curses.newwin(ev_h, LW, 1 + menu_h, 0)
    done = sum(1 for v in app.checks.values() if v)
    panel(e, f"EVIDÊNCIAS {done}/{len(CHECKS)}")
    for i, (key, txt) in enumerate(CHECKS):
        v = app.checks[key]
        mark, col = ("[x]", (1, True)) if v else (("[!]", (3, True)) if v is False else ("[ ]", (0, False)))
        put(e, 1 + i, 2, f"{mark} {txt}", attr_for(*col))
    e.noutrefresh()
    # --- log
    bottom_h = 10
    log_h = body - bottom_h
    lg = curses.newwin(log_h, RW, 1, LW)
    status = f"LOG DE EVENTOS · {app.running}" if app.running else "LOG DE EVENTOS"
    if app.paused:
        status += "  [PAUSADO]"
    panel(lg, status)
    inner = RW - 4
    lines = []
    for ts, lvl, txt in app.log:
        wrapped = textwrap.wrap(txt, inner - 9, subsequent_indent="    ") or [""]
        for j, w in enumerate(wrapped):
            lines.append((ts if j == 0 else "        ", lvl, w))
    for row, (ts, lvl, txt) in enumerate(lines[-(log_h - 2):]):
        put(lg, 1 + row, 2, ts, curses.A_DIM)
        put(lg, 1 + row, 11, txt, attr_for(*LVL_COLOR.get(lvl, (0, False))))
    lg.noutrefresh()
    # --- alertas (largura variavel) e trafego (33 colunas fixas)
    TW = 33
    AW = RW - TW
    al = curses.newwin(bottom_h, AW, 1 + log_h, LW)
    panel(al, f"ZABBIX · ALERTAS ({len(app.alerts)})", 5)
    rows = []
    for ts, sev, txt in app.alerts:
        wrapped = textwrap.wrap(txt, AW - 4 - 6, subsequent_indent="") or [""]
        for j, w in enumerate(wrapped):
            rows.append((sev if j == 0 else "", w))
    for row, (sev, txt) in enumerate(rows[-(bottom_h - 2):]):
        if sev:
            put(al, 1 + row, 2, f"{sev:<5}", attr_for(*SEV_COLOR.get(sev, (0, False))))
        put(al, 1 + row, 8, txt)
    if not rows:
        put(al, 1, 2, "sem alertas", curses.A_DIM)
    al.noutrefresh()
    tr = curses.newwin(bottom_h, TW, 1 + log_h, LW + AW)
    panel(tr, "PFSENSE · TRÁFEGO/VLAN")
    put(tr, 1, 2, "VLAN             perm. bloq.", curses.A_BOLD)
    for i, v in enumerate(VLANS):
        okc, blk = app.net.stat[v]
        quar = [h for h in app.net.quar if HOSTS[h][0] == v]
        put(tr, 2 + i, 2, f"{v} {VLANS[v]:<12}", curses.A_NORMAL)
        put(tr, 2 + i, 17, f"{okc:>4}", attr_for(1, False))
        put(tr, 2 + i, 22, f"{blk:>4}", attr_for(2, blk > 0))
        if quar:
            put(tr, 2 + i, 27, "ISOL", attr_for(3, True))
    tr.noutrefresh()
    curses.doupdate()


def tui(scr, app, autostart=False):
    curses.curs_set(0)
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    curses.init_pair(1, curses.COLOR_GREEN, bg)
    curses.init_pair(2, curses.COLOR_RED, bg)
    curses.init_pair(3, curses.COLOR_YELLOW, bg)
    curses.init_pair(4, curses.COLOR_CYAN, bg)
    curses.init_pair(5, curses.COLOR_MAGENTA, bg)
    curses.init_pair(6, curses.COLOR_BLUE, bg)
    curses.init_pair(7, curses.COLOR_WHITE, bg)
    curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_BLUE)
    scr.timeout(80)
    scr.keypad(True)
    if autostart:
        app.start([f for _, _, f in SCENARIOS] + [sc_resumo], "AUTOPILOT")
    while True:
        app.tick(time.time())
        draw(scr, app)
        k = scr.getch()
        if k in (ord("q"), ord("Q")):
            break
        if k == curses.KEY_RESIZE:
            scr.clear()
        elif ord("1") <= k <= ord("8") and app.gen is None:
            i = k - ord("1")
            app.sel = i
            app.start([SCENARIOS[i][2]], SCENARIOS[i][1])
        elif k in (curses.KEY_UP, ord("k")):
            app.sel = (app.sel - 1) % len(SCENARIOS)
        elif k in (curses.KEY_DOWN, ord("j")):
            app.sel = (app.sel + 1) % len(SCENARIOS)
        elif k in (10, 13, curses.KEY_ENTER) and app.gen is None:
            app.start([SCENARIOS[app.sel][2]], SCENARIOS[app.sel][1])
        elif k in (ord("a"), ord("A")) and app.gen is None:
            app.start([f for _, _, f in SCENARIOS] + [sc_resumo], "AUTOPILOT")
        elif k == ord(" "):
            app.next_at = 0
        elif k in (ord("p"), ord("P")):
            app.paused = not app.paused
        elif k in (ord("+"), ord("=")):
            app.speed = min(5.0, app.speed + 0.5)
        elif k in (ord("-"), ord("_")):
            app.speed = max(0.5, app.speed - 0.5)
        elif k in (ord("e"), ord("E")):
            p = app.export()
            app.emit(Ev("ok", f"Relatório salvo em: {p}"))
        elif k in (ord("r"), ord("R")):
            app.reset()


def plain(app):
    funcs = [f for _, _, f in SCENARIOS] + [sc_resumo]
    for fn in funcs:
        for ev in fn(app):
            app.emit(ev)
            ts, lvl, txt = app.log[-1]
            print(f"{ts} [{lvl:<5}] {txt}")
    print()
    print("Alertas gerados:", len(app.alerts))


def main():
    ap = argparse.ArgumentParser(description="Demo de segurança de rede do coworking (offline)")
    ap.add_argument("--plain", action="store_true", help="sem TUI: imprime tudo e gera o relatório")
    ap.add_argument("--auto", action="store_true", help="inicia o autopilot ao abrir")
    args = ap.parse_args()
    locale.setlocale(locale.LC_ALL, "")
    app = App()
    if args.plain:
        plain(app)
        return
    curses.wrapper(tui, app, args.auto)


if __name__ == "__main__":
    main()

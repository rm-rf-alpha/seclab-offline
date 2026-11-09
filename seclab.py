#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SECLAB COWORKING - simulador do fluxo de seguranca e alertas (seclab.py)

* So biblioteca padrao do Python 3.8+. Nada para instalar; nenhuma chamada de rede.
  Funciona igual com ou sem Internet, em Linux real ou virtualizado.
* TUDO aqui e SIMULADO em memoria. Nao e o ambiente real nem evidencia do laboratorio.
* Unico teste executado no laboratorio real: isolamento da VLAN de visitantes
  (slide 7). O cenario 1 REPRODUZ esse teste; o resto e proposta/planejamento.
* Zabbix e Grafana sao PROPOSTA (nao implantados). RTO/RPO sao METAS (nao medidos).

Uso:
  python3 seclab.py                  TUI (adapta-se ao tamanho; minimo 70x20)
  python3 seclab.py --auto           TUI ja com o autopilot
  python3 seclab.py --plain          texto puro, roda tudo e gera o relatorio
  python3 seclab.py --plain --live   texto puro com ritmo (bom para gravar video)
  python3 seclab.py --snapshot 110x30 --scenario 5   imprime a tela como texto
"""
import argparse
import datetime
import hashlib
import locale
import os
import sys
import tempfile
import textwrap
import time
import unicodedata
from collections import namedtuple

try:
    import curses
except ImportError:  # ex.: Python sem curses -> cai no modo texto
    curses = None

# --------------------------------------------------------------------------
# Modelo da rede (mesmo enderecamento dos slides). Hosts: vlan, ip, portas abertas
# --------------------------------------------------------------------------
VLANS = {10: "TI/Gerência", 20: "Workspace", 30: "Privativa",
         40: "IoT", 50: "Visitantes", 60: "DMZ"}

HOSTS = {
    "admin-pc":        (10, "192.168.10.10", [22]),
    "proxmox":         (10, "192.168.10.5", [22, 8006]),
    "ad-dc":           (10, "192.168.10.20", [88, 389, 445]),
    "monitor":         (10, "192.168.10.30", [10051]),   # monitoramento (Zabbix: proposta)
    "ws-01":           (20, "192.168.20.15", []),
    "camera-01":       (40, "192.168.40.21", [554]),
    "biometria-01":    (40, "192.168.40.22", []),
    "tablet-01":       (40, "192.168.40.31", []),
    "pfsense-vis":     (50, "192.168.50.1", [53]),        # interface do firewall na VLAN 50
    "visitante":       (50, "192.168.50.77", []),
    "site":            (60, "192.168.60.10", [80, 443]),
    "autoatendimento": (60, "192.168.60.20", [443]),
    "internet":        (0, "203.0.113.10", [80, 443]),
}

# Regras em ordem; padrao final = NEGAR. Porta 0 = ICMP.
# As 3 regras da VLAN 50 espelham as do pfSense real (slide 7); o resto e projeto.
RULES = [
    ("vlan:10", "any", None, "allow", "TI administra a infraestrutura"),
    ("vlan:60", "vlan:10", None, "deny", "DMZ nunca acessa a rede interna"),
    ("tablet-01", "autoatendimento", {443}, "allow", "tablet só no autoatendimento:443"),
    ("vlan:40", "monitor", {10051}, "allow", "IoT só fala com o monitoramento"),
    ("vlan:20", "ad-dc", {53, 88, 389, 445}, "allow", "estações -> Active Directory"),
    ("vlan:20", "vlan:60", {80, 443}, "allow", "workspace -> site/autoatendimento"),
    ("vlan:30", "vlan:60", {80, 443}, "allow", "privativa -> site/autoatendimento"),
    ("vlan:20", "internet", {53, 80, 443}, "allow", "workspace -> Internet"),
    ("vlan:30", "internet", {53, 80, 443}, "allow", "privativa -> Internet"),
    ("vlan:50", "pfsense-vis", {53}, "allow", "DNS do firewall"),
    ("vlan:50", "interno", None, "deny", "Bloqueia rede interna"),
    ("vlan:50", "internet", {80, 443}, "allow", "Saída somente web"),
    ("internet", "site", {80, 443}, "allow", "site publicado na DMZ"),
]

# Itens do slide "Testes de validacao" que so existem como simulacao/proposta
SIM_CHECKS = [
    ("seg_iot", "IoT e tablets restritos"),
    ("seg_scan", "nmap entre VLANs filtrado"),
    ("svc_site", "Site só nas portas 80/443"),
    ("svc_mfa", "Força bruta barrada; MFA"),
    ("svc_dhcp", "DHCP falso barrado (snooping)"),
    ("op_alert", "Fluxo de alertas ao responsável"),
    ("op_backup", "Restauração de backup (fluxo)"),
]
LAB_LINE = "Visitante sem acesso à VLAN de TI"
RTO_LINE = "RTO/RPO: só metas, não medido"
ALERT_DEST = {"ALTA": "TI mensagem", "MÉDIA": "TI e-mail", "INFO": "painel"}

Ev = namedtuple("Ev", "lvl txt delay prog", defaults=(0.5, False))


class Net:
    """Firewall simulado: avalia as regras em ordem."""

    def __init__(self):
        self.quar = set()

    @staticmethod
    def match(pat, host):
        if pat == "any":
            return True
        if pat == "interno":  # enderecos privados (RFC1918), como o alias do pfSense
            a = HOSTS[host][1].split(".")
            return a[0] == "10" or (a[0] == "192" and a[1] == "168") or \
                (a[0] == "172" and 16 <= int(a[1]) <= 31)
        if pat.startswith("vlan:"):
            return HOSTS[host][0] == int(pat[5:])
        return pat == host

    def check(self, src, dst, port):
        if src in self.quar or dst in self.quar:
            return False, "host em quarentena"
        for rs, rd, rp, act, lab in RULES:
            if (self.match(rs, src) and self.match(rd, dst)
                    and (rp is None or port in rp)):
                return act == "allow", lab
        return False, "negar por padrão"

    def scan(self, src, dst, ports):
        out = {}
        for p in ports:
            ok, _ = self.check(src, dst, p)
            out[p] = "filtrada" if not ok else ("aberta" if p in HOSTS[dst][2] else "fechada")
        return out


def ip(h):
    return HOSTS[h][1]


def flow(src, dst, port):
    return f"{src} -> {dst}" + (f":{port}" if port else " (ICMP)")


# --------------------------------------------------------------------------
# Cenarios: cada yield e um passo da demonstracao
# --------------------------------------------------------------------------
def sc1(a):
    yield Ev("step", "TESTE 1 | SEGMENTAÇÃO - pfSense com \"negar por padrão\"", 0.9)
    yield Ev("info", "-- Parte A: reproduz o teste REAL do slide 7 (VLAN de visitantes)", 0.7)
    yield Ev("cmd", f"$ ping -c 3 (de {ip('visitante')}) para cada destino", 0.6)
    for dst in ("proxmox", "ad-dc", "pfsense-vis"):
        ok, rule = a.net.check("visitante", dst, 0)
        yield Ev("warn" if ok else "block",
                 f"[{'PERMITIDO' if ok else 'BLOQUEADO'}] {ip('visitante')} -> {ip(dst)} ICMP ({rule})"
                 + ("  <-- INESPERADO" if ok else ""), 0.5)
    ok, rule = a.net.check("visitante", "internet", 443)
    yield Ev("ok" if ok else "warn", f"[PERMITIDO] visitante -> internet:443 ({rule})", 0.5)
    yield Ev("dim", "No pfSense real: Status > System Logs > Firewall registra os bloqueios.", 0.5)
    yield Ev("info", "-- Parte B: SIMULADO (IoT e tablets ainda não foram testados no lab)", 0.7)
    tests = [("camera-01", "monitor", 10051, True), ("camera-01", "ad-dc", 445, False),
             ("camera-01", "internet", 443, False), ("biometria-01", "proxmox", 22, False),
             ("tablet-01", "autoatendimento", 443, True), ("tablet-01", "proxmox", 8006, False),
             ("tablet-01", "admin-pc", 22, False)]
    allok = True
    for src, dst, port, expect in tests:
        ok, rule = a.net.check(src, dst, port)
        good = ok == expect
        allok &= good
        lvl = ("ok" if ok else "block") if good else "warn"
        yield Ev(lvl, f"[{'PERMITIDO' if ok else 'BLOQUEADO'}] {flow(src, dst, port)} ({rule})"
                 + ("" if good else "  <-- INESPERADO"), 0.45)
    a.mark("seg_iot", allok)
    yield Ev("ok" if allok else "warn", "IoT e tablets: " + ("conforme a política (simulado)." if allok else "FORA da política."), 0.6)


def sc2(a):
    yield Ev("step", "TESTE 2 | VARREDURA DE PORTAS (nmap) - SIMULADO", 0.9)
    yield Ev("dim", "No lab só o ping do visitante foi executado (slide 7); o nmap é planejado.", 0.6)
    ports = [22, 80, 443, 445, 3389, 8006]
    yield Ev("cmd", f"$ nmap -sS -p {','.join(map(str, ports))} 192.168.10.0/24   (origem {ip('visitante')})", 0.8)
    hidden = True
    for h in ("proxmox", "ad-dc", "monitor"):
        res = a.net.scan("visitante", h, ports)
        filt = sum(v == "filtrada" for v in res.values())
        hidden &= filt == len(ports)
        yield Ev("block", f"   {ip(h):<14} ({h}): {filt}/{len(ports)} portas FILTRADAS", 0.5)
    yield Ev("info", "Nenhum serviço interno ficou visível para o visitante.", 0.5)
    a.alert("ALTA", "Varredura de portas da VLAN 50")
    yield Ev("alert", f"IDS/IPS (proposta): \"SCAN nmap SYN\" vindo de {ip('visitante')}", 0.7)
    yield Ev("ok", "pfSense: origem bloqueada por 1 h; evento enviado ao monitoramento.", 0.6)
    a.mark("seg_scan", hidden)
    yield Ev("info", "-- Usuário legítimo confere o site na DMZ", 0.5)
    ports2 = [22, 80, 443, 3306, 8080]
    yield Ev("cmd", f"$ nmap -p {','.join(map(str, ports2))} {ip('site')}   (origem ws-01)", 0.6)
    res = a.net.scan("ws-01", "site", ports2)
    for p, st in res.items():
        yield Ev("ok" if st == "aberta" else "block", f"   {p}/tcp  {st}", 0.3)
    good = {p for p, s in res.items() if s == "aberta"} == {80, 443}
    a.mark("svc_site", good)
    yield Ev("ok" if good else "warn", "Site responde apenas nas portas permitidas (80 e 443).", 0.6)


def sc3(a):
    yield Ev("step", "TESTE 3 | FORÇA BRUTA CONTRA O ACTIVE DIRECTORY + MFA - SIMULADO", 0.9)
    ok, rule = a.net.check("ws-01", "ad-dc", 389)
    yield Ev("info", f"Origem: ws-01 (estação comprometida) -> AD:389 [{'permitido' if ok else 'bloqueado'}: {rule}]", 0.6)
    yield Ev("cmd", f"$ hydra -l admin.ti -P senhas.txt ldap://{ip('ad-dc')}", 0.7)
    for i, pw in enumerate(["123456", "admin", "coworking", "Senha@123", "Welcome1"], 1):
        yield Ev("block", f"   tentativa {i}/5  \"{pw}\" -> FALHOU", 0.3)
    yield Ev("warn", "AD: limite de 5 tentativas -> conta admin.ti BLOQUEADA por 15 min", 0.7)
    a.alert("ALTA", "Força bruta: admin.ti bloqueada")
    yield Ev("alert", "Alerta ALTA enviado ao TI de plantão (mensagem)", 0.6)
    yield Ev("info", "-- Pior caso: a senha vazou e o atacante acertou", 0.6)
    yield Ev("warn", "   login admin.ti com a senha correta -> senha OK, mas...", 0.6)
    yield Ev("info", "   MFA: desafio enviado ao celular do administrador", 0.6)
    for i in range(1, 4):
        yield Ev("block", f"   código MFA do atacante ({i}/3) -> INVÁLIDO", 0.35)
    yield Ev("ok", "Acesso NEGADO: senha roubada sozinha não basta (MFA + privilégio mínimo).", 0.7)
    a.mark("svc_mfa", True)


def sc4(a):
    yield Ev("step", "TESTE 4 | DHCP FALSO + DHCP SNOOPING (exige switch gerenciável) - SIMULADO", 0.9)
    yield Ev("info", "Novo notebook entra na VLAN 20 (Workspace) e pede endereço:", 0.5)
    yield Ev("cmd", "DHCPDISCOVER (broadcast) ...", 0.5)
    yield Ev("ok", "DHCPOFFER de 192.168.20.1 (pfSense): IP 192.168.20.101/24  gw e dns 192.168.20.1", 0.7)
    yield Ev("info", "-- Alguém liga um roteador doméstico na tomada da sala:", 0.6)
    yield Ev("warn", "   DHCPOFFER de 192.168.20.99 (roteador falso): gw 192.168.20.99  dns 8.8.8.8", 0.7)
    yield Ev("block", "[DESCARTADO] Switch gerenciável: porta Gi0/7 não é confiável para ofertas DHCP", 0.8)
    a.alert("MÉDIA", "DHCP falso na porta Gi0/7 (VLAN 20)")
    yield Ev("alert", "Alerta MÉDIA enviado ao TI de plantão (e-mail)", 0.6)
    yield Ev("ok", "Clientes continuam recebendo configuração apenas do pfSense.", 0.5)
    a.mark("svc_dhcp", True)
    yield Ev("dim", "Sem switch gerenciável (como no lab virtual) o snooping não é possível.", 0.4)


def sc5(a):
    yield Ev("step", "TESTE 5 | MONITORAMENTO E ALERTAS - SIMULADO (Zabbix é proposta)", 0.9)
    yield Ev("info", "Fluxo: severidade -> destinatário -> canal -> escalonamento", 0.7)
    yield Ev("warn", "proxmox: CPU em 93% há 5 min", 0.7)
    a.alert("MÉDIA", "proxmox: CPU em 93% há 5 min")
    yield Ev("alert", "Alerta MÉDIA enviado ao TI de plantão (e-mail)", 0.7)
    yield Ev("warn", "Sem confirmação em 15 min -> escalonado para a gestão", 0.7)
    a.alert("MÉDIA", "Sem confirmação em 15 min", "gestão")
    yield Ev("info", "-- Pior caso: queda de energia no servidor único (Proxmox)", 0.7)
    yield Ev("block", "ping proxmox ... sem resposta (1/3)", 0.4)
    yield Ev("block", "ping proxmox ... sem resposta (2/3)", 0.4)
    yield Ev("warn", "VMs previstas (pfSense, AD, Zabbix, Grafana, site) caem juntas.", 0.8)
    yield Ev("warn", "O monitoramento interno caiu junto: nenhum alerta interno sai!", 0.8)
    yield Ev("info", "Proposta: monitor externo ao host (ex.: mini-PC).", 0.6)
    yield Ev("block", "monitor externo: ping proxmox ... sem resposta (3/3)", 0.5)
    a.alert("ALTA", "Host Proxmox indisponível")
    yield Ev("alert", "Alerta ALTA enviado ao TI de plantão (mensagem)", 0.7)
    yield Ev("ok", "Alerta chegou ao responsável mesmo com o monitoramento interno fora do ar.", 0.7)
    a.mark("op_alert", True)


def _bar(pct):
    n = pct // 5
    return "[" + "#" * n + "." * (20 - n) + f"] {pct:3d}%"


def sc6(a):
    yield Ev("step", "TESTE 6 | RANSOMWARE E RESTAURAÇÃO DE BACKUP - SIMULADO", 0.9)
    yield Ev("info", "Proposta: Proxmox Backup Server, cópia imutável, backup a cada 4 h.", 0.7)
    yield Ev("warn", "autoatendimento: arquivos renomeados em massa (.locked)", 0.8)
    a.alert("ALTA", "Ransomware na VM autoatendimento")
    yield Ev("alert", "Alerta ALTA enviado ao TI de plantão (mensagem)", 0.6)
    a.net.quar.add("autoatendimento")
    yield Ev("ok", "CONTER: VM isolada no firewall; demais serviços seguem normais.", 0.7)
    ok, _ = a.net.check("tablet-01", "autoatendimento", 443)
    yield Ev("block" if not ok else "warn", f"   tablet-01 -> autoatendimento:443: {'PERMITIDO' if ok else 'BLOQUEADO (quarentena)'}", 0.5)
    yield Ev("block", "[NEGADO] PBS: a conta da VM não tem permissão de apagar backups (imutável)", 0.8)
    yield Ev("cmd", "$ restaurar autoatendimento a partir do último backup", 0.6)
    for pct in range(0, 101, 20):
        yield Ev("info", "   restaurando " + _bar(pct), 0.3, True)
    a.net.quar.discard("autoatendimento")
    ok, _ = a.net.check("tablet-01", "autoatendimento", 443)
    yield Ev("ok" if ok else "warn", "   validação: tablet-01 -> autoatendimento:443 voltou a funcionar", 0.6)
    a.mark("op_backup", ok)
    yield Ev("warn", "RTO e RPO: metas de 4 h / 4 h (slide de backup) - NÃO MEDIDOS no laboratório.", 0.8)
    yield Ev("dim", "Medir exige restaurar no PBS e registrar horários de início e fim.", 0.4)


def sc7(a):
    yield Ev("step", "TESTE 7 | RESPOSTA A INCIDENTE (câmera IoT) - SIMULADO", 0.9)
    yield Ev("info", "1) DETECTAR E REGISTRAR", 0.4)
    yield Ev("warn", "   camera-01 enviando 4 GB/h para 198.51.100.23 (padrão anormal)", 0.7)
    a.alert("ALTA", "camera-01 com tráfego anômalo")
    ok, rule = a.net.check("camera-01", "internet", 443)
    yield Ev("block", f"   a política já barra IoT -> Internet ({rule})", 0.6)
    yield Ev("info", "2) CONTER", 0.4)
    a.net.quar.add("camera-01")
    yield Ev("ok", "   camera-01 isolada em quarentena (porta desativada no switch)", 0.6)
    ok2, _ = a.net.check("biometria-01", "monitor", 10051)
    yield Ev("ok" if ok2 else "warn", "   biometria-01 segue falando com o monitoramento (sem dano colateral)", 0.5)
    yield Ev("info", "3) INVESTIGAR", 0.4)
    h = hashlib.sha256("\n".join(t for _, _, t in a.log).encode()).hexdigest()[:16]
    yield Ev("ok", f"   logs preservados (sha256 {h}...); origem: senha padrão", 0.7)
    yield Ev("info", "4) ERRADICAR E RECUPERAR", 0.4)
    yield Ev("ok", "   firmware regravado e senha padrão trocada", 0.6)
    a.net.quar.discard("camera-01")
    yield Ev("info", "5) COMUNICAR E APRENDER", 0.4)
    yield Ev("ok", "   avaliar dado pessoal (vídeo): ANPD e titulares em até 3 dias úteis", 0.7)
    yield Ev("info", "   Lição: trocar senhas padrão antes de ligar o dispositivo.", 0.4)


def sc_resumo(a):
    n = sum(1 for k, _ in SIM_CHECKS if a.checks[k])
    yield Ev("step", "RESUMO | o que foi executado x o que é simulação", 0.8)
    yield Ev("ok", f"NO LABORATÓRIO (real, slide 7): {LAB_LINE.lower()}; bloqueio no log do pfSense.", 0.4)
    yield Ev("info", f"SIMULADO (proposta): {n}/{len(SIM_CHECKS)} fluxos demonstrados", 0.4)
    for k, t in SIM_CHECKS:
        v = a.checks[k]
        yield Ev("ok" if v else "warn", f"   [{'s' if v else ' '}] {t}", 0.15)
    yield Ev("warn", "NÃO MEDIDO: RTO/RPO (apenas metas). Zabbix e Grafana: proposta, não implantados.", 0.5)
    yield Ev("dim", "Esta saída é simulação; não substitui as evidências do laboratório.", 0.3)
    yield Ev("ok", f"Relatório salvo em: {a.export()}", 0.5)


SCENARIOS = [
    ("1", "Segmentação (VLANs/ACLs)", sc1),
    ("2", "Varredura de portas (nmap)", sc2),
    ("3", "Força bruta + MFA", sc3),
    ("4", "DHCP falso + snooping", sc4),
    ("5", "Monitoramento e alertas", sc5),
    ("6", "Backup e restauração", sc6),
    ("7", "Resposta a incidente (IoT)", sc7),
]
ALL_FUNCS = [f for _, _, f in SCENARIOS] + [sc_resumo]


# --------------------------------------------------------------------------
# Estado da aplicacao
# --------------------------------------------------------------------------
class App:
    def __init__(self, outdir=".", speed=1.0):
        self.net = Net()
        self.log = []        # (ts, lvl, txt)
        self.prog = False
        self.alerts = []     # (ts, sev, txt, destino)
        self.checks = {k: None for k, _ in SIM_CHECKS}
        self.gen = self.cur = None
        self.queue = []
        self.speed, self.paused = speed, False
        self.next_at = 0.0
        self.sel = 0
        self.running = ""
        self.outdir = outdir
        self.rev = 0         # muda a cada alteracao visivel (redesenho so quando muda)

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
        self.rev += 1

    def alert(self, sev, txt, dest=None):
        self.alerts.append((self.ts(), sev, txt, dest or ALERT_DEST.get(sev, "painel")))
        self.rev += 1

    def mark(self, key, ok):
        self.checks[key] = bool(ok)
        self.rev += 1

    def start(self, funcs, label=""):
        if self.gen is None:
            self.queue, self.running = list(funcs), label
            self._advance()

    def _advance(self):
        if self.queue:
            fn = self.queue.pop(0)
            self.gen, self.cur, self.next_at = fn(self), fn, 0.0
        else:
            self.gen = self.cur = None
            self.running = ""
        self.rev += 1

    def tick(self, now):
        if self.gen is None or self.paused or now < self.next_at:
            return
        try:
            ev = next(self.gen)
            self.emit(ev)
            self.next_at = now + ev.delay / self.speed
        except StopIteration:
            self._advance()
            if self.gen is not None:
                self.next_at = now + 0.8 / self.speed

    def reset(self):
        if self.gen is not None:
            self.gen.close()
        self.__init__(self.outdir, self.speed)

    def export(self):
        stamp = datetime.datetime.now()
        n = sum(1 for k, _ in SIM_CHECKS if self.checks[k])
        lines = ["RELATÓRIO DA SIMULAÇÃO - SEGURANÇA DA REDE DE UM COWORKING",
                 "Gerado em " + stamp.strftime("%d/%m/%Y %H:%M:%S"),
                 "ATENÇÃO: saída de SIMULAÇÃO (seclab.py). Não é evidência do laboratório.", "",
                 "EXECUTADO NO LABORATÓRIO (real; evidência = prints do pfSense, slide 7)",
                 f"  [x] {LAB_LINE}", "",
                 f"SIMULADO / PROPOSTA ({n}/{len(SIM_CHECKS)} fluxos demonstrados)"]
        for k, t in SIM_CHECKS:
            v = self.checks[k]
            lines.append(f"  [{'s' if v else '!' if v is False else ' '}] {t}" + ("  (não executado)" if v is None else ""))
        lines += ["", "NÃO MEDIDO", f"  [-] {RTO_LINE}", "  Zabbix e Grafana: proposta, não implantados.",
                  "", "ALERTAS SIMULADOS"]
        lines += [f"  {t} [{s}] {x} > {d}" for t, s, x, d in self.alerts] or ["  (nenhum)"]
        lines += ["", "LOG COMPLETO"] + [f"  {t} {x}" for t, _, x in self.log]
        name = stamp.strftime("relatorio_simulacao_%Y%m%d_%H%M%S.txt")
        for d in (self.outdir, tempfile.gettempdir()):  # cai no /tmp se a pasta for somente leitura
            try:
                path = os.path.join(d, name)
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
                return path
            except OSError:
                continue
        return "(não foi possível gravar)"


# --------------------------------------------------------------------------
# Renderizacao em um canvas de texto (independente do curses => testavel)
# --------------------------------------------------------------------------
_FOLD = str.maketrans({"·": "-", "—": "-", "–": "-", "→": ">", "…": "...",
                       "“": '"', "”": '"', "’": "'", "─": "-", "│": "|"})


def fold(s):
    """Remove acentos/simbolos nao-ASCII (terminais sem UTF-8: LANG=C, console serial)."""
    return unicodedata.normalize("NFKD", s.translate(_FOLD)).encode("ascii", "ignore").decode()


# estilo -> (par de cor, flags: b=negrito d=apagado r=reverso)
STY = {"n": (0, ""), "dim": (0, "d"), "box": (6, ""), "boxt": (6, "b"), "abox": (5, ""),
       "aboxt": (5, "b"), "ok": (1, ""), "block": (2, "b"), "warn": (3, "b"), "alert": (5, "b"),
       "cmd": (0, "b"), "step": (4, "b"), "info": (0, ""), "hdr": (8, "b"), "key": (8, ""),
       "sel": (0, "r"), "ALTA": (2, "b"), "MÉDIA": (3, "b"), "INFO": (4, ""), "tag": (3, "b")}


class Canvas:
    def __init__(self, h, w, ascii_=False):
        self.h, self.w, self.ascii = h, w, ascii_
        self.cells = [[(" ", "n")] * w for _ in range(h)]

    def put(self, y, x, s, st="n", maxw=None):
        if not 0 <= y < self.h or x >= self.w:
            return
        if self.ascii:
            s = fold(s)
        lim = self.w - x if maxw is None else min(maxw, self.w - x)
        for i, ch in enumerate(s[:max(0, lim)]):
            if x + i >= 0:
                self.cells[y][x + i] = (ch, st)

    def box(self, y, x, h, w, title, st="box"):
        tl, tr, bl, br, hz, vt = ("+", "+", "+", "+", "-", "|") if self.ascii else "┌┐└┘─│"
        for i in range(1, w - 1):
            self.put(y, x + i, hz, st)
            self.put(y + h - 1, x + i, hz, st)
        for j in range(1, h - 1):
            self.put(y + j, x, vt, st)
            self.put(y + j, x + w - 1, vt, st)
        for yy, xx, c in ((y, x, tl), (y, x + w - 1, tr), (y + h - 1, x, bl), (y + h - 1, x + w - 1, br)):
            self.put(yy, xx, c, st)
        self.put(y, x + 2, f" {title} ", st + "t", w - 4)

    def lines(self):
        return ["".join(c for c, _ in row).rstrip() for row in self.cells]


def fit(options, maxw):
    return next((o for o in options if len(o) <= maxw), options[-1][:max(0, maxw)])


def mode_for(H, W):
    return "full" if W >= 104 and H >= 28 else "compact" if W >= 70 and H >= 20 else "tiny"


def evidence_rows(app):
    n = sum(1 for k, _ in SIM_CHECKS if app.checks[k])
    rows = [("NO LABORATÓRIO (real, slide 7)", "boxt"), ("[x] " + LAB_LINE, "ok"),
            (f"SIMULADO (proposta) {n}/{len(SIM_CHECKS)}", "boxt")]
    for k, t in SIM_CHECKS:
        v = app.checks[k]
        rows.append((("[s] " if v else "[!] " if v is False else "[ ] ") + t,
                     "ok" if v else "warn" if v is False else "dim"))
    rows.append(("[-] " + RTO_LINE, "warn"))
    return rows


def panel_log(cv, app, y, x, h, w):
    title = "LOG DE EVENTOS" + (f" | {app.running}" if app.running else "") + ("  [PAUSADO]" if app.paused else "")
    cv.box(y, x, h, w, title)
    tw = max(10, w - 4 - 9)
    rows = []
    for ts, lvl, txt in app.log:
        for j, part in enumerate(textwrap.wrap(txt, tw, subsequent_indent="    ") or [""]):
            rows.append((ts if j == 0 else "", lvl, part))
    for i, (ts, lvl, part) in enumerate(rows[-(h - 2):] if h > 2 else []):
        cv.put(y + 1 + i, x + 2, ts, "dim")
        cv.put(y + 1 + i, x + 11, part, lvl, w - 13)


def panel_alerts(cv, app, y, x, h, w):
    cv.box(y, x, h, w, f"ALERTAS SIMULADOS ({len(app.alerts)}) | Zabbix: proposta", "abox")
    if not app.alerts:
        cv.put(y + 1, x + 2, "sem alertas", "dim")
    inner = w - 4
    for i, (ts, sev, txt, dest) in enumerate(app.alerts[-(h - 2):] if h > 2 else []):
        row, left = y + 1 + i, 15
        cv.put(row, x + 2, ts, "dim")
        cv.put(row, x + 11, f"{sev:<5}", sev if sev in STY else "n")
        dtxt = f"> {dest}"
        tw = inner - left - len(dtxt) - 1
        if tw >= 20:
            cv.put(row, x + 2 + left, txt, "n", tw)
            cv.put(row, x + 2 + inner - len(dtxt), dtxt, "dim")
        else:
            cv.put(row, x + 2 + left, txt, "n", inner - left)


def render(app, H, W, asc=False, hint_plain=True):
    cv = Canvas(H, W, asc)
    mode = mode_for(H, W)
    if mode == "tiny":
        cv.put(1, 2, f"Terminal pequeno ({W}x{H}). Mínimo 70x20, ideal 110x30.", "warn")
        cv.put(2, 2, "Aumente a janela ou reduza a fonte (Ctrl + -).", "n")
        if hint_plain:
            cv.put(3, 2, "Ou rode: python3 seclab.py --plain --live", "n")
        cv.put(5, 2, "Q = sair", "dim")
        return cv
    # cabecalho
    cv.put(0, 0, " " * W, "hdr")
    lefts = [" SEGURANÇA DA REDE DE UM COWORKING | seclab ", " SEGURANÇA DA REDE | seclab "]
    tags = [" SIMULAÇÃO | Zabbix planejado, não implantado ", " SIMULAÇÃO | Zabbix: proposta ", " SIMULAÇÃO "]
    # prioriza manter a mensagem completa sobre o titulo: tenta todas as combinacoes por ordem
    left, tag = next(((l, t) for t in tags for l in lefts if len(l) + len(t) + 2 <= W),
                      (lefts[-1][:W - 12], tags[-1]))
    cv.put(0, 0, left, "hdr")
    cv.put(0, W - len(tag) - 1, tag, "hdr")
    vel = f" vel {app.speed:.1f}x "
    if len(left) + len(tag) + len(vel) + 2 <= W:
        cv.put(0, W - len(tag) - len(vel) - 1, vel, "key")
    # rodape
    keys = fit([" 1-7 cenário | A autopilot | ESPAÇO pula espera | P pausa | +/- velocidade | E relatório | R zera | Q sai ",
                " 1-7 cenário | A auto | ESPAÇO pula | P pausa | +/- vel | E relatório | R zera | Q sai ",
                " 1-7 A auto SPC P +/- E R Q "], W)
    cv.put(H - 1, 0, keys.ljust(W), "key")
    if mode == "full":
        lw, menu_h, body = 44, len(SCENARIOS) + 3, H - 2
        cv.box(1, 0, menu_h, lw, "CENÁRIOS")
        for i, (k, title, fn) in enumerate(SCENARIOS):
            mark = ">" if app.cur is fn else " "
            line = f"{mark}{k}  {title}"
            cv.put(2 + i, 1, line.ljust(lw - 2), "sel" if i == app.sel else "n")
        cv.put(2 + len(SCENARIOS), 2, "A  AUTOPILOT (todos + relatório)", "step")
        ev_h = body - menu_h
        cv.box(1 + menu_h, 0, ev_h, lw, "EVIDÊNCIAS")
        for i, (t, st) in enumerate(evidence_rows(app)[:ev_h - 2]):
            cv.put(2 + menu_h + i, 2, t, st, lw - 4)
        ah = 10
        panel_log(cv, app, 1, lw, body - ah, W - lw)
        panel_alerts(cv, app, 1 + body - ah, lw, ah, W - lw)
    else:
        n = sum(1 for k, _ in SIM_CHECKS if app.checks[k])
        strip = fit([f" Lab real: visitante isolado [x] | Simulado {n}/{len(SIM_CHECKS)} | RTO/RPO: não medido ",
                     f" Lab: visitante [x] | Sim. {n}/{len(SIM_CHECKS)} | RTO/RPO n/m "], W)
        cv.put(1, 0, strip, "tag")
        body, ah = H - 3, 8
        panel_log(cv, app, 2, 0, body - ah, W)
        panel_alerts(cv, app, 2 + body - ah, 0, ah, W)
    return cv


# --------------------------------------------------------------------------
# Interface curses (so desenha o canvas) e modo texto
# --------------------------------------------------------------------------
def build_attrs(colors):
    attrs = {}
    for name, (c, fl) in STY.items():
        a = curses.color_pair(c) if colors and c else 0
        a |= curses.A_BOLD if "b" in fl else 0
        a |= curses.A_DIM if "d" in fl else 0
        a |= curses.A_REVERSE if ("r" in fl or (c == 8 and not colors)) else 0
        attrs[name] = a
    return attrs


def blit(scr, cv, attrs):
    for y, row in enumerate(cv.cells):
        x = 0
        while x < cv.w:
            st, j = row[x][1], x
            while j < cv.w and row[j][1] == st:
                j += 1
            try:
                scr.addstr(y, x, "".join(c for c, _ in row[x:j]), attrs.get(st, 0))
            except curses.error:  # escrever na ultima celula levanta erro; e inofensivo
                pass
            x = j


def tui(scr, app, autostart, asc):
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    colors = False
    try:
        curses.start_color()
        colors = curses.has_colors()
        if colors:
            try:
                curses.use_default_colors()
                bg = -1
            except curses.error:
                bg = curses.COLOR_BLACK
            for i, c in enumerate((curses.COLOR_GREEN, curses.COLOR_RED, curses.COLOR_YELLOW,
                                   curses.COLOR_CYAN, curses.COLOR_MAGENTA, curses.COLOR_BLUE), 1):
                curses.init_pair(i, c, bg)
            curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_BLUE)
    except curses.error:
        colors = False
    attrs = build_attrs(colors)
    scr.timeout(100)
    scr.keypad(True)
    if autostart:
        app.start(ALL_FUNCS, "AUTOPILOT")
    last = None
    while True:
        app.tick(time.time())
        H, W = scr.getmaxyx()
        if last != (app.rev, H, W):
            scr.erase()
            blit(scr, render(app, H, W, asc), attrs)
            scr.refresh()
            last = (app.rev, H, W)
        k = scr.getch()
        if k == -1:
            continue
        last = None
        if k in (ord("q"), ord("Q")):
            break
        if k == curses.KEY_RESIZE:
            scr.clear()
        elif ord("1") <= k <= ord("0") + len(SCENARIOS) and app.gen is None:
            app.sel = k - ord("1")
            app.start([SCENARIOS[app.sel][2]], SCENARIOS[app.sel][1])
        elif k in (curses.KEY_UP, ord("k")):
            app.sel = (app.sel - 1) % len(SCENARIOS)
        elif k in (curses.KEY_DOWN, ord("j")):
            app.sel = (app.sel + 1) % len(SCENARIOS)
        elif k in (10, 13, curses.KEY_ENTER) and app.gen is None:
            app.start([SCENARIOS[app.sel][2]], SCENARIOS[app.sel][1])
        elif k in (ord("a"), ord("A")) and app.gen is None:
            app.start(ALL_FUNCS, "AUTOPILOT")
        elif k == ord(" "):
            app.next_at = 0
        elif k in (ord("p"), ord("P")):
            app.paused = not app.paused
        elif k in (ord("+"), ord("=")):
            app.speed = min(5.0, app.speed + 0.5)
        elif k in (ord("-"), ord("_")):
            app.speed = max(0.5, app.speed - 0.5)
        elif k in (ord("e"), ord("E")):
            app.emit(Ev("ok", f"Relatório salvo em: {app.export()}"))
        elif k in (ord("r"), ord("R")):
            app.reset()


TAG = {"step": "====", "cmd": "$", "ok": "OK", "block": "BLOQ", "warn": "ATENC", "alert": "ALERTA",
       "info": "..", "dim": ""}
ANSI = {"step": "1;36", "cmd": "1", "ok": "32", "block": "1;31", "warn": "1;33", "alert": "1;35", "dim": "2"}


def plain(app, funcs, live=False, speed=1.0, asc=False, color=False):
    for fn in funcs:
        for ev in fn(app):
            app.emit(ev)
            ts, lvl, txt = app.log[-1]
            line = f"{ts} [{TAG.get(lvl, ''):<6}] {txt}"
            if asc:
                line = fold(line)
            if color and lvl in ANSI:
                line = f"\033[{ANSI[lvl]}m{line}\033[0m"
            print(line, flush=live)
            if live:
                time.sleep(ev.delay / speed)
    print(f"\nAlertas simulados: {len(app.alerts)}")


def duration(funcs):
    """Duracao total (s, a 1.0x) de uma lista de cenarios, sem esperar."""
    tmp = App(outdir=tempfile.gettempdir())
    t = 0.0
    for fn in funcs:
        t += 0.8
        for ev in fn(tmp):
            tmp.emit(ev)
            t += ev.delay
    return t


def utf8_ok():
    norm = lambda e: (e or "").lower().replace("-", "").replace("_", "")
    return all(norm(e) == "utf8" for e in (getattr(sys.stdout, "encoding", None),
                                          locale.getpreferredencoding(False)))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Simulador de segurança de rede do coworking (100% local)")
    ap.add_argument("--plain", action="store_true", help="modo texto: roda tudo e gera o relatório")
    ap.add_argument("--live", action="store_true", help="com --plain: imprime no ritmo da demo")
    ap.add_argument("--auto", action="store_true", help="TUI: inicia o autopilot")
    ap.add_argument("--scenario", type=int, metavar="N", help="roda só o cenário N (1-7)")
    ap.add_argument("--speed", type=float, default=1.0, help="velocidade (0.5-5, padrão 1.0)")
    ap.add_argument("--ascii", action="store_true", help="só ASCII (terminal sem UTF-8)")
    ap.add_argument("--snapshot", metavar="LxA", help="imprime a tela como texto (ex.: 110x30) e sai")
    ap.add_argument("--out", default=".", help="pasta do relatório (padrão: atual)")
    args = ap.parse_args(argv)
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
    asc = args.ascii or not utf8_ok()
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    speed = min(5.0, max(0.5, args.speed))
    if args.scenario is not None and not 1 <= args.scenario <= len(SCENARIOS):
        ap.error(f"--scenario deve ser de 1 a {len(SCENARIOS)}")
    funcs = [SCENARIOS[args.scenario - 1][2]] if args.scenario else ALL_FUNCS
    app = App(args.out, speed)

    if args.snapshot:
        try:
            w, h = (int(v) for v in args.snapshot.lower().split("x"))
        except ValueError:
            ap.error("--snapshot espera LARGURAxALTURA, ex.: 110x30")
        for fn in funcs:
            for ev in fn(app):
                app.emit(ev)
        print("\n".join(render(app, h, w, asc).lines()))
        return 0

    tty = sys.stdout.isatty() and sys.stdin.isatty()
    why = None
    if args.plain:
        pass
    elif curses is None:
        why = "módulo curses indisponível"
    elif not tty:
        why = "saída não é um terminal"
    if args.plain or why:
        if why:
            print(f"[seclab] {why}: usando modo texto.", file=sys.stderr)
        live = args.live or (why is not None and sys.stdout.isatty())
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ and not asc
        try:
            plain(app, funcs, live, speed, asc, color)
        except KeyboardInterrupt:
            return 130
        return 0

    try:
        if args.scenario:
            app.sel = args.scenario - 1
        curses.wrapper(tui, app, args.auto, asc)
    except KeyboardInterrupt:
        return 130
    except curses.error as e:  # TERM invalido/nao suportado
        print(f"[seclab] terminal sem suporte a curses ({e}): usando modo texto.", file=sys.stderr)
        app = App(args.out, speed)
        plain(app, funcs, True, speed, asc, False)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # ex.: python3 seclab.py --plain | head
        os._exit(0)

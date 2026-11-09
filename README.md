# SecLab Coworking — simulador de fluxo de segurança e alertas

Demonstração em terminal do projeto **Segurança da Rede de um Coworking**.
Arquivo único (`seclab.py`), só biblioteca padrão do Python 3.8+. **Nada para instalar e nenhuma chamada de rede**:
funciona igual com ou sem Internet, em Linux real ou virtualizado (Kali, VM, SSH, tmux, console).

> **Isto é uma simulação.** Tudo roda em memória e não toca em nenhuma rede.
> A saída do simulador **não é evidência do laboratório**.

## O que é real e o que é simulado

| Item | Situação | Onde aparece |
|---|---|---|
| Proxmox, pfSense, VLANs, regras e log de bloqueio | **Executado no laboratório** (prints) | slides 4, 6 e 7 |
| Isolamento da VLAN de visitantes (ping bloqueado) | **Executado**; o cenário 1 (parte A) o **reproduz** | slide 7 |
| IoT/tablets, nmap entre VLANs, MFA, DHCP snooping | Planejado — **simulado** | cenários 1B, 2, 3, 4 |
| Zabbix e Grafana, fluxo de alertas | **Proposta, não implantados** — simulado | cenário 5 |
| Backup e restauração | Proposta — fluxo simulado | cenário 6 |
| RTO/RPO | **Metas, não medidas** (o simulador não inventa tempos) | cenário 6 / resumo |
| Resposta a incidentes | Plano — simulado | cenário 7 |

O cabeçalho mostra sempre *“SIMULAÇÃO | Zabbix planejado, não implantado”*, e o painel de evidências separa
**NO LABORATÓRIO (real)**, **SIMULADO (proposta)** e **RTO/RPO: só metas, não medido**.
As regras da VLAN de visitantes (DNS do firewall, “Bloqueia rede interna”, saída somente web) espelham as do pfSense real.

## Como rodar

```bash
git clone <URL-do-repositorio> && cd <pasta>
python3 seclab.py                 # interface TUI
python3 seclab.py --auto          # já inicia o autopilot (~70 s a 1.0x)
python3 seclab.py --plain         # texto puro: roda tudo e gera o relatório
python3 seclab.py --plain --live  # texto puro no ritmo da demo (bom para gravar vídeo)
python3 seclab.py --scenario 5    # só o cenário 5 (monitoramento e alertas)
python3 -m unittest -v            # testes (rode antes de apresentar)
```

Teclas: `1`–`7` cenário · `A` autopilot · `ESPAÇO` pula a espera · `P` pausa · `+`/`-` velocidade ·
`E` salva relatório · `R` zera · `Q` sai · `↑/↓` + `Enter` também escolhem o cenário.

Cenários (mapeados para os slides): 1 Segmentação · 2 Varredura de portas · 3 Força bruta + MFA ·
4 DHCP falso + snooping · 5 Monitoramento e alertas · 6 Backup e restauração · 7 Resposta a incidente.
Para o print do slide de monitoramento: tecle `5` (ou `A` e capture quando as linhas “ALERTA” aparecerem) e use `P` para congelar a tela.

## Tamanho do terminal (projetor)

A tela se adapta ao tamanho — não precisa mais de 110x30 fixos:

| Tamanho | Layout |
|---|---|
| ≥ 104x28 | completo: cenários, evidências, log e alertas |
| ≥ 70x20 | compacto: faixa de status, log e alertas |
| menor | aviso na tela (e `--plain --live` como saída) |

Ctrl `+` aumenta a fonte e **reduz** colunas/linhas; o layout compacto existe para isso. Redimensionar a janela com o
programa aberto funciona. O desenho só é refeito quando algo muda (leve em VM e SSH).

## Robustez (VM, SSH, console)

* **Sem UTF-8** (`LANG=C`, console serial): troca para ASCII automaticamente (acentos removidos). Force com `--ascii`.
* **Sem cores** (`TERM=vt100`): usa negrito e vídeo reverso.
* **Sem terminal** (pipe, `TERM` inválido, Python sem `curses`): cai sozinho no modo texto.
* **Pasta somente leitura**: o relatório vai para o diretório temporário. Escolha a pasta com `--out DIR`.
* `python3 seclab.py --snapshot 110x30 --scenario 5` imprime a tela como texto (útil para conferir o layout sem terminal).

## Relatório

`E` (ou o fim do autopilot) grava `relatorio_simulacao_AAAAMMDD_HHMMSS.txt`, com a marcação de simulação,
a separação lab real × simulado × não medido, os alertas e o log completo.

## Combinados com a plateia

* Rede, hosts e regras seguem o plano de VLANs dos slides. O servidor de autoatendimento está na DMZ (suposição).
* Zabbix, Grafana, IDS/IPS, MFA, DHCP snooping e backup são **proposta**: o simulador mostra o *fluxo*, não uma implantação.
* Não há tempos de restauração: RTO/RPO são **metas** (4 h / 4 h para o autoatendimento) e **não foram medidos**.

## Plano B

Teste `python3 seclab.py --plain --live` antes. Grave um vídeo do autopilot e leve o repositório (ou o `seclab.py`) em pendrive.

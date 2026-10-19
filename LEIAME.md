# SecLab Coworking — demo ao vivo (100% offline)

Um único arquivo (`seclab.py`), só biblioteca padrão do Python 3. Nada para instalar, nenhuma internet necessária.
Os ataques e defesas são **simulados em memória** e não tocam em nenhuma rede. A exceção é o cenário 8, que usa
tráfego real apenas na interface local (127.0.0.1).

## Como rodar no Kali
    python3 seclab.py          # interface TUI
    python3 seclab.py --auto   # já inicia o autopilot
    python3 seclab.py --plain  # sem tela interativa (plano B / gera o relatório)

Use um terminal em tela cheia (mínimo 110x30). Dica: Ctrl e + (aumentar fonte) para o projetor.

## Teclas
    1-8 cenário · A autopilot · ESPAÇO pula a espera · P pausa · +/- velocidade · E salva relatório · R zera · Q sai

## Roteiro sugerido (cada cenário = um teste do slide "Testes de validação")
    1 Segmentação        -> visitante, IoT e tablets não chegam à TI/admin
    2 Varredura de portas -> nmap do visitante é barrado, IDS alerta, site expõe só 80/443
    3 Força bruta + MFA  -> conta bloqueada; senha roubada sozinha não basta
    4 DHCP falso         -> DHCP snooping descarta o roteador intruso
    5 Incidente IoT      -> detectar, conter, investigar, recuperar, documentar
    6 Ransomware+backup  -> restauração e metas de RTO/RPO
    7 Queda do host      -> o risco do servidor único e o monitor externo
    8 Bônus (real)       -> scan de verdade em 127.0.0.1 (usa o nmap se estiver instalado)
    A autopilot (~1,5 min no 1.0x) roda tudo e salva evidencias_coworking_*.txt

## Combinados da simulação (avisem a plateia)
    - Rede, hosts e regras seguem o plano de VLANs dos slides. O servidor de autoatendimento foi colocado na DMZ (suposição).
    - Backup a cada 4 h e tempos de restauração (RTO 0h41 / RPO 1h47) são **valores simulados**.
    - Monitor externo, segundo nó e MFA aparecem como proposta de melhoria do projeto.

## Plano B
    Teste `python3 seclab.py --plain` antes. Grave um vídeo do autopilot e leve o OVA + o seclab.py em pendrive.

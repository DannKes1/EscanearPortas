#!/usr/bin/env python3

import argparse
import sys
from scapy.all import sr1, IP, TCP, UDP, ICMP, conf
import logging

# Suprime mensagens de aviso do Scapy para um output mais limpo
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0 # Torna o Scapy menos verboso

def parse_ports(port_str):
    """
    Analisa a string de portas fornecida pelo usuário.
    Exemplos: '80', '22,80,443', '1-1024'
    """
    ports = set()
    if not port_str:
        return []
    
    # Divide por vírgulas para múltiplos intervalos/portas
    ranges = port_str.split(',')
    for r in ranges:
        r = r.strip()
        if '-' in r:
            start, end = map(int, r.split('-'))
            if start > end:
                start, end = end, start # Garante a ordem correta
            ports.update(range(start, end + 1))
        else:
            ports.add(int(r))
    
    return sorted(list(ports))


def tcp_syn_scan(target_ip, port):
    """
    Realiza uma varredura TCP SYN em uma única porta.
    """
    try:
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        # sr1: envia e recebe apenas uma resposta
        response = sr1(pkt, timeout=1.5, verbose=0)

        if response is None:
            return "FILTRADA"
        elif response.haslayer(TCP):
            # Flags: 0x12 -> SYN/ACK (Porta Aberta)
            if response.getlayer(TCP).flags == 0x12:
                # Envia um RST para fechar a conexão "meio-aberta"
                sr1(IP(dst=target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return "ABERTA"
            # Flags: 0x14 -> RST/ACK (Porta Fechada)
            elif response.getlayer(TCP).flags == 0x14:
                return "FECHADA"
        
        return "FILTRADA" # Se a resposta não for o esperado

    except Exception as e:
        print(f"Erro na varredura TCP da porta {port}: {e}")
        return "ERRO"


def udp_scan(target_ip, port):
    """
    Realiza uma varredura UDP em uma única porta.
    """
    try:
        pkt = IP(dst=target_ip)/UDP(dport=port)
        response = sr1(pkt, timeout=2, verbose=0)

        if response is None:
            # Sem resposta, a porta pode estar aberta ou filtrada
            return "ABERTA|FILTRADA"
        elif response.haslayer(ICMP):
            # Verifica o tipo e código do ICMP (3, 3) -> Port Unreachable
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                return "FECHADA"
        
        return "ABERTA|FILTRADA" # Outra resposta ICMP pode indicar filtragem

    except Exception as e:
        print(f"Erro na varredura UDP da porta {port}: {e}")
        return "ERRO"


def main():
    parser = argparse.ArgumentParser(description="Ferramenta de Varredura de Portas TCP e UDP.")
    parser.add_argument("target", help="Endereço IP ou hostname do alvo.")
    parser.add_argument("-p", "--ports", default="1-1024", help="Portas para escanear (ex: '22,80,443' ou '1-1024').")
    parser.add_argument("--tcp", action="store_true", help="Realizar varredura TCP (padrão se nenhum tipo for especificado).")
    parser.add_argument("--udp", action="store_true", help="Realizar varredura UDP.")

    args = parser.parse_args()

    # Se nem --tcp nem --udp forem especificados, assume --tcp como padrão
    if not args.tcp and not args.udp:
        args.tcp = True

    target_ip = args.target
    ports_to_scan = parse_ports(args.ports)
    
    print(f"[*] Iniciando varredura em {target_ip}")
    print("-" * 50)

    if args.tcp:
        print("[+] Varredura TCP:")
        for port in ports_to_scan:
            status = tcp_syn_scan(target_ip, port)
            if status in ["ABERTA", "FILTRADA"]: # Mostra apenas o que é interessante
                 print(f"  Porta {port}/tcp: {status}")
            sys.stdout.flush() # Força a impressão imediata do resultado

    if args.udp:
        print("\n[+] Varredura UDP:")
        for port in ports_to_scan:
            status = udp_scan(target_ip, port)
            # Para UDP, o mais interessante é saber se NÃO está fechada.
            if status != "FECHADA":
                print(f"  Porta {port}/udp: {status}")
            sys.stdout.flush()

    print("-" * 50)
    print("[*] Varredura concluída.")


if __name__ == "__main__":
    # Scapy requer privilégios de root para criar sockets raw
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print("[!] Erro: Este script precisa ser executado com privilégios de root (use sudo).")
        sys.exit(1)
    main()
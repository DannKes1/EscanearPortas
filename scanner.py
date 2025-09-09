#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os
from queue import Queue
from scapy.all import sr1, IP, TCP, UDP, ICMP, conf
import logging
from typing import List, Set, Tuple

# --- Configurações do Scapy e Logging ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# --- Lógica de Varredura (a mesma de antes, mas adaptada para a GUI) ---

def parse_ports(port_str: str) -> List[int]:
    ports: Set[int] = set()
    if not port_str:
        return []
    try:
        ranges = port_str.split(',')
        for r in ranges:
            r = r.strip()
            if '-' in r:
                start, end = map(int, r.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(r))
    except ValueError:
        # Em vez de sair, mostramos um erro na GUI
        messagebox.showerror("Erro de Formato", f"Formato de porta inválido: '{port_str}'.\nUse '80', '22,80' ou '1-1024'.")
        return []
    return sorted(list(ports))

def tcp_syn_scan(target_ip: str, port: int) -> str:
    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1.5, verbose=0)
        if response is None: return "FILTRADA"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12: # SYN/ACK
                sr1(IP(dst=target_ip) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return "ABERTA"
            elif response.getlayer(TCP).flags == 0x14: # RST/ACK
                return "FECHADA"
        return "FILTRADA"
    except Exception:
        return "ERRO"

def udp_scan(target_ip: str, port: int) -> str:
    try:
        pkt = IP(dst=target_ip) / UDP(dport=port)
        response = sr1(pkt, timeout=2, verbose=0)
        if response is None: return "ABERTA|FILTRADA"
        elif response.haslayer(ICMP):
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                return "FECHADA"
        return "ABERTA|FILTRADA"
    except Exception:
        return "ERRO"

# --- Classe da Aplicação Gráfica ---

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ferramenta de Varredura de Portas")
        self.root.geometry("600x500")

        # Frame principal
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Widgets de Entrada ---
        input_frame = ttk.LabelFrame(main_frame, text="Configurações da Varredura", padding="10")
        input_frame.pack(fill=tk.X, pady=5)

        ttk.Label(input_frame, text="Alvo (IP):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ttk.Entry(input_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.target_entry.insert(0, "127.0.0.1") # IP de exemplo

        ttk.Label(input_frame, text="Portas:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ports_entry = ttk.Entry(input_frame, width=40)
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.ports_entry.insert(0, "1-1024") # Portas de exemplo

        # Checkboxes para tipo de scan
        self.tcp_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="TCP", variable=self.tcp_var).grid(row=2, column=0, padx=5, pady=5, sticky="w")
        ttk.Checkbutton(input_frame, text="UDP", variable=self.udp_var).grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # Botão de Scan
        self.scan_button = ttk.Button(main_frame, text="Iniciar Varredura", command=self.start_scan_thread)
        self.scan_button.pack(pady=10, fill=tk.X)

        # --- Área de Resultados ---
        output_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, state="disabled")
        self.results_text.pack(fill=tk.BOTH, expand=True)

    def log_message(self, message):
        """Adiciona uma mensagem à área de texto da GUI de forma segura."""
        self.results_text.configure(state="normal")
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.configure(state="disabled")
        self.results_text.see(tk.END) # Rola para o final

    def start_scan_thread(self):
        """Inicia a varredura em uma nova thread para não bloquear a GUI."""
        
        if sys.platform.startswith('linux') and os.geteuid() != 0:
            messagebox.showerror("Erro de Permissão", "Este script precisa ser executado com privilégios de root (use sudo) para funcionar corretamente.")
            return
        
        target_ip = self.target_entry.get()
        if not target_ip:
            messagebox.showwarning("Entrada Inválida", "Por favor, insira um endereço IP alvo.")
            return

        
        self.results_text.configure(state="normal")
        self.results_text.delete(1.0, tk.END)
        self.results_text.configure(state="disabled")
        self.scan_button.config(state="disabled", text="Varrendo...")

        # Inicia a thread
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()

    def run_scan(self):
        """A lógica principal da varredura que roda em segundo plano."""
        target_ip = self.target_entry.get()
        ports_str = self.ports_entry.get()
        ports_to_scan = parse_ports(ports_str)

        if not ports_to_scan:
            self.scan_button.config(state="normal", text="Iniciar Varredura")
            return

        self.log_message(f"[*] Iniciando varredura em {target_ip}...")
        self.log_message("-" * 50)

        scan_types = []
        if self.tcp_var.get(): scan_types.append("tcp")
        if self.udp_var.get(): scan_types.append("udp")

        if not scan_types:
            self.log_message("[!] Nenhum tipo de varredura selecionado.")
            self.scan_button.config(state="normal", text="Iniciar Varredura")
            return

        for scan_type in scan_types:
            self.log_message(f"[+] Varrendo portas {scan_type.upper()}...")
            
            port_queue = Queue()
            for port in ports_to_scan:
                port_queue.put(port)

            results: List[Tuple[int, str]] = []
            
            def worker():
                while not port_queue.empty():
                    port = port_queue.get()
                    status = tcp_syn_scan(target_ip, port) if scan_type == "tcp" else udp_scan(target_ip, port)
                    if status not in ["FECHADA", "ERRO"]:
                        results.append((port, status))
                    port_queue.task_done()

            threads = []
            for _ in range(50): 
                thread = threading.Thread(target=worker, daemon=True)
                thread.start()
                threads.append(thread)
            
            port_queue.join() 

            results.sort()
            for port, status in results:
                self.log_message(f"  Porta {port}/{scan_type}: {status}")
            
            if not results:
                self.log_message("  Nenhuma porta aberta ou filtrada encontrada.")
            
            self.log_message("") 

        self.log_message("-" * 50)
        self.log_message("[*] Varredura concluída.")
        self.scan_button.config(state="normal", text="Iniciar Varredura")


if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

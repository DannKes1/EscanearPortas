import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os
from queue import Queue, Empty
from scapy.all import sr1, IP, TCP, UDP, ICMP, conf
import logging
from typing import List, Set

# Silencia os logs do Scapy para uma saída mais limpa
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# --- Funções de Scan (Núcleo da Lógica de Rede) ---

def tcp_syn_scan(target_ip: str, port: int) -> str:
    """Realiza um scan TCP SYN em uma única porta."""
    try:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        
        if response is None:
            return "FILTRADA"
        
        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            # 0x12 é SYN/ACK (porta aberta)
            if flags == 0x12:
                # Envia um RST para fechar a conexão de forma limpa
                sr1(IP(dst=target_ip) / TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return "ABERTA"
            # 0x14 é RST/ACK (porta fechada)
            elif flags == 0x14:
                return "FECHADA"
                
        return "FILTRADA"
    except Exception:
        return "ERRO"

def udp_scan(target_ip: str, port: int) -> str:
    """Realiza um scan UDP em uma única porta."""
    try:
        pkt = IP(dst=target_ip) / UDP(dport=port)
        response = sr1(pkt, timeout=2, verbose=0)
        
        if response is None:
            # Sem resposta, a porta pode estar aberta ou filtrada
            return "ABERTA|FILTRADA"
        
        if response.haslayer(ICMP):
            # ICMP tipo 3, código 3 significa "Port Unreachable" (porta fechada)
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                return "FECHADA"
                
        return "ABERTA|FILTRADA"
    except Exception:
        return "ERRO"

# --- Interface Gráfica (GUI) com Tkinter ---

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner Otimizado")
        self.root.geometry("650x550")
        
        self.scan_thread = None
        self.results_queue = Queue()
        self.open_ports_count = 0

        self._setup_gui()

    def _setup_gui(self):
        """Configura os widgets da interface gráfica."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Frame de Configurações
        input_frame = ttk.LabelFrame(main_frame, text="Configurações", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="Alvo (IP):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ttk.Entry(input_frame, width=40)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.target_entry.insert(0, "127.0.0.1")

        ttk.Label(input_frame, text="Portas:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.ports_entry = ttk.Entry(input_frame, width=40)
        self.ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.ports_entry.insert(0, "1-1024")

        # Checkboxes para tipo de scan
        scan_type_frame = ttk.Frame(input_frame)
        scan_type_frame.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.tcp_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(scan_type_frame, text="TCP", variable=self.tcp_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(scan_type_frame, text="UDP", variable=self.udp_var).pack(side=tk.LEFT, padx=5)

        # Slider para número de threads
        ttk.Label(input_frame, text="Threads:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.threads_var = tk.IntVar(value=50)
        self.threads_scale = ttk.Scale(input_frame, from_=1, to=200, orient="horizontal", variable=self.threads_var, command=lambda v: self.threads_label.config(text=f"{int(float(v))}"))
        self.threads_scale.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.threads_label = ttk.Label(input_frame, text="50")
        self.threads_label.grid(row=3, column=2, padx=5, pady=5)
        
        # Botão de Iniciar
        self.scan_button = ttk.Button(main_frame, text="Iniciar Varredura", command=self.start_scan)
        self.scan_button.pack(pady=10, fill=tk.X)

        # Área de Resultados
        output_frame = ttk.LabelFrame(main_frame, text="Resultados (Portas Abertas ou Filtradas)", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, state="disabled", height=10)
        self.results_text.pack(fill=tk.BOTH, expand=True)

    def log_message(self, message: str, tag: str = None):
        """Adiciona uma mensagem à área de texto da GUI de forma segura."""
        self.results_text.configure(state="normal")
        if tag:
            self.results_text.insert(tk.END, message + "\n", tag)
        else:
            self.results_text.insert(tk.END, message + "\n")
        self.results_text.configure(state="disabled")
        self.results_text.see(tk.END)

    def start_scan(self):
        """Prepara e inicia a thread de varredura."""
        if sys.platform.startswith('linux') and os.geteuid() != 0:
            messagebox.showerror("Erro de Permissão", "Execute o script com 'sudo' para usar raw sockets.")
            return

        target_ip = self.target_entry.get().strip()
        if not target_ip:
            messagebox.showwarning("Entrada Inválida", "O endereço IP alvo não pode ser vazio.")
            return

        # Limpa resultados anteriores e prepara a GUI
        self.results_text.configure(state="normal")
        self.results_text.delete(1.0, tk.END)
        self.results_text.tag_config("open", foreground="green", font=("TkDefaultFont", 10, "bold"))
        self.results_text.configure(state="disabled")
        
        self.scan_button.config(state="disabled", text="Varrendo...")
        self.open_ports_count = 0
        
        self.log_message(f"[*] Iniciando varredura em {target_ip}...")
        self.log_message("-" * 60)

        # Inicia a thread principal do scan
        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()
        
        # Inicia o processador da fila de resultados
        self.root.after(100, self._process_results_queue)

    def _process_results_queue(self):
        """Verifica a fila de resultados e atualiza a GUI em tempo real."""
        try:
            while True:
                port, scan_type, status = self.results_queue.get_nowait()
                self.log_message(f"  Porta {port}/{scan_type.upper()}: {status}", tag="open")
                self.open_ports_count += 1
        except Empty:
            pass  # A fila está vazia, continue

        # Se o scan terminou, finaliza tudo
        if not self.scan_thread.is_alive() and self.results_queue.empty():
            self.log_message("-" * 60)
            if self.open_ports_count == 0:
                self.log_message("[*] Nenhuma porta aberta/filtrada encontrada.")
            else:
                self.log_message(f"[*] Varredura concluída. {self.open_ports_count} porta(s) encontrada(s).")
            self.scan_button.config(state="normal", text="Iniciar Varredura")
        else:
            # Se não, reagenda a verificação
            self.root.after(100, self._process_results_queue)

    def _worker(self, target_ip, port_queue, scan_type):
        """Função executada por cada thread para escanear portas."""
        while not port_queue.empty():
            try:
                port = port_queue.get_nowait()
                scan_func = tcp_syn_scan if scan_type == "tcp" else udp_scan
                status = scan_func(target_ip, port)
                
                # Apenas adiciona à fila se o status for relevante (ABERTA ou ABERTA|FILTRADA)
                if "ABERTA" in status:
                    self.results_queue.put((port, scan_type, status))
            except Empty:
                break
            finally:
                port_queue.task_done()
    
    def _run_scan(self):
        """Lógica principal da varredura que roda em segundo plano."""
        target_ip = self.target_entry.get().strip()
        ports_str = self.ports_entry.get()
        
        ports_to_scan = self._parse_ports(ports_str)
        if not ports_to_scan:
            return

        scan_types = []
        if self.tcp_var.get(): scan_types.append("tcp")
        if self.udp_var.get(): scan_types.append("udp")
        
        if not scan_types:
            # Envia mensagem para a GUI de forma segura
            self.root.after(0, lambda: messagebox.showinfo("Aviso", "Nenhum tipo de varredura (TCP/UDP) foi selecionado."))
            return

        for scan_type in scan_types:
            self.root.after(0, self.log_message, f"[+] Varrendo {len(ports_to_scan)} portas {scan_type.upper()}...")
            
            port_queue = Queue()
            for port in ports_to_scan:
                port_queue.put(port)
            
            threads = []
            num_threads = self.threads_var.get()
            for _ in range(num_threads):
                thread = threading.Thread(target=self._worker, args=(target_ip, port_queue, scan_type), daemon=True)
                thread.start()
                threads.append(thread)
            
            # Espera a fila ser processada por todas as threads
            port_queue.join()

    def _parse_ports(self, port_str: str) -> List[int]:
        """Converte a string de portas em uma lista de inteiros."""
        ports: Set[int] = set()
        if not port_str: return []
        try:
            for part in port_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(part))
        except ValueError:
            messagebox.showerror("Erro de Formato", f"Formato de porta inválido: '{port_str}'.\nUse '80', '22,80' ou '1-1024'.")
            return []
        return sorted(list(ports))

if __name__ == "__main__":
    if sys.platform.startswith('win'):
        messagebox.showinfo("Aviso", "No Windows, o Scapy pode exigir a instalação do Npcap e privilégios de administrador.")

    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

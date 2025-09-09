# Ferramenta de Varredura de Portas (Port Scanner) com GUI
<img width="1281" height="799" alt="image" src="https://github.com/user-attachments/assets/a9f0aab3-141b-4558-af1f-96f0bce6bc89" />



## 🎯 Objetivo do Projeto

Esta ferramenta foi desenvolvida para realizar a varredura de portas TCP e UDP em um ou mais endereços IP. Utilizando técnicas de envio de pacotes SYN (para TCP) e sondagem (para UDP), o scanner identifica se as portas de um alvo estão abertas, fechadas ou filtradas por um firewall.

O projeto cumpre os requisitos de ser funcional em sistemas Linux, com uma interface gráfica opcional (implementada com `tkinter`) para facilitar o uso.

## ✨ Funcionalidades

-   **Varredura TCP SYN:** Envia pacotes TCP SYN para detectar portas abertas sem completar a conexão (stealth scan).
-   **Varredura UDP:** Envia pacotes UDP para verificar se as portas estão abertas ou fechadas com base na resposta ICMP.
-   **Interface Gráfica Simples:** Permite que o usuário insira o alvo, a faixa de portas e selecione o tipo de varredura de forma intuitiva.
-   **Execução com Threads:** Utiliza múltiplas threads para escanear portas em paralelo, tornando o processo significativamente mais rápido.
-   **Resultados Claros:** Exibe os resultados em tempo real em uma área de texto, mostrando apenas as portas de interesse (Abertas e Filtradas).

## 🛠️ Tecnologias Utilizadas

-   **Linguagem:** Python 3
-   **Bibliotecas Principais:**
    -   `Scapy`: Para criação e envio de pacotes de rede customizados.
    -   `Tkinter`: Para a construção da interface gráfica do usuário (GUI).
    -   `Threading`: Para a execução concorrente das tarefas de varredura.

## ⚙️ Requisitos e Instalação

Este script foi projetado para rodar em sistemas **Linux** (como Ubuntu, Debian, Mint, etc.).

### 1. Pré-requisitos

-   Python 3
-   Gerenciador de pacotes `pip`

Na maioria das distribuições baseadas em Debian (como o Linux Mint), você pode instalar isso com:
```bash
sudo apt update
sudo apt install python3 python3-pip
```

### 2. Instalação das Dependências

A única dependência externa é a biblioteca `scapy`. Instale-a usando o `pip`:
```bash
pip3 install scapy
```

## 🚀 Como Executar

Devido à natureza da varredura de rede (criação de *raw sockets*), o script **precisa ser executado com privilégios de administrador (root)**.

1.  Abra o terminal no diretório onde o arquivo `scanner_gui.py` está localizado.

2.  Execute o seguinte comando:
    ```bash
    sudo python3 scanner_gui.py
    ```

3.  Digite sua senha de usuário quando solicitado.

4.  A interface gráfica da aplicação será iniciada.

## 📖 Guia de Uso da Interface

1.  **Alvo (IP):** Insira o endereço IP do dispositivo que você deseja escanear (ex: `192.168.1.1` ou `127.0.0.1` para sua própria máquina).
2.  **Portas:** Defina as portas a serem escaneadas. Você pode usar os seguintes formatos:
    -   Uma única porta: `80`
    -   Múltiplas portas separadas por vírgula: `22,80,443`
    -   Um intervalo de portas: `1-1024`
3.  **Tipo de Varredura:** Marque as caixas `TCP` e/ou `UDP` para selecionar os protocolos desejados.
4.  **Iniciar Varredura:** Clique no botão para começar. O botão ficará desabilitado durante o processo.
5.  **Resultados:** Acompanhe o status e os resultados na área de texto na parte inferior da janela. Ao final, uma mensagem de conclusão será exibida.

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida para fins educacionais e para ser utilizada em ambientes controlados e com autorização explícita. O uso de scanners de porta em redes sem permissão é ilegal e antiético. O autor não se responsabiliza por qualquer uso indevido desta aplicação.

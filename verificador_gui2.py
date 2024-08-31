import tkinter as tk
from tkinter import scrolledtext
import nmap
import socket
import ssl
from urllib.parse import urlparse
import threading

def ensure_https(url):
    """Adiciona 'https://' à URL se não estiver presente."""
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    return url

def check_ssl_certificate(url):
    url = ensure_https(url)  # Garantir que a URL tenha o protocolo
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return False, "URL inválida."
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return False, "Certificado SSL não encontrado ou inválido."
                
                # Tentativa de lidar com peculiaridades de certos certificados
                ssl_info = cert.get('subject', [('Unknown', 'Unknown')])
                return True, ssl_info
    except ssl.SSLError as e:
        return False, f"Erro de SSL: {e}"
    except socket.timeout as e:
        return False, "Erro: Conexão expirou (timeout)."
    except Exception as e:
        return False, f"Erro ao conectar ao servidor: {e}"

def scan():
    target = entry.get()
    nm = nmap.PortScanner()
    result_text.delete(1.0, tk.END)  # Limpa o texto anterior
    result_text.insert(tk.END, "Escaneando...\n")
    try:
        # Verificação do SSL/TLS
        ssl_valid, ssl_info = check_ssl_certificate(target)
        if ssl_valid:
            result_text.insert(tk.END, f"Certificado SSL válido: {ssl_info}\n")
        else:
            result_text.insert(tk.END, f"Problema com o certificado SSL: {ssl_info}\n")
            # Se o SSL não for válido, marcamos o site como inseguro
            risk_level = "Inseguro"
            risk_message = "Este site pode ser inseguro devido a problemas com o certificado SSL."
            result_text.insert(tk.END, f'\nClassificação de Risco: {risk_level}\n')
            result_text.insert(tk.END, f'{risk_message}\n')
            return  # Para não continuar o escaneamento de portas
        
        nm.scan(target, '1-1024')
        result_text.delete(1.0, tk.END)  # Limpa a mensagem de "Escaneando..."
        risk_level = "Seguro"
        risk_message = "O site parece seguro com as portas padrão abertas."
        
        for host in nm.all_hosts():
            result_text.insert(tk.END, f'Host : {host} ({nm[host].hostname()})\n')
            result_text.insert(tk.END, f'State : {nm[host].state()}\n')
            for proto in nm[host].all_protocols():
                result_text.insert(tk.END, '----------\n')
                result_text.insert(tk.END, f'Protocol : {proto}\n')
                lport = nm[host][proto].keys()
                for port in lport:
                    port_state = nm[host][proto][port]["state"]
                    result_text.insert(tk.END, f'port : {port}\tstate : {port_state}\n')
                    
                    # Simples classificação de risco
                    if port in [21, 23, 25, 110, 139, 445] and port_state == "open":
                        risk_level = "Inseguro"
                        risk_message = "Este site pode ser inseguro. Evite inserir informações pessoais ou acessar a partir de uma rede pública."
                    elif port in [80, 443] and risk_level != "Inseguro":
                        risk_level = "Seguro"
                        risk_message = "O site parece seguro com as portas padrão abertas."
                    else:
                        if risk_level != "Inseguro":
                            risk_level = "Moderado"
                            risk_message = "O site possui portas incomuns abertas. Use com cautela."

        result_text.insert(tk.END, f'\nClassificação de Risco: {risk_level}\n')
        result_text.insert(tk.END, f'{risk_message}\n')
        
    except Exception as e:
        result_text.delete(1.0, tk.END)  # Limpa a mensagem de "Escaneando..." em caso de erro
        result_text.insert(tk.END, f"Erro ao escanear o alvo: {e}\n")

def start_scan():
    scan_thread = threading.Thread(target=scan)
    scan_thread.start()

# Cria a janela principal
window = tk.Tk()
window.title("Ferramenta de Verificação de Vulnerabilidades")

# Cria e posiciona os elementos na janela
label = tk.Label(window, text="Digite o domínio ou IP:")
label.pack(pady=10)

entry = tk.Entry(window, width=50)
entry.pack(pady=5)

scan_button = tk.Button(window, text="Escanear", command=start_scan)
scan_button.pack(pady=10)

result_text = scrolledtext.ScrolledText(window, width=60, height=20)
result_text.pack(pady=10)

# Inicia a interface gráfica
window.mainloop()

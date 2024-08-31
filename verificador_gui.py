import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox
import nmap
import socket
import ssl
from urllib.parse import urlparse
import threading
import datetime

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
                
                # Verifica se o certificado está expirado ou próximo do vencimento
                not_after = cert.get('notAfter')
                if not_after:
                    expiration_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if expiration_date < datetime.datetime.now():
                        return False, f"Certificado SSL expirado em {expiration_date}"
                    elif expiration_date < datetime.datetime.now() + datetime.timedelta(days=30):
                        return True, f"Certificado SSL válido, mas expira em menos de 30 dias ({expiration_date})"
                
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
    ports = port_entry.get() or '1-1024'  # Usar um range de portas padrão se o usuário não especificar
    nm = nmap.PortScanner()
    result_text.delete(1.0, tk.END)
    progress_bar.start()  # Iniciar a barra de progresso
    try:
        # Verificação do SSL/TLS
        ssl_valid, ssl_info = check_ssl_certificate(target)
        if ssl_valid:
            result_text.insert(tk.END, f"Certificado SSL válido: {ssl_info}\n")
        else:
            result_text.insert(tk.END, f"Problema com o certificado SSL: {ssl_info}\n")
            progress_bar.stop()  # Parar a barra de progresso
            risk_level = "Inseguro"
            risk_message = "Este site pode ser inseguro devido a problemas com o certificado SSL."
            result_text.insert(tk.END, f'\nClassificação de Risco: {risk_level}\n')
            result_text.insert(tk.END, f'{risk_message}\n')
            messagebox.showwarning("Alerta de Segurança", "Problemas críticos encontrados no certificado SSL.")
            return
        
        nm.scan(target, ports)
        result_text.delete(1.0, tk.END)
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
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Erro ao escanear o alvo: {e}\n")
    finally:
        progress_bar.stop()  # Parar a barra de progresso no final do scan

def start_scan():
    scan_thread = threading.Thread(target=scan)
    scan_thread.start()

def save_results():
    result = result_text.get(1.0, tk.END)
    if result.strip():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(result)

def toggle_advanced_options():
    if advanced_frame.winfo_viewable():
        advanced_frame.pack_forget()
    else:
        advanced_frame.pack(pady=5, anchor="ne")  # Coloca o frame no topo direito

# Cria a janela principal
window = tk.Tk()
window.title("Ferramenta de Verificação de Vulnerabilidades")
window.geometry('650x500')

# Cria e posiciona os elementos na janela
label_frame = tk.Frame(window)
label_frame.pack(fill=tk.X)

label = tk.Label(label_frame, text="Digite o domínio ou IP:", font=('Arial', 12))
label.pack(side=tk.LEFT, padx=10, pady=10)

advanced_button = tk.Button(label_frame, text="Opções Avançadas", command=toggle_advanced_options, font=('Arial', 10))
advanced_button.pack(side=tk.RIGHT, padx=10, pady=10)

entry = tk.Entry(window, width=50, font=('Arial', 12))
entry.pack(pady=5)

scan_button = tk.Button(window, text="Escanear", command=start_scan, font=('Arial', 12))
scan_button.pack(pady=10)

# Cria o frame para opções avançadas, mas não exibe inicialmente
advanced_frame = tk.Frame(window)
advanced_frame.pack_forget()  # Começa escondido

port_label = tk.Label(advanced_frame, text="Digite as portas a serem escaneadas (ex: 1-1024):", font=('Arial', 10))
port_label.pack(pady=5)

port_entry = tk.Entry(advanced_frame, width=50, font=('Arial', 10))
port_entry.pack(pady=5)

result_text = scrolledtext.ScrolledText(window, width=70, height=20, font=('Arial', 10))
result_text.pack(pady=10)

save_button = tk.Button(window, text="Salvar Resultados", command=save_results, font=('Arial', 12))
save_button.pack(pady=10)  # Posicionado logo abaixo do resultado

# Adiciona a barra de progresso
progress_bar = ttk.Progressbar(window, mode='indeterminate')
progress_bar.pack(pady=5, fill=tk.X)

# Inicia a interface gráfica
window.mainloop()

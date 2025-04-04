import os
import psutil
import subprocess
import socket
import time
import ctypes
import sys
import winreg
from threading import Thread
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import Fore, Style, init

# Initialisation de colorama
init()

# Vérification et relance en mode administrateur
def run_as_admin():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(Fore.YELLOW + "Relancement en mode administrateur..." + Style.RESET_ALL)
        script = os.path.abspath(sys.argv[0])
        params = " ".join(sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit()

# Vérification de la signature des fichiers exécutables
def is_signed(file_path):
    try:
        result = subprocess.run(
            ["powershell", "-Command", f"(Get-AuthenticodeSignature '{file_path}').SignerCertificate"],
            capture_output=True, text=True, shell=True
        )
        return bool(result.stdout.strip())  # Si le champ n'est pas vide, le fichier est signé
    except Exception:
        return False  # En cas d'erreur, on considère le fichier comme non signé

# Vérification des processus suspects (exécutables non signés)
def check_suspicious_processes():
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe']):
        try:
            process_path = proc.info['exe']
            cpu_usage = proc.info['cpu_percent']
            memory_usage = proc.info['memory_percent']
            if process_path and not is_signed(process_path):
                print(Fore.RED + f"ALERTE : Processus non signé {proc.info['name']} (PID: {proc.info['pid']})" + Style.RESET_ALL)
            if cpu_usage > 50 or memory_usage > 50:
                print(Fore.RED + f"ALERTE : Processus suspect détecté {proc.info['name']} (PID: {proc.info['pid']})" + Style.RESET_ALL)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Surveillance des fichiers système
class FileMonitor(FileSystemEventHandler):
    def on_modified(self, event):
        print(Fore.YELLOW + f"Modification détectée : {event.src_path}" + Style.RESET_ALL)
        if "System32" in event.src_path or "etc" in event.src_path:
            print(Fore.RED + "ALERTE : Fichier critique modifié !" + Style.RESET_ALL)

def start_file_monitoring():
    path = "C:\\Windows\\System32" if os.name == "nt" else "/etc"
    event_handler = FileMonitor()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Protection du registre (Windows)
def protect_registry():
    keys_to_protect = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    ]
    
    while True:
        for key in keys_to_protect:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ) as reg_key:
                    print(Fore.GREEN + f"Vérification du registre : {key} OK" + Style.RESET_ALL)
            except Exception:
                print(Fore.RED + f"ALERTE : Tentative de modification du registre détectée !" + Style.RESET_ALL)
        time.sleep(5)

# Désactivation des ports inutiles
def disable_unused_ports():
    ports_to_block = [135, 139, 445]  # Ports critiques
    print(Fore.MAGENTA + "Désactivation des ports inutiles..." + Style.RESET_ALL)
    for port in ports_to_block:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", "name=Block Port", "dir=in", "action=block", 
             f"protocol=TCP", f"localport={port}"], 
            shell=True
        )
    print(Fore.RED + "Ports inutiles bloqués !" + Style.RESET_ALL)

# Surveillance des connexions réseau
def monitor_network():
    while True:
        #os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.CYAN + "--- Connexions réseau actives ---" + Style.RESET_ALL)
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr:
                print(Fore.GREEN + f"Connexion active : {conn.raddr.ip}:{conn.raddr.port}" + Style.RESET_ALL)
        print(Fore.YELLOW + "\nMise à jour des connexions..." + Style.RESET_ALL)
        time.sleep(10)

# Démarrage du programme
if __name__ == "__main__":
    run_as_admin()
    print(Fore.BLUE + "Lancement des protections..." + Style.RESET_ALL)
    Thread(target=monitor_network, daemon=True).start()
    Thread(target=start_file_monitoring, daemon=True).start()
    Thread(target=protect_registry, daemon=True).start()
    disable_unused_ports()
    
    while True:
        check_suspicious_processes()
        time.sleep(10)

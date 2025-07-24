import random
import threading
import time
from logger import log_attempt
from geoip import get_geoip
from attack_detection import register_failed_attempt
from config import DEFAULT_PORT
from malicious_code_simulator import log_malicious_code
from gmail_report_simulator import simulate_gmail_report

# Listas de ejemplo para simulación
COMMON_USERS = ["root", "admin", "user", "test", "guest"]
COMMON_PASSWORDS = ["123456", "password", "admin", "root", "toor", "qwerty", "letmein"]
COMMON_IPS = [
    "192.168.1.100", "10.0.0.5", "172.16.0.2", "203.0.113.45", "198.51.100.23",
    "8.8.8.8", "185.199.108.153", "45.33.32.156", "104.244.42.1", "51.15.0.1"
]

# Simula N intentos desde una IP
def simulate_bruteforce(ip=None, n=10, port=DEFAULT_PORT, delay=0.1, on_new_log=None):
    if not ip:
        ip = random.choice(COMMON_IPS)
    for _ in range(n):
        username = random.choice(COMMON_USERS)
        password = random.choice(COMMON_PASSWORDS)
        country, city = get_geoip(ip)
        blocked = register_failed_attempt(ip)
        log_attempt(ip, port, username, password, country, city, event='simulated_attack', blocked=blocked)
        # Simular código malicioso y reporte Gmail
        log_malicious_code(ip, username)
        simulate_gmail_report('Ataque simulado', ip, username, details=f'Intento con password: {password}')
        if on_new_log:
            on_new_log()
        time.sleep(delay)

# Simula ataques desde múltiples IPs
def simulate_mass_attack(num_ips=5, attempts_per_ip=5, port=DEFAULT_PORT, delay=0.05, on_new_log=None):
    ips = random.sample(COMMON_IPS, min(num_ips, len(COMMON_IPS)))
    for ip in ips:
        simulate_bruteforce(ip, n=attempts_per_ip, port=port, delay=delay, on_new_log=on_new_log)

# Simula un ataque personalizado
def simulate_custom_attack(ip, usernames, passwords, port=DEFAULT_PORT, delay=0.1, on_new_log=None):
    for username in usernames:
        for password in passwords:
            country, city = get_geoip(ip)
            blocked = register_failed_attempt(ip)
            log_attempt(ip, port, username, password, country, city, event='simulated_attack', blocked=blocked)
            log_malicious_code(ip, username)
            simulate_gmail_report('Ataque personalizado', ip, username, details=f'Intento con password: {password}')
            if on_new_log:
                on_new_log()
            time.sleep(delay)

# Ejecuta la simulación en un hilo para no bloquear la GUI
def run_simulation(sim_func, *args, **kwargs):
    threading.Thread(target=sim_func, args=args, kwargs=kwargs, daemon=True).start() 
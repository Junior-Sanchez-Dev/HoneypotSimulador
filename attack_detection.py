import time
import threading
from config import FAILED_ATTEMPTS_THRESHOLD, BLOCK_TIME_SECONDS

# Diccionario: ip -> [timestamps de intentos fallidos]
failed_attempts = {}
# Diccionario: ip -> tiempo de desbloqueo
blocked_ips = {}
lock = threading.Lock()

# Llama esto en cada intento fallido
def register_failed_attempt(ip):
    now = time.time()
    with lock:
        if ip in blocked_ips and blocked_ips[ip] > now:
            return True  # Ya está bloqueada
        attempts = failed_attempts.setdefault(ip, [])
        attempts.append(now)
        # Limpiar intentos viejos (últimos 10 minutos)
        failed_attempts[ip] = [t for t in attempts if now - t < 600]
        if len(failed_attempts[ip]) >= FAILED_ATTEMPTS_THRESHOLD:
            blocked_ips[ip] = now + BLOCK_TIME_SECONDS
            failed_attempts[ip] = []
            return True  # Ahora bloqueada
    return False

def is_blocked(ip):
    now = time.time()
    with lock:
        if ip in blocked_ips and blocked_ips[ip] > now:
            return True
        elif ip in blocked_ips:
            del blocked_ips[ip]
    return False

def get_blocked_ips():
    with lock:
        return {ip: unblock for ip, unblock in blocked_ips.items() if unblock > time.time()} 
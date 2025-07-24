import csv
import threading
from datetime import datetime
from config import LOG_FILE

log_lock = threading.Lock()

# Columnas del CSV
CSV_FIELDS = [
    'timestamp', 'ip', 'port', 'username', 'password', 'country', 'city', 'event', 'blocked'
]

def log_attempt(ip, port, username, password, country='', city='', event='login_attempt', blocked=False):
    with log_lock:
        file_exists = False
        try:
            with open(LOG_FILE, 'r', newline='', encoding='utf-8') as f:
                file_exists = True
        except FileNotFoundError:
            pass
        with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ip': ip,
                'port': port,
                'username': username,
                'password': password,
                'country': country,
                'city': city,
                'event': event,
                'blocked': blocked
            })

def read_logs(filter_func=None):
    with log_lock:
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                logs = list(reader)
        except FileNotFoundError:
            return []
    if filter_func:
        return list(filter(filter_func, logs))
    return logs

def export_logs(filename, filter_func=None):
    logs = read_logs(filter_func)
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(logs) 
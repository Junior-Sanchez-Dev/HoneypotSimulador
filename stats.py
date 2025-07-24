from collections import Counter, defaultdict

from logger import read_logs
from datetime import datetime

def stats_by_country():
    logs = read_logs()
    return Counter(log['country'] for log in logs if log['country'])

def stats_by_ip():
    logs = read_logs()
    return Counter(log['ip'] for log in logs)

def stats_by_username():
    logs = read_logs()
    return Counter(log['username'] for log in logs)

def stats_by_hour():
    logs = read_logs()
    hours = [datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S').hour for log in logs]
    return Counter(hours)

def top_n(counter, n=10):
    return counter.most_common(n) 
from datetime import datetime

report_log = []

def simulate_gmail_report(event, ip, username, details=None):
    entry = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "event": event,
        "ip": ip,
        "username": username,
        "details": details or ""
    }
    report_log.append(entry)
    return entry

def get_recent_reports(n=20):
    return report_log[-n:] 
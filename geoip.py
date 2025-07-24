import requests
from config import GEOIP_API_URL

def get_geoip(ip):
    try:
        response = requests.get(GEOIP_API_URL + ip, timeout=3)
        data = response.json()
        if data.get('status') == 'success':
            return data.get('country', ''), data.get('city', '')
    except Exception:
        pass
    return '', '' 
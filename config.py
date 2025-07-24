import os

# Puerto por defecto para el honeypot SSH
DEFAULT_PORT = 2222

# Ruta del archivo de logs CSV
LOG_FILE = os.path.join(os.path.dirname(__file__), 'logs.csv')

# Umbral de intentos fallidos antes de bloquear una IP
FAILED_ATTEMPTS_THRESHOLD = 5

# Tiempo de bloqueo en segundos para IPs sospechosas
BLOCK_TIME_SECONDS = 600  # 10 minutos

# API para geolocalización de IPs
GEOIP_API_URL = 'http://ip-api.com/json/'

# Tema de la interfaz gráfica
GUI_THEME = 'superhero'  # ttkbootstrap theme 
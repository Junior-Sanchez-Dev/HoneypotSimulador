# SSH Honeypot Avanzado

Este proyecto es un honeypot SSH robusto y profesional, diseñado para simular un servidor SSH falso, registrar todos los intentos de conexión y ayudar en la detección temprana de atacantes.

## Características principales

- Simulación realista de servidor SSH (banner, usuario, contraseña)
- Registro de todos los intentos (IP, puerto, usuario, contraseña, país, ciudad, evento, bloqueo)
- Geolocalización de IPs en tiempo real
- Detección y bloqueo automático de ataques de fuerza bruta
- Exportación avanzada de logs filtrados
- Notificaciones visuales y sonoras en la interfaz
- Dashboard de estadísticas en tiempo real (por país, IP, usuario, hora)
- Interfaz gráfica moderna y llamativa (ttkbootstrap)
- Puerto configurable
- Soporte para múltiples conexiones simultáneas

## Instalación

1. Clona este repositorio o copia los archivos en una carpeta.
2. Instala las dependencias:

```bash
pip install -r requirements.txt
```

## Uso

Ejecuta el honeypot con:

```bash
python main.py
```

- Elige el puerto en la interfaz gráfica.
- Haz clic en "Iniciar" para comenzar a escuchar intentos SSH.
- Visualiza los intentos en tiempo real, estadísticas y alertas.
- Exporta los logs a CSV cuando lo desees.

## Requisitos
- Python 3.8+
- Acceso a internet para la geolocalización de IPs

## Seguridad
Este honeypot **no otorga acceso real** a ningún sistema. Solo simula la autenticación SSH y registra los intentos.

## Licencia
MIT 
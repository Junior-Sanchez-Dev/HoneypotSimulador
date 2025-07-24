import socket
import threading
from config import DEFAULT_PORT
from logger import log_attempt
from geoip import get_geoip
from attack_detection import register_failed_attempt, is_blocked

BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"

class SSHHoneypotServer:
    def __init__(self, port=DEFAULT_PORT, on_new_log=None):
        self.port = port
        self.on_new_log = on_new_log  # Callback para la GUI
        self.running = False
        self.server_socket = None
        self.threads = []

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.port))
        self.server_socket.listen(100)
        threading.Thread(target=self.accept_loop, daemon=True).start()

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        for t in self.threads:
            if t.is_alive():
                try:
                    t.join(timeout=1)
                except Exception:
                    pass

    def accept_loop(self):
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                t = threading.Thread(target=self.handle_client, args=(client, addr), daemon=True)
                t.start()
                self.threads.append(t)
            except Exception:
                break

    def handle_client(self, client, addr):
        ip, port = addr[0], addr[1]
        if is_blocked(ip):
            client.close()
            log_attempt(ip, port, '', '', event='blocked', blocked=True)
            if self.on_new_log:
                self.on_new_log()
            return
        try:
            client.sendall(BANNER.encode())
            client.sendall(b"login as: ")
            username = self.recv_line(client)
            client.sendall(b"Password: ")
            password = self.recv_line(client, echo=False)
            country, city = get_geoip(ip)
            blocked = register_failed_attempt(ip)
            log_attempt(ip, port, username, password, country, city, event='login_attempt', blocked=blocked)
            if self.on_new_log:
                self.on_new_log()
            if blocked:
                client.sendall(b"Too many failed attempts. Connection closed.\r\n")
            else:
                client.sendall(b"Permission denied, please try again.\r\n")
        except Exception:
            pass
        finally:
            client.close()

    def recv_line(self, client, echo=True):
        data = b''
        while True:
            c = client.recv(1)
            if not c or c in b'\r\n':
                break
            if echo:
                client.sendall(c)
            data += c
        return data.decode(errors='ignore').strip() 
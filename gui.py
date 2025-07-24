import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from config import DEFAULT_PORT, GUI_THEME
from ssh_honeypot_server import SSHHoneypotServer
from logger import read_logs, export_logs
from stats import stats_by_country, stats_by_ip, stats_by_username, stats_by_hour, top_n
from attack_detection import get_blocked_ips
import threading
import os
from attack_simulator import simulate_bruteforce, simulate_mass_attack, run_simulation
from gmail_report_simulator import get_recent_reports
from malicious_code_simulator import get_recent_malicious

class HoneypotGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Honeypot Avanzado")
        self.style = tb.Style(theme=GUI_THEME)
        self.server = None
        self.port_var = tk.IntVar(value=DEFAULT_PORT)
        self.status_var = tk.StringVar(value="Detenido")
        self.log_tree = None
        self.stats_frame = None
        self.alert_var = tk.StringVar(value="")
        self._build_ui()
        self.refresh_logs()
        self.refresh_stats()

    def _build_ui(self):
        # Panel superior: Configuración y control
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=X)
        ttk.Label(top, text="Puerto:").pack(side=LEFT)
        port_entry = ttk.Entry(top, textvariable=self.port_var, width=6)
        port_entry.pack(side=LEFT, padx=5)
        self.start_btn = ttk.Button(top, text="Iniciar", bootstyle=SUCCESS, command=self.toggle_server)
        self.start_btn.pack(side=LEFT, padx=5)
        ttk.Label(top, textvariable=self.status_var, font=("Arial", 10, "bold")).pack(side=LEFT, padx=10)
        ttk.Button(top, text="Exportar logs", bootstyle=INFO, command=self.export_logs).pack(side=RIGHT, padx=5)
        ttk.Button(top, text="Actualizar", bootstyle=SECONDARY, command=self.refresh_all).pack(side=RIGHT, padx=5)
        # Botones de simulación de ataques
        sim_frame = ttk.Frame(self.root, padding=5)
        sim_frame.pack(fill=X)
        ttk.Label(sim_frame, text="Simulación de ataques:", font=("Arial", 10, "bold")).pack(side=LEFT)
        ttk.Button(sim_frame, text="Fuerza bruta", bootstyle=WARNING, command=self.simulate_bruteforce).pack(side=LEFT, padx=3)
        ttk.Button(sim_frame, text="Ataque masivo", bootstyle=DANGER, command=self.simulate_mass_attack).pack(side=LEFT, padx=3)
        # Botón para ver códigos recibidos
        ttk.Button(sim_frame, text="Códigos recibidos", bootstyle=INFO, command=self.open_malicious_window).pack(side=LEFT, padx=10)
        # Panel de alertas
        alert = ttk.Label(self.root, textvariable=self.alert_var, font=("Arial", 11, "bold"), foreground="red")
        alert.pack(fill=X, pady=2)
        # Panel central: Logs en vivo
        log_frame = ttk.Labelframe(self.root, text="Intentos capturados", padding=5)
        log_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        columns = ("timestamp", "ip", "port", "username", "password", "country", "city", "event", "blocked")
        self.log_tree = ttk.Treeview(log_frame, columns=columns, show="headings", height=10, bootstyle=PRIMARY)
        for col in columns:
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, width=90, anchor=CENTER)
        self.log_tree.pack(fill=BOTH, expand=True)
        # Panel derecho: Estadísticas
        self.stats_frame = ttk.Labelframe(self.root, text="Estadísticas", padding=5)
        self.stats_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        # Panel inferior: IPs bloqueadas
        block_frame = ttk.Labelframe(self.root, text="IPs bloqueadas", padding=5)
        block_frame.pack(fill=X, padx=10, pady=5)
        self.blocked_list = ttk.Label(block_frame, text="")
        self.blocked_list.pack(fill=X)
        # Panel de reportes enviados a Gmail
        gmail_frame = ttk.Labelframe(self.root, text="Reportes enviados a Gmail", padding=5)
        gmail_frame.pack(fill=X, padx=10, pady=2)
        self.gmail_list = ttk.Treeview(gmail_frame, columns=("timestamp", "event", "ip", "username", "details"), show="headings", height=3, bootstyle=INFO)
        for col in ("timestamp", "event", "ip", "username", "details"):
            self.gmail_list.heading(col, text=col)
            self.gmail_list.column(col, width=100, anchor=CENTER)
        self.gmail_list.pack(fill=X)
        # Panel de códigos maliciosos recibidos
        code_frame = ttk.Labelframe(self.root, text="Códigos maliciosos recibidos", padding=5)
        code_frame.pack(fill=BOTH, expand=True, padx=10, pady=2)
        self.code_list = ttk.Treeview(code_frame, columns=("timestamp", "ip", "username", "type", "code"), show="headings", height=5, bootstyle=WARNING)
        for col in ("timestamp", "ip", "username", "type", "code"):
            self.code_list.heading(col, text=col)
            self.code_list.column(col, width=120, anchor=CENTER)
        self.code_list.pack(fill=BOTH, expand=True)

    def toggle_server(self):
        if self.server and self.server.running:
            self.server.stop()
            self.server = None
            self.status_var.set("Detenido")
            self.start_btn.config(text="Iniciar", bootstyle=SUCCESS)
            self.alert_var.set("")
        else:
            port = self.port_var.get()
            try:
                self.server = SSHHoneypotServer(port=port, on_new_log=self.on_new_log)
                self.server.start()
                self.status_var.set(f"Escuchando en puerto {port}")
                self.start_btn.config(text="Detener", bootstyle=DANGER)
                self.alert_var.set("")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo iniciar el servidor: {e}")

    def on_new_log(self):
        self.refresh_logs()
        self.refresh_stats()
        self.check_alerts()
        self.refresh_gmail_reports()
        self.refresh_malicious_codes()

    def refresh_logs(self):
        logs = read_logs()
        self.log_tree.delete(*self.log_tree.get_children())
        for log in logs[-100:]:  # Solo los últimos 100
            self.log_tree.insert('', 'end', values=[log[c] for c in self.log_tree['columns']])

    def refresh_stats(self):
        for widget in self.stats_frame.winfo_children():
            widget.destroy()
        # Países
        ttk.Label(self.stats_frame, text="Top países:", font=("Arial", 10, "bold")).pack(anchor=W)
        for country, count in top_n(stats_by_country()):
            ttk.Label(self.stats_frame, text=f"{country}: {count}").pack(anchor=W)
        # IPs
        ttk.Label(self.stats_frame, text="Top IPs:", font=("Arial", 10, "bold")).pack(anchor=W, pady=(8,0))
        for ip, count in top_n(stats_by_ip()):
            ttk.Label(self.stats_frame, text=f"{ip}: {count}").pack(anchor=W)
        # Usuarios
        ttk.Label(self.stats_frame, text="Top usuarios:", font=("Arial", 10, "bold")).pack(anchor=W, pady=(8,0))
        for user, count in top_n(stats_by_username()):
            ttk.Label(self.stats_frame, text=f"{user}: {count}").pack(anchor=W)
        # Horas
        ttk.Label(self.stats_frame, text="Intentos por hora:", font=("Arial", 10, "bold")).pack(anchor=W, pady=(8,0))
        for hour, count in sorted(stats_by_hour().items()):
            ttk.Label(self.stats_frame, text=f"{hour:02d}:00 - {count}").pack(anchor=W)

    def export_logs(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            export_logs(filename)
            messagebox.showinfo("Exportación", f"Logs exportados a {filename}")

    def refresh_all(self):
        self.refresh_logs()
        self.refresh_stats()
        self.check_alerts()
        self.refresh_gmail_reports()
        self.refresh_malicious_codes()

    def refresh_gmail_reports(self):
        self.gmail_list.delete(*self.gmail_list.get_children())
        for r in get_recent_reports(10):
            self.gmail_list.insert('', 'end', values=(r['timestamp'], r['event'], r['ip'], r['username'], r['details']))

    def refresh_malicious_codes(self):
        self.code_list.delete(*self.code_list.get_children())
        for c in get_recent_malicious(15):
            self.code_list.insert('', 'end', values=(c['timestamp'], c['ip'], c['username'], c['type'], c['code']))

    def check_alerts(self):
        blocked = get_blocked_ips()
        if blocked:
            self.alert_var.set(f"¡{len(blocked)} IP(s) bloqueadas por actividad sospechosa!")
        else:
            self.alert_var.set("")
        self.blocked_list.config(text=", ".join(blocked.keys()) if blocked else "Ninguna")

    def simulate_bruteforce(self):
        run_simulation(simulate_bruteforce, n=15, port=self.port_var.get(), on_new_log=self.on_new_log)
        self.alert_var.set("Simulando ataque de fuerza bruta...")

    def simulate_mass_attack(self):
        run_simulation(simulate_mass_attack, num_ips=6, attempts_per_ip=8, port=self.port_var.get(), on_new_log=self.on_new_log)
        self.alert_var.set("Simulando ataque masivo...")

    def open_malicious_window(self):
        win = tk.Toplevel(self.root)
        win.title("Códigos maliciosos recibidos - Detalle")
        win.geometry("900x400")
        columns = ("timestamp", "type", "code", "ip", "username")
        tree = ttk.Treeview(win, columns=columns, show="headings", height=18, bootstyle=WARNING)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=160 if col=="code" else 100, anchor=tk.CENTER)
        tree.pack(fill=tk.BOTH, expand=True)
        # Llenar la tabla ordenada por timestamp descendente
        data = sorted(get_recent_malicious(100), key=lambda x: x['timestamp'], reverse=True)
        for c in data:
            tree.insert('', 'end', values=(c['timestamp'], c['type'], c['code'], c['ip'], c['username']))
        # Scrollbar
        scrollbar = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


def run_gui():
    root = tb.Window(themename=GUI_THEME)
    app = HoneypotGUI(root)
    root.mainloop() 
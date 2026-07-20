"""
Главный интерфейс Sentinel SIEM на CustomTkinter (5 вкладок SOC).
"""

from datetime import datetime
import os
import webbrowser
from tkinter import messagebox, ttk
import customtkinter as ctk
from sentinel.config import REPORTS_DIR
from sentinel.database.db_manager import SIEMDatabaseManager
from sentinel.engine.report_generator import SecurityReportGenerator
from sentinel.sample_data.generator import generate_siem_test_logs

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class SentinelSIEMApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sentinel SIEM — Платформа мониторинга и расследования инцидентов ИБ (SOC)")
        self.geometry("1140x760")
        self.minsize(980, 650)

        self.db = SIEMDatabaseManager()
        self._seed_sample_data_if_empty()

        self._build_ui()

    def _seed_sample_data_if_empty(self):
        """Если база пуста, наполняем реалистичными логами атак."""
        metrics = self.db.get_soc_metrics()
        if metrics["total_events"] == 0:
            self.generate_and_ingest_test_logs()

    def generate_and_ingest_test_logs(self):
        logs = generate_siem_test_logs(count=100)
        for line in logs:
            self.db.ingest_log_line(line)
        self.db.run_correlation_scan()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.grid(row=0, column=0, padx=16, pady=16, sticky="nsew")

        self.tab_soc = self.tabview.add("🛡️ 1. Главный пульт SOC")
        self.tab_incidents = self.tabview.add("🚨 2. Инциденты & Workflow")
        self.tab_hunting = self.tabview.add("🔍 3. Threat Hunting & Логи")
        self.tab_rules = self.tabview.add("⚙️ 4. Правила детектирования")
        self.tab_reports = self.tabview.add("📄 5. Аудит & Отчетность")

        self._build_tab_soc()
        self._build_tab_incidents()
        self._build_tab_hunting()
        self._build_tab_rules()
        self._build_tab_reports()

    # ================= 1. TAB SOC OVERVIEW =================
    def _build_tab_soc(self):
        tab = self.tab_soc
        tab.grid_columnconfigure((0, 1), weight=1)

        # Баннер статуса угрозы
        self.banner = ctk.CTkFrame(tab, fg_color="#450a0a", border_width=1, border_color="#dc2626")
        self.banner.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 15))

        lbl_threat = ctk.CTkLabel(
            self.banner,
            text="🚨 ТЕКУЩИЙ УРОВЕНЬ УГРОЗЫ: КРИТИЧЕСКИЙ (CRITICAL DEFCON 2)",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#fca5a5"
        )
        lbl_threat.pack(side="left", padx=16, pady=12)

        btn_rescan = ctk.CTkButton(
            self.banner, text="⚡ Корреляционный скан", width=160,
            fg_color="#dc2626", hover_color="#991b1b",
            command=self.run_rescan
        )
        btn_rescan.pack(side="right", padx=16, pady=12)

        # 4 Карточки KPI
        kpi_frame = ctk.CTkFrame(tab, fg_color="transparent")
        kpi_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=6, pady=5)
        kpi_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        def make_kpi(col, title, initial_val, color):
            f = ctk.CTkFrame(kpi_frame)
            f.grid(row=0, column=col, padx=5, sticky="ew")
            ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=11), text_color="gray").pack(anchor="w", padx=12, pady=(10, 0))
            lbl = ctk.CTkLabel(f, text=initial_val, font=ctk.CTkFont(size=24, weight="bold"), text_color=color)
            lbl.pack(anchor="w", padx=12, pady=(2, 10))
            return lbl

        self.kpi_events = make_kpi(0, "Событий безопасности", "0", "#38BDF8")
        self.kpi_incidents = make_kpi(1, "Активных инцидентов", "0", "#F59E0B")
        self.kpi_critical = make_kpi(2, "Критических угроз (P1)", "0", "#EF4444")
        self.kpi_attackers = make_kpi(3, "Уникальных атакующих IP", "0", "#A855F7")

        # Нижняя сетка: Топ IP и MITRE
        sec_left = ctk.CTkFrame(tab)
        sec_left.grid(row=2, column=0, sticky="nsew", padx=10, pady=15)
        ctk.CTkLabel(sec_left, text="🎯 Топ источников атак (Attacker IPs):", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(14, 6))

        self.txt_top_ips = ctk.CTkTextbox(sec_left, height=180, font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_top_ips.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        sec_right = ctk.CTkFrame(tab)
        sec_right.grid(row=2, column=1, sticky="nsew", padx=10, pady=15)
        ctk.CTkLabel(sec_right, text="🛡️ Задействованные тактики MITRE ATT&CK:", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=16, pady=(14, 6))

        self.txt_mitre = ctk.CTkTextbox(sec_right, height=180, font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_mitre.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.refresh_soc_overview()

    def refresh_soc_overview(self):
        metrics = self.db.get_soc_metrics()
        self.kpi_events.configure(text=str(metrics["total_events"]))
        self.kpi_incidents.configure(text=str(metrics["total_incidents"]))
        self.kpi_critical.configure(text=str(metrics["critical_count"]))
        self.kpi_attackers.configure(text=str(metrics["unique_attackers"]))

        # IP
        self.txt_top_ips.delete("1.0", "end")
        for i, ip in enumerate(metrics.get("top_ips", []), 1):
            self.txt_top_ips.insert("end", f"[{i}] {ip['source_ip']:<18} — {ip['cnt']} атак (Заблокирован в WAF)\n")

        # MITRE
        self.txt_mitre.delete("1.0", "end")
        for m in metrics.get("mitre_dist", []):
            self.txt_mitre.insert("end", f"• {m['mitre_id']:<8} — {m['cnt']} срабатываний сигнатур\n")

    def run_rescan(self):
        self.db.run_correlation_scan()
        self.refresh_soc_overview()
        self.load_incidents_table()
        messagebox.showinfo("Корреляция", "Корреляционный движок проанализировал временные окна логов. База инцидентов обновлена.")

    # ================= 2. TAB INCIDENTS & WORKFLOW =================
    def _build_tab_incidents(self):
        tab = self.tab_incidents
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Тулбар фильтрации
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        ctk.CTkLabel(top, text="Статус:").pack(side="left", padx=5)
        self.inc_status_filter = ctk.CTkOptionMenu(top, values=["ВСЕ", "NEW", "INVESTIGATING", "RESOLVED"], command=lambda v: self.load_incidents_table())
        self.inc_status_filter.pack(side="left", padx=5)

        ctk.CTkLabel(top, text="Критичность:").pack(side="left", padx=10)
        self.inc_sev_filter = ctk.CTkOptionMenu(top, values=["ВСЕ", "CRITICAL", "HIGH", "MEDIUM", "LOW"], command=lambda v: self.load_incidents_table())
        self.inc_sev_filter.pack(side="left", padx=5)

        btn_act_investigate = ctk.CTkButton(top, text="🔍 В работу", width=90, fg_color="#F59E0B", hover_color="#D97706", command=lambda: self.change_selected_incident_status("INVESTIGATING"))
        btn_act_investigate.pack(side="right", padx=5)

        btn_act_resolve = ctk.CTkButton(top, text="✔ Устранено", width=90, fg_color="#10B981", hover_color="#059669", command=lambda: self.change_selected_incident_status("RESOLVED"))
        btn_act_resolve.pack(side="right", padx=5)

        # Таблица инцидентов
        cols = ("id", "severity", "rule_name", "mitre_id", "source_ip", "status", "created_at")
        self.tree_inc = ttk.Treeview(tab, columns=cols, show="headings")
        self.tree_inc.heading("id", text="ID")
        self.tree_inc.heading("severity", text="Критичность")
        self.tree_inc.heading("rule_name", text="Обнаруженное правило / Сигнатура")
        self.tree_inc.heading("mitre_id", text="MITRE ATT&CK")
        self.tree_inc.heading("source_ip", text="IP Атакующего")
        self.tree_inc.heading("status", text="Статус")
        self.tree_inc.heading("created_at", text="Время")

        self.tree_inc.column("id", width=50, anchor="center")
        self.tree_inc.column("severity", width=110, anchor="center")
        self.tree_inc.column("rule_name", width=280)
        self.tree_inc.column("mitre_id", width=110, anchor="center")
        self.tree_inc.column("source_ip", width=130, anchor="center")
        self.tree_inc.column("status", width=120, anchor="center")
        self.tree_inc.column("created_at", width=150, anchor="center")

        self.tree_inc.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self.tree_inc.bind("<<TreeviewSelect>>", self._on_incident_select)

        # Детали инцидента
        self.txt_incident_detail = ctk.CTkTextbox(tab, height=90, font=ctk.CTkFont(family="Consolas", size=12))
        self.txt_incident_detail.grid(row=2, column=0, sticky="ew", padx=10, pady=(5, 10))
        self.txt_incident_detail.insert("1.0", "Выберите инцидент в таблице выше для просмотра полезной нагрузки (Payload) и подробностей.\n")

        self.load_incidents_table()

    def load_incidents_table(self):
        st = self.inc_status_filter.get() if hasattr(self, "inc_status_filter") else "ВСЕ"
        sev = self.inc_sev_filter.get() if hasattr(self, "inc_sev_filter") else "ВСЕ"
        incidents = self.db.get_incidents(status=st, severity=sev)

        for row in self.tree_inc.get_children():
            self.tree_inc.delete(row)

        for inc in incidents:
            self.tree_inc.insert("", "end", values=(
                inc["id"], inc["severity"], inc["rule_name"], inc["mitre_id"],
                inc["source_ip"], inc["status"], inc["created_at"]
            ))

    def _on_incident_select(self, event):
        sel = self.tree_inc.selection()
        if not sel:
            return
        item_vals = self.tree_inc.item(sel[0], "values")
        inc_id = int(item_vals[0])
        incidents = self.db.get_incidents()
        match = next((x for x in incidents if x["id"] == inc_id), None)
        if match:
            self.txt_incident_detail.delete("1.0", "end")
            self.txt_incident_detail.insert("1.0",
                f"ИНЦИДЕНТ #{match['id']} | {match['rule_name']} ({match['severity']})\n"
                f"Описание: {match['description']}\n"
                f"Атакующий IP: {match['source_ip']} | Целевой аккаунт: {match.get('target_user') or 'N/A'}\n"
                f"Payload / Сигнатура: {match.get('payload') or 'Комплексная цепочка событий'}\n"
            )

    def change_selected_incident_status(self, new_status):
        sel = self.tree_inc.selection()
        if not sel:
            messagebox.showwarning("Внимание", "Выберите инцидент в таблице!")
            return
        inc_id = int(self.tree_inc.item(sel[0], "values")[0])
        self.db.update_incident_status(inc_id, new_status)
        self.load_incidents_table()
        self.refresh_soc_overview()

    # ================= 3. TAB THREAT HUNTING =================
    def _build_tab_hunting(self):
        tab = self.tab_hunting
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        search_bar = ctk.CTkFrame(tab, fg_color="transparent")
        search_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=10)

        ctk.CTkLabel(search_bar, text="Фильтр по IP:").pack(side="left", padx=5)
        self.hunt_ip = ctk.CTkEntry(search_bar, placeholder_text="198.51.100.45", width=140)
        self.hunt_ip.pack(side="left", padx=5)

        ctk.CTkLabel(search_bar, text="Ключевое слово:").pack(side="left", padx=10)
        self.hunt_kw = ctk.CTkEntry(search_bar, placeholder_text="UNION / root / 404", width=200)
        self.hunt_kw.pack(side="left", padx=5)

        btn_find = ctk.CTkButton(search_bar, text="Найти", width=80, command=self.load_hunting_logs)
        btn_find.pack(side="left", padx=10)

        self.hunt_textbox = ctk.CTkTextbox(tab, font=ctk.CTkFont(family="Consolas", size=12))
        self.hunt_textbox.grid(row=1, column=0, sticky="nsew", padx=10, pady=(5, 10))
        self.load_hunting_logs()

    def load_hunting_logs(self):
        ip = self.hunt_ip.get().strip() if hasattr(self, "hunt_ip") else ""
        kw = self.hunt_kw.get().strip() if hasattr(self, "hunt_kw") else ""
        events = self.db.search_events(ip_filter=ip, keyword=kw, limit=200)

        self.hunt_textbox.delete("1.0", "end")
        for ev in events:
            self.hunt_textbox.insert("end", f"[{ev['timestamp']}] [{ev['service']:<7}] [{ev['status']:<9}] IP={ev['source_ip']:<15} {ev['message']}\n")

    # ================= 4. TAB DETECTION RULES =================
    def _build_tab_rules(self):
        tab = self.tab_rules
        tab.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(tab, text="База активных корреляционных и сигнатурных правил SIEM", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(16, 10))

        rules = [
            ("SQL Injection Attack (UNION / Blind)", "CRITICAL", "T1190", "Детектирование внедрения операторов UNION, SLEEP, INFORMATION_SCHEMA в URI"),
            ("Linux SSH Brute-Force Campaign", "HIGH", "T1110", "Корреляция: >5 неудачных попыток входа по SSH с одного IP за 60 секунд"),
            ("Path Traversal / LFI System File Access", "HIGH", "T1190", "Попытки чтения /etc/passwd, win.ini через относительные пути ../.."),
            ("Web Shell / Command Execution", "CRITICAL", "T1059", "Исполнение функций eval(), system(), cmd.exe через загруженные скрипты"),
            ("Off-Hours Privileged Account Logon", "HIGH", "T1078", "Успешный вход под root / Administrator в период с 01:00 до 05:00 ночи"),
            ("Automated Vulnerability Scanner Probe", "MEDIUM", "T1046", "Массовые запросы к чувствительным файлам (.env, wp-login, .git)"),
        ]

        for name, sev, mitre, desc in rules:
            card = ctk.CTkFrame(tab)
            card.pack(fill="x", padx=16, pady=6)
            top_line = ctk.CTkFrame(card, fg_color="transparent")
            top_line.pack(fill="x", padx=12, pady=(10, 4))

            ctk.CTkLabel(top_line, text=name, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
            sev_col = "#DC2626" if sev == "CRITICAL" else ("#EF4444" if sev == "HIGH" else "#F59E0B")
            ctk.CTkLabel(top_line, text=f" {sev} ", fg_color=sev_col, text_color="white", corner_radius=4, font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=10)
            ctk.CTkLabel(top_line, text=f"MITRE: {mitre}", text_color="#38BDF8", font=ctk.CTkFont(size=12)).pack(side="left", padx=5)

            sw = ctk.CTkSwitch(top_line, text="Активно")
            sw.select()
            sw.pack(side="right")

            ctk.CTkLabel(card, text=desc, text_color="gray", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=12, pady=(0, 10))

    # ================= 5. TAB REPORTS =================
    def _build_tab_reports(self):
        tab = self.tab_reports
        tab.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(tab, text="Генерация официального аудиторского отчета об инцидентах", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(16, 6))
        ctk.CTkLabel(tab, text="Формирует профессиональный сводный документ для Руководства / CISO с классификацией MITRE ATT&CK и рекомендациями по устранению.", text_color="gray", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=16, pady=(0, 20))

        btn_gen = ctk.CTkButton(
            tab, text="📊 Сгенерировать и открыть отчет (HTML / PDF)", height=44,
            fg_color="#10B981", hover_color="#059669", font=ctk.CTkFont(weight="bold", size=14),
            command=self.generate_report
        )
        btn_gen.pack(anchor="w", padx=16, pady=10)

        self.lbl_report_path = ctk.CTkLabel(tab, text="Отчеты сохраняются в папку reports/", text_color="gray")
        self.lbl_report_path.pack(anchor="w", padx=16, pady=6)

    def generate_report(self):
        incidents = self.db.get_incidents(limit=200)
        metrics = self.db.get_soc_metrics()
        out = SecurityReportGenerator.generate_html_report(incidents, metrics)
        self.lbl_report_path.configure(text=f"Отчет успешно создан: {out.name}", text_color="#10B981")
        webbrowser.open(out.as_uri())


if __name__ == "__main__":
    app = SentinelSIEMApp()
    app.mainloop()


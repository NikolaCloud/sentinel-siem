"""
Конфигурация и константы Sentinel SIEM.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "sentinel_siem.db"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Уровни критичности инцидентов
SEVERITY_LEVELS = {
    "INFO": {"color": "#94A3B8", "weight": 0},
    "LOW": {"color": "#3B82F6", "weight": 1},
    "MEDIUM": {"color": "#F59E0B", "weight": 2},
    "HIGH": {"color": "#EF4444", "weight": 3},
    "CRITICAL": {"color": "#DC2626", "weight": 4},
}

# Маппинг техник MITRE ATT&CK
MITRE_TACTICS = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1190": {"name": "Exploit Public-Facing Application (SQLi / LFI)", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1078": {"name": "Valid Accounts (Suspicious Login)", "tactic": "Defense Evasion"},
    "T1046": {"name": "Network Service Discovery (Port Scan)", "tactic": "Discovery"},
    "T1505": {"name": "Server Software Component (Web Shell)", "tactic": "Persistence"},
}

DEFAULT_RULES_CONFIG = {
    "brute_force_threshold": 5,      # неудачных попыток входа
    "brute_force_window_sec": 60,    # за 60 секунд
    "port_scan_threshold": 8,        # разных URL/портов за 30 секунд
    "off_hours_start": 1,            # 01:00 ночи
    "off_hours_end": 5,              # 05:00 утра
}


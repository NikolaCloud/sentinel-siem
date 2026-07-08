"""
Хранилище данных SQLite для Sentinel SIEM: события безопасности, инциденты и аудит.
"""

from datetime import datetime
import json
import sqlite3
from typing import Any, Dict, List, Optional
from sentinel.config import DB_PATH
from sentinel.engine.correlation_engine import CorrelationEngine
from sentinel.engine.signature_rules import SignatureEngine
from sentinel.parsers.base_parser import ParsedEvent
from sentinel.parsers.syslog_parser import SyslogParser
from sentinel.parsers.web_parser import WebLogParser
from sentinel.parsers.windows_parser import WindowsEventParser


class SIEMDatabaseManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self.parsers = [WebLogParser(), SyslogParser(), WindowsEventParser()]
        self.correlation_engine = CorrelationEngine()
        self.init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    service TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    user TEXT,
                    message TEXT NOT NULL,
                    raw_log TEXT NOT NULL
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_user TEXT,
                    description TEXT NOT NULL,
                    payload TEXT,
                    status TEXT NOT NULL DEFAULT 'NEW',
                    created_at TEXT NOT NULL,
                    analyst_notes TEXT
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
            conn.commit()

    def ingest_log_line(self, line: str) -> Optional[ParsedEvent]:
        for parser in self.parsers:
            ev = parser.parse_line(line)
            if ev:
                self._save_event(ev)
                # Проверка сигнатур атак
                matches = SignatureEngine.check_payload(ev.raw_log)
                for m in matches:
                    self.create_incident(
                        rule_name=m.rule_name,
                        severity=m.severity,
                        mitre_id=m.mitre_id,
                        source_ip=ev.source_ip,
                        target_user=ev.user,
                        description=m.description,
                        payload=m.matched_payload
                    )
                return ev
        return None

    def _save_event(self, ev: ParsedEvent):
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO events (timestamp, source_ip, service, event_type, status, user, message, raw_log)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ev.timestamp, ev.source_ip, ev.service, ev.event_type, ev.status, ev.user, ev.message, ev.raw_log))
            conn.commit()

    def create_incident(self, rule_name: str, severity: str, mitre_id: str,
                        source_ip: str, target_user: Optional[str],
                        description: str, payload: Optional[str] = None):
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO incidents (rule_name, severity, mitre_id, source_ip, target_user, description, payload, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (rule_name, severity, mitre_id, source_ip, target_user, description, payload, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()

    def run_correlation_scan(self):
        """Анализирует последние события на наличие цепочек атак (Brute-force и др.)."""
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 500")
            rows = c.fetchall()
            events = [
                ParsedEvent(
                    timestamp=r["timestamp"], source_ip=r["source_ip"], service=r["service"],
                    event_type=r["event_type"], status=r["status"], user=r["user"],
                    message=r["message"], raw_log=r["raw_log"]
                ) for r in rows
            ]

        alerts = self.correlation_engine.analyze_events(events)
        for a in alerts:
            # Проверка, нет ли уже такого незакрытого инцидента
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT id FROM incidents WHERE rule_name = ? AND source_ip = ? AND status != 'RESOLVED'", (a.rule_name, a.source_ip))
                if not c.fetchone():
                    self.create_incident(
                        rule_name=a.rule_name,
                        severity=a.severity,
                        mitre_id=a.mitre_id,
                        source_ip=a.source_ip,
                        target_user=a.target_user,
                        description=a.description,
                        payload=f"Total events correlated: {a.event_count}"
                    )

    def get_incidents(self, status: Optional[str] = None, severity: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            c = conn.cursor()
            q = "SELECT * FROM incidents WHERE 1=1"
            params = []
            if status and status != "ВСЕ":
                q += " AND status = ?"
                params.append(status)
            if severity and severity != "ВСЕ":
                q += " AND severity = ?"
                params.append(severity)
            q += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            c.execute(q, params)
            return [dict(r) for r in c.fetchall()]

    def update_incident_status(self, incident_id: int, new_status: str, notes: Optional[str] = None):
        with self._get_connection() as conn:
            c = conn.cursor()
            if notes:
                c.execute("UPDATE incidents SET status = ?, analyst_notes = ? WHERE id = ?", (new_status, notes, incident_id))
            else:
                c.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
            conn.commit()

    def get_soc_metrics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM events")
            total_events = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM incidents")
            total_incidents = c.fetchone()[0]

            c.execute("SELECT COUNT(DISTINCT source_ip) FROM incidents")
            unique_attackers = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL'")
            critical_count = c.fetchone()[0]

            # Топ атакующих IP
            c.execute("SELECT source_ip, COUNT(*) as cnt FROM incidents GROUP BY source_ip ORDER BY cnt DESC LIMIT 5")
            top_ips = [dict(r) for r in c.fetchall()]

            # Распределение по MITRE
            c.execute("SELECT mitre_id, COUNT(*) as cnt FROM incidents GROUP BY mitre_id ORDER BY cnt DESC")
            mitre_dist = [dict(r) for r in c.fetchall()]

            return {
                "total_events": total_events,
                "total_incidents": total_incidents,
                "unique_attackers": unique_attackers,
                "critical_count": critical_count,
                "top_ips": top_ips,
                "mitre_dist": mitre_dist
            }

    def search_events(self, ip_filter: str = "", keyword: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            c = conn.cursor()
            q = "SELECT * FROM events WHERE 1=1"
            params = []
            if ip_filter:
                q += " AND source_ip LIKE ?"
                params.append(f"%{ip_filter}%")
            if keyword:
                q += " AND (message LIKE ? OR raw_log LIKE ?)"
                params.append(f"%{keyword}%")
                params.append(f"%{keyword}%")
            q += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            c.execute(q, params)
            return [dict(r) for r in c.fetchall()]


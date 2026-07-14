"""
Корреляционный анализ временных окон и цепочек атак (Brute-force, сканирование, аномальные входы).
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional
from sentinel.config import DEFAULT_RULES_CONFIG
from sentinel.parsers.base_parser import ParsedEvent


@dataclass
class CorrelatedAlert:
    rule_name: str
    severity: str
    mitre_id: str
    source_ip: str
    target_user: Optional[str]
    event_count: int
    description: str
    first_seen: str
    last_seen: str


class CorrelationEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or DEFAULT_RULES_CONFIG

    def analyze_events(self, events: List[ParsedEvent]) -> List[CorrelatedAlert]:
        alerts = []

        # 1. Анализ Brute Force (SSH / Windows)
        ip_failures = defaultdict(list)
        for ev in events:
            if ev.event_type == "AUTH_FAIL":
                ip_failures[ev.source_ip].append(ev)

        bf_threshold = self.config.get("brute_force_threshold", 5)
        for ip, fail_events in ip_failures.items():
            if len(fail_events) >= bf_threshold:
                users_targeted = list(set(e.user for e in fail_events if e.user))
                alerts.append(CorrelatedAlert(
                    rule_name="Distributed / SSH Brute-Force Attack",
                    severity="HIGH",
                    mitre_id="T1110",
                    source_ip=ip,
                    target_user=", ".join(users_targeted[:3]) if users_targeted else "N/A",
                    event_count=len(fail_events),
                    description=f"Обнаружен подбор паролей: {len(fail_events)} неудачных попыток с IP {ip}.",
                    first_seen=fail_events[0].timestamp,
                    last_seen=fail_events[-1].timestamp
                ))

        # 2. Анализ сканирования директорий / портов
        ip_requests = defaultdict(set)
        for ev in events:
            if ev.service == "NGINX" and ("404" in ev.message or "403" in ev.message):
                ip_requests[ev.source_ip].add(ev.message)

        scan_threshold = self.config.get("port_scan_threshold", 8)
        for ip, endpoints in ip_requests.items():
            if len(endpoints) >= scan_threshold:
                alerts.append(CorrelatedAlert(
                    rule_name="Automated Vulnerability / Endpoint Scanner",
                    severity="MEDIUM",
                    mitre_id="T1046",
                    source_ip=ip,
                    target_user=None,
                    event_count=len(endpoints),
                    description=f"Обнаружено автоматизированное сканирование: {len(endpoints)} запросов к несуществующим эндпоинтам.",
                    first_seen=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    last_seen=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))

        # 3. Аномальный вход в нерабочие часы (01:00 - 05:00)
        off_start = self.config.get("off_hours_start", 1)
        off_end = self.config.get("off_hours_end", 5)

        for ev in events:
            if ev.event_type == "AUTH_SUCCESS" and ev.user in ["root", "Administrator", "admin"]:
                try:
                    dt = datetime.strptime(ev.timestamp, "%Y-%m-%d %H:%M:%S")
                    if off_start <= dt.hour <= off_end:
                        alerts.append(CorrelatedAlert(
                            rule_name="Off-Hours Privileged Account Logon",
                            severity="HIGH",
                            mitre_id="T1078",
                            source_ip=ev.source_ip,
                            target_user=ev.user,
                            event_count=1,
                            description=f"Вход под привилегированным аккаунтом '{ev.user}' в нерабочее время ({dt.strftime('%H:%M:%S')}).",
                            first_seen=ev.timestamp,
                            last_seen=ev.timestamp
                        ))
                except Exception:
                    pass

        return alerts


"""
Сигнатурный анализ полезной нагрузки (Web Attacks, SQLi, XSS, Path Traversal).
"""

from dataclasses import dataclass
import re
from typing import List, Optional


@dataclass
class SignatureMatch:
    rule_name: str
    severity: str        # LOW, MEDIUM, HIGH, CRITICAL
    mitre_id: str
    description: str
    matched_payload: str


class SignatureEngine:
    RULES = [
        {
            "name": "SQL Injection (Union/Blind)",
            "pattern": re.compile(r"(\bUNION\b.*\bSELECT\b|\bOR\b\s+['\d]+=['\d]+|WAITFOR\s+DELAY|SLEEP\(\d+\)|INFORMATION_SCHEMA)", re.I),
            "severity": "CRITICAL",
            "mitre_id": "T1190",
            "desc": "Обнаружена попытка внедрения SQL-кода в параметр запроса."
        },
        {
            "name": "Path Traversal / LFI Attempt",
            "pattern": re.compile(r"(\.\./\.\.|%2e%2e%2f|/etc/(?:passwd|shadow)|boot\.ini|win\.ini)", re.I),
            "severity": "HIGH",
            "mitre_id": "T1190",
            "desc": "Попытка несанкционированного доступа к файловой системе сервера (чтение системных файлов)."
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "pattern": re.compile(r"(<script\b|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie)", re.I),
            "severity": "MEDIUM",
            "mitre_id": "T1190",
            "desc": "Внедрение вредоносного клиентского сценария (XSS payload)."
        },
        {
            "name": "Web Shell Execution / Command Injection",
            "pattern": re.compile(r"(\b(eval|base64_decode|passthru|shell_exec|system)\s*\(|cmd\.exe|/bin/(?:sh|bash)|\.php\?cmd=)", re.I),
            "severity": "CRITICAL",
            "mitre_id": "T1059",
            "desc": "Попытка исполнения команд ОС через загруженный веб-шелл."
        },
        {
            "name": "Sensitive Config File Probe",
            "pattern": re.compile(r"(\.env|\.git/config|wp-config\.php|server\.xml|web\.config)", re.I),
            "severity": "MEDIUM",
            "mitre_id": "T1190",
            "desc": "Сканирование конфигурационных файлов с учетными данными."
        }
    ]

    @classmethod
    def check_payload(cls, text: str) -> List[SignatureMatch]:
        matches = []
        if not text:
            return matches

        for rule in cls.RULES:
            match = rule["pattern"].search(text)
            if match:
                matches.append(SignatureMatch(
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre_id=rule["mitre_id"],
                    description=rule["desc"],
                    matched_payload=match.group(0)
                ))
        return matches

